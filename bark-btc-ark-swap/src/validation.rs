use std::collections::{HashMap, HashSet};

use anyhow::{Context, bail};
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{SecretKey, schnorr};
use bitcoin::{FeeRate, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use serde::Serialize;

use ark::{Vtxo, VtxoPolicy};
use ark::arkoor::package::TransferableAdaptorArkoorPackage;
use ark::vtxo::Full;
use bark::Wallet;
use bark::swap::btc_ark::{ArkOffer, BtcLockContract};
use bitcoin_ext::{BlockRef, TxStatus};

/// Check the promised inputs and their live ancestry after public package verification.
pub(crate) async fn verify_live_ark_transfer(
	wallet: &Wallet,
	offer: &ArkOffer,
	transfer: &TransferableAdaptorArkoorPackage,
	refund_height: u32,
	safety_margin_blocks: u32,
) -> anyhow::Result<()> {
	if transfer.packages().is_empty()
		|| !transfer.input_ids().eq(offer.ark_input_ids.iter().copied())
	{
		bail!("Ark transfer input IDs do not match the offer");
	}
	for package in transfer.packages() {
		if package.input().server_pubkey() != offer.ark_server_pubkey {
			bail!(
				"Ark swap input {} has the wrong server key",
				package.input().id()
			);
		}
	}
	verify_live_ark_inputs(
		wallet,
		transfer.packages().iter().map(|package| package.input()),
		refund_height,
		safety_margin_blocks,
	)
	.await
}

/// Check selected inputs before cosigning, and again before releasing BTC funding.
///
/// An ordinary honest operator's valid policy issuance, a current trusted chain
/// backend, bounded inclusion/reorgs, and continuous refund monitoring are still
/// required. Historical arkoor tweaks do not disclose their entire script trees.
/// This check does not promise safety while the BTC payer remains offline.
pub(crate) async fn verify_live_ark_inputs<'a>(
	wallet: &Wallet,
	inputs: impl IntoIterator<Item = &'a Vtxo<Full>>,
	refund_height: u32,
	safety_margin_blocks: u32,
) -> anyhow::Result<()> {
	let tip = wallet.chain().tip_ref().await?;
	verify_refund_window(tip.height.to_u32(), refund_height, safety_margin_blocks)?;
	let refund_safe_height = refund_height
		.checked_add(safety_margin_blocks)
		.context("refund safety height overflow")?;
	let mut input_points = HashSet::new();

	let mut anchor_txs = HashMap::<Txid, Transaction>::new();
	let mut anchor_outputs = HashMap::<OutPoint, TxOut>::new();
	let mut ancestor_spends = HashMap::<OutPoint, Txid>::new();
	let mut ancestor_txids = HashSet::new();
	for input in inputs {
		if !input_points.insert(input.point()) {
			bail!("duplicate Ark transfer input {}", input.id());
		}
		if !matches!(input.policy(), VtxoPolicy::Pubkey(_)) {
			bail!("Ark swap input {} must have a pubkey policy", input.id());
		}
		if input.expiry_height() <= refund_safe_height.into() {
			bail!(
				"Ark swap input {} expires before the refund safety deadline",
				input.id()
			);
		}
		let earliest_old_state_spend = tip
			.height
			.to_u32()
			.checked_add(u32::from(input.exit_delta()))
			.context("Ark exit deadline overflow")?;
		if refund_safe_height >= earliest_old_state_spend {
			bail!(
				"BTC refund safety deadline reaches Ark input {} exit maturity",
				input.id()
			);
		}

		let anchor = input.chain_anchor();
		// An on-chain input's CSV clock has already started. The fresh-tip
		// inequality is only sound for an entirely off-chain exit path.
		if input.point() == anchor {
			bail!("Ark swap input {} is already on chain", input.id());
		}
		if let std::collections::hash_map::Entry::Vacant(entry) = anchor_txs.entry(anchor.txid) {
			confirmed_block(wallet, anchor.txid, tip).await?;
			let tx = wallet
				.chain()
				.get_tx(&anchor.txid)
				.await?
				.with_context(|| format!("unknown Ark chain anchor {}", anchor))?;
			if tx.compute_txid() != anchor.txid {
				bail!("incorrect Ark chain anchor transaction for {}", anchor);
			}
			entry.insert(tx);
		}
		let anchor_tx = &anchor_txs[&anchor.txid];
		// Validate before transactions(): invalid genesis amounts can otherwise
		// panic when the transaction iterator reconstructs the path.
		input
			.validate(anchor_tx)
			.with_context(|| format!("invalid full genesis for Ark input {}", input.id()))?;
		let anchor_output = anchor_tx
			.output
			.get(anchor.vout as usize)
			.context("Ark chain anchor output is out of range")?;
		anchor_outputs
			.entry(anchor)
			.or_insert_with(|| anchor_output.clone());

		for ancestor in input.transactions() {
			let txid = ancestor.tx.compute_txid();
			let output = ancestor
				.tx
				.output
				.get(ancestor.output_idx)
				.context("Ark genesis output index is out of range")?;
			if OutPoint::new(txid, ancestor.output_idx as u32) == input.point()
				&& *output != input.txout()
			{
				bail!(
					"Ark genesis final output does not match input {}",
					input.id()
				);
			}
			for txin in &ancestor.tx.input {
				if let Some(previous_txid) = ancestor_spends.insert(txin.previous_output, txid) {
					if previous_txid != txid {
						bail!(
							"Ark swap inputs have conflicting ancestry at {}",
							txin.previous_output
						);
					}
				}
			}
			// Shared ancestry is legitimate; only query each transaction once.
			if ancestor_txids.insert(txid) {
				if wallet.chain().tx_status(txid).await? != TxStatus::NotFound {
					bail!(
						"Ark input {} has an already-published exit ancestor {}",
						input.id(),
						txid
					);
				}
			}
		}
	}
	if input_points.is_empty() {
		bail!("Ark swap requires at least one input");
	}
	if input_points
		.iter()
		.any(|point| ancestor_spends.contains_key(point))
	{
		bail!("an Ark swap input is an ancestor of another input");
	}

	// A spent root also detects conflicting old-state exits not present in the
	// supplied genesis. Do this last to minimize the unobserved race window.
	for (anchor, expected) in anchor_outputs {
		let actual = wallet
			.chain()
			.unspent_txout(anchor)
			.await?
			.with_context(|| format!("Ark chain anchor {} is spent or unknown", anchor))?;
		if actual != expected {
			bail!(
				"Ark chain anchor {} does not match its confirmed transaction",
				anchor
			);
		}
	}
	ensure_unchanged_tip(wallet, tip).await
}

/// Validate the public, txid-stable funding template against live Bitcoin UTXOs.
/// Witnesses need not be present: Bob signs only his locally stored PSBT later.
pub(crate) async fn verify_funding_inputs(
	wallet: &Wallet,
	tx: &Transaction,
	prevouts: &[TxOut],
) -> anyhow::Result<()> {
	if tx.input.is_empty() || tx.input.len() != prevouts.len() {
		bail!("funding transaction input/prevout count mismatch");
	}
	let tip = wallet.chain().tip_ref().await?;
	let mut inputs = HashSet::new();
	let mut confirmed = HashSet::new();
	for (input, expected) in tx.input.iter().zip(prevouts) {
		let outpoint = input.previous_output;
		if !inputs.insert(outpoint) {
			bail!("duplicate funding input {}", outpoint);
		}
		if !input.script_sig.is_empty() {
			bail!("funding input {} has a nonempty scriptSig", outpoint);
		}
		let script = &expected.script_pubkey;
		if !(script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr()) {
			bail!("funding input {} is not native SegWit", outpoint);
		}
		if confirmed.insert(outpoint.txid) {
			confirmed_block(wallet, outpoint.txid, tip).await?;
		}
		let actual = wallet
			.chain()
			.unspent_txout(outpoint)
			.await?
			.with_context(|| format!("funding input {} is spent or unknown", outpoint))?;
		if actual != *expected {
			bail!(
				"funding input {} does not match its declared prevout",
				outpoint
			);
		}
	}
	ensure_unchanged_tip(wallet, tip).await
}

/// Alice may release the adaptor secret only after sufficiently deep funding,
/// while the exact lock is unspent and enough time remains before Bob's refund.
pub(crate) async fn verify_claim_window(
	wallet: &Wallet,
	funding_outpoint: OutPoint,
	lock: &BtcLockContract,
	minimum_funding_confirmations: u32,
	safety_margin_blocks: u32,
) -> anyhow::Result<()> {
	if minimum_funding_confirmations == 0 {
		bail!("minimum funding confirmations must be positive");
	}
	let tip = wallet.chain().tip_ref().await?;
	verify_refund_window(tip.height.to_u32(), lock.refund_height.to_u32(), safety_margin_blocks)?;
	let funding_block = confirmed_block(wallet, funding_outpoint.txid, tip).await?;
	let confirmations = tip
		.height
		.checked_blocks_since(funding_block.height)
		.map(|depth| depth.saturating_add(1))
		.context("funding confirmation count overflow")?;
	if confirmations < minimum_funding_confirmations {
		bail!(
			"BTC funding has {} confirmations; need {}",
			confirmations,
			minimum_funding_confirmations
		);
	}
	let output = wallet
		.chain()
		.unspent_txout(funding_outpoint)
		.await?
		.context("BTC funding output is spent or unknown")?;
	if output != lock.txout() {
		bail!("BTC funding output does not match the agreed swap lock");
	}
	ensure_unchanged_tip(wallet, tip).await
}

fn verify_refund_window(
	tip_height: u32,
	refund_height: u32,
	safety_margin_blocks: u32,
) -> anyhow::Result<()> {
	if safety_margin_blocks == 0 {
		bail!("safety margin must be positive");
	}
	bitcoin::absolute::LockTime::from_height(refund_height)
		.context("BTC refund must use an absolute block height")?;
	let deadline = tip_height
		.checked_add(safety_margin_blocks)
		.context("claim safety deadline overflow")?;
	if deadline >= refund_height {
		bail!("insufficient time before the BTC refund height");
	}
	Ok(())
}

async fn confirmed_block(wallet: &Wallet, txid: Txid, tip: BlockRef) -> anyhow::Result<BlockRef> {
	let TxStatus::Confirmed(block) = wallet.chain().tx_status(txid).await? else {
		bail!("transaction {} is not confirmed", txid);
	};
	if block.height > tip.height || wallet.chain().block_ref(block.height).await? != block {
		bail!("transaction {} is not confirmed in the current chain", txid);
	}
	Ok(block)
}

async fn ensure_unchanged_tip(wallet: &Wallet, tip: BlockRef) -> anyhow::Result<()> {
	if wallet.chain().tip_ref().await? != tip {
		bail!("chain tip changed during swap validation; retry with the current chain");
	}
	Ok(())
}

pub(crate) fn fee_rate_from_sat_vb(fee_rate: u64) -> anyhow::Result<FeeRate> {
	if fee_rate == 0 {
		bail!("fee-rate must be greater than zero");
	}
	Ok(FeeRate::from_sat_per_vb_u32(
		u32::try_from(fee_rate).context("fee-rate is too large")?,
	))
}

pub(crate) fn hash_json_hex<T: Serialize>(value: &T) -> anyhow::Result<String> {
	let bytes = serde_json::to_vec(value).context("failed to serialize value for hash")?;
	Ok(bytes_hex(
		&bitcoin::hashes::sha256::Hash::hash(&bytes).to_byte_array(),
	))
}

pub(crate) fn bytes_hex(bytes: &[u8]) -> String {
	bytes.as_hex().to_string()
}

pub(crate) fn bytes_from_hex(hex: &str) -> anyhow::Result<Vec<u8>> {
	Vec::<u8>::from_hex(hex).context("invalid hex")
}

pub(crate) fn bytes32_from_hex(hex: &str) -> anyhow::Result<[u8; 32]> {
	bytes_from_hex(hex)?
		.try_into()
		.map_err(|_| anyhow::anyhow!("expected 32-byte hex string"))
}

pub(crate) fn script_from_hex(hex: &str) -> anyhow::Result<ScriptBuf> {
	Ok(ScriptBuf::from_bytes(bytes_from_hex(hex)?))
}

pub(crate) fn secret_key_hex(secret_key: SecretKey) -> String {
	bytes_hex(&secret_key.secret_bytes())
}

pub(crate) fn secret_key_from_hex(hex: &str) -> anyhow::Result<SecretKey> {
	SecretKey::from_slice(&bytes32_from_hex(hex)?).context("invalid secret key")
}

pub(crate) fn signature_from_hex(hex: &str) -> anyhow::Result<schnorr::Signature> {
	schnorr::Signature::from_slice(&bytes_from_hex(hex)?).context("invalid schnorr signature")
}

pub(crate) fn public_nonce_from_hex(hex: &str) -> anyhow::Result<ark::musig::PublicNonce> {
	let bytes = bytes_from_hex(hex)?;
	let bytes = <[u8; 66]>::try_from(bytes.as_slice())
		.map_err(|_| anyhow::anyhow!("expected 66-byte MuSig public nonce"))?;
	ark::musig::PublicNonce::from_byte_array(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
}

pub(crate) fn partial_sig_from_hex(hex: &str) -> anyhow::Result<ark::musig::PartialSignature> {
	let bytes = bytes_from_hex(hex)?;
	let bytes = <[u8; 32]>::try_from(bytes.as_slice())
		.map_err(|_| anyhow::anyhow!("expected 32-byte MuSig partial signature"))?;
	ark::musig::PartialSignature::from_byte_array(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
}
