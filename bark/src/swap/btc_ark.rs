//! Bark-native BTC-to-Ark VTXO PTLC swap primitives.
//!
//! This module keeps wallet-side protocol primitives and signing helpers. Relay
//! and communication orchestration live outside the wallet crate.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, XOnlyPublicKey, schnorr};
use bitcoin::{
	Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
	TxOut, Witness, absolute::LockTime, sighash, taproot, transaction::Version,
};
use bitcoin_ext::{BlockHeight, P2TR_DUST, TaprootSpendInfoExt, TxOutExt, fee};

use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::{
	ArkoorPackageBuilder, ArkoorPackageCosignResponse, TransferPackageVerificationError,
	TransferableAdaptorArkoorPackage,
};
use ark::musig::{self, AdaptorPreSignature, AdaptorSecret};
use ark::vtxo::Full;
use ark::{Vtxo, VtxoId, VtxoPolicy};
use server_rpc::protos;

use crate::{ImportVtxoArgs, Wallet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SwapId([u8; 32]);

impl SwapId {
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	pub fn random() -> Self {
		Self(rand::random())
	}

	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

impl fmt::Display for SwapId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		for byte in self.0 {
			write!(f, "{:02x}", byte)?;
		}
		Ok(())
	}
}

impl FromStr for SwapId {
	type Err = SwapIdParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != 64 {
			return Err(SwapIdParseError);
		}

		let mut bytes = [0u8; 32];
		for (idx, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
			let hi = decode_hex_nibble(chunk[0]).ok_or(SwapIdParseError)?;
			let lo = decode_hex_nibble(chunk[1]).ok_or(SwapIdParseError)?;
			bytes[idx] = (hi << 4) | lo;
		}

		Ok(Self(bytes))
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwapIdParseError;

impl fmt::Display for SwapIdParseError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("invalid swap id")
	}
}

impl std::error::Error for SwapIdParseError {}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwapRole {
	BtcPayer,
	ArkPayer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwapStatus {
	Requested,
	Offered,
	BtcClaimReady,
	BtcClaimed,
	ArkCompleted,
	Refunded,
	Cancelled,
	ArkRecovering,
	ArkReclaimed,
}

#[derive(Clone, Debug)]
pub struct ArkOffer {
	pub id: SwapId,
	pub amount: Amount,
	pub btc_payout_script: ScriptBuf,
	pub ark_input_ids: Vec<VtxoId>,
	pub ark_receive_policy: VtxoPolicy,
	pub ark_server_pubkey: PublicKey,
	pub adaptor_point: PublicKey,
}

pub struct PreparedArkSwapPackage {
	pub offer: ArkOffer,
	pub transfer: TransferableAdaptorArkoorPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArkTransferOfferError {
	#[error("Ark transfer swap id mismatch: expected {expected}, got {got}")]
	SwapIdMismatch { expected: SwapId, got: SwapId },
	#[error("Ark transfer amount mismatch: expected {expected}, got {got}")]
	AmountMismatch { expected: Amount, got: Amount },
	#[error("Ark transfer BTC payout script mismatch")]
	BtcPayoutScriptMismatch,
	#[error("Ark transfer receive policy mismatch")]
	ArkReceivePolicyMismatch,
	#[error("Ark transfer server pubkey mismatch: expected {expected}, got {got}")]
	ServerPubkeyMismatch { expected: PublicKey, got: PublicKey },
	#[error("Ark transfer adaptor point mismatch: expected {expected}, got {got}")]
	AdaptorPointMismatch { expected: PublicKey, got: PublicKey },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArkTransferAcceptanceOptions {
	pub allow_short_output_expiry: bool,
}

#[derive(Clone, Debug)]
pub struct BtcLockContract {
	pub amount: Amount,
	pub refund_height: BlockHeight,
	pub refund_script: ScriptBuf,
	pub taproot: taproot::TaprootSpendInfo,
	pub address: Address,
}

impl BtcLockContract {
	pub fn new(
		amount: Amount,
		network: Network,
		btc_payer_pubkey: PublicKey,
		ark_payer_pubkey: PublicKey,
		refund_pubkey: XOnlyPublicKey,
		refund_height: BlockHeight,
	) -> Result<Self> {
		LockTime::from_height(refund_height.into()).context("invalid BTC refund block height")?;
		let aggregate_key = musig::combine_keys([btc_payer_pubkey, ark_payer_pubkey])
			.x_only_public_key()
			.0;
		let refund_script = ark::scripts::timelock_sign(refund_height, refund_pubkey);
		let taproot = taproot::TaprootBuilder::new()
			.add_leaf(0, refund_script.clone())
			.expect("valid refund leaf")
			.finalize(&ark::SECP, aggregate_key)
			.expect("valid taproot tree");
		let address = Address::from_script(&taproot.script_pubkey(), network)
			.expect("taproot script has an address");

		Ok(Self {
			amount,
			refund_height,
			refund_script,
			taproot,
			address,
		})
	}

	pub fn funding_destination(&self) -> (Address, Amount) {
		(self.address.clone(), self.amount)
	}

	pub fn txout(&self) -> TxOut {
		TxOut {
			value: self.amount,
			script_pubkey: self.address.script_pubkey(),
		}
	}

	pub fn refund_sequence(&self) -> Sequence {
		Sequence::ENABLE_RBF_NO_LOCKTIME
	}

	pub fn refund_is_mature(&self, tip: BlockHeight) -> bool {
		tip >= self.refund_height
	}

}

#[derive(Clone, Debug)]
pub struct BtcClaimAdaptorPackage {
	pub adaptor_point: PublicKey,
	pub aggregate_key: XOnlyPublicKey,
	pub sighash: [u8; 32],
	pub pre_signature: AdaptorPreSignature,
}

impl BtcClaimAdaptorPackage {
	pub fn verify(&self) -> Result<()> {
		self.pre_signature
			.verify_adaptor(self.adaptor_point, self.aggregate_key, self.sighash)
			.context("BTC claim adaptor pre-signature does not verify against T")
	}

	pub fn finalize_with_secret(&self, secret: AdaptorSecret) -> Result<schnorr::Signature> {
		self.verify()?;
		Ok(self
			.pre_signature
			.finalize_with_secret(secret, self.aggregate_key, self.sighash)?)
	}

	pub fn recover_secret(&self, final_sig: schnorr::Signature) -> Result<AdaptorSecret> {
		ark::SECP
			.verify_schnorr(
				&final_sig,
				&Message::from_digest(self.sighash),
				&self.aggregate_key,
			)
			.context("final BTC claim signature does not verify")?;
		Ok(self
			.pre_signature
			.recover_secret(final_sig, self.adaptor_point)?)
	}
}

pub fn build_cooperative_claim_tx(
	funding_outpoint: OutPoint,
	btc_lock: &BtcLockContract,
	btc_payout_script: ScriptBuf,
	fee_rate: FeeRate,
) -> Result<Transaction> {
	let mut tx = Transaction {
		version: Version(3),
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: funding_outpoint,
			script_sig: ScriptBuf::new(),
			sequence: Sequence::MAX,
			witness: Witness::new(),
		}],
		output: vec![
			TxOut {
				value: btc_lock.amount,
				script_pubkey: btc_payout_script,
			},
			fee::fee_anchor_with_amount(P2TR_DUST),
		],
	};

	let mut fee_probe = tx.clone();
	fee_probe.input[0].witness.push([0u8; 64]);
	let fee = fee_rate
		.checked_mul_by_weight(fee_probe.weight())
		.context("BTC claim fee computation overflow")?;
	tx.output[0].value = btc_lock
		.amount
		.checked_sub(P2TR_DUST)
		.and_then(|amount| amount.checked_sub(fee))
		.with_context(|| {
			format!(
				"BTC claim fee {fee} and anchor {P2TR_DUST} exceed locked amount {}",
				btc_lock.amount,
			)
		})?;
	if !tx.output[0].is_standard() {
		bail!(
			"BTC claim output {} to {} is non-standard after subtracting fee {fee}",
			tx.output[0].value,
			tx.output[0].script_pubkey,
		);
	}
	Ok(tx)
}

pub fn cooperative_claim_sighash(
	claim_tx: &Transaction,
	btc_lock: &BtcLockContract,
) -> Result<[u8; 32]> {
	Ok(sighash::SighashCache::new(claim_tx)
		.taproot_key_spend_signature_hash(
			0,
			&sighash::Prevouts::All(&[btc_lock.txout()]),
			sighash::TapSighashType::Default,
		)
		.context("failed to compute BTC claim key-spend sighash")?
		.to_byte_array())
}

pub fn build_refund_tx(
	funding_outpoint: OutPoint,
	btc_lock: &BtcLockContract,
	refund_script_pubkey: ScriptBuf,
	fee_rate: FeeRate,
) -> Result<Transaction> {
	let mut tx = Transaction {
		version: Version::TWO,
		lock_time: LockTime::from_height(btc_lock.refund_height.into())
			.context("invalid BTC refund block height")?,
		input: vec![TxIn {
			previous_output: funding_outpoint,
			script_sig: ScriptBuf::new(),
			sequence: btc_lock.refund_sequence(),
			witness: Witness::new(),
		}],
		output: vec![TxOut {
			value: btc_lock.amount,
			script_pubkey: refund_script_pubkey,
		}],
	};

	let control_block = btc_lock
		.taproot
		.control_block(&(
			btc_lock.refund_script.clone(),
			taproot::LeafVersion::TapScript,
		))
		.context("BTC refund script is not in taproot tree")?;
	let control_block_bytes = control_block.serialize();

	let mut fee_probe = tx.clone();
	let dummy_signature = [0u8; 64];
	let witness_items: [&[u8]; 3] = [
		dummy_signature.as_slice(),
		btc_lock.refund_script.as_bytes(),
		control_block_bytes.as_slice(),
	];
	fee_probe.input[0].witness = Witness::from_slice(&witness_items);
	let fee = fee_rate
		.checked_mul_by_weight(fee_probe.weight())
		.context("BTC refund fee computation overflow")?;
	tx.output[0].value = btc_lock.amount.checked_sub(fee).with_context(|| {
		format!(
			"BTC refund fee {fee} exceeds locked amount {}",
			btc_lock.amount
		)
	})?;
	if !tx.output[0].is_standard() {
		bail!(
			"BTC refund output {} to {} is non-standard after subtracting fee {fee}",
			tx.output[0].value,
			tx.output[0].script_pubkey,
		);
	}

	Ok(tx)
}

pub fn sign_refund_tx(
	mut refund_tx: Transaction,
	btc_lock: &BtcLockContract,
	refund_keypair: &Keypair,
) -> Result<Transaction> {
	let control_block = btc_lock
		.taproot
		.control_block(&(
			btc_lock.refund_script.clone(),
			taproot::LeafVersion::TapScript,
		))
		.context("BTC refund script is not in taproot tree")?;
	let leaf_hash =
		taproot::TapLeafHash::from_script(&btc_lock.refund_script, taproot::LeafVersion::TapScript);
	let sighash = sighash::SighashCache::new(&refund_tx)
		.taproot_script_spend_signature_hash(
			0,
			&sighash::Prevouts::All(&[btc_lock.txout()]),
			leaf_hash,
			sighash::TapSighashType::Default,
		)
		.context("failed to compute BTC refund script-spend sighash")?;
	let signature = ark::SECP.sign_schnorr_with_aux_rand(
		&Message::from_digest(sighash.to_byte_array()),
		refund_keypair,
		&rand::random(),
	);
	let control_block_bytes = control_block.serialize();
	refund_tx.input[0].witness = Witness::from_slice(&[
		&signature[..],
		btc_lock.refund_script.as_bytes(),
		&control_block_bytes,
	]);

	Ok(refund_tx)
}

/// Sign Alice's BTC claim share, hiding the adaptor point in her public nonce.
///
/// Bob's ordinary nonce can be fixed before the funding and claim transactions
/// are known. Alice creates a fresh nonce for this exact claim; callers must
/// persist and replay this response instead of signing a changed transcript.
pub fn sign_cooperative_claim_adaptor_partial(
	ark_payer_keypair: &Keypair,
	btc_payer_pubkey: PublicKey,
	btc_payer_public_nonce: &musig::PublicNonce,
	sighash: [u8; 32],
	tap_tweak: Option<[u8; 32]>,
	adaptor_point: PublicKey,
) -> Result<(musig::PublicNonce, musig::PartialSignature)> {
	let (secret_nonce, public_nonce) =
		musig::adaptor_nonce_pair_with_msg(ark_payer_keypair, &sighash, adaptor_point)?;
	let aggregate_nonce = musig::nonce_agg(&[btc_payer_public_nonce, &public_nonce]);
	let (partial_sig, _) = musig::partial_sign(
		[btc_payer_pubkey, ark_payer_keypair.public_key()],
		aggregate_nonce,
		ark_payer_keypair,
		secret_nonce,
		sighash,
		tap_tweak,
		None,
	);
	Ok((public_nonce, partial_sig))
}

pub fn build_cooperative_claim_adaptor_package_from_parts(
	btc_payer_keypair: &Keypair,
	btc_secret_nonce: musig::SecretNonce,
	btc_public_nonce: &musig::PublicNonce,
	ark_payer_pubkey: PublicKey,
	ark_public_nonce: &musig::PublicNonce,
	ark_partial_sig: &musig::PartialSignature,
	sighash: [u8; 32],
	tap_tweak: Option<[u8; 32]>,
	adaptor_point: PublicKey,
) -> Result<BtcClaimAdaptorPackage> {
	let aggregate_nonce = musig::nonce_agg(&[btc_public_nonce, ark_public_nonce]);
	let (_partial_sig, pre_sig) = musig::partial_sign(
		[btc_payer_keypair.public_key(), ark_payer_pubkey],
		aggregate_nonce,
		btc_payer_keypair,
		btc_secret_nonce,
		sighash,
		tap_tweak,
		Some(&[ark_partial_sig]),
	);

	let aggregate_key = if let Some(tweak) = tap_tweak {
		musig::tweaked_key_agg([btc_payer_keypair.public_key(), ark_payer_pubkey], tweak).1
	} else {
		musig::combine_keys([btc_payer_keypair.public_key(), ark_payer_pubkey])
	}
	.x_only_public_key()
	.0;

	let package = BtcClaimAdaptorPackage {
		adaptor_point,
		aggregate_key,
		sighash,
		pre_signature: AdaptorPreSignature::new(
			pre_sig.expect("pre-signature exists when counterparty partial is provided"),
		),
	};
	package.verify()?;
	Ok(package)
}

pub fn build_cooperative_claim_adaptor_package(
	btc_payer_keypair: &Keypair,
	ark_payer_keypair: &Keypair,
	sighash: [u8; 32],
	tap_tweak: Option<[u8; 32]>,
	adaptor_point: PublicKey,
) -> Result<BtcClaimAdaptorPackage> {
	let (btc_secret_nonce, btc_public_nonce) = musig::nonce_pair(btc_payer_keypair);

	let (ark_public_nonce, ark_partial_sig) = sign_cooperative_claim_adaptor_partial(
		ark_payer_keypair,
		btc_payer_keypair.public_key(),
		&btc_public_nonce,
		sighash,
		tap_tweak,
		adaptor_point,
	)?;

	build_cooperative_claim_adaptor_package_from_parts(
		btc_payer_keypair,
		btc_secret_nonce,
		&btc_public_nonce,
		ark_payer_keypair.public_key(),
		&ark_public_nonce,
		&ark_partial_sig,
		sighash,
		tap_tweak,
		adaptor_point,
	)
}

pub fn verify_ark_transfer_offer(
	offer: &ArkOffer,
	expected_id: SwapId,
	expected_amount: Amount,
	expected_btc_payout_script: &ScriptBuf,
	expected_receive_policy: &VtxoPolicy,
	expected_server_pubkey: PublicKey,
	expected_adaptor_point: PublicKey,
) -> std::result::Result<(), ArkTransferOfferError> {
	if offer.id != expected_id {
		return Err(ArkTransferOfferError::SwapIdMismatch {
			expected: expected_id,
			got: offer.id,
		});
	}
	if offer.amount != expected_amount {
		return Err(ArkTransferOfferError::AmountMismatch {
			expected: expected_amount,
			got: offer.amount,
		});
	}
	if offer.btc_payout_script != *expected_btc_payout_script {
		return Err(ArkTransferOfferError::BtcPayoutScriptMismatch);
	}
	if offer.ark_receive_policy != *expected_receive_policy {
		return Err(ArkTransferOfferError::ArkReceivePolicyMismatch);
	}
	if offer.ark_server_pubkey != expected_server_pubkey {
		return Err(ArkTransferOfferError::ServerPubkeyMismatch {
			expected: expected_server_pubkey,
			got: offer.ark_server_pubkey,
		});
	}
	if offer.adaptor_point != expected_adaptor_point {
		return Err(ArkTransferOfferError::AdaptorPointMismatch {
			expected: expected_adaptor_point,
			got: offer.adaptor_point,
		});
	}

	Ok(())
}

pub fn verify_ark_transfer_before_acceptance(
	offer: &ArkOffer,
	transfer: &TransferableAdaptorArkoorPackage,
	minimum_output_expiry_height: BlockHeight,
) -> Result<(), TransferPackageVerificationError> {
	verify_ark_transfer_before_acceptance_with_options(
		offer,
		transfer,
		minimum_output_expiry_height,
		ArkTransferAcceptanceOptions::default(),
	)
}

pub fn verify_ark_transfer_before_acceptance_with_options(
	offer: &ArkOffer,
	transfer: &TransferableAdaptorArkoorPackage,
	minimum_output_expiry_height: BlockHeight,
	options: ArkTransferAcceptanceOptions,
) -> Result<(), TransferPackageVerificationError> {
	transfer.verify_public_transfer(
		&offer.ark_input_ids,
		&offer.ark_receive_policy,
		offer.amount,
		offer.ark_server_pubkey,
		offer.adaptor_point,
	)?;

	for output in transfer.build_unsigned_vtxos() {
		let expiry_height = output.expiry_height();
		if !options.allow_short_output_expiry && expiry_height <= minimum_output_expiry_height {
			return Err(TransferPackageVerificationError::OutputExpiryTooSoon {
				vtxo_id: output.id(),
				expiry_height,
				minimum_expiry_height: minimum_output_expiry_height,
			});
		}
	}

	Ok(())
}

impl Wallet {
	/// Select the exact inputs that must be persisted and reserved before cosigning.
	pub async fn select_btc_ark_transfer_inputs(&self, amount: Amount) -> Result<Vec<Vtxo<Full>>> {
		let inputs = self.select_any_vtxos_to_cover(amount).await?;
		let ids = inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
		self.inner.db
			.get_full_vtxos(&ids)
			.await
			.context("failed to hydrate BTC-Ark input VTXOs")
	}

	/// Prepare a server-co-signed private transfer.
	///
	/// The caller must durably freeze and locally lock `input_ids` before calling:
	/// server co-signing marks them as spent by this transfer and cannot be rolled back.
	pub async fn prepare_btc_ark_transfer(
		&self,
		destination: &ark::Address,
		amount: Amount,
		btc_payout_script: ScriptBuf,
		adaptor_point: PublicKey,
		input_ids: &[VtxoId],
	) -> Result<PreparedArkSwapPackage> {
		self.validate_arkoor_address(destination)
			.await
			.context("address validation failed")?;

		let (mut srv, ark_info) = self.require_server().await?;
		let dest = ArkoorDestination {
			total_amount: amount,
			policy: destination.policy().clone(),
		};
		let full_inputs = self
			.inner.db
			.get_full_vtxos(input_ids)
			.await
			.context("failed to hydrate BTC-Ark input VTXOs")?;

		self.register_vtxo_transactions_with_server(&full_inputs)
			.await
			.context("failed to register BTC-Ark input VTXO transactions with server")?;

		let (change_keypair, change_key_index) = self.peek_next_keypair().await?;
		let change_pubkey = change_keypair.public_key();
		let change_policy = VtxoPolicy::new_pubkey(change_pubkey);

		if dest.policy.user_pubkey() == change_pubkey {
			bail!("Cannot create BTC-Ark transfer to same address as change");
		}

		let mut user_keypairs = Vec::with_capacity(full_inputs.len());
		for vtxo in &full_inputs {
			user_keypairs.push(self.get_vtxo_key(vtxo).await?);
		}

		let builder = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			full_inputs.into_iter(),
			dest.clone(),
			change_policy.clone(),
		)
		.context("failed to construct BTC-Ark arkoor package")?
		.generate_user_adaptor_nonces(&user_keypairs, adaptor_point)
		.context("invalid number of keypairs")?;

		let response = srv
			.client
			.request_arkoor_cosign(protos::ArkoorPackageCosignRequest::from(
				builder.cosign_request(),
			))
			.await
			.context("server failed to cosign BTC-Ark arkoor package")?
			.into_inner();

		let cosign_responses = ArkoorPackageCosignResponse::try_from(response)
			.context("failed to parse BTC-Ark cosign response from server")?;

		let transfer = builder
			.user_adaptor_cosign(&user_keypairs, cosign_responses)
			.context("failed to adaptor-cosign BTC-Ark arkoor package")?
			.into_transfer_package();

		if transfer
			.build_unsigned_vtxos()
			.any(|vtxo| *vtxo.policy() == change_policy)
		{
			self.inner.db
				.store_vtxo_key(change_key_index, change_pubkey)
				.await?;
		}

		let offer = ArkOffer {
			id: SwapId::random(),
			amount,
			btc_payout_script,
			ark_input_ids: input_ids.to_vec(),
			ark_receive_policy: dest.policy,
			ark_server_pubkey: ark_info.server_pubkey,
			adaptor_point,
		};

		Ok(PreparedArkSwapPackage { offer, transfer })
	}

	pub async fn complete_btc_ark_transfer(
		&self,
		transfer: TransferableAdaptorArkoorPackage,
		secret: AdaptorSecret,
	) -> Result<Vec<Vtxo<Full>>> {
		let signed_vtxos = transfer
			.finalize_with_secret(secret)
			.context("failed to finalize BTC-Ark arkoor package")?
			.build_signed_vtxos();

		self.register_vtxo_transactions_with_server(&signed_vtxos)
			.await
			.context("failed to register BTC-Ark output VTXO transactions with server")?;

		let mut owned_vtxos = Vec::with_capacity(signed_vtxos.len());
		for vtxo in signed_vtxos {
			if self.find_signable_clause(&vtxo).await.is_some() {
				self.import_vtxo(&vtxo, ImportVtxoArgs {
					skip_status_check: true,
					..Default::default()
				}).await
					.context("failed to import BTC-Ark output VTXO")?;
				owned_vtxos.push(vtxo);
			}
		}

		Ok(owned_vtxos)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::secp256k1::{SecretKey, rand};

	#[test]
	fn final_btc_claim_signature_reveals_t() {
		let btc_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let ark_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
		let claim = build_cooperative_claim_adaptor_package(
			&btc_payer_keypair,
			&ark_payer_keypair,
			[9u8; 32],
			Some([7u8; 32]),
			secret.point(),
		)
		.expect("claim adaptor package");

		let final_sig = claim
			.finalize_with_secret(secret)
			.expect("final claim signature");
		let recovered = claim.recover_secret(final_sig).expect("revealed secret");

		assert_eq!(recovered.secret_key(), secret.secret_key());
	}

	#[test]
	fn recover_secret_rejects_invalid_final_signature() {
		let btc_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let ark_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
		let claim = build_cooperative_claim_adaptor_package(
			&btc_payer_keypair,
			&ark_payer_keypair,
			[9u8; 32],
			Some([7u8; 32]),
			secret.point(),
		)
		.expect("claim adaptor package");

		let final_sig = claim
			.finalize_with_secret(secret)
			.expect("final claim signature");
		let mut invalid_sig_bytes = final_sig.serialize();
		invalid_sig_bytes[0] ^= 1;
		let invalid_sig = schnorr::Signature::from_slice(&invalid_sig_bytes)
			.expect("invalid signature remains schnorr-shaped");

		claim
			.pre_signature
			.recover_secret(invalid_sig, claim.adaptor_point)
			.expect("tampered signature still reveals same scalar delta");
		assert!(claim.recover_secret(invalid_sig).is_err());
	}

	#[test]
	fn verify_ark_transfer_offer_rejects_wrong_receive_policy() {
		let server_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
		let expected_policy =
			VtxoPolicy::new_pubkey(Keypair::new(&ark::SECP, &mut rand::thread_rng()).public_key());
		let wrong_policy =
			VtxoPolicy::new_pubkey(Keypair::new(&ark::SECP, &mut rand::thread_rng()).public_key());
		let offer = ArkOffer {
			id: SwapId::random(),
			amount: Amount::from_sat(10_000),
			btc_payout_script: ScriptBuf::new_p2tr(
				&ark::SECP,
				Keypair::new(&ark::SECP, &mut rand::thread_rng())
					.x_only_public_key()
					.0,
				None,
			),
			ark_input_ids: vec![],
			ark_receive_policy: wrong_policy,
			ark_server_pubkey: server_keypair.public_key(),
			adaptor_point: secret.point(),
		};

		let err = verify_ark_transfer_offer(
			&offer,
			offer.id,
			offer.amount,
			&offer.btc_payout_script,
			&expected_policy,
			server_keypair.public_key(),
			secret.point(),
		)
		.expect_err("wrong receive policy must be rejected");
		assert_eq!(ArkTransferOfferError::ArkReceivePolicyMismatch, err);
	}

	#[test]
	fn cooperative_claim_accounts_for_anchor_fee_and_dust_boundary() {
		let bob = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let alice = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let payout = ScriptBuf::new_p2tr(&ark::SECP, alice.x_only_public_key().0, None);
		let mut lock = BtcLockContract::new(
			Amount::from_sat(50_000),
			Network::Regtest,
			bob.public_key(),
			alice.public_key(),
			bob.x_only_public_key().0,
			100.into(),
		)
		.unwrap();
		let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
		let mut claim =
			build_cooperative_claim_tx(OutPoint::null(), &lock, payout.clone(), fee_rate).unwrap();
		claim.input[0].witness.push([0u8; 64]);
		let fee = fee_rate * claim.weight();
		assert_eq!(claim.version, Version(3));
		assert_eq!(
			claim.output[1],
			fee::fee_anchor_with_amount(Amount::from_sat(330))
		);
		assert!(claim.output[1].value >= claim.output[1].script_pubkey.minimal_non_dust());
		assert_eq!(
			claim.output[0].value + claim.output[1].value + fee,
			lock.amount
		);

		lock.amount = P2TR_DUST + claim.output[1].value + fee;
		let minimum =
			build_cooperative_claim_tx(OutPoint::null(), &lock, payout.clone(), fee_rate).unwrap();
		assert_eq!(minimum.output[0].value, P2TR_DUST);
		lock.amount -= Amount::ONE_SAT;
		assert!(
			build_cooperative_claim_tx(OutPoint::null(), &lock, payout.clone(), fee_rate,).is_err()
		);
		lock.amount = Amount::ZERO;
		assert!(
			build_cooperative_claim_tx(OutPoint::null(), &lock, payout.clone(), fee_rate,).is_err()
		);
		lock.amount = Amount::MAX;
		assert!(build_cooperative_claim_tx(
			OutPoint::null(),
			&lock,
			payout,
			FeeRate::from_sat_per_kwu(u64::MAX),
		)
		.is_err());
	}

	#[test]
	fn verify_ark_transfer_before_acceptance_rejects_expired_outputs() {
		let user_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let server_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let (_funding_tx, input) = ark::test_util::dummy::DummyTestVtxoSpec {
			amount: Amount::from_sat(10_000),
			fee: Amount::ZERO,
			expiry_height: 100.into(),
			exit_delta: 12.into(),
			user_keypair,
			server_keypair,
		}
		.build();
		let amount = input.amount();
		let input_id = input.id();
		let receive_policy =
			VtxoPolicy::new_pubkey(Keypair::new(&ark::SECP, &mut rand::thread_rng()).public_key());
		let change_policy =
			VtxoPolicy::new_pubkey(Keypair::new(&ark::SECP, &mut rand::thread_rng()).public_key());
		let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));

		let user_builder = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[input],
			ArkoorDestination {
				total_amount: amount,
				policy: receive_policy.clone(),
			},
			change_policy,
		)
		.expect("valid arkoor package")
		.generate_user_adaptor_nonces(&[user_keypair], secret.point())
		.expect("valid user nonces");
		let cosign_response =
			ArkoorPackageBuilder::from_cosign_request(user_builder.cosign_request())
				.expect("valid cosign request")
				.server_cosign(&server_keypair)
				.expect("server cosigns")
				.cosign_response();
		let transfer = user_builder
			.user_adaptor_cosign(&[user_keypair], cosign_response)
			.expect("user adaptor cosigns")
			.into_transfer_package();
		let output_id = transfer.build_unsigned_vtxos().next().unwrap().id();
		let offer = ArkOffer {
			id: SwapId::random(),
			amount,
			btc_payout_script: ScriptBuf::new(),
			ark_input_ids: vec![input_id],
			ark_receive_policy: receive_policy,
			ark_server_pubkey: server_keypair.public_key(),
			adaptor_point: secret.point(),
		};

		let err = verify_ark_transfer_before_acceptance(&offer, &transfer, 100.into())
			.expect_err("expired outputs must be rejected");
		assert!(
			matches!(
				err,
				TransferPackageVerificationError::OutputExpiryTooSoon {
					vtxo_id,
					expiry_height,
					minimum_expiry_height,
				} if vtxo_id == output_id
					&& expiry_height == 100.into()
					&& minimum_expiry_height == 100.into()
			),
			"{err:#}",
		);

		verify_ark_transfer_before_acceptance_with_options(
			&offer,
			&transfer,
			100.into(),
			ArkTransferAcceptanceOptions {
				allow_short_output_expiry: true,
			},
		)
		.expect("short output expiry can be accepted explicitly for testing");
	}

	#[test]
	fn refund_height_is_absolute_and_rejects_timestamp_locktimes() {
		let bob = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let alice = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let make_lock = |height| {
			BtcLockContract::new(
				Amount::from_sat(50_000),
				Network::Regtest,
				bob.public_key(),
				alice.public_key(),
				bob.x_only_public_key().0,
				height,
			)
		};
		let lock = make_lock(499_999_999.into()).unwrap();
		assert!(!lock.refund_is_mature(499_999_998.into()));
		assert!(lock.refund_is_mature(499_999_999.into()));
		assert!(make_lock(500_000_000.into()).is_err());
	}

	#[test]
	fn refund_can_be_repriced_and_signed_by_bob_alone() {
		let bob = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let alice = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let lock = BtcLockContract::new(
			Amount::from_sat(50_000),
			Network::Regtest,
			bob.public_key(),
			alice.public_key(),
			bob.x_only_public_key().0,
			100.into(),
		)
		.unwrap();
		let destination = ScriptBuf::new_p2tr(&ark::SECP, bob.x_only_public_key().0, None);
		let original = build_refund_tx(
			OutPoint::null(),
			&lock,
			destination.clone(),
			FeeRate::from_sat_per_vb(1).unwrap(),
		)
		.unwrap();
		let replacement = build_refund_tx(
			OutPoint::null(),
			&lock,
			destination,
			FeeRate::from_sat_per_vb(10).unwrap(),
		)
		.unwrap();
		assert!(replacement.output[0].value < original.output[0].value);
		assert_ne!(replacement.compute_txid(), original.compute_txid());
		for refund in [original, replacement] {
			assert_eq!(refund.version, Version::TWO);
			assert_eq!(refund.lock_time, LockTime::from_height(100).unwrap());
			assert_eq!(refund.input[0].sequence, Sequence::ENABLE_RBF_NO_LOCKTIME);
			let signed = sign_refund_tx(refund, &lock, &bob).unwrap();
			let witness = signed.input[0].witness.to_vec();
			assert_eq!(
				witness[1],
				ark::scripts::timelock_sign(100.into(), bob.x_only_public_key().0,).into_bytes()
			);
			let signature = schnorr::Signature::from_slice(&witness[0]).unwrap();
			let leaf = taproot::TapLeafHash::from_script(
				&lock.refund_script,
				taproot::LeafVersion::TapScript,
			);
			let sighash = sighash::SighashCache::new(&signed)
				.taproot_script_spend_signature_hash(
					0,
					&sighash::Prevouts::All(&[lock.txout()]),
					leaf,
					sighash::TapSighashType::Default,
				)
				.unwrap();
			ark::SECP
				.verify_schnorr(
					&signature,
					&Message::from_digest(sighash.to_byte_array()),
					&bob.x_only_public_key().0,
				)
				.unwrap();
		}
	}

	#[test]
	fn alice_adapted_partial_binds_funding_and_both_claim_outputs() {
		let bob = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		// Bob commits his ordinary nonce before knowing Alice or the claim.
		let (bob_secret_nonce, bob_nonce) = musig::nonce_pair(&bob);
		let alice = Keypair::new(&ark::SECP, &mut rand::thread_rng());
		let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
		let lock = BtcLockContract::new(
			Amount::from_sat(50_000),
			Network::Regtest,
			bob.public_key(),
			alice.public_key(),
			bob.x_only_public_key().0,
			100.into(),
		)
		.unwrap();
		let claim = build_cooperative_claim_tx(
			OutPoint::null(),
			&lock,
			ScriptBuf::new_p2tr(&ark::SECP, alice.x_only_public_key().0, None),
			FeeRate::from_sat_per_vb(1).unwrap(),
		)
		.unwrap();
		let sighash = cooperative_claim_sighash(&claim, &lock).unwrap();
		let tweak = Some(lock.taproot.tap_tweak().to_byte_array());
		let (alice_nonce, alice_partial) = sign_cooperative_claim_adaptor_partial(
			&alice,
			bob.public_key(),
			&bob_nonce,
			sighash,
			tweak,
			secret.point(),
		)
		.unwrap();
		let adaptor = build_cooperative_claim_adaptor_package_from_parts(
			&bob,
			bob_secret_nonce,
			&bob_nonce,
			alice.public_key(),
			&alice_nonce,
			&alice_partial,
			sighash,
			tweak,
			secret.point(),
		)
		.unwrap();
		assert!(ark::SECP
			.verify_schnorr(
				&adaptor.pre_signature.as_pre_signature(),
				&Message::from_digest(sighash),
				&adaptor.aggregate_key,
			)
			.is_err());
		let signature = adaptor.finalize_with_secret(secret).unwrap();
		assert_eq!(
			adaptor.recover_secret(signature).unwrap().secret_key(),
			secret.secret_key()
		);

		let mut other_funding = claim.clone();
		other_funding.input[0].previous_output.vout = 0;
		let mut other_payout = claim.clone();
		other_payout.output[0].value -= Amount::ONE_SAT;
		let mut other_anchor = claim.clone();
		other_anchor.output[1].value += Amount::ONE_SAT;
		for changed in [other_funding, other_payout, other_anchor] {
			let changed_sighash = cooperative_claim_sighash(&changed, &lock).unwrap();
			assert!(ark::SECP
				.verify_schnorr(
					&signature,
					&Message::from_digest(changed_sighash),
					&adaptor.aggregate_key,
				)
				.is_err());
		}
		let mut other_amount = lock.clone();
		other_amount.amount += Amount::ONE_SAT;
		assert!(ark::SECP
			.verify_schnorr(
				&signature,
				&Message::from_digest(cooperative_claim_sighash(&claim, &other_amount).unwrap()),
				&adaptor.aggregate_key,
			)
			.is_err());
	}
}
