use std::io;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, ensure};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{PublicKey, SecretKey, XOnlyPublicKey, rand, schnorr};
use bitcoin::{Address, Amount, FeeRate, OutPoint, Psbt, Transaction, TxOut, Txid, Witness, address};
use serde::Serialize;

use ark::arkoor::package::TransferableAdaptorArkoorPackage;
use ark::musig::{self, AdaptorSecret, DangerousSecretNonce};
use ark::vtxo::policy::signing::VtxoSigner;
use ark::{ProtocolEncoding, VtxoId};
use bark::Wallet;
use bark::onchain::OnchainWalletTrait;
use bark::swap::btc_ark::{
	ArkOffer, BtcLockContract, SwapId, SwapRole, SwapStatus,
	build_cooperative_claim_adaptor_package_from_parts, build_cooperative_claim_tx,
	build_refund_tx, cooperative_claim_sighash, sign_cooperative_claim_adaptor_partial,
	sign_refund_tx, verify_ark_transfer_before_acceptance, verify_ark_transfer_offer,
};
use bitcoin_ext::cpfp::MakeCpfpFees;
use bitcoin_ext::{TxOutExt, TxStatus};

use crate::relay::{
	ArkClaimPartialArtifact, ArkOfferArtifact, ArkTransferArtifact, BtcArkRequestArtifact,
	BtcClaimAdaptorArtifact, BtcClaimRequestArtifact, BtcFundingArtifact, OfferTerms,
	RelayFile, coordinator_path, load_relay, store_relay,
};
use crate::state::{
	StoredBtcArkSwap, acquire_swap_lock, load_swap_state, load_swap_state_if_exists,
	store_swap_state,
};
use crate::validation::{
	bytes_hex, bytes32_from_hex, fee_rate_from_sat_vb, partial_sig_from_hex,
	public_nonce_from_hex, script_from_hex, secret_key_from_hex, secret_key_hex,
	verify_claim_window, verify_funding_inputs, verify_live_ark_inputs, verify_live_ark_transfer,
};

#[derive(clap::Subcommand)]
pub enum SwapCommand {
	/// Private BTC-to-Ark adaptor swaps using ordinary Ark transfers.
	#[command(name = "btc-ark", subcommand)]
	BtcArk(BtcArkCommand),
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum ProgressRole {
	BtcPayer,
	ArkPayer,
}

impl From<ProgressRole> for SwapRole {
	fn from(role: ProgressRole) -> Self {
		match role {
			ProgressRole::BtcPayer => Self::BtcPayer,
			ProgressRole::ArkPayer => Self::ArkPayer,
		}
	}
}

/// Three peer messages; chain observation and recovery need no further handoff.
/// The Ark server sees only ordinary arkoor co-signing and chain registration.
#[derive(clap::Subcommand)]
pub enum BtcArkCommand {
	/// M1: prepare a funding template and publish a one-use public nonce.
	#[command(name = "btc-request")]
	BtcRequest {
		#[arg(long)]
		coordinator: String,
		#[arg(long)]
		amount: Amount,
		#[arg(long)]
		ark_receive: ark::Address,
		#[arg(long)]
		fee_rate: u64,
		/// Blocks from this request to the ABSOLUTE BTC refund height, not CSV.
		#[arg(long, default_value_t = 24)]
		refund_delay: u32,
		#[arg(long, default_value_t = 6)]
		confirmations: u32,
		/// Claim and old-state response margin in blocks.
		#[arg(long, default_value_t = 6)]
		safety_margin: u32,
	},
	/// M2: prepare the Ark package and adapted claim partial before Bob funds.
	/// Bob can abandon here and force an emergency exit of the Ark inputs.
	#[command(name = "ark-offer")]
	ArkOffer {
		#[arg(long)]
		coordinator: String,
		#[arg(long)]
		swap: String,
		#[arg(long)]
		btc_payout: Address<address::NetworkUnchecked>,
	},
	/// M3: accept the pinned Ark package, fund, and release the BTC adaptor.
	/// Keep `progress --role btc-payer --watch` running until settlement.
	#[command(name = "btc-fund")]
	BtcFund {
		#[arg(long)]
		coordinator: String,
		#[arg(long)]
		swap: String,
	},
	/// Observe the chain and automatically claim, complete, refund, or exit.
	Progress {
		#[arg(long)]
		coordinator: String,
		#[arg(long)]
		swap: String,
		#[arg(long, value_enum)]
		role: ProgressRole,
		#[arg(long)]
		watch: bool,
		/// Override the automatic fee estimate, in sat/vB.
		#[arg(long)]
		fee_rate: Option<u64>,
	},
	/// Reveal the secret only after confirmed, unspent, timely BTC funding.
	/// Afterwards, keep fee-bumping the claim until it confirms; disclosure is irreversible.
	#[command(name = "ark-finalize-btc-claim")]
	ArkFinalizeBtcClaim {
		#[arg(long)]
		coordinator: String,
		#[arg(long)]
		swap: String,
	},
	/// Recover the secret from the BTC claim, register and import owned VTXOs.
	#[command(name = "btc-complete-ark")]
	BtcCompleteArk {
		#[arg(long)]
		coordinator: String,
		#[arg(long)]
		swap: String,
	},
	/// Refund at the absolute deadline; remain online until it confirms.
	#[command(name = "btc-refund")]
	BtcRefund {
		#[arg(long)]
		coordinator: String,
		#[arg(long)]
		swap: String,
		#[arg(long)]
		fee_rate: Option<u64>,
	},
	/// Start emergency exits of the pinned Ark inputs before secret disclosure.
	#[command(name = "ark-abort")]
	ArkAbort {
		#[arg(long)]
		coordinator: String,
		#[arg(long)]
		swap: String,
	},
}

pub async fn execute_swap_command(
	command: SwapCommand,
	wallet: &mut Wallet,
	onchain: &mut dyn OnchainWalletTrait,
	datadir: &Path,
) -> anyhow::Result<()> {
	let _lock = acquire_swap_lock(datadir).await?;
	match command {
		SwapCommand::BtcArk(command) => execute_btc_ark_command(command, wallet, onchain, datadir).await,
	}
}

async fn execute_btc_ark_command(
	command: BtcArkCommand,
	wallet: &mut Wallet,
	onchain: &mut dyn OnchainWalletTrait,
	datadir: &Path,
) -> anyhow::Result<()> {
	wallet.chain().require_version().await?;
	wallet.chain().require_transaction_index().await?;
	match command {
		BtcArkCommand::BtcRequest {
			coordinator, amount, ark_receive, fee_rate, refund_delay, confirmations, safety_margin,
		} => {
			let state = btc_request(wallet, onchain, datadir, &coordinator, amount, ark_receive,
				fee_rate, refund_delay, confirmations, safety_margin).await?;
			output_state(&state, "ark-offer");
		},
		BtcArkCommand::ArkOffer { coordinator, swap, btc_payout } => {
			let swap_id = SwapId::from_str(&swap)?;
			let state = ark_offer(wallet, datadir, &coordinator, swap_id, btc_payout).await?;
			output_state(&state, "btc-fund");
		},
		BtcArkCommand::BtcFund { coordinator, swap } => {
			let swap_id = SwapId::from_str(&swap)?;
			let state = btc_fund(wallet, onchain, datadir, &coordinator, swap_id).await?;
			output_state(&state, "progress");
		},
		BtcArkCommand::Progress { coordinator, swap, role, watch, fee_rate } => {
			let swap_id = SwapId::from_str(&swap)?;
			let role = role.into();
			loop {
				// A failed durable write may already have renamed its file. Reload
				// authoritative state before retrying any signing or recovery step.
				let mut state = load_swap_state(datadir, swap_id, role).await?;
				let step = progress_swap(wallet, onchain, datadir, &coordinator, &mut state, fee_rate).await;
				let completed = match step {
					Ok(next) => {
						output_state(&state, next);
						is_terminal(&state)
					},
					Err(error) if watch => {
						eprintln!("Swap {}: {error:#}", state.swap_id);
						false
					},
					Err(error) => return Err(error),
				};
				if !watch || completed { break; }
				tokio::select! {
					_ = tokio::time::sleep(Duration::from_secs(2)) => {},
					result = tokio::signal::ctrl_c() => {
						result?;
						eprintln!("Swap monitoring stopped; resume progress --watch before its deadlines.");
						break;
					},
				}
			}
		},
		BtcArkCommand::ArkFinalizeBtcClaim { coordinator, swap } => {
			let mut state = load_swap_state(datadir, SwapId::from_str(&swap)?, SwapRole::ArkPayer).await?;
			receive_funding_message(wallet, datadir, &coordinator, &mut state).await?;
			claim_btc(wallet, onchain, datadir, &mut state, None).await?;
			output_state(&state, if is_terminal(&state) { "done" } else { "progress" });
		},
		BtcArkCommand::BtcCompleteArk { coordinator: _, swap } => {
			let mut state = load_swap_state(datadir, SwapId::from_str(&swap)?, SwapRole::BtcPayer).await?;
			ensure!(observe_claim(wallet, datadir, &mut state).await?, "BTC claim is not visible yet");
			complete_ark(wallet, onchain, datadir, &mut state).await?;
			output_state(&state, if is_terminal(&state) { "done" } else { "progress" });
		},
		BtcArkCommand::BtcRefund { coordinator: _, swap, fee_rate } => {
			let mut state = load_swap_state(datadir, SwapId::from_str(&swap)?, SwapRole::BtcPayer).await?;
			refund_btc(wallet, datadir, &mut state, fee_rate).await?;
			output_state(&state, if is_terminal(&state) { "done" } else { "progress" });
		},
		BtcArkCommand::ArkAbort { coordinator: _, swap } => {
			let mut state = load_swap_state(datadir, SwapId::from_str(&swap)?, SwapRole::ArkPayer).await?;
			abort_ark(wallet, datadir, &mut state).await?;
			output_state(&state, if is_terminal(&state) { "done" } else { "progress" });
		},
	}
	Ok(())
}

async fn btc_request(
	wallet: &Wallet,
	onchain: &mut dyn OnchainWalletTrait,
	datadir: &Path,
	coordinator: &str,
	amount: Amount,
	ark_receive: ark::Address,
	fee_rate: u64,
	refund_delay: u32,
	confirmations: u32,
	safety_margin: u32,
) -> anyhow::Result<StoredBtcArkSwap> {
	if tokio::fs::try_exists(coordinator_path(coordinator)).await? {
		let relay = load_relay(coordinator).await?;
		let state = load_swap_state(datadir, relay.swap_id()?, SwapRole::BtcPayer).await?;
		let request = &state.relay.request;
		ensure!(request.amount_sat == amount.to_sat() && request.ark_receive == ark_receive.to_string()
			&& request.fee_rate_sat_vb == fee_rate && request.minimum_funding_confirmations == confirmations
			&& request.safety_margin_blocks == safety_margin
			&& request.refund_height.checked_sub(request.created_height) == Some(refund_delay),
			"request arguments changed; use a new relay for a new swap");
		ensure!(relay.request == *request, "peer changed the funding request");
		return Ok(state);
	}
	ensure!(amount > Amount::ZERO && confirmations > 0 && safety_margin > 0, "amount, confirmations and margin must be positive");
	ensure!(safety_margin >= confirmations, "safety margin must cover the required confirmation depth");
	ensure!(refund_delay > confirmations.checked_add(safety_margin).context("refund window overflow")?,
		"refund window must exceed funding confirmations plus safety margin");
	wallet.validate_arkoor_address(&ark_receive).await?;
	let fee_rate_value = fee_rate_from_sat_vb(fee_rate)?;
	let created_height: u32 = wallet.chain().tip().await?.into();
	let refund_height = created_height.checked_add(refund_delay).context("refund height overflow")?;
	ensure!(refund_height < 500_000_000, "refund must be a block height, not a timestamp");
	let (key, index) = wallet.derive_store_next_keypair().await?;
	let placeholder = Address::p2tr(&ark::SECP, key.x_only_public_key().0, None, wallet.network().await?);
	onchain.sync(wallet.chain()).await?;
	let psbt = onchain.prepare_tx(&[(placeholder.clone(), amount)], fee_rate_value).await?;
	crate::state::ensure_funding_inputs_available(datadir, &psbt.unsigned_tx, created_height).await?;
	let slot = psbt.unsigned_tx.output.iter().position(|o| o.script_pubkey == placeholder.script_pubkey() && o.value == amount)
		.context("funding template has no lock placeholder")?;
	let prevouts = psbt.inputs.iter().map(|input| input.witness_utxo.clone().context("funding must use native SegWit prevouts"))
		.collect::<anyhow::Result<Vec<_>>>()?;
	verify_funding_inputs(wallet, &psbt.unsigned_tx, &prevouts).await?;
	let (secret_nonce, public_nonce) = musig::nonce_pair(&key);
	let swap_id = SwapId::random();
	let relay = RelayFile::new_request(swap_id, BtcArkRequestArtifact {
		amount_sat: amount.to_sat(), ark_receive: ark_receive.to_string(),
		btc_payer_claim_pubkey: key.public_key().to_string(), btc_refund_pubkey: key.x_only_public_key().0.to_string(),
		fee_rate_sat_vb: fee_rate, created_height, refund_height,
		minimum_funding_confirmations: confirmations, safety_margin_blocks: safety_margin,
		funding_template_hex: serialize_hex(&psbt.unsigned_tx), funding_output_index: slot.try_into()?,
		funding_prevouts_hex: prevouts.iter().map(serialize_hex).collect(),
		btc_payer_public_nonce_hex: bytes_hex(&public_nonce.serialize()),
	});
	let mut state = StoredBtcArkSwap::new(swap_id, SwapRole::BtcPayer, coordinator.to_owned(), index, relay);
	state.funding_psbt_hex = Some(bytes_hex(&psbt.serialize()));
	state.btc_secret_nonce = Some(DangerousSecretNonce::dangerous_from_secret_nonce(secret_nonce));
	store_swap_state(datadir, &state).await?;
	store_relay(coordinator, &state.relay).await?;
	Ok(state)
}

async fn ark_offer(
	wallet: &Wallet,
	datadir: &Path,
	coordinator: &str,
	swap_id: SwapId,
	btc_payout: Address<address::NetworkUnchecked>,
) -> anyhow::Result<StoredBtcArkSwap> {
	let payout = btc_payout.require_network(wallet.network().await?)?;
	let mut state = if let Some(state) = load_swap_state_if_exists(datadir, swap_id, SwapRole::ArkPayer).await? {
		ensure!(state.status != SwapStatus::Cancelled, "swap was aborted; the adaptor secret cannot be reused");
		ensure!(state.relay.terms()?.btc_payout_address == payout.to_string(), "BTC payout changed after acceptance");
		if state.relay.ark_claim_partial.is_some() {
			ensure!(state.status == SwapStatus::Offered, "swap is not awaiting BTC funding");
			if let Ok(current) = load_relay(coordinator).await {
				if current.btc_claim_adaptor.is_some() {
					current.require_swap(swap_id)?;
					ensure!(current.request == state.relay.request, "funding request changed after offer");
					ensure!(Some(current.response_commitment_hash_hex()?) == state.peer_transcript_hash_hex,
						"published funding response does not match the accepted transcript");
					return Ok(state);
				}
			}
			store_relay(coordinator, &state.relay).await?;
			return Ok(state);
		}
		state
	} else {
		let mut relay = load_relay(coordinator).await?;
		relay.require_swap(swap_id)?;
		ensure!(relay.terms.is_none() && relay.ark_transfer.is_none() && relay.btc_funding.is_none()
			&& relay.claim_request.is_none() && relay.ark_claim_partial.is_none() && relay.btc_claim_adaptor.is_none(),
			"expected an unaccepted funding request");
		validate_request(wallet, &relay.request).await?;
		let destination = ark::Address::from_str(relay.payer_ark_receive()?)?;
		wallet.validate_arkoor_address(&destination).await?;
		let inputs = wallet.select_btc_ark_transfer_inputs(Amount::from_sat(relay.request.amount_sat)).await?;
		verify_live_ark_inputs(wallet, inputs.iter(), relay.request.refund_height, relay.request.safety_margin_blocks).await?;
		let (key, index) = wallet.derive_store_next_keypair().await?;
		let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
		relay.terms = Some(OfferTerms {
			amount_sat: relay.request.amount_sat, btc_payout_address: payout.to_string(),
			btc_payout_script_hex: bytes_hex(payout.script_pubkey().as_bytes()),
			adaptor_point: secret.point().to_string(), ark_payer_claim_pubkey: key.public_key().to_string(),
		});
		let mut state = StoredBtcArkSwap::new(swap_id, SwapRole::ArkPayer, coordinator.to_owned(), index, relay);
		state.adaptor_secret_hex = Some(secret_key_hex(secret.secret_key()));
		state.ark_input_ids = inputs.iter().map(|input| input.id().to_string()).collect();
		// Record recovery inputs BEFORE the server irreversibly co-signs anything.
		store_swap_state(datadir, &state).await?;
		state
	};
	validate_request(wallet, &state.relay.request).await?;
	let input_ids = state.accepted_ark_input_ids()?;
	let inputs = wallet.get_full_vtxos(input_ids.iter().copied()).await?;
	verify_live_ark_inputs(wallet, inputs.iter(), state.relay.request.refund_height, state.relay.request.safety_margin_blocks).await?;
	wallet.lock_vtxos(&input_ids, None).await?;
	let destination = ark::Address::from_str(state.relay.payer_ark_receive()?)?;
	let secret = AdaptorSecret::new(secret_key_from_hex(state.adaptor_secret_hex.as_deref().context("missing adaptor secret")?)?);
	let key = wallet.peek_keypair(state.claim_key_index).await?;
	let lock = expected_lock(wallet, &state.relay).await?;
	let (mut funding, _) = funding_template(&state.relay.request)?;
	let slot = usize::try_from(state.relay.request.funding_output_index)?;
	funding.output[slot] = lock.txout();
	let outpoint = OutPoint::new(funding.compute_txid(), state.relay.request.funding_output_index);
	let claim = build_cooperative_claim_tx(outpoint, &lock, payout.script_pubkey(), request_fee(&state.relay)?)?;
	let sighash = cooperative_claim_sighash(&claim, &lock)?;
	let bob_nonce = public_nonce_from_hex(&state.relay.request.btc_payer_public_nonce_hex)?;
	let (nonce, partial) = sign_cooperative_claim_adaptor_partial(
		&key, PublicKey::from_str(state.relay.btc_payer_claim_pubkey()?)?, &bob_nonce, sighash,
		Some(lock.taproot.tap_tweak().to_byte_array()), secret.point(),
	)?;
	let mut prepared = wallet.prepare_btc_ark_transfer(&destination, lock.amount, payout.script_pubkey(), secret.point(), &input_ids).await?;
	prepared.offer.id = swap_id;
	state.relay.ark_transfer = Some(ArkTransferArtifact {
		offer: ArkOfferArtifact::from_offer(&prepared.offer), transfer_package_hex: prepared.transfer.serialize_hex(),
	});
	state.relay.btc_funding = Some(BtcFundingArtifact {
		funding_txid: funding.compute_txid().to_string(), funding_vout: outpoint.vout,
		funding_tx_hex: serialize_hex(&funding), lock_address: lock.address.to_string(), lock_amount_sat: lock.amount.to_sat(),
	});
	state.relay.claim_request = Some(BtcClaimRequestArtifact {
		claim_tx_hex: serialize_hex(&claim), claim_sighash_hex: bytes_hex(&sighash),
		tap_tweak_hex: bytes_hex(&lock.taproot.tap_tweak().to_byte_array()),
		btc_payer_public_nonce_hex: state.relay.request.btc_payer_public_nonce_hex.clone(),
		claim_amount_sat: claim.output[0].value.to_sat(),
	});
	state.relay.ark_claim_partial = Some(ArkClaimPartialArtifact {
		ark_public_nonce_hex: bytes_hex(&nonce.serialize()), ark_partial_sig_hex: bytes_hex(&partial.serialize()),
	});
	state.relay.status = SwapStatus::Offered;
	state.status = SwapStatus::Offered;
	state.peer_transcript_hash_hex = Some(state.relay.response_commitment_hash_hex()?);
	store_swap_state(datadir, &state).await?;
	store_relay(coordinator, &state.relay).await?;
	Ok(state)
}

async fn btc_fund(
	wallet: &Wallet,
	onchain: &mut dyn OnchainWalletTrait,
	datadir: &Path,
	coordinator: &str,
	swap_id: SwapId,
) -> anyhow::Result<StoredBtcArkSwap> {
	let mut state = load_swap_state(datadir, swap_id, SwapRole::BtcPayer).await?;
	ensure!(!is_terminal(&state), "swap is already settled or cancelled");
	let response = if state.relay.btc_claim_adaptor.is_some() {
		None
	} else {
		let peer = load_relay(coordinator).await?;
		peer.require_swap(swap_id)?;
		ensure!(peer.request == state.relay.request, "funding request changed after nonce generation");
		let commitment = peer.response_commitment_hash_hex()?;
		if let Some(expected) = &state.peer_transcript_hash_hex {
			ensure!(*expected == commitment, "peer changed the pinned signing transcript");
		}
		Some((peer, commitment))
	};
	if state.relay.btc_claim_adaptor.is_none() {
		let (peer, commitment) = response.context("missing peer response")?;
		validate_request(wallet, &peer.request).await?;
		let (lock, funding, claim) = verify_response(wallet, &peer).await?;
		let (offer, transfer) = verify_public_ark_package(wallet, &peer).await?;
		verify_live_ark_transfer(wallet, &offer, &transfer, peer.request.refund_height, peer.request.safety_margin_blocks).await?;
		state.ark_input_ids = offer.ark_input_ids.iter().map(ToString::to_string).collect();
		state.peer_transcript_hash_hex = Some(commitment);
		state.relay = peer;
		// A crash before result persistence may recompute ONLY this exact transcript.
		store_swap_state(datadir, &state).await?;
		let key = wallet.peek_keypair(state.claim_key_index).await?;
		ensure!(key.public_key().to_string() == state.relay.request.btc_payer_claim_pubkey, "local claim key mismatch");
		let partial = state.relay.ark_claim_partial.as_ref().context("missing Alice partial")?;
		let package = build_cooperative_claim_adaptor_package_from_parts(
			&key, state.btc_secret_nonce.as_ref().context("BTC nonce already consumed")?.to_sec_nonce(),
			&public_nonce_from_hex(&state.relay.request.btc_payer_public_nonce_hex)?,
			PublicKey::from_str(&state.relay.terms()?.ark_payer_claim_pubkey)?,
			&public_nonce_from_hex(&partial.ark_public_nonce_hex)?, &partial_sig_from_hex(&partial.ark_partial_sig_hex)?,
			cooperative_claim_sighash(&claim, &lock)?, Some(lock.taproot.tap_tweak().to_byte_array()),
			PublicKey::from_str(&state.relay.terms()?.adaptor_point)?,
		)?;
		package.verify()?;
		let mut psbt = Psbt::deserialize(&Vec::<u8>::from_hex(state.funding_psbt_hex.as_deref().context("missing private funding PSBT")?)?)?;
		ensure!(serialize_hex(&psbt.unsigned_tx) == state.relay.request.funding_template_hex, "private PSBT/template mismatch");
		psbt.unsigned_tx = funding;
		psbt.outputs[state.relay.request.funding_output_index as usize] = Default::default();
		let signed_funding = onchain.finish_psbt(psbt).await?.extract_tx()?;
		ensure!(signed_funding.compute_txid() == claim.input[0].previous_output.txid, "funding signing changed the committed txid");
		ensure!(signed_funding.input.iter().all(|i| !i.witness.is_empty()), "funding transaction is not fully signed");
		let refund_destination = onchain.address().await?.script_pubkey();
		let refund = sign_refund_tx(build_refund_tx(claim.input[0].previous_output, &lock, refund_destination, request_fee(&state.relay)?)?, &lock, &key)?;
		state.relay.btc_funding.as_mut().context("missing funding")?.funding_tx_hex = serialize_hex(&signed_funding);
		state.relay.btc_claim_adaptor = Some(BtcClaimAdaptorArtifact::from_package(&package));
		state.relay.status = SwapStatus::BtcClaimReady;
		state.status = SwapStatus::BtcClaimReady;
		state.signed_refund_tx_hex = Some(serialize_hex(&refund));
		state.btc_secret_nonce = None;
		state.funding_psbt_hex = None;
		// Result, transcript and nonce consumption are one durable write, before disclosure.
		store_swap_state(datadir, &state).await?;
	}
	let funding = funding_tx(&state.relay)?;
	if wallet.chain().tx_status(funding.compute_txid()).await? == TxStatus::NotFound {
		validate_request(wallet, &state.relay.request).await?;
		let (offer, transfer) = verify_public_ark_package(wallet, &state.relay).await?;
		verify_live_ark_transfer(wallet, &offer, &transfer, state.relay.request.refund_height, state.relay.request.safety_margin_blocks).await?;
		wallet.chain().broadcast_tx(&funding).await?;
	}
	store_relay(coordinator, &state.relay).await?;
	Ok(state)
}

fn funding_template(request: &BtcArkRequestArtifact) -> anyhow::Result<(Transaction, Vec<TxOut>)> {
	let tx: Transaction = deserialize_hex(&request.funding_template_hex)?;
	let funding_locktime_mature = match tx.lock_time {
		bitcoin::absolute::LockTime::Blocks(height) => height.to_consensus_u32() <= request.created_height,
		bitcoin::absolute::LockTime::Seconds(_) => false,
	};
	ensure!(funding_locktime_mature, "funding template must not be timelocked beyond the request height");
	ensure!(!tx.input.is_empty() && tx.input.iter().all(|i| i.script_sig.is_empty() && i.witness.is_empty()), "funding template must be unsigned native SegWit");
	let slot = usize::try_from(request.funding_output_index)?;
	let placeholder = tx.output.get(slot).context("invalid funding output slot")?;
	ensure!(placeholder.value.to_sat() == request.amount_sat && placeholder.script_pubkey.is_p2tr(), "funding placeholder amount/script mismatch");
	let prevouts = request.funding_prevouts_hex.iter().map(|hex| deserialize_hex(hex).map_err(anyhow::Error::from)).collect::<anyhow::Result<Vec<TxOut>>>()?;
	ensure!(prevouts.len() == tx.input.len(), "funding prevout count mismatch");
	let incoming = sum_outputs(&prevouts)?;
	ensure!(incoming > sum_outputs(&tx.output)?, "funding template must pay a positive miner fee");
	Ok((tx, prevouts))
}

async fn validate_request(wallet: &Wallet, request: &BtcArkRequestArtifact) -> anyhow::Result<()> {
	ensure!(request.amount_sat > 0 && request.minimum_funding_confirmations > 0 && request.safety_margin_blocks > 0, "invalid swap safety parameters");
	ensure!(request.safety_margin_blocks >= request.minimum_funding_confirmations, "safety margin must cover the required confirmation depth");
	let tip: u32 = wallet.chain().tip().await?.into();
	ensure!(request.created_height <= tip && request.refund_height < 500_000_000, "invalid request/refund height");
	let ready_by = tip.checked_add(request.minimum_funding_confirmations).and_then(|h| h.checked_add(request.safety_margin_blocks)).context("claim window overflow")?;
	ensure!(ready_by < request.refund_height, "insufficient time to confirm funding and claim safely");
	let (tx, prevouts) = funding_template(request)?;
	verify_funding_inputs(wallet, &tx, &prevouts).await?;
	fee_rate_from_sat_vb(request.fee_rate_sat_vb)?;
	PublicKey::from_str(&request.btc_payer_claim_pubkey)?;
	XOnlyPublicKey::from_str(&request.btc_refund_pubkey)?;
	public_nonce_from_hex(&request.btc_payer_public_nonce_hex)?;
	Ok(())
}

async fn expected_lock(wallet: &Wallet, relay: &RelayFile) -> anyhow::Result<BtcLockContract> {
	let terms = relay.terms()?;
	ensure!(terms.amount_sat == relay.request.amount_sat, "offered amount differs from request");
	BtcLockContract::new(Amount::from_sat(terms.amount_sat), wallet.network().await?,
		PublicKey::from_str(relay.btc_payer_claim_pubkey()?)?, PublicKey::from_str(&terms.ark_payer_claim_pubkey)?,
		XOnlyPublicKey::from_str(&relay.request.btc_refund_pubkey)?, relay.request.refund_height.into())
}

async fn verify_response(wallet: &Wallet, relay: &RelayFile) -> anyhow::Result<(BtcLockContract, Transaction, Transaction)> {
	let lock = expected_lock(wallet, relay).await?;
	let (mut expected_funding, _) = funding_template(&relay.request)?;
	expected_funding.output[relay.request.funding_output_index as usize] = lock.txout();
	let funding = funding_tx(relay)?;
	ensure!(without_witness(&funding) == expected_funding, "funding transaction changed outside the agreed lock output");
	let artifact = relay.btc_funding.as_ref().context("missing funding artifact")?;
	ensure!(artifact.funding_txid == expected_funding.compute_txid().to_string()
		&& artifact.funding_vout == relay.request.funding_output_index
		&& artifact.lock_address == lock.address.to_string() && artifact.lock_amount_sat == lock.amount.to_sat(), "funding contract mismatch");
	let terms = relay.terms()?;
	let payout = Address::from_str(&terms.btc_payout_address)?.require_network(wallet.network().await?)?;
	ensure!(payout.script_pubkey() == script_from_hex(&terms.btc_payout_script_hex)?, "payout script/address mismatch");
	let claim = build_cooperative_claim_tx(OutPoint::new(expected_funding.compute_txid(), relay.request.funding_output_index), &lock, payout.script_pubkey(), request_fee(relay)?)?;
	let request = relay.claim_request.as_ref().context("missing claim request")?;
	ensure!(deserialize_hex::<Transaction>(&request.claim_tx_hex)? == claim, "BTC claim transaction changed");
	ensure!(request.btc_payer_public_nonce_hex == relay.request.btc_payer_public_nonce_hex
		&& bytes32_from_hex(&request.claim_sighash_hex)? == cooperative_claim_sighash(&claim, &lock)?
		&& bytes32_from_hex(&request.tap_tweak_hex)? == lock.taproot.tap_tweak().to_byte_array()
		&& request.claim_amount_sat == claim.output[0].value.to_sat(), "BTC claim signing context changed");
	if let Some(adaptor) = &relay.btc_claim_adaptor {
		let package = adaptor.to_package()?;
		package.verify()?;
		ensure!(package.sighash == cooperative_claim_sighash(&claim, &lock)?
			&& package.adaptor_point == PublicKey::from_str(&terms.adaptor_point)?
			&& package.aggregate_key == lock.taproot.output_key().to_x_only_public_key(), "BTC adaptor context mismatch");
	}
	Ok((lock, funding, claim))
}

async fn verify_public_ark_package(wallet: &Wallet, relay: &RelayFile) -> anyhow::Result<(ArkOffer, TransferableAdaptorArkoorPackage)> {
	let artifact = relay.ark_transfer.as_ref().context("missing Ark transfer")?;
	let offer = artifact.offer.to_offer()?;
	let transfer = TransferableAdaptorArkoorPackage::deserialize_hex(&artifact.transfer_package_hex)?;
	let destination = ark::Address::from_str(relay.payer_ark_receive()?)?;
	wallet.validate_arkoor_address(&destination).await?;
	verify_ark_transfer_offer(&offer, relay.swap_id()?, Amount::from_sat(relay.request.amount_sat),
		&script_from_hex(&relay.terms()?.btc_payout_script_hex)?, destination.policy(),
		wallet.require_ark_info().await?.server_pubkey, PublicKey::from_str(&relay.terms()?.adaptor_point)?)?;
	let expiry = relay.request.refund_height.checked_add(relay.request.safety_margin_blocks).context("expiry overflow")?;
	verify_ark_transfer_before_acceptance(&offer, &transfer, expiry.into())?;
	Ok((offer, transfer))
}

async fn receive_funding_message(wallet: &Wallet, datadir: &Path, coordinator: &str, state: &mut StoredBtcArkSwap) -> anyhow::Result<bool> {
	ensure!(matches!(state.status, SwapStatus::Offered | SwapStatus::BtcClaimReady | SwapStatus::BtcClaimed)
		&& state.ark_recovery_input_ids.is_empty(), "cannot reveal an aborted swap's secret");
	if state.relay.btc_claim_adaptor.is_some() { return Ok(true); }
	let peer = load_relay(coordinator).await?;
	peer.require_swap(SwapId::from_str(&state.swap_id)?)?;
	ensure!(Some(peer.response_commitment_hash_hex()?) == state.peer_transcript_hash_hex, "peer changed accepted Ark/funding/nonce transcript");
	if peer.btc_claim_adaptor.is_none() { return Ok(false); }
	let (_, funding, _) = verify_response(wallet, &peer).await?;
	ensure!(funding.input.iter().all(|input| !input.witness.is_empty()), "Bob has not signed funding");
	state.relay = peer;
	state.status = SwapStatus::BtcClaimReady;
	store_swap_state(datadir, state).await?;
	Ok(true)
}

async fn progress_swap(wallet: &Wallet, onchain: &mut dyn OnchainWalletTrait, datadir: &Path, coordinator: &str, state: &mut StoredBtcArkSwap, fee_rate: Option<u64>) -> anyhow::Result<&'static str> {
	if is_terminal(state) { return Ok("done"); }
	wallet.chain().require_transaction_index().await?;
	if state.status == SwapStatus::ArkRecovering
		|| (state.role == SwapRole::ArkPayer && state.status == SwapStatus::Cancelled) {
		return progress_ark_recovery(wallet, onchain, datadir, state, fee_rate).await;
	}
	match state.role {
		SwapRole::BtcPayer => {
			if state.relay.btc_claim_adaptor.is_none() { return Ok("btc-fund"); }
			if observe_claim(wallet, datadir, state).await? {
				complete_ark(wallet, onchain, datadir, state).await?;
				return Ok(if is_terminal(state) { "done" } else { "await-ark-exit" });
			}
			if wallet.chain().tip().await? >= state.relay.request.refund_height.into() {
				refund_btc(wallet, datadir, state, fee_rate).await?;
				return Ok(if is_terminal(state) { "done" } else { "await-refund-confirmation" });
			}
			let funding = funding_tx(&state.relay)?;
			if wallet.chain().tx_status(funding.compute_txid()).await? == TxStatus::NotFound {
				wallet.chain().broadcast_tx(&funding).await?;
			}
			Ok("await-btc-claim")
		},
		SwapRole::ArkPayer => {
			if state.signed_claim_tx_hex.is_some() {
				claim_btc(wallet, onchain, datadir, state, fee_rate).await?;
				return Ok(if is_terminal(state) { "done" } else { "await-claim-confirmation" });
			}
			let tip: u32 = wallet.chain().tip().await?.into();
			if tip.checked_add(state.relay.request.safety_margin_blocks).context("height overflow")? >= state.relay.request.refund_height {
				abort_ark(wallet, datadir, state).await?;
				return progress_ark_recovery(wallet, onchain, datadir, state, fee_rate).await;
			}
			if !receive_funding_message(wallet, datadir, coordinator, state).await? { return Ok("await-btc-funding"); }
			let funding = funding_tx(&state.relay)?;
			let Some(height) = wallet.chain().tx_confirmed(funding.compute_txid()).await? else { return Ok("await-funding-confirmation"); };
			if tip.saturating_sub(u32::from(height)).saturating_add(1) < state.relay.request.minimum_funding_confirmations { return Ok("await-funding-confirmation"); }
			claim_btc(wallet, onchain, datadir, state, fee_rate).await?;
			Ok("await-claim-confirmation")
		},
	}
}

async fn claim_btc(wallet: &Wallet, onchain: &mut dyn OnchainWalletTrait, datadir: &Path, state: &mut StoredBtcArkSwap, fee_rate: Option<u64>) -> anyhow::Result<()> {
	ensure!(matches!(state.status, SwapStatus::Offered | SwapStatus::BtcClaimReady | SwapStatus::BtcClaimed)
		&& state.ark_recovery_input_ids.is_empty(), "cannot reveal an aborted swap's secret");
	let (lock, _, mut claim) = verify_response(wallet, &state.relay).await?;
	if state.signed_claim_tx_hex.is_none() {
		verify_claim_window(wallet, claim.input[0].previous_output, &lock,
			state.relay.request.minimum_funding_confirmations, state.relay.request.safety_margin_blocks).await?;
		let target = target_fee(wallet, &state.relay, fee_rate).await?;
		onchain.sync(wallet.chain()).await?;
		// CPFP commits the parent txid, not its witness. Prepare fee funding
		// with the correct witness weight before creating a revealing signature.
		let mut fee_probe = claim.clone();
		fee_probe.input[0].witness.push([0u8; 64]);
		let child = onchain.make_signed_p2a_cpfp(&fee_probe, MakeCpfpFees::Effective(target)).await
			.context("claim requires confirmed on-chain fee funds")?;
		verify_claim_window(wallet, claim.input[0].previous_output, &lock,
			state.relay.request.minimum_funding_confirmations, state.relay.request.safety_margin_blocks).await?;
		let secret = AdaptorSecret::new(secret_key_from_hex(state.adaptor_secret_hex.as_deref().context("missing adaptor secret")?)?);
		let signature = state.relay.btc_claim_adaptor.as_ref().context("missing Bob claim adaptor")?.to_package()?.finalize_with_secret(secret)?;
		claim.input[0].witness.push(signature.serialize());
		state.signed_claim_tx_hex = Some(serialize_hex(&claim));
		state.cpfp_tx_hex = Some(serialize_hex(&child));
		// No further fee-estimation/network preparation before first disclosure.
		// Broadcast can leak t even if its RPC fails; abort is now forbidden.
		store_swap_state(datadir, state).await?;
		onchain.store_signed_p2a_cpfp(&child).await?;
		wallet.chain().broadcast_package(&[&claim, &child]).await?;
	} else {
		claim = deserialize_hex(state.signed_claim_tx_hex.as_deref().expect("checked above"))?;
		if wallet.chain().tx_confirmed(claim.compute_txid()).await?.is_none() {
			broadcast_claim(wallet, onchain, datadir, state, &claim, fee_rate).await?;
		}
	}
	wallet.mark_vtxos_as_spent(state.accepted_ark_input_ids()?).await?;
	let transfer = TransferableAdaptorArkoorPackage::deserialize_hex(&state.relay.ark_transfer.as_ref().context("missing Ark package")?.transfer_package_hex)?;
	let secret = AdaptorSecret::new(secret_key_from_hex(state.adaptor_secret_hex.as_deref().context("missing adaptor secret")?)?);
	// Ordinary registration provisions the watchman, but is not an atomicity guarantee.
	// This also imports Alice's change, never the outputs belonging to Bob.
	wallet.complete_btc_ark_transfer(transfer, secret).await?;
	if has_confirmations(wallet, claim.compute_txid(), state.relay.request.minimum_funding_confirmations).await? {
		state.status = SwapStatus::BtcClaimed;
		store_swap_state(datadir, state).await?;
	}
	Ok(())
}

async fn broadcast_claim(wallet: &Wallet, onchain: &mut dyn OnchainWalletTrait, datadir: &Path, state: &mut StoredBtcArkSwap, claim: &Transaction, override_fee: Option<u64>) -> anyhow::Result<()> {
	let target = target_fee(wallet, &state.relay, override_fee).await?;
	onchain.sync(wallet.chain()).await?;
	let mut fees = MakeCpfpFees::Effective(target);
	if let Some(hex) = &state.cpfp_tx_hex {
		let child: Transaction = deserialize_hex(hex)?;
		let package_fee = if wallet.chain().tx_status(child.compute_txid()).await? == TxStatus::Mempool {
			let info = wallet.chain().mempool_ancestor_info(child.compute_txid()).await?;
			if info.effective_fee_rate().is_some_and(|rate| rate >= target) { return Ok(()); }
			info.total_fee
		} else {
			// An evicted/never-accepted child must not freeze its old fee forever.
			let child_fee = transaction_fee(wallet, &child, Some(claim)).await?;
			let parent_fee = Amount::from_sat(state.relay.request.amount_sat)
				.checked_sub(sum_outputs(&claim.output)?).context("invalid claim fee")?;
			let mut fee = child_fee.checked_add(parent_fee).context("package fee overflow")?;
			let anchor = OutPoint::new(claim.compute_txid(), 1);
			let spends = wallet.chain().txs_spending_inputs([anchor], wallet.chain().tip().await?).await?;
			if let Some((txid, TxStatus::Mempool)) = spends.map.get(&anchor) {
				fee = fee.max(wallet.chain().mempool_ancestor_info(*txid).await?.total_fee);
			}
			fee
		};
		fees = MakeCpfpFees::Rbf { min_effective_fee_rate: target, current_package_fee: package_fee };
	}
	let child = onchain.make_signed_p2a_cpfp(claim, fees).await.context("claim requires confirmed on-chain fee funds")?;
	state.cpfp_tx_hex = Some(serialize_hex(&child));
	store_swap_state(datadir, state).await?;
	onchain.store_signed_p2a_cpfp(&child).await?;
	wallet.chain().broadcast_package(&[claim, &child]).await.context("failed to broadcast claim/CPFP package")
}

async fn observe_claim(wallet: &Wallet, datadir: &Path, state: &mut StoredBtcArkSwap) -> anyhow::Result<bool> {
	if state.signed_claim_tx_hex.is_some() { return Ok(true); }
	let Some(request) = &state.relay.claim_request else { return Ok(false); };
	let expected: Transaction = deserialize_hex(&request.claim_tx_hex)?;
	let Some(observed) = wallet.chain().get_tx(&expected.compute_txid()).await? else { return Ok(false); };
	ensure!(without_witness(&observed) == expected, "observed claim differs from signed template");
	let bytes = observed.input[0].witness.nth(0).context("observed claim has no signature")?;
	ensure!(bytes.len() == 64 && observed.input[0].witness.len() == 1, "claim is not the committed default key spend");
	state.relay.btc_claim_adaptor.as_ref().context("missing local adaptor")?.to_package()?.recover_secret(schnorr::Signature::from_slice(bytes)?)?;
	state.signed_claim_tx_hex = Some(serialize_hex(&observed));
	store_swap_state(datadir, state).await?;
	Ok(true)
}

async fn complete_ark(wallet: &Wallet, onchain: &mut dyn OnchainWalletTrait, datadir: &Path, state: &mut StoredBtcArkSwap) -> anyhow::Result<()> {
	if state.status == SwapStatus::ArkCompleted { return Ok(()); }
	if state.status == SwapStatus::ArkRecovering {
		progress_ark_recovery(wallet, onchain, datadir, state, None).await?;
		return Ok(());
	}
	let claim: Transaction = deserialize_hex(state.signed_claim_tx_hex.as_deref().context("claim signature not yet observed")?)?;
	let signature = schnorr::Signature::from_slice(claim.input[0].witness.nth(0).context("missing claim signature")?)?;
	let secret = state.relay.btc_claim_adaptor.as_ref().context("missing adaptor")?.to_package()?.recover_secret(signature)?;
	let artifact = state.relay.ark_transfer.as_ref().context("missing Ark package")?;
	let transfer = TransferableAdaptorArkoorPackage::deserialize_hex(&artifact.transfer_package_hex)?;
	let signed = transfer.finalize_with_secret(secret)?.build_signed_vtxos();
	let receive = ark::Address::from_str(state.relay.payer_ark_receive()?)?;
	let mut received = Vec::new();
	for vtxo in &signed {
		if vtxo.policy() == receive.policy() {
			// Import first: the full exit witnesses survive a server outage.
			wallet.import_vtxo(vtxo, bark::ImportVtxoArgs {
				skip_status_check: true,
				..Default::default()
			}).await?;
			received.push(vtxo.id());
		}
	}
	if let Err(error) = wallet.register_vtxo_transactions_with_server(&signed).await {
		// Freeze the owned receive outputs before starting an irreversible exit.
		state.ark_recovery_input_ids = received.iter().map(ToString::to_string).collect();
		state.status = SwapStatus::ArkRecovering;
		store_swap_state(datadir, state).await?;
		eprintln!("Ark registration failed; recovering received VTXOs on-chain: {error:#}");
		progress_ark_recovery(wallet, onchain, datadir, state, None).await?;
		return Ok(());
	}
	state.status = SwapStatus::ArkCompleted;
	store_swap_state(datadir, state).await?;
	Ok(())
}

async fn refund_btc(wallet: &Wallet, datadir: &Path, state: &mut StoredBtcArkSwap, override_fee: Option<u64>) -> anyhow::Result<()> {
	ensure!(!matches!(state.status, SwapStatus::ArkCompleted | SwapStatus::ArkRecovering | SwapStatus::ArkReclaimed), "Ark already received; refusing BTC refund");
	ensure!(!observe_claim(wallet, datadir, state).await?, "claim signature is visible; complete Ark instead of refunding");
	let (lock, funding, _) = verify_response(wallet, &state.relay).await?;
	ensure!(lock.refund_is_mature(wallet.chain().tip().await?), "absolute BTC refund height has not arrived");
	let mut refund: Transaction = deserialize_hex(state.signed_refund_tx_hex.as_deref().context("missing durable refund transaction")?)?;
	if let Some((txid, stable)) = confirmed_recovery(wallet, refund.compute_txid(), &state.previous_refund_txids, state.relay.request.minimum_funding_confirmations).await? {
		if txid != refund.compute_txid() {
			state.signed_refund_tx_hex = Some(serialize_hex(&wallet.chain().get_tx(&txid).await?.context("confirmed refund disappeared")?));
		}
		if stable { state.status = SwapStatus::Refunded; }
		store_swap_state(datadir, state).await?;
		return Ok(());
	}
	let funding_status = wallet.chain().tx_status(funding.compute_txid()).await?;
	let funding_confirmed = matches!(funding_status, TxStatus::Confirmed(_));
	if funding_status == TxStatus::NotFound {
		let tip = wallet.chain().tip_ref().await?;
		if state.funding_conflict_scan_tip != Some(tip) {
			let from = state.funding_conflict_scan_tip.map(|last| last.height.to_u32().saturating_sub(state.relay.request.safety_margin_blocks))
				.unwrap_or(state.relay.request.created_height.saturating_sub(state.relay.request.safety_margin_blocks))
				.min(tip.height.to_u32());
			let conflicts = wallet.chain().txs_spending_inputs(funding.input.iter().map(|i| i.previous_output), from.into()).await?;
			if conflicts.map.values().any(|(txid, status)| *txid != funding.compute_txid()
				&& status.confirmed_height().is_some_and(|h| tip.height.to_u32().saturating_sub(h.to_u32()).saturating_add(1) >= state.relay.request.minimum_funding_confirmations)) {
				state.status = SwapStatus::Cancelled;
			}
			state.funding_conflict_scan_tip = Some(tip);
			store_swap_state(datadir, state).await?;
			if state.status == SwapStatus::Cancelled { return Ok(()); }
		}
	}
	let target = target_fee(wallet, &state.relay, override_fee).await?;
	let parent_fee = sum_outputs(&funding_template(&state.relay.request)?.1)?.checked_sub(sum_outputs(&funding.output)?).context("invalid funding fee")?;
	let old_fee = lock.amount.checked_sub(sum_outputs(&refund.output)?).context("invalid refund fee")?;
	let needed = if funding_confirmed { target * refund.weight() }
		else { (target * (funding.weight() + refund.weight())).checked_sub(parent_fee).unwrap_or(Amount::ZERO) };
	if needed > old_fee {
		let previous_id = refund.compute_txid();
		let replacement_fee = needed.max(old_fee + FeeRate::from_sat_per_vb(1).expect("valid rate") * refund.weight());
		refund.input[0].witness = Witness::new();
		refund.output[0].value = lock.amount.checked_sub(replacement_fee).context("refund fee exceeds locked amount")?;
		ensure!(refund.output[0].is_standard(), "refund fee leaves a nonstandard payout");
		let key = wallet.peek_keypair(state.claim_key_index).await?;
		refund = sign_refund_tx(refund, &lock, &key)?;
		if !state.previous_refund_txids.contains(&previous_id) { state.previous_refund_txids.push(previous_id); }
		state.signed_refund_tx_hex = Some(serialize_hex(&refund));
		store_swap_state(datadir, state).await?;
	}
	if funding_status != TxStatus::NotFound {
		// With a mempool parent use ordinary single-transaction RBF, not
		// non-TRUC package RBF (which Bitcoin Core does not support).
		wallet.chain().broadcast_tx(&refund).await?;
	} else {
		wallet.chain().broadcast_package(&[&funding, &refund]).await?;
	}
	Ok(())
}

async fn abort_ark(wallet: &Wallet, datadir: &Path, state: &mut StoredBtcArkSwap) -> anyhow::Result<()> {
	ensure!(state.signed_claim_tx_hex.is_none() && state.status != SwapStatus::BtcClaimed, "adaptor secret may already be public; cannot abort");
	if state.status == SwapStatus::ArkReclaimed { return Ok(()); }
	if let Some(request) = &state.relay.claim_request {
		let tx: Transaction = deserialize_hex(&request.claim_tx_hex)?;
		ensure!(wallet.chain().get_tx(&tx.compute_txid()).await?.is_none(), "BTC claim is visible; cannot abort");
	}
	let ids = state.accepted_ark_input_ids()?;
	state.ark_recovery_input_ids = ids.iter().map(ToString::to_string).collect();
	state.status = SwapStatus::Cancelled;
	// Persist the no-disclosure decision before any exit database mutation.
	store_swap_state(datadir, state).await?;
	let mut vtxos = Vec::with_capacity(ids.len());
	for id in ids { vtxos.push(wallet.get_vtxo_by_id(id).await?.vtxo); }
	wallet.exit_mgr().start_exit_for_vtxos(&vtxos).await?;
	Ok(())
}

async fn progress_exits_with_held_onchain(
	wallet: &Wallet,
	onchain: &mut dyn OnchainWalletTrait,
	exit_mgr: &bark::exit::Exit,
	target: FeeRate,
) -> anyhow::Result<()> {
	exit_mgr.progress_exits(wallet).await?;
	for request in exit_mgr.exits_needing_cpfp().await {
		let fees = match request.rbf_requirement {
			None => MakeCpfpFees::Effective(target),
			Some(rbf) => {
				if target <= rbf.min_fee_rate { continue; }
				MakeCpfpFees::Rbf {
					min_effective_fee_rate: target,
					current_package_fee: rbf.current_package_fee,
				}
			},
		};
		let child = onchain.make_signed_p2a_cpfp(&request.exit_tx, fees).await?;
		onchain.store_signed_p2a_cpfp(&child).await?;
		exit_mgr.provide_cpfp_tx(wallet, request.exit_tx.compute_txid(), child).await?;
	}
	Ok(())
}

async fn progress_ark_recovery(wallet: &Wallet, onchain: &mut dyn OnchainWalletTrait, datadir: &Path, state: &mut StoredBtcArkSwap, override_fee: Option<u64>) -> anyhow::Result<&'static str> {
	let ids = state.ark_recovery_input_ids.iter().map(|id| VtxoId::from_str(id))
		.collect::<Result<Vec<_>, _>>()?;
	ensure!(!ids.is_empty(), "missing frozen Ark recovery inputs");
	onchain.sync(wallet.chain()).await?;
	let exit_mgr = wallet.exit_mgr();
	let tracked = exit_mgr.get_exit_vtxos().await;
	let mut missing = Vec::new();
	for id in &ids {
		if !tracked.iter().any(|exit| exit.id() == *id) {
			missing.push(wallet.get_vtxo_by_id(*id).await?.vtxo);
		}
	}
	exit_mgr.start_exit_for_vtxos(&missing).await?;
	let target = target_fee(wallet, &state.relay, override_fee).await?;
	if let Some(hex) = &state.ark_exit_claim_tx_hex {
		let mut tx: Transaction = deserialize_hex(hex)?;
		let previous_txid = tx.compute_txid();
		if let Some((txid, stable)) = confirmed_recovery(wallet, previous_txid, &state.previous_ark_exit_claim_txids, state.relay.request.minimum_funding_confirmations).await? {
			if txid != previous_txid {
				state.ark_exit_claim_tx_hex = Some(serialize_hex(&wallet.chain().get_tx(&txid).await?.context("confirmed Ark reclaim disappeared")?));
			}
			if stable { state.status = SwapStatus::ArkReclaimed; }
			store_swap_state(datadir, state).await?;
			return Ok(if stable { "done" } else { "await-ark-reclaim-confirmation" });
		}
		let old_fee = transaction_fee(wallet, &tx, None).await?;
		if old_fee >= target * tx.weight() {
			if wallet.chain().tx_status(previous_txid).await? == TxStatus::NotFound {
				wallet.chain().broadcast_tx(&tx).await?;
			}
			return Ok("await-ark-reclaim-confirmation");
		}
		let minimum = old_fee.checked_add(FeeRate::from_sat_per_vb(1).expect("valid rate") * tx.weight())
			.context("reclaim replacement fee overflow")?;
		let fee = minimum.max(target * tx.weight());
		ensure!(tx.output.len() == 1, "unexpected Ark reclaim output count");
		tx.output[0].value = tx.output[0].value.checked_sub(fee - old_fee)
			.context("Ark reclaim fee exceeds output")?;
		ensure!(tx.output[0].value >= tx.output[0].script_pubkey.minimal_non_dust(), "Ark reclaim fee leaves dust");
		let mut vtxos = Vec::with_capacity(tx.input.len());
		for input in &tx.input {
			let id = VtxoId::from(input.previous_output);
			ensure!(ids.contains(&id), "Ark reclaim input is not in the frozen recovery set");
			vtxos.push(wallet.get_vtxo_by_id(id).await?.vtxo);
		}
		ensure!(vtxos.len() == ids.len(), "Ark reclaim does not cover the frozen recovery set");
		let prevouts = vtxos.iter().map(|vtxo| vtxo.txout()).collect::<Vec<_>>();
		let mut sighashes = bitcoin::sighash::SighashCache::new(&mut tx);
		for (index, vtxo) in vtxos.iter().enumerate() {
			let witness = wallet.sign_input(vtxo, index, &mut sighashes, &bitcoin::sighash::Prevouts::All(&prevouts)).await?;
			*sighashes.witness_mut(index).context("missing reclaim input")? = witness;
		}
		if !state.previous_ark_exit_claim_txids.contains(&previous_txid) {
			state.previous_ark_exit_claim_txids.push(previous_txid);
		}
		state.ark_exit_claim_tx_hex = Some(serialize_hex(&tx));
		store_swap_state(datadir, state).await?;
		wallet.chain().broadcast_tx(&tx).await?;
		return Ok("await-ark-reclaim-confirmation");
	}
	progress_exits_with_held_onchain(wallet, onchain, exit_mgr, target).await?;
	let claimable = exit_mgr.list_claimable().await.into_iter()
		.filter(|vtxo| ids.contains(&vtxo.id())).collect::<Vec<_>>();
	if claimable.len() != ids.len() { return Ok("await-ark-exit"); }
	let destination = onchain.address().await?;
	let claim = exit_mgr.drain_exits(&claimable, wallet, destination, Some(target)).await?.extract_tx()?;
	state.ark_exit_claim_tx_hex = Some(serialize_hex(&claim));
	store_swap_state(datadir, state).await?;
	wallet.chain().broadcast_tx(&claim).await?;
	Ok("await-ark-reclaim-confirmation")
}

async fn target_fee(wallet: &Wallet, relay: &RelayFile, override_fee: Option<u64>) -> anyhow::Result<FeeRate> {
	if let Some(rate) = override_fee { return fee_rate_from_sat_vb(rate); }
	wallet.chain().update_fee_rates(Some(request_fee(relay)?)).await?;
	Ok(wallet.chain().fee_rates().await.fast.max(request_fee(relay)?))
}

fn request_fee(relay: &RelayFile) -> anyhow::Result<FeeRate> {
	fee_rate_from_sat_vb(relay.request.fee_rate_sat_vb)
}

fn funding_tx(relay: &RelayFile) -> anyhow::Result<Transaction> {
	Ok(deserialize_hex(&relay.btc_funding.as_ref().context("missing funding transaction")?.funding_tx_hex)?)
}

fn without_witness(tx: &Transaction) -> Transaction {
	let mut unsigned = tx.clone();
	for input in &mut unsigned.input { input.witness = Witness::new(); }
	unsigned
}

fn sum_outputs(outputs: &[TxOut]) -> anyhow::Result<Amount> {
	outputs.iter().try_fold(Amount::ZERO, |sum, output| sum.checked_add(output.value).context("transaction amount overflow"))
}

fn is_terminal(state: &StoredBtcArkSwap) -> bool {
	matches!(state.status, SwapStatus::BtcClaimed | SwapStatus::ArkCompleted | SwapStatus::Refunded | SwapStatus::ArkReclaimed)
		|| (state.role == SwapRole::BtcPayer && state.status == SwapStatus::Cancelled)
}

fn output_json<T: ?Sized + Serialize>(value: &T) {
	serde_json::to_writer_pretty(io::stdout(), value).expect("JSON write failed");
	println!();
}

fn output_state(state: &StoredBtcArkSwap, next: &str) {
	output_json(&serde_json::json!({
		"protocol": "btc-ark", "version": 3, "swap_id": state.swap_id, "role": state.role,
		"status": state.status, "coordinator": state.coordinator, "next": next,
		"refund_height": state.relay.request.refund_height,
		"claim_txid": state.relay.claim_request.as_ref().and_then(|r| deserialize_hex::<Transaction>(&r.claim_tx_hex).ok()).map(|t| t.compute_txid()),
		"refund_txid": state.signed_refund_tx_hex.as_ref().and_then(|r| deserialize_hex::<Transaction>(r).ok()).map(|t| t.compute_txid()),
		"relay": state.relay,
	}));
}

async fn has_confirmations(wallet: &Wallet, txid: Txid, required: u32) -> anyhow::Result<bool> {
	let Some(height) = wallet.chain().tx_confirmed(txid).await? else { return Ok(false); };
	Ok(wallet.chain().tip().await?.checked_blocks_since(height)
		.is_some_and(|depth| depth.saturating_add(1) >= required))
}

async fn confirmed_recovery(wallet: &Wallet, current: Txid, previous: &[Txid], required: u32) -> anyhow::Result<Option<(Txid, bool)>> {
	for txid in std::iter::once(current).chain(previous.iter().copied()) {
		if wallet.chain().tx_confirmed(txid).await?.is_some() {
			return Ok(Some((txid, has_confirmations(wallet, txid, required).await?)));
		}
	}
	Ok(None)
}

async fn transaction_fee(wallet: &Wallet, tx: &Transaction, known_parent: Option<&Transaction>) -> anyhow::Result<Amount> {
	let mut incoming = Amount::ZERO;
	let known_id = known_parent.map(Transaction::compute_txid);
	for input in &tx.input {
		let point = input.previous_output;
		let value = if known_id == Some(point.txid) {
			known_parent.expect("matching known parent").output.get(point.vout as usize).context("missing parent output")?.value
		} else {
			wallet.chain().get_tx(&point.txid).await?.context("missing fee input transaction")?
				.output.get(point.vout as usize).context("missing fee input output")?.value
		};
		incoming = incoming.checked_add(value).context("fee input overflow")?;
	}
	incoming.checked_sub(sum_outputs(&tx.output)?).context("invalid transaction fee")
}
