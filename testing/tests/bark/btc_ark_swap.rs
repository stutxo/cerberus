use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ark::musig::AdaptorSecret;
use ark_testing::daemon::captaind::{ArkClient, proxy::ArkRpcProxy};
use ark_testing::{Bark, Captaind, TestContext, btc, sat};
use bark::swap::btc_ark::{
	BtcLockContract, build_cooperative_claim_adaptor_package, build_cooperative_claim_tx,
	build_refund_tx, cooperative_claim_sighash, sign_refund_tx,
};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{Keypair, SecretKey, rand};
use bitcoin::{Amount, FeeRate, Network, OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use parking_lot::Mutex;
use prost::Message;
use serde_json::Value;
use server_rpc::protos;

#[derive(Clone, Default)]
struct OperatorView {
	cosigns: Arc<Mutex<Vec<Vec<u8>>>>,
	registrations: Arc<Mutex<Vec<Vec<u8>>>>,
	reject_registrations: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ArkRpcProxy for OperatorView {
	async fn request_arkoor_cosign(&self, upstream: &mut ArkClient, request: protos::ArkoorPackageCosignRequest) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		self.cosigns.lock().push(request.encode_to_vec());
		Ok(upstream.request_arkoor_cosign(request).await?.into_inner())
	}

	async fn register_vtxo_transactions(&self, upstream: &mut ArkClient, request: protos::RegisterVtxoTransactionsRequest) -> Result<protos::Empty, tonic::Status> {
		self.registrations.lock().push(request.encode_to_vec());
		if self.reject_registrations.load(Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("registration unavailable"));
		}
		Ok(upstream.register_vtxo_transactions(request).await?.into_inner())
	}
}

struct Swap {
	ctx: TestContext,
	_server: Arc<Captaind>,
	_proxy: ark_testing::daemon::captaind::proxy::ArkRpcProxyServer,
	alice: Bark,
	bob: Bark,
	alice_relay: PathBuf,
	bob_relay: PathBuf,
	id: String,
	operator: OperatorView,
}

impl Swap {
	async fn request(name: &str, board_amount: Amount, amount: Amount, refund_window: u32) -> Self {
		let ctx = TestContext::new(format!("bark/{name}")).await;
		let server = ctx.captaind("server").funded(btc(10)).cfg(|cfg| cfg.vtxo_exit_delta = 32.into()).create().await;
		let operator = OperatorView::default();
		let proxy = server.start_proxy_no_mailbox(operator.clone()).await;
		let alice = ctx.bark("alice", &proxy.address).funded(sat(300_000)).create().await;
		let bob = ctx.bark("bob", &proxy.address).funded(sat(300_000)).create().await;
		alice.board_and_confirm_and_register(&ctx, board_amount).await;
		let alice_relay = ctx.datadir.join("alice-relay.json");
		let bob_relay = ctx.datadir.join("bob-relay.json");
		let requested: Value = bob.run_json([
			"swap", "btc-ark", "btc-request", "--coordinator", bob_relay.to_str().unwrap(),
			"--amount", &amount.to_string(), "--ark-receive", bob.address().await.trim(),
			"--fee-rate", "1", "--refund-delay", &refund_window.to_string(),
			"--confirmations", "1", "--safety-margin", "2",
		]).await;
		let id = requested["swap_id"].as_str().unwrap().to_owned();
		// Peer handoff 1: no Ark transfer or signed funding exists yet.
		tokio::fs::copy(&bob_relay, &alice_relay).await.unwrap();
		Self { ctx, _server: server, _proxy: proxy, alice, bob, alice_relay, bob_relay, id, operator }
	}

	async fn offer(&self) -> Value {
		let offer = self.alice.run_json([
			"swap", "btc-ark", "ark-offer", "--coordinator", self.alice_relay.to_str().unwrap(),
			"--swap", &self.id, "--btc-payout", &self.alice.get_onchain_address().await.to_string(),
		]).await;
		// Peer handoff 2: Alice's public Ark package and adapted BTC partial.
		tokio::fs::copy(&self.alice_relay, &self.bob_relay).await.unwrap();
		offer
	}

	async fn fund(&self) -> Value {
		let funded = self.bob.run_json([
			"swap", "btc-ark", "btc-fund", "--coordinator", self.bob_relay.to_str().unwrap(), "--swap", &self.id,
		]).await;
		// Peer handoff 3: signed funding and the aggregate BTC adaptor.
		tokio::fs::copy(&self.bob_relay, &self.alice_relay).await.unwrap();
		funded
	}

	async fn progress(&self, alice: bool) -> Value {
		let (wallet, relay, role) = if alice { (&self.alice, &self.alice_relay, "ark-payer") }
			else { (&self.bob, &self.bob_relay, "btc-payer") };
		wallet.run_json([
			"swap", "btc-ark", "progress", "--coordinator", relay.to_str().unwrap(),
			"--swap", &self.id, "--role", role, "--fee-rate", "2",
		]).await
	}

	async fn public(&self) -> Value {
		serde_json::from_slice(&tokio::fs::read(&self.bob_relay).await.unwrap()).unwrap()
	}

	async fn private(&self, alice: bool) -> Value {
		let (wallet, role) = if alice { (&self.alice, "ark-payer") } else { (&self.bob, "btc-payer") };
		let file = wallet.datadir().join("swap").join(format!("btc-ark-{}-{role}.json", self.id));
		serde_json::from_slice(&tokio::fs::read(file).await.unwrap()).unwrap()
	}

	async fn mine_to(&self, height: u32) {
		let tip = self.ctx.bitcoind().get_block_count().await as u32;
		if height > tip { self.ctx.generate_blocks(height - tip).await; }
	}
}

#[tokio::test]
async fn private_three_message_swap_settles_and_returns_change() {
	let swap = Swap::request("private_three_message_swap_settles_and_returns_change", sat(100_000), sat(80_000), 12).await;
	let alice_btc_before = swap.alice.onchain_balance().await;
	let offer = swap.offer().await;
	let unsigned: Transaction = deserialize_hex(offer["relay"]["btc_funding"]["funding_tx_hex"].as_str().unwrap()).unwrap();
	assert!(unsigned.input.iter().all(|input| input.witness.is_empty()));
	let funded = swap.fund().await;
	let signed: Transaction = deserialize_hex(funded["relay"]["btc_funding"]["funding_tx_hex"].as_str().unwrap()).unwrap();
	assert_eq!(signed.compute_txid(), unsigned.compute_txid());
	assert_ne!(signed.compute_wtxid(), unsigned.compute_wtxid());
	let early = swap.progress(true).await;
	assert_eq!(early["next"], "await-funding-confirmation");
	swap.ctx.generate_blocks(1).await;
	let claimed = swap.progress(true).await;
	let claim_id = Txid::from_str(claimed["claim_txid"].as_str().unwrap()).unwrap();
	let rpc = swap.ctx.bitcoind().sync_client();
	assert!(rpc.get_mempool_entry(&claim_id).is_ok());
	let _: Value = swap.alice.run_json([
		"swap", "btc-ark", "progress", "--coordinator", swap.alice_relay.to_str().unwrap(),
		"--swap", &swap.id, "--role", "ark-payer", "--fee-rate", "10",
	]).await;
	let child: Transaction = deserialize_hex(swap.private(true).await["cpfp_tx_hex"].as_str().unwrap()).unwrap();
	let wallet = swap.alice.client().await;
	let child_id = child.compute_txid();
	let info = ark_testing::util::FutureExt::wait_millis(async {
		loop {
			if let Ok(info) = wallet.chain().mempool_ancestor_info(child_id).await {
				break info;
			}
			tokio::time::sleep(std::time::Duration::from_millis(100)).await;
		}
	}, ark_testing::util::get_tx_propagation_timeout_millis()).await;
	assert!(info.effective_fee_rate().unwrap() >= FeeRate::from_sat_per_vb(10).unwrap());
	// Neither side requires another relay exchange after receiving M3.
	tokio::fs::remove_file(&swap.alice_relay).await.unwrap();
	tokio::fs::remove_file(&swap.bob_relay).await.unwrap();
	let completed = swap.progress(false).await;
	assert_eq!(completed["status"], "ArkCompleted");
	assert_eq!(swap.bob.spendable_balance().await, sat(80_000));
	assert_eq!(swap.alice.spendable_balance().await, sat(20_000));
	tokio::join!(
		swap.alice.run([
			"swap", "btc-ark", "progress", "--coordinator", swap.alice_relay.to_str().unwrap(),
			"--swap", &swap.id, "--role", "ark-payer", "--watch", "--fee-rate", "10",
		]),
		swap.ctx.generate_blocks(1),
	);
	assert_eq!(swap.private(true).await["status"], "BtcClaimed");
	assert!(swap.alice.onchain_balance().await > alice_btc_before + sat(70_000));
	let lock = OutPoint::new(signed.compute_txid(), funded["relay"]["btc_funding"]["funding_vout"].as_u64().unwrap() as u32);
	assert!(rpc.get_tx_out(&lock.txid, lock.vout, Some(true)).unwrap().is_none());
	let private = swap.private(true).await;
	let secret_hex = private["adaptor_secret_hex"].as_str().unwrap();
	let point_hex = offer["relay"]["terms"]["adaptor_point"].as_str().unwrap();
	let secret = Vec::<u8>::from_hex(secret_hex).unwrap();
	let point = Vec::<u8>::from_hex(point_hex).unwrap();
	let cosigns = swap.operator.cosigns.lock();
	assert_eq!(cosigns.len(), 1, "one ordinary arkoor cosign, not a swap-aware server exchange");
	for request in cosigns.iter().chain(swap.operator.registrations.lock().iter()) {
		for forbidden in [&secret[..], &point[..], secret_hex.as_bytes(), point_hex.as_bytes(), swap.id.as_bytes()] {
			assert!(!request.windows(forbidden.len()).any(|window| window == forbidden), "operator RPC exposed private swap material");
		}
	}
}

#[tokio::test]
async fn private_swap_refuses_unsafe_window_before_ark_commitment() {
	let swap = Swap::request("private_swap_refuses_unsafe_window_before_ark_commitment", sat(80_000), sat(80_000), 80).await;
	let result = swap.alice.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "ark-offer", "--coordinator", swap.alice_relay.to_str().unwrap(),
		"--swap", &swap.id, "--btc-payout", &swap.alice.get_onchain_address().await.to_string(),
	]).await;
	assert!(result.is_err(), "BTC refund must precede the earliest old Ark reclaim");
	assert_eq!(swap.alice.spendable_balance().await, sat(80_000));
	assert!(swap.operator.cosigns.lock().is_empty());
}

#[tokio::test]
async fn private_swap_rejects_future_funding_locktime() {
	let swap = Swap::request("private_swap_rejects_future_funding_locktime", sat(80_000), sat(80_000), 12).await;
	let mut relay = swap.public().await;
	let mut funding: Transaction = deserialize_hex(relay["request"]["funding_template_hex"].as_str().unwrap()).unwrap();
	funding.lock_time = bitcoin::absolute::LockTime::from_height(relay["request"]["created_height"].as_u64().unwrap() as u32 + 1).unwrap();
	relay["request"]["funding_template_hex"] = Value::String(serialize_hex(&funding));
	tokio::fs::write(&swap.alice_relay, serde_json::to_vec(&relay).unwrap()).await.unwrap();
	let result = swap.alice.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "ark-offer", "--coordinator", swap.alice_relay.to_str().unwrap(),
		"--swap", &swap.id, "--btc-payout", &swap.alice.get_onchain_address().await.to_string(),
	]).await;
	assert!(result.is_err());
	assert_eq!(swap.alice.spendable_balance().await, sat(80_000));
	assert!(swap.operator.cosigns.lock().is_empty());
}

#[tokio::test]
async fn private_swap_rejects_exiting_ark_before_funding() {
	let swap = Swap::request("private_swap_rejects_exiting_ark_before_funding", sat(80_000), sat(80_000), 12).await;
	let offer = swap.offer().await;
	let _: Value = swap.alice.run_json([
		"swap", "btc-ark", "ark-abort", "--coordinator", swap.alice_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await;
	// Broadcast the pinned old exit without modifying Bob's copy of M2.
	swap.progress(true).await;
	let result = swap.bob.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "btc-fund", "--coordinator", swap.bob_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await;
	assert!(result.is_err());
	let funding_id = Txid::from_str(offer["relay"]["btc_funding"]["funding_txid"].as_str().unwrap()).unwrap();
	assert!(swap.ctx.bitcoind().sync_client().get_raw_transaction(&funding_id, None).is_err());
}

#[tokio::test]
async fn private_swap_aborted_offer_cannot_resume_secret_disclosure() {
	let swap = Swap::request("private_swap_aborted_offer_cannot_resume_secret_disclosure", sat(80_000), sat(80_000), 12).await;
	let offer = swap.offer().await;
	let _: Value = swap.alice.run_json([
		"swap", "btc-ark", "ark-abort", "--coordinator", swap.alice_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await;
	// The local abort has not broadcast an exit: Bob can still send M3.
	swap.fund().await;
	swap.ctx.generate_blocks(1).await;
	assert!(swap.alice.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "ark-finalize-btc-claim", "--coordinator", swap.alice_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await.is_err());
	let private = swap.private(true).await;
	assert_eq!(private["status"], "Cancelled");
	assert!(private["signed_claim_tx_hex"].is_null());
	let claim: Transaction = deserialize_hex(offer["relay"]["claim_request"]["claim_tx_hex"].as_str().unwrap()).unwrap();
	assert!(swap.ctx.bitcoind().sync_client().get_raw_transaction(&claim.compute_txid(), None).is_err());
}

#[tokio::test]
async fn private_swap_does_not_promise_funding_twice() {
	let swap = Swap::request("private_swap_does_not_promise_funding_twice", sat(80_000), sat(80_000), 12).await;
	let second_relay = swap.ctx.datadir.join("second-request.json");
	assert!(swap.bob.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "btc-request", "--coordinator", second_relay.to_str().unwrap(),
		"--amount", "80000 sat", "--ark-receive", swap.bob.address().await.trim(),
		"--fee-rate", "1", "--refund-delay", "12", "--confirmations", "1", "--safety-margin", "2",
	]).await.is_err());
	assert!(!second_relay.exists());
	swap.offer().await;
	swap.fund().await;
}

#[tokio::test]
async fn private_swap_rejects_spent_funding_inputs_before_ark_commitment() {
	let swap = Swap::request("private_swap_rejects_spent_funding_inputs_before_ark_commitment", sat(80_000), sat(80_000), 12).await;
	let destination = swap.alice.get_onchain_address().await;
	swap.bob.run(["onchain", "send", &destination.to_string(), "0.0025 BTC"]).await;
	let result = swap.alice.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "ark-offer", "--coordinator", swap.alice_relay.to_str().unwrap(),
		"--swap", &swap.id, "--btc-payout", &destination.to_string(),
	]).await;
	assert!(result.is_err());
	assert_eq!(swap.alice.spendable_balance().await, sat(80_000));
	assert!(swap.operator.cosigns.lock().is_empty());
}

#[tokio::test]
async fn private_swap_replays_exact_signature_and_rejects_changed_transcript() {
	let swap = Swap::request("private_swap_replays_exact_signature_and_rejects_changed_transcript", sat(80_000), sat(80_000), 12).await;
	swap.offer().await;
	let original = swap.public().await;
	let _: Value = swap.bob.run_json([
		"swap", "btc-ark", "btc-request", "--coordinator", swap.bob_relay.to_str().unwrap(),
		"--amount", "80000 sat", "--ark-receive", original["request"]["ark_receive"].as_str().unwrap(),
		"--fee-rate", "1", "--refund-delay", "12", "--confirmations", "1", "--safety-margin", "2",
	]).await;
	assert_eq!(swap.public().await, original, "retrying M1 must not erase M2");
	let mut tampered = original.clone();
	let mut claim: Transaction = deserialize_hex(tampered["claim_request"]["claim_tx_hex"].as_str().unwrap()).unwrap();
	claim.output[0].value -= sat(1);
	tampered["claim_request"]["claim_tx_hex"] = Value::String(serialize_hex(&claim));
	tokio::fs::write(&swap.bob_relay, serde_json::to_vec(&tampered).unwrap()).await.unwrap();
	assert!(swap.bob.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "btc-fund", "--coordinator", swap.bob_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await.is_err());
	tokio::fs::write(&swap.bob_relay, serde_json::to_vec(&original).unwrap()).await.unwrap();
	let first = swap.fund().await;
	// Alice's M2 retry must not erase Bob's published M3.
	let _: Value = swap.alice.run_json([
		"swap", "btc-ark", "ark-offer", "--coordinator", swap.alice_relay.to_str().unwrap(),
		"--swap", &swap.id, "--btc-payout", original["terms"]["btc_payout_address"].as_str().unwrap(),
	]).await;
	let preserved: Value = serde_json::from_slice(&tokio::fs::read(&swap.alice_relay).await.unwrap()).unwrap();
	assert_eq!(first["relay"]["btc_claim_adaptor"], preserved["btc_claim_adaptor"]);
	let mut changed_nonce = original.clone();
	let key = Keypair::new(&ark::SECP, &mut rand::thread_rng());
	let (_, nonce) = ark::musig::nonce_pair(&key);
	changed_nonce["ark_claim_partial"]["ark_public_nonce_hex"] = Value::String(bitcoin::hex::DisplayHex::as_hex(&nonce.serialize()[..]).to_string());
	tokio::fs::write(&swap.bob_relay, serde_json::to_vec(&changed_nonce).unwrap()).await.unwrap();
	let replay = swap.fund().await;
	assert_eq!(first["relay"]["btc_claim_adaptor"], replay["relay"]["btc_claim_adaptor"]);
	assert_eq!(first["relay"]["btc_funding"]["funding_tx_hex"], replay["relay"]["btc_funding"]["funding_tx_hex"]);
	assert!(swap.private(false).await["btc_secret_nonce"].is_null());
	tokio::fs::remove_file(&swap.bob_relay).await.unwrap();
	let restored = swap.fund().await;
	assert_eq!(first["relay"]["btc_claim_adaptor"], restored["relay"]["btc_claim_adaptor"]);
	assert_eq!(first["relay"]["btc_funding"]["funding_tx_hex"], restored["relay"]["btc_funding"]["funding_tx_hex"]);
	// A request-only or otherwise regressed relay is also repaired from the
	// authoritative local M3 result.
	tokio::fs::write(&swap.bob_relay, serde_json::to_vec(&original).unwrap()).await.unwrap();
	let repaired = swap.fund().await;
	assert_eq!(first["relay"]["btc_claim_adaptor"], repaired["relay"]["btc_claim_adaptor"]);
	assert_eq!(first["relay"]["btc_funding"]["funding_tx_hex"], repaired["relay"]["btc_funding"]["funding_tx_hex"]);
}

#[tokio::test]
async fn private_swap_late_claim_refuses_disclosure_and_refunds() {
	let swap = Swap::request("private_swap_late_claim_refuses_disclosure_and_refunds", sat(80_000), sat(80_000), 12).await;
	swap.offer().await;
	let funded = swap.fund().await;
	let refund_height = funded["refund_height"].as_u64().unwrap() as u32;
	swap.mine_to(refund_height - 2).await;
	let claim = swap.alice.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "ark-finalize-btc-claim", "--coordinator", swap.alice_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await;
	assert!(claim.is_err());
	assert!(swap.private(true).await["signed_claim_tx_hex"].is_null());
	let aborted: Value = swap.alice.run_json([
		"swap", "btc-ark", "ark-abort", "--coordinator", swap.alice_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await;
	assert_eq!(aborted["status"], "Cancelled");
	swap.mine_to(refund_height).await;
	let refund = swap.progress(false).await;
	let refund_id = Txid::from_str(refund["refund_txid"].as_str().unwrap()).unwrap();
	assert!(swap.ctx.bitcoind().sync_client().get_mempool_entry(&refund_id).is_ok());
	swap.ctx.generate_blocks(1).await;
	assert_eq!(swap.progress(false).await["status"], "Refunded");
	let tx = swap.ctx.bitcoind().sync_client().get_raw_transaction(&refund_id, None).unwrap();
	assert_eq!(tx.lock_time.to_consensus_u32(), refund_height);
	assert_eq!(tx.input[0].previous_output.txid.to_string(), funded["relay"]["btc_funding"]["funding_txid"].as_str().unwrap());
	// The swap monitor, not manual exit commands, completes Alice's recovery.
	swap.progress(true).await;
	swap.ctx.generate_blocks(1).await;
	swap.progress(true).await;
	swap.ctx.generate_blocks(32).await;
	swap.progress(true).await;
	let old_drain: Transaction = deserialize_hex(swap.private(true).await["ark_exit_claim_tx_hex"].as_str().unwrap()).unwrap();
	let _: Value = swap.alice.run_json([
		"swap", "btc-ark", "progress", "--coordinator", swap.alice_relay.to_str().unwrap(),
		"--swap", &swap.id, "--role", "ark-payer", "--fee-rate", "10",
	]).await;
	let drain: Transaction = deserialize_hex(swap.private(true).await["ark_exit_claim_tx_hex"].as_str().unwrap()).unwrap();
	assert!(swap.ctx.bitcoind().sync_client().get_mempool_entry(&drain.compute_txid()).is_ok());
	assert!(swap.ctx.bitcoind().sync_client().get_mempool_entry(&old_drain.compute_txid()).is_err());
	swap.ctx.generate_blocks(1).await;
	assert_eq!(swap.progress(true).await["status"], "ArkReclaimed");
}

#[tokio::test]
async fn private_swap_refunds_unconfirmed_funding_at_fixed_height() {
	let swap = Swap::request("private_swap_refunds_unconfirmed_funding_at_fixed_height", sat(80_000), sat(80_000), 12).await;
	swap.offer().await;
	let funded = swap.fund().await;
	let refund_height = funded["refund_height"].as_u64().unwrap() as u32;
	let rpc = swap.ctx.bitcoind().sync_client();
	let miner = swap.bob.get_onchain_address().await.to_string();
	while rpc.get_block_count().unwrap() < u64::from(refund_height) {
		let _: Value = rpc.call("generateblock", &[Value::String(miner.clone()), serde_json::json!([])]).unwrap();
	}
	let funding_id = Txid::from_str(funded["relay"]["btc_funding"]["funding_txid"].as_str().unwrap()).unwrap();
	assert!(rpc.get_mempool_entry(&funding_id).is_ok(), "funding intentionally did not confirm");
	let refund = swap.progress(false).await;
	let refund_id = Txid::from_str(refund["refund_txid"].as_str().unwrap()).unwrap();
	assert!(rpc.get_mempool_entry(&refund_id).is_ok());
	let original_refund = swap.private(false).await["signed_refund_tx_hex"].as_str().unwrap().to_owned();
	let replacement: Value = swap.bob.run_json([
		"swap", "btc-ark", "btc-refund", "--coordinator", swap.bob_relay.to_str().unwrap(),
		"--swap", &swap.id, "--fee-rate", "10",
	]).await;
	let replacement_id = Txid::from_str(replacement["refund_txid"].as_str().unwrap()).unwrap();
	assert!(rpc.get_mempool_entry(&replacement_id).is_ok(), "replace a child of an unconfirmed non-TRUC parent");
	assert!(rpc.get_mempool_entry(&refund_id).is_err());
	// Miners may still choose the previous refund. Durable history must
	// recognize its confirmation rather than report an unknown spend.
	let _: Value = rpc.call("generateblock", &[
		Value::String(miner), serde_json::json!([funded["relay"]["btc_funding"]["funding_tx_hex"], original_refund]),
	]).unwrap();
	assert_eq!(swap.progress(false).await["status"], "Refunded");
	assert_eq!(swap.progress(false).await["refund_txid"], refund_id.to_string());
	assert!(rpc.get_tx_out(&funding_id, funded["relay"]["btc_funding"]["funding_vout"].as_u64().unwrap() as u32, Some(true)).unwrap().is_none());
}

#[tokio::test]
async fn private_swap_claim_reorg_does_not_allow_abort_after_disclosure() {
	let swap = Swap::request("private_swap_claim_reorg_does_not_allow_abort_after_disclosure", sat(80_000), sat(80_000), 12).await;
	swap.offer().await;
	swap.fund().await;
	swap.ctx.generate_blocks(1).await;
	let claimed = swap.progress(true).await;
	let claim_id = Txid::from_str(claimed["claim_txid"].as_str().unwrap()).unwrap();
	swap.ctx.generate_blocks(1).await;
	let rpc = swap.ctx.bitcoind().sync_client();
	let tip = rpc.get_best_block_hash().unwrap();
	rpc.invalidate_block(&tip).unwrap();
	assert!(rpc.get_mempool_entry(&claim_id).is_ok());
	assert!(swap.alice.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "ark-abort", "--coordinator", swap.alice_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await.is_err());
	assert_eq!(swap.progress(false).await["status"], "ArkCompleted");
	assert_eq!(swap.bob.spendable_balance().await, sat(80_000));
}

/// Reproduce the old protocol's missing cross-leg deadline bound using raw
/// primitives. Production M2/M3 now reject this window before signing/funding.
#[tokio::test]
async fn unsafe_refund_window_allows_old_ark_reclaim_before_btc_claim() {
	let ctx = TestContext::new("bark/unsafe_refund_window_allows_old_ark_reclaim_before_btc_claim").await;
	let server = ctx.captaind("server").funded(btc(10)).create().await;
	let alice = ctx.bark("alice", &server).funded(sat(300_000)).create().await;
	let bob = ctx.bark("bob", &server).funded(sat(300_000)).create().await;
	alice.board_and_confirm_and_register(&ctx, sat(80_000)).await;
	let alice_key = Keypair::new(&ark::SECP, &mut rand::thread_rng());
	let bob_key = Keypair::new(&ark::SECP, &mut rand::thread_rng());
	let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
	let refund_height = ctx.bitcoind().get_block_count().await as u32 + 80;
	let lock = BtcLockContract::new(sat(80_000), Network::Regtest, bob_key.public_key(), alice_key.public_key(), bob_key.x_only_public_key().0, refund_height.into()).unwrap();
	let funding: ark_testing::bark::json::cli::onchain::Send = bob.run_json([
		"onchain", "send", &lock.address.to_string(), &lock.amount.to_string(), "--verbose",
	]).await;
	ctx.generate_blocks(1).await;
	let payout = alice.get_onchain_address().await;
	let receive = ark::Address::from_str(bob.address().await.trim()).unwrap();
	let prepared = {
		let wallet = alice.client().await;
		let inputs = wallet.select_btc_ark_transfer_inputs(sat(80_000)).await.unwrap();
		let ids = inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
		wallet.prepare_btc_ark_transfer(&receive, sat(80_000), payout.script_pubkey(), secret.point(), &ids).await.unwrap()
	};
	let rpc = ctx.bitcoind().sync_client();
	let funding_tx = rpc.get_raw_transaction(&funding.txid, None).unwrap();
	let vout = funding_tx.output.iter().position(|o| *o == lock.txout()).unwrap() as u32;
	let mut claim = build_cooperative_claim_tx(OutPoint::new(funding.txid, vout), &lock, payout.script_pubkey(), FeeRate::from_sat_per_vb(2).unwrap()).unwrap();
	let adaptor = build_cooperative_claim_adaptor_package(&bob_key, &alice_key, cooperative_claim_sighash(&claim, &lock).unwrap(), Some(lock.taproot.tap_tweak().to_byte_array()), secret.point()).unwrap();
	let original = prepared.offer.ark_input_ids[0].to_point();
	alice.start_exit_vtxos(&prepared.offer.ark_input_ids).await;
	ark_testing::exit::complete_exit(&ctx, &alice).await;
	alice.claim_all_exits(&payout).await;
	ctx.generate_blocks(1).await;
	assert!(rpc.get_tx_out(&original.txid, original.vout, Some(true)).unwrap().is_none());
	assert!((rpc.get_block_count().unwrap() as u32) < refund_height);
	let signature = adaptor.finalize_with_secret(secret).unwrap();
	claim.input[0].witness.push(signature.serialize());
	rpc.send_raw_transaction(&claim).unwrap();
	ctx.generate_blocks(1).await;
	let recovered = adaptor.recover_secret(signature).unwrap();
	assert_eq!(recovered.secret_key(), secret.secret_key());
	let signed = prepared.transfer.finalize_with_secret(recovered).unwrap().build_signed_vtxos();
	let replacement = signed[0].transactions().find(|item| item.tx.input[0].previous_output == original).unwrap();
	assert_eq!(replacement.tx.input[0].previous_output, original);
	assert!(rpc.get_tx_out(&original.txid, original.vout, Some(true)).unwrap().is_none(), "learning t cannot resurrect Alice's reclaimed Ark outpoint");
	let confirmed: Value = rpc.call("getrawtransaction", &[serde_json::json!(claim.compute_txid()), Value::Bool(true)]).unwrap();
	assert!(confirmed["confirmations"].as_u64().unwrap() > 0);
}

/// A final adaptor signature reveals t even when miners settle its competitor.
#[tokio::test]
async fn unsafe_late_claim_reveals_secret_even_when_refund_confirms() {
	let ctx = TestContext::new("bark/unsafe_late_claim_reveals_secret_even_when_refund_confirms").await;
	let server = ctx.captaind("server").funded(btc(10)).create().await;
	let alice = ctx.bark("alice", &server).create().await;
	let bob = ctx.bark("bob", &server).funded(sat(300_000)).create().await;
	let alice_key = Keypair::new(&ark::SECP, &mut rand::thread_rng());
	let bob_key = Keypair::new(&ark::SECP, &mut rand::thread_rng());
	let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
	let refund_height = ctx.bitcoind().get_block_count().await as u32 + 3;
	let lock = BtcLockContract::new(sat(80_000), Network::Regtest, bob_key.public_key(), alice_key.public_key(), bob_key.x_only_public_key().0, refund_height.into()).unwrap();
	let funding: ark_testing::bark::json::cli::onchain::Send = bob.run_json([
		"onchain", "send", &lock.address.to_string(), &lock.amount.to_string(), "--verbose",
	]).await;
	ctx.generate_blocks(3).await;
	let rpc = ctx.bitcoind().sync_client();
	let funding_tx = rpc.get_raw_transaction(&funding.txid, None).unwrap();
	let outpoint = OutPoint::new(funding.txid, funding_tx.output.iter().position(|o| *o == lock.txout()).unwrap() as u32);
	let mut claim = build_cooperative_claim_tx(outpoint, &lock, alice.get_onchain_address().await.script_pubkey(), FeeRate::from_sat_per_vb(2).unwrap()).unwrap();
	let adaptor = build_cooperative_claim_adaptor_package(&bob_key, &alice_key, cooperative_claim_sighash(&claim, &lock).unwrap(), Some(lock.taproot.tap_tweak().to_byte_array()), secret.point()).unwrap();
	let signature = adaptor.finalize_with_secret(secret).unwrap();
	claim.input[0].witness.push(signature.serialize());
	rpc.send_raw_transaction(&claim).unwrap();
	assert!(rpc.get_mempool_entry(&claim.compute_txid()).is_ok());
	let refund = sign_refund_tx(build_refund_tx(outpoint, &lock, bob.get_onchain_address().await.script_pubkey(), FeeRate::from_sat_per_vb(10).unwrap()).unwrap(), &lock, &bob_key).unwrap();
	// Choose the consensus-valid refund explicitly; mempool policy is not a
	// guarantee about which conflicting transaction miners can confirm.
	let _: Value = rpc.call("generateblock", &[Value::String(bob.get_onchain_address().await.to_string()), serde_json::json!([serialize_hex(&refund)])]).unwrap();
	assert!(rpc.get_raw_transaction_info(&refund.compute_txid(), None).unwrap().confirmations.unwrap_or(0) > 0);
	assert!(rpc.get_mempool_entry(&claim.compute_txid()).is_err());
	assert_eq!(adaptor.recover_secret(signature).unwrap().secret_key(), secret.secret_key());
	assert!(rpc.get_tx_out(&claim.compute_txid(), 0, Some(true)).unwrap().is_none());
}

#[tokio::test]
async fn private_swap_reprices_claim_after_mempool_eviction() {
	let swap = Swap::request("private_swap_reprices_claim_after_mempool_eviction", sat(80_000), sat(80_000), 12).await;
	swap.offer().await;
	swap.fund().await;
	swap.ctx.generate_blocks(1).await;
	let claimed = swap.progress(true).await;
	let claim_id = Txid::from_str(claimed["claim_txid"].as_str().unwrap()).unwrap();
	let rpc = swap.ctx.bitcoind().sync_client();
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
	let _: Value = rpc.call("setmocktime", &[serde_json::json!(now + 337 * 3600)]).unwrap();
	// Accepting another transaction runs Bitcoin Core's mempool expiry.
	swap.bob.onchain_send(swap.alice.get_onchain_address().await, sat(1_000)).await;
	assert!(rpc.get_mempool_entry(&claim_id).is_err());
	let _: Value = rpc.call("setmocktime", &[serde_json::json!(0)]).unwrap();
	let _: Value = swap.alice.run_json([
		"swap", "btc-ark", "progress", "--coordinator", swap.alice_relay.to_str().unwrap(),
		"--swap", &swap.id, "--role", "ark-payer", "--fee-rate", "50",
	]).await;
	let child: Transaction = deserialize_hex(swap.private(true).await["cpfp_tx_hex"].as_str().unwrap()).unwrap();
	let info = swap.alice.client().await.chain().mempool_ancestor_info(child.compute_txid()).await.unwrap();
	assert!(info.effective_fee_rate().unwrap() >= FeeRate::from_sat_per_vb(50).unwrap());
	assert!(rpc.get_mempool_entry(&claim_id).is_ok());
	swap.ctx.generate_blocks(1).await;
	assert_eq!(swap.progress(true).await["status"], "BtcClaimed");
	assert_eq!(swap.progress(false).await["status"], "ArkCompleted");
}

#[tokio::test]
async fn private_swap_fee_preparation_failure_does_not_disclose_secret() {
	let swap = Swap::request("private_swap_fee_preparation_failure_does_not_disclose_secret", sat(80_000), sat(80_000), 12).await;
	swap.offer().await;
	swap.fund().await;
	swap.ctx.generate_blocks(1).await;
	swap.alice.onchain_drain(swap.bob.get_onchain_address().await).await;
	swap.ctx.generate_blocks(1).await;
	assert!(swap.alice.try_run_json::<Value, _, _>([
		"swap", "btc-ark", "ark-finalize-btc-claim", "--coordinator", swap.alice_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await.is_err());
	let aborted: Value = swap.alice.run_json([
		"swap", "btc-ark", "ark-abort", "--coordinator", swap.alice_relay.to_str().unwrap(), "--swap", &swap.id,
	]).await;
	assert_eq!(aborted["status"], "Cancelled", "a failed fee preparation must not burn safe abort");
}

#[tokio::test]
async fn private_swap_requires_confirmed_transaction_lookup() {
	let ctx = TestContext::new("bark/private_swap_requires_confirmed_transaction_lookup").await;
	let mut cfg = ctx.bitcoind_default_cfg("no-index");
	cfg.txindex = false;
	let node = ctx.new_bitcoind_with_cfg("no-index", cfg).await;
	assert!(bark::chain::ChainSource::new(bark::chain::ChainSourceSpec::Bitcoind {
		url: node.rpc_url(), auth: node.auth(), zmq: None,
	}, Network::Regtest, None, None).await.is_err());
}

#[tokio::test]
async fn private_swap_receiver_recovers_when_seller_exits_and_registration_fails() {
	let swap = Swap::request("private_swap_receiver_recovers_when_seller_exits_and_registration_fails", sat(80_000), sat(80_000), 12).await;
	swap.offer().await;
	swap.fund().await;
	swap.ctx.generate_blocks(1).await;
	let input_ids = swap.private(true).await["ark_input_ids"].as_array().unwrap().iter()
		.map(|id| id.as_str().unwrap().to_owned()).collect::<Vec<_>>();
	// Attack after funding: Alice starts the pinned old-state exit outside the
	// swap state machine, then still reveals the BTC claim signature.
	swap.alice.start_exit_vtxos(&input_ids).await;
	swap.alice.progress_exit().await;
	swap.ctx.generate_blocks(1).await;
	let _: Result<Value, _> = swap.alice.try_run_json([
		"swap", "btc-ark", "progress", "--coordinator", swap.alice_relay.to_str().unwrap(),
		"--swap", &swap.id, "--role", "ark-payer", "--fee-rate", "2",
	]).await;
	let claim: Transaction = deserialize_hex(swap.private(true).await["signed_claim_tx_hex"].as_str().unwrap()).unwrap();
	assert!(swap.ctx.bitcoind().sync_client().get_mempool_entry(&claim.compute_txid()).is_ok());
	let before = swap.bob.onchain_balance().await;
	swap.operator.reject_registrations.store(true, Ordering::SeqCst);
	let mut recovered = false;
	for _ in 0..40 {
		// Keep driving the conflicting old exit; Bob's recovery must still be
		// able to publish the newer transfer path before that exit matures.
		let _ = swap.alice.try_run_json::<Value, _, _>(["exit", "progress"]).await;
		let status = swap.progress(false).await;
		if status["status"] == "ArkReclaimed" { recovered = true; break; }
		assert_eq!(status["status"], "ArkRecovering");
		swap.ctx.generate_blocks(1).await;
	}
	assert!(recovered, "receiver must recover the new Ark path before the seller's old exit matures");
	assert!(swap.bob.onchain_balance().await > before + sat(60_000));
}

#[tokio::test]
async fn private_swap_receiver_exits_when_registration_is_unavailable() {
	let swap = Swap::request("private_swap_receiver_exits_when_registration_is_unavailable", sat(80_000), sat(80_000), 12).await;
	swap.offer().await;
	swap.fund().await;
	swap.ctx.generate_blocks(1).await;
	swap.progress(true).await;
	let before = swap.bob.onchain_balance().await;
	swap.operator.reject_registrations.store(true, Ordering::SeqCst);
	let mut recovered = false;
	for _ in 0..10 {
		let status = swap.progress(false).await;
		if status["status"] == "ArkReclaimed" { recovered = true; break; }
		assert_eq!(status["status"], "ArkRecovering");
		let exits: Vec<Value> = swap.bob.run_json(["exit", "list", "--no-sync"]).await;
		let height = exits.iter().filter_map(|exit| exit["state"]["claimable_height"].as_u64())
			.map(|height| u32::try_from(height).unwrap()).max();
		let tip = swap.ctx.bitcoind().sync_client().get_block_count().unwrap() as u32;
		swap.ctx.generate_blocks(height.map(|h| h.saturating_sub(tip)).unwrap_or(1).max(1)).await;
	}
	assert!(recovered, "receiver must finish its local exit without a registration acknowledgement");
	assert!(swap.bob.onchain_balance().await > before + sat(60_000));
}
