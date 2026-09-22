//! Offline acceptance and completion benchmark; run with `bash autoresearch.sh`.
//!
//! The checked-in fixtures contain real signatures from the existing board and
//! arkoor builders: one fresh input, and eight inputs sharing four arkoor hops
//! followed by a split. Both swaps return change. All fixture keys and the
//! adaptor secret are public test material and must never hold real funds.
//!
//! Measures decoding, public acceptance, full-genesis validation, BTC adaptor
//! verification/finalization/extraction, and Ark completion. It does NOT measure
//! RPC latency, durable wallet writes, live chain checks, or block inclusion.
//! Those safety checks are not replaced by this offline benchmark.

use std::hint::black_box;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{Keypair, SecretKey, schnorr};
use bitcoin::{Amount, FeeRate, Network, ScriptBuf, Transaction};
use serde::Deserialize;

use ark::arkoor::package::TransferableAdaptorArkoorPackage;
use ark::musig::{AdaptorPreSignature, AdaptorSecret};
use ark::vtxo::Full;
use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use bark::swap::btc_ark::{
	ArkOffer, BtcClaimAdaptorPackage, BtcLockContract, SwapId,
	build_cooperative_claim_tx, cooperative_claim_sighash, verify_ark_transfer_before_acceptance,
};

const FIXTURES: &str = include_str!("data/btc_ark_swap_bench.json");
const WARMUP: usize = 8;
const SAMPLES: usize = 11;
const ITERATIONS: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
	name: String,
	input_ids: Vec<VtxoId>,
	output_ids: Vec<VtxoId>,
	amount_sat: u64,
	change_sat: u64,
	anchor_hex: String,
	transfer_hex: String,
	claim_hex: String,
	btc_pre_signature: String,
	minimum_expiry_height: u32,
	refund_height: u32,
	history_hops: usize,
}

struct Case {
	fixture: Fixture,
	offer: ArkOffer,
	anchor: Transaction,
	transfer: Vec<u8>,
	claim: Transaction,
	lock: BtcLockContract,
	btc_adaptor: BtcClaimAdaptorPackage,
	secret: AdaptorSecret,
}

fn key(byte: u8) -> Keypair {
	Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[byte; 32]).unwrap())
}

fn transaction(hex: &str) -> Result<Transaction> {
	Ok(bitcoin::consensus::deserialize(&Vec::<u8>::from_hex(hex)?)?)
}

impl Case {
	fn new(fixture: Fixture) -> Result<Self> {
		let alice = key(1);
		let bob = key(2);
		let secret = AdaptorSecret::new(SecretKey::from_slice(&[42; 32])?);
		let amount = Amount::from_sat(fixture.amount_sat);
		let lock = BtcLockContract::new(
			amount, Network::Regtest, bob.public_key(), alice.public_key(),
			bob.x_only_public_key().0, fixture.refund_height.into(),
		)?;
		let claim = transaction(&fixture.claim_hex)?;
		let btc_adaptor = BtcClaimAdaptorPackage {
			adaptor_point: secret.point(),
			aggregate_key: lock.taproot.output_key().to_x_only_public_key(),
			sighash: cooperative_claim_sighash(&claim, &lock)?,
			pre_signature: AdaptorPreSignature::deserialize_hex(&fixture.btc_pre_signature)?,
		};
		let offer = ArkOffer {
			id: SwapId::from_bytes([fixture.input_ids.len() as u8; 32]),
			amount,
			btc_payout_script: ScriptBuf::new_p2tr(&ark::SECP, alice.x_only_public_key().0, None),
			ark_input_ids: fixture.input_ids.clone(),
			ark_receive_policy: VtxoPolicy::new_pubkey(bob.public_key()),
			ark_server_pubkey: key(3).public_key(),
			adaptor_point: secret.point(),
		};
		Ok(Self {
			anchor: transaction(&fixture.anchor_hex)?,
			transfer: Vec::<u8>::from_hex(&fixture.transfer_hex)?,
			fixture, offer, claim, lock, btc_adaptor, secret,
		})
	}

	fn decode(&self) -> Result<TransferableAdaptorArkoorPackage> {
		Ok(TransferableAdaptorArkoorPackage::deserialize(black_box(&self.transfer))?)
	}

	fn accept(&self, offer: &ArkOffer, transfer: &TransferableAdaptorArkoorPackage) -> Result<()> {
		Ok(verify_ark_transfer_before_acceptance(
			offer, transfer, self.fixture.minimum_expiry_height.into(),
		)?)
	}

	fn roundtrip(&self) -> Result<Vec<Vtxo<Full>>> {
		let transfer = self.decode()?;
		self.accept(black_box(&self.offer), &transfer)?;
		for package in transfer.packages() {
			package.input().validate(black_box(&self.anchor))?;
		}
		let claim = build_cooperative_claim_tx(
			self.claim.input[0].previous_output, &self.lock,
			self.offer.btc_payout_script.clone(), FeeRate::from_sat_per_vb(1).unwrap(),
		)?;
		ensure!(claim == self.claim, "BTC claim changed");
		ensure!(
			cooperative_claim_sighash(&claim, &self.lock)? == self.btc_adaptor.sighash,
			"BTC claim sighash changed",
		);
		self.btc_adaptor.verify()?;
		let signature = self.btc_adaptor.finalize_with_secret(black_box(self.secret))?;
		let recovered = self.btc_adaptor.recover_secret(signature)?;
		ensure!(recovered == self.secret, "incorrect adaptor secret extraction");
		let outputs = transfer.finalize_with_secret(recovered)?.build_signed_vtxos();
		ensure!(
			outputs.iter().map(|v| v.id()).eq(self.fixture.output_ids.iter().copied()),
			"Ark output identities changed",
		);
		let mut received = Amount::ZERO;
		let mut change = Amount::ZERO;
		let change_policy = VtxoPolicy::new_pubkey(key(1).public_key());
		for output in &outputs {
			output.validate(black_box(&self.anchor))?;
			if output.policy() == &self.offer.ark_receive_policy {
				received += output.amount();
			} else {
				ensure!(output.policy() == &change_policy, "unexpected Ark output policy");
				change += output.amount();
			}
		}
		ensure!(received == self.offer.amount, "incorrect Ark receive amount");
		ensure!(change.to_sat() == self.fixture.change_sat, "incorrect Ark change amount");
		Ok(outputs)
	}

	// Run outside the timed loop. Invalid material must still fail closed, so a
	// faster result from deleting checks is not a successful benchmark run.
	fn check_rejections(&self) -> Result<usize> {
		let transfer = self.decode()?;
		let mut checks = 0;
		let mut reject_offer = |offer: ArkOffer| -> Result<()> {
			ensure!(self.accept(&offer, &transfer).is_err(), "accepted invalid Ark terms");
			checks += 1;
			Ok(())
		};
		let mut wrong = self.offer.clone();
		wrong.amount += Amount::ONE_SAT;
		reject_offer(wrong)?;
		let mut wrong = self.offer.clone();
		wrong.ark_receive_policy = VtxoPolicy::new_pubkey(key(9).public_key());
		reject_offer(wrong)?;
		let mut wrong = self.offer.clone();
		wrong.ark_server_pubkey = key(9).public_key();
		reject_offer(wrong)?;
		let mut wrong = self.offer.clone();
		wrong.adaptor_point = key(9).public_key();
		reject_offer(wrong)?;
		let mut wrong = self.offer.clone();
		wrong.ark_input_ids[0] = VtxoId::from(bitcoin::OutPoint::null());
		reject_offer(wrong)?;

		let expiry = transfer.build_unsigned_vtxos().map(|v| v.expiry_height()).min().unwrap();
		ensure!(
			verify_ark_transfer_before_acceptance(&self.offer, &transfer, expiry).is_err(),
			"accepted an output at the expiry boundary",
		);
		checks += 1;

		let mut wire = self.transfer.clone();
		*wire.last_mut().unwrap() ^= 1;
		let corrupted = TransferableAdaptorArkoorPackage::deserialize(&wire)?;
		ensure!(self.accept(&self.offer, &corrupted).is_err(), "accepted altered Ark signature");
		checks += 1;

		let first = transfer.packages()[0].serialize();
		let duplicated_wire = [&self.transfer[..2], &[2], &first[..], &first[..]].concat();
		let duplicated = TransferableAdaptorArkoorPackage::deserialize(&duplicated_wire)?;
		let mut doubled = self.offer.clone();
		doubled.ark_input_ids = duplicated.input_ids().collect();
		doubled.amount = duplicated.build_unsigned_vtxos()
			.filter(|v| v.policy() == &self.offer.ark_receive_policy)
			.map(|v| v.amount()).sum();
		ensure!(self.accept(&doubled, &duplicated).is_err(), "double-counted a duplicate input");
		checks += 1;

		let mut bad_anchor = self.anchor.clone();
		bad_anchor.output[0].value += Amount::ONE_SAT;
		ensure!(
			transfer.packages()[0].input().validate(&bad_anchor).is_err(),
			"accepted a mismatched full-genesis anchor",
		);
		checks += 1;

		let mut bad_genesis = transfer.packages()[0].input().clone();
		bad_genesis.invalidate_final_sig();
		ensure!(bad_genesis.validate(&self.anchor).is_err(), "accepted invalid genesis signature");
		checks += 1;

		let mut wrong_version = self.transfer.clone();
		wrong_version[0] ^= 1;
		let mut trailing = self.transfer.clone();
		trailing.push(0);
		for malformed in [
			wrong_version.as_slice(), &self.transfer[..self.transfer.len() - 1], &trailing,
		] {
			ensure!(
				TransferableAdaptorArkoorPackage::deserialize(malformed).is_err(),
				"accepted malformed package encoding",
			);
			checks += 1;
		}

		let wrong_secret = AdaptorSecret::new(SecretKey::from_slice(&[9; 32])?);
		ensure!(self.decode()?.finalize_with_secret(wrong_secret).is_err(), "accepted wrong secret");
		checks += 1;
		let mut wrong = self.btc_adaptor.clone();
		wrong.adaptor_point = wrong_secret.point();
		ensure!(wrong.verify().is_err(), "accepted incorrect BTC adaptor point");
		checks += 1;
		let mut wrong = self.btc_adaptor.clone();
		wrong.sighash[0] ^= 1;
		ensure!(wrong.verify().is_err(), "accepted changed BTC claim sighash");
		checks += 1;
		let mut wrong = self.btc_adaptor.clone();
		let mut sig = wrong.pre_signature.as_pre_signature().serialize();
		sig[63] ^= 1;
		wrong.pre_signature = AdaptorPreSignature::new(schnorr::Signature::from_slice(&sig)?);
		ensure!(wrong.verify().is_err(), "accepted altered BTC adaptor signature");
		checks += 1;
		let mut sig = self.btc_adaptor.finalize_with_secret(self.secret)?.serialize();
		sig[63] ^= 1;
		ensure!(
			self.btc_adaptor.recover_secret(schnorr::Signature::from_slice(&sig)?).is_err(),
			"extracted a secret from an invalid final signature",
		);
		checks += 1;
		Ok(checks)
	}
}

fn main() -> Result<()> {
	let fixtures: Vec<Fixture> = serde_json::from_str(FIXTURES)?;
	let cases = fixtures.into_iter().map(Case::new).collect::<Result<Vec<_>>>()?;
	ensure!(cases.len() == 2, "benchmark requires both workload sizes");
	for (case, (name, input_count, hops)) in cases.iter().zip([
		("single_input", 1, 0), ("shared_eight_input", 8, 4),
	]) {
		ensure!(
			case.fixture.name == name && case.fixture.input_ids.len() == input_count
				&& case.fixture.history_hops == hops,
			"unexpected workload shape",
		);
		case.roundtrip().with_context(|| format!("invalid fixture {name}"))?;
	}
	let mut guard_cases = 0;
	for case in &cases {
		guard_cases += case.check_rejections().with_context(|| case.fixture.name.clone())?;
	}
	for _ in 0..WARMUP {
		for case in &cases {
			black_box(case.roundtrip()?);
		}
	}
	let mut timings = vec![Vec::with_capacity(SAMPLES); cases.len()];
	for sample in 0..SAMPLES {
		// Alternate the case order to avoid assigning every cold sample to one case.
		for position in 0..cases.len() {
			let index = (sample + position) % cases.len();
			let case = black_box(&cases[index]);
			let start = Instant::now();
			for _ in 0..ITERATIONS {
				black_box(case.roundtrip()?);
			}
			timings[index].push(start.elapsed().as_secs_f64() * 1_000_000.0 / ITERATIONS as f64);
		}
	}
	let mut medians = Vec::with_capacity(cases.len());
	for samples in &mut timings {
		samples.sort_by(f64::total_cmp);
		medians.push(samples[SAMPLES / 2]);
	}
	let mean = medians.iter().sum::<f64>() / medians.len() as f64;
	ensure!(mean.is_finite() && mean > 0.0, "invalid benchmark timing");
	println!("ASI workload=offline_acceptance_and_completion");
	println!("ASI fixture_sha256={}", sha256::Hash::hash(FIXTURES.as_bytes()));
	println!("ASI samples={SAMPLES}");
	println!("ASI iterations_per_sample={ITERATIONS}");
	println!("ASI rejection_checks={guard_cases}");
	println!("METRIC swap_crypto_us={mean:.3}");
	for (case, median) in cases.iter().zip(medians) {
		println!("METRIC {}_us={median:.3}", case.fixture.name);
	}
	println!("METRIC transfer_bytes={}", cases.iter().map(|c| c.transfer.len()).sum::<usize>());
	Ok(())
}
