use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, bail};
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bitcoin::{Transaction, Witness};
use serde::{Deserialize, Deserializer, Serialize};

use ark::{ProtocolEncoding, VtxoId, VtxoPolicy};
use bark::swap::btc_ark::{ArkOffer, BtcClaimAdaptorPackage, SwapId, SwapStatus};

use crate::state::atomic_write;
use crate::validation::{
	bytes_hex, bytes_from_hex, bytes32_from_hex, hash_json_hex, script_from_hex, signature_from_hex,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayFile {
	#[serde(deserialize_with = "deserialize_protocol")]
	pub(crate) protocol: String,
	#[serde(deserialize_with = "deserialize_version")]
	pub(crate) version: u16,
	pub(crate) swap_id: String,
	pub(crate) status: SwapStatus,
	pub(crate) request: BtcArkRequestArtifact,
	pub(crate) terms: Option<OfferTerms>,
	pub(crate) ark_transfer: Option<ArkTransferArtifact>,
	pub(crate) btc_funding: Option<BtcFundingArtifact>,
	pub(crate) claim_request: Option<BtcClaimRequestArtifact>,
	pub(crate) ark_claim_partial: Option<ArkClaimPartialArtifact>,
	pub(crate) btc_claim_adaptor: Option<BtcClaimAdaptorArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfferTerms {
	pub(crate) amount_sat: u64,
	pub(crate) btc_payout_address: String,
	pub(crate) btc_payout_script_hex: String,
	pub(crate) adaptor_point: String,
	pub(crate) ark_payer_claim_pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BtcArkRequestArtifact {
	pub(crate) amount_sat: u64,
	pub(crate) ark_receive: String,
	pub(crate) btc_payer_claim_pubkey: String,
	pub(crate) btc_refund_pubkey: String,
	pub(crate) fee_rate_sat_vb: u64,
	pub(crate) created_height: u32,
	pub(crate) refund_height: u32,
	pub(crate) minimum_funding_confirmations: u32,
	pub(crate) safety_margin_blocks: u32,
	pub(crate) funding_template_hex: String,
	pub(crate) funding_output_index: u32,
	pub(crate) funding_prevouts_hex: Vec<String>,
	pub(crate) btc_payer_public_nonce_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArkTransferArtifact {
	pub(crate) offer: ArkOfferArtifact,
	pub(crate) transfer_package_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArkOfferArtifact {
	pub(crate) id: String,
	pub(crate) amount_sat: u64,
	pub(crate) btc_payout_script_hex: String,
	pub(crate) ark_input_ids: Vec<String>,
	pub(crate) ark_receive_policy_hex: String,
	pub(crate) ark_server_pubkey: String,
	pub(crate) adaptor_point: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BtcFundingArtifact {
	pub(crate) funding_txid: String,
	pub(crate) funding_vout: u32,
	pub(crate) funding_tx_hex: String,
	pub(crate) lock_address: String,
	pub(crate) lock_amount_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BtcClaimRequestArtifact {
	pub(crate) claim_tx_hex: String,
	pub(crate) claim_sighash_hex: String,
	pub(crate) tap_tweak_hex: String,
	pub(crate) btc_payer_public_nonce_hex: String,
	pub(crate) claim_amount_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArkClaimPartialArtifact {
	pub(crate) ark_public_nonce_hex: String,
	pub(crate) ark_partial_sig_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BtcClaimAdaptorArtifact {
	pub(crate) adaptor_point: String,
	pub(crate) aggregate_key: String,
	pub(crate) sighash_hex: String,
	pub(crate) pre_signature_hex: String,
}

fn deserialize_protocol<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
	let protocol = String::deserialize(deserializer)?;
	if protocol != "btc-ark" {
		return Err(serde::de::Error::custom("unsupported relay protocol; btc-ark is required"));
	}
	Ok(protocol)
}

fn deserialize_version<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
	let version = u16::deserialize(deserializer)?;
	if version != 3 {
		return Err(serde::de::Error::custom(format!(
			"unsupported BTC-Ark relay version {version}; version 3 is required",
		)));
	}
	Ok(version)
}

impl RelayFile {
	pub(crate) fn new_request(swap_id: SwapId, request: BtcArkRequestArtifact) -> Self {
		Self {
			protocol: "btc-ark".to_owned(),
			version: 3,
			swap_id: swap_id.to_string(),
			status: SwapStatus::Requested,
			request,
			terms: None,
			ark_transfer: None,
			btc_funding: None,
			claim_request: None,
			ark_claim_partial: None,
			btc_claim_adaptor: None,
		}
	}

	fn validate(&self) -> anyhow::Result<()> {
		if self.protocol != "btc-ark" || self.version != 3 {
			bail!("unsupported BTC-Ark relay protocol/version; btc-ark version 3 is required");
		}
		self.swap_id()?;
		Ok(())
	}

	pub(crate) fn swap_id(&self) -> anyhow::Result<SwapId> {
		SwapId::from_str(&self.swap_id).context("relay swap id is invalid")
	}

	pub(crate) fn require_swap(&self, expected: SwapId) -> anyhow::Result<()> {
		self.validate()?;
		if self.swap_id()? != expected {
			bail!("relay file contains swap {}, but command requested {}", self.swap_id, expected);
		}
		Ok(())
	}

	pub(crate) fn terms(&self) -> anyhow::Result<&OfferTerms> {
		self.terms.as_ref().context("Ark transfer terms are missing; run ark-offer first")
	}

	pub(crate) fn payer_ark_receive(&self) -> anyhow::Result<&str> {
		Ok(&self.request.ark_receive)
	}

	pub(crate) fn btc_payer_claim_pubkey(&self) -> anyhow::Result<&str> {
		Ok(&self.request.btc_payer_claim_pubkey)
	}

	/// Commit the complete M2 signing context. Funding witnesses are the only
	/// transaction data allowed to change when Bob publishes M3. Mutable progress
	/// and the resulting aggregate adaptor/refund do not alter this commitment.
	pub(crate) fn response_commitment_hash_hex(&self) -> anyhow::Result<String> {
		#[derive(Serialize)]
		struct FundingCommitment<'a> {
			funding_txid: &'a str,
			funding_vout: u32,
			funding_tx_hex: String,
			lock_address: &'a str,
			lock_amount_sat: u64,
		}

		#[derive(Serialize)]
		struct ResponseCommitment<'a> {
			protocol: &'a str,
			version: u16,
			swap_id: &'a str,
			request: &'a BtcArkRequestArtifact,
			terms: &'a OfferTerms,
			ark_transfer: &'a ArkTransferArtifact,
			btc_funding: FundingCommitment<'a>,
			claim_request: &'a BtcClaimRequestArtifact,
			ark_claim_partial: &'a ArkClaimPartialArtifact,
		}

		self.validate()?;
		let funding = self.btc_funding.as_ref().context("BTC funding response is missing")?;
		let mut transaction: Transaction = deserialize(&bytes_from_hex(&funding.funding_tx_hex)?)
			.context("invalid BTC funding response transaction")?;
		for input in &mut transaction.input {
			input.witness = Witness::new();
		}
		hash_json_hex(&ResponseCommitment {
			protocol: &self.protocol,
			version: self.version,
			swap_id: &self.swap_id,
			request: &self.request,
			terms: self.terms()?,
			ark_transfer: self.ark_transfer.as_ref().context("Ark transfer response is missing")?,
			btc_funding: FundingCommitment {
				funding_txid: &funding.funding_txid,
				funding_vout: funding.funding_vout,
				funding_tx_hex: serialize_hex(&transaction),
				lock_address: &funding.lock_address,
				lock_amount_sat: funding.lock_amount_sat,
			},
			claim_request: self.claim_request.as_ref().context("BTC claim response is missing")?,
			ark_claim_partial: self.ark_claim_partial.as_ref().context("Ark claim partial is missing")?,
		})
	}
}

impl ArkOfferArtifact {
	pub(crate) fn from_offer(offer: &ArkOffer) -> Self {
		Self {
			id: offer.id.to_string(),
			amount_sat: offer.amount.to_sat(),
			btc_payout_script_hex: bytes_hex(offer.btc_payout_script.as_bytes()),
			ark_input_ids: offer.ark_input_ids.iter().map(ToString::to_string).collect(),
			ark_receive_policy_hex: offer.ark_receive_policy.serialize_hex(),
			ark_server_pubkey: offer.ark_server_pubkey.to_string(),
			adaptor_point: offer.adaptor_point.to_string(),
		}
	}

	pub(crate) fn to_offer(&self) -> anyhow::Result<ArkOffer> {
		Ok(ArkOffer {
			id: SwapId::from_str(&self.id).context("invalid Ark offer swap id")?,
			amount: bitcoin::Amount::from_sat(self.amount_sat),
			btc_payout_script: script_from_hex(&self.btc_payout_script_hex)?,
			ark_input_ids: self.ark_input_ids.iter()
				.map(|id| VtxoId::from_str(id).context("invalid Ark input VTXO id"))
				.collect::<anyhow::Result<Vec<_>>>()?,
			ark_receive_policy: VtxoPolicy::deserialize_hex(&self.ark_receive_policy_hex)
				.context("invalid Ark receive policy")?,
			ark_server_pubkey: PublicKey::from_str(&self.ark_server_pubkey)
				.context("invalid Ark server pubkey")?,
			adaptor_point: PublicKey::from_str(&self.adaptor_point)
				.context("invalid adaptor point")?,
		})
	}
}

impl BtcClaimAdaptorArtifact {
	pub(crate) fn from_package(package: &BtcClaimAdaptorPackage) -> Self {
		Self {
			adaptor_point: package.adaptor_point.to_string(),
			aggregate_key: package.aggregate_key.to_string(),
			sighash_hex: bytes_hex(&package.sighash),
			pre_signature_hex: bytes_hex(&package.pre_signature.as_pre_signature().serialize()),
		}
	}

	pub(crate) fn to_package(&self) -> anyhow::Result<BtcClaimAdaptorPackage> {
		let pre_signature = signature_from_hex(&self.pre_signature_hex)?;
		Ok(BtcClaimAdaptorPackage {
			adaptor_point: PublicKey::from_str(&self.adaptor_point)
				.context("invalid BTC claim adaptor point")?,
			aggregate_key: XOnlyPublicKey::from_str(&self.aggregate_key)
				.context("invalid BTC claim aggregate key")?,
			sighash: bytes32_from_hex(&self.sighash_hex)?,
			pre_signature: ark::musig::AdaptorPreSignature::new(pre_signature),
		})
	}
}

pub(crate) fn coordinator_path(coordinator: &str) -> PathBuf {
	PathBuf::from(coordinator.strip_prefix("file://").unwrap_or(coordinator))
}

pub(crate) async fn store_relay(coordinator: &str, relay: &RelayFile) -> anyhow::Result<()> {
	relay.validate()?;
	let path = coordinator_path(coordinator);
	let bytes = serde_json::to_vec_pretty(relay)?;
	ensure_relay_secret_free(&bytes)?;
	atomic_write(&path, bytes).await
		.with_context(|| format!("failed to write relay file {}", path.display()))
}

pub(crate) async fn load_relay(coordinator: &str) -> anyhow::Result<RelayFile> {
	let path = coordinator_path(coordinator);
	let bytes = tokio::fs::read(&path).await
		.with_context(|| format!("failed to read relay file {}", path.display()))?;
	ensure_relay_secret_free(&bytes)?;
	let relay: RelayFile = serde_json::from_slice(&bytes).with_context(|| {
		format!("invalid BTC-Ark relay {}; btc-ark version 3 is required (legacy wire is unsupported)", path.display())
	})?;
	relay.validate()?;
	Ok(relay)
}

fn ensure_relay_secret_free(bytes: &[u8]) -> anyhow::Result<()> {
	// The closed, public-only schemas above are the primary boundary. This also
	// rejects accidental secret-bearing labels inside otherwise public strings.
	let text = std::str::from_utf8(bytes).context("relay JSON is not UTF-8")?;
	for forbidden in ["mnemonic", "adaptor_secret", "secret_nonce", "funding_psbt"] {
		if text.contains(forbidden) {
			bail!("relay file contains secret-bearing field {forbidden}");
		}
	}
	Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
	use bitcoin::absolute::LockTime;
	use bitcoin::transaction::Version;
	use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut};

	use super::*;

	pub(crate) fn sample_response() -> RelayFile {
		let id = SwapId::from_bytes([1; 32]);
		let transaction = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(80_000), script_pubkey: ScriptBuf::new() }],
		};
		let transaction_hex = serialize_hex(&transaction);
		let mut relay = RelayFile::new_request(id, BtcArkRequestArtifact {
			amount_sat: 80_000,
			ark_receive: "ark-receive".to_owned(),
			btc_payer_claim_pubkey: "bob-claim-key".to_owned(),
			btc_refund_pubkey: "bob-refund-key".to_owned(),
			fee_rate_sat_vb: 1,
			created_height: 100,
			refund_height: 124,
			minimum_funding_confirmations: 6,
			safety_margin_blocks: 6,
			funding_template_hex: transaction_hex.clone(),
			funding_output_index: 0,
			funding_prevouts_hex: vec![serialize_hex(&transaction.output[0])],
			btc_payer_public_nonce_hex: "11".repeat(66),
		});
		relay.status = SwapStatus::Offered;
		relay.terms = Some(OfferTerms {
			amount_sat: 80_000,
			btc_payout_address: "alice-payout".to_owned(),
			btc_payout_script_hex: "51".to_owned(),
			adaptor_point: "alice-adaptor-point".to_owned(),
			ark_payer_claim_pubkey: "alice-claim-key".to_owned(),
		});
		relay.ark_transfer = Some(ArkTransferArtifact {
			offer: ArkOfferArtifact {
				id: id.to_string(),
				amount_sat: 80_000,
				btc_payout_script_hex: "51".to_owned(),
				ark_input_ids: vec![VtxoId::from_slice(&[7; 36]).unwrap().to_string()],
				ark_receive_policy_hex: "00".to_owned(),
				ark_server_pubkey: "ark-server-key".to_owned(),
				adaptor_point: "alice-adaptor-point".to_owned(),
			},
			transfer_package_hex: "deadbeef".to_owned(),
		});
		relay.btc_funding = Some(BtcFundingArtifact {
			funding_txid: transaction.compute_txid().to_string(),
			funding_vout: 0,
			funding_tx_hex: transaction_hex.clone(),
			lock_address: "swap-lock".to_owned(),
			lock_amount_sat: 80_000,
		});
		relay.claim_request = Some(BtcClaimRequestArtifact {
			claim_tx_hex: transaction_hex,
			claim_sighash_hex: "22".repeat(32),
			tap_tweak_hex: "33".repeat(32),
			btc_payer_public_nonce_hex: relay.request.btc_payer_public_nonce_hex.clone(),
			claim_amount_sat: 79_000,
		});
		relay.ark_claim_partial = Some(ArkClaimPartialArtifact {
			ark_public_nonce_hex: "44".repeat(66),
			ark_partial_sig_hex: "55".repeat(32),
		});
		relay
	}

	#[test]
	fn response_commitment_accepts_funding_witnesses_but_not_transaction_changes() {
		let mut relay = sample_response();
		let expected = relay.response_commitment_hash_hex().unwrap();
		let funding = relay.btc_funding.as_mut().unwrap();
		let mut transaction: Transaction = deserialize(&bytes_from_hex(&funding.funding_tx_hex).unwrap()).unwrap();
		transaction.input[0].witness.push([1; 64]);
		funding.funding_tx_hex = serialize_hex(&transaction);
		relay.status = SwapStatus::BtcClaimReady;
		relay.btc_claim_adaptor = Some(BtcClaimAdaptorArtifact {
			adaptor_point: "adaptor-point".to_owned(), aggregate_key: "key".to_owned(),
			sighash_hex: "sighash".to_owned(), pre_signature_hex: "presignature".to_owned(),
		});
		assert_eq!(relay.response_commitment_hash_hex().unwrap(), expected);
		transaction.output[0].value += Amount::from_sat(1);
		relay.btc_funding.as_mut().unwrap().funding_tx_hex = serialize_hex(&transaction);
		assert_ne!(relay.response_commitment_hash_hex().unwrap(), expected);
		transaction.output[0].value -= Amount::from_sat(1);
		transaction.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
		relay.btc_funding.as_mut().unwrap().funding_tx_hex = serialize_hex(&transaction);
		assert_ne!(relay.response_commitment_hash_hex().unwrap(), expected);
	}

	#[test]
	fn response_commitment_binds_nonces_keys_economics_and_ark_package() {
		let original = sample_response();
		let expected = original.response_commitment_hash_hex().unwrap();
		let mutations: &[(&str, fn(&mut RelayFile))] = &[
			("swap identity", |r| r.swap_id = SwapId::from_bytes([2; 32]).to_string()),
			("request nonce", |r| r.request.btc_payer_public_nonce_hex = "66".repeat(66)),
			("claim nonce", |r| r.claim_request.as_mut().unwrap().btc_payer_public_nonce_hex = "66".repeat(66)),
			("Alice nonce", |r| r.ark_claim_partial.as_mut().unwrap().ark_public_nonce_hex = "66".repeat(66)),
			("Alice partial", |r| r.ark_claim_partial.as_mut().unwrap().ark_partial_sig_hex = "66".repeat(32)),
			("Bob key", |r| r.request.btc_payer_claim_pubkey.push('x')),
			("refund key", |r| r.request.btc_refund_pubkey.push('x')),
			("Alice key", |r| r.terms.as_mut().unwrap().ark_payer_claim_pubkey.push('x')),
			("adaptor point", |r| r.terms.as_mut().unwrap().adaptor_point.push('x')),
			("payout", |r| r.terms.as_mut().unwrap().btc_payout_script_hex.push_str("51")),
			("Ark destination", |r| r.request.ark_receive.push('x')),
			("request amount", |r| r.request.amount_sat += 1),
			("offered amount", |r| r.terms.as_mut().unwrap().amount_sat += 1),
			("claim amount", |r| r.claim_request.as_mut().unwrap().claim_amount_sat += 1),
			("fee rate", |r| r.request.fee_rate_sat_vb += 1),
			("creation height", |r| r.request.created_height += 1),
			("refund height", |r| r.request.refund_height += 1),
			("confirmations", |r| r.request.minimum_funding_confirmations += 1),
			("margin", |r| r.request.safety_margin_blocks += 1),
			("funding template", |r| r.request.funding_template_hex.push_str("00")),
			("funding output index", |r| r.request.funding_output_index += 1),
			("funding prevout", |r| r.request.funding_prevouts_hex[0].push_str("00")),
			("funding amount", |r| r.btc_funding.as_mut().unwrap().lock_amount_sat += 1),
			("funding txid", |r| r.btc_funding.as_mut().unwrap().funding_txid.push('0')),
			("funding vout", |r| r.btc_funding.as_mut().unwrap().funding_vout += 1),
			("claim transaction", |r| r.claim_request.as_mut().unwrap().claim_tx_hex.push_str("00")),
			("claim sighash", |r| r.claim_request.as_mut().unwrap().claim_sighash_hex = "66".repeat(32)),
			("claim tweak", |r| r.claim_request.as_mut().unwrap().tap_tweak_hex = "66".repeat(32)),
			("Ark package", |r| r.ark_transfer.as_mut().unwrap().transfer_package_hex.push_str("00")),
			("Ark inputs", |r| r.ark_transfer.as_mut().unwrap().offer.ark_input_ids.push("another-input".to_owned())),
		];
		for (name, mutate) in mutations {
			let mut changed = original.clone();
			mutate(&mut changed);
			assert_ne!(changed.response_commitment_hash_hex().unwrap(), expected, "unbound {name}");
		}
	}

	#[test]
	fn legacy_wire_unknown_fields_and_secret_material_are_rejected() {
		let original = serde_json::to_value(sample_response()).unwrap();
		let mut legacy = original.clone();
		legacy["version"] = 2.into();
		assert!(serde_json::from_value::<RelayFile>(legacy).is_err());
		let mut foreign = original.clone();
		foreign["protocol"] = "other".into();
		assert!(serde_json::from_value::<RelayFile>(foreign).is_err());
		let mut optional_old_keys = original.clone();
		optional_old_keys["request"]["btc_payer_claim_pubkey"] = serde_json::Value::Null;
		assert!(serde_json::from_value::<RelayFile>(optional_old_keys).is_err());
		for field in ["btc_secret_nonce", "adaptor_secret_hex", "funding_psbt_hex", "unknown"] {
			let mut injected = original.clone();
			injected["request"][field] = "secret".into();
			assert!(serde_json::from_value::<RelayFile>(injected).is_err());
		}
		assert!(ensure_relay_secret_free(br#"{"btc_secret_nonce":"deadbeef"}"#).is_err());
		let mut incomplete = sample_response();
		incomplete.ark_claim_partial = None;
		assert!(incomplete.response_commitment_hash_hex().is_err());
	}
}
