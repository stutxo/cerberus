use std::collections::{HashMap, HashSet};
use std::io;
use std::marker::PhantomData;

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::Txid;
use bitcoin_ext::BlockHeight;

use crate::arkoor::{
	ArkoorBuilder, ArkoorSigningError, PreparedAdaptorArkoor, TransferableAdaptorArkoor, state,
};
use crate::encode::{
	LengthPrefixedVector, OversizedVectorError, ProtocolDecodingError, ProtocolEncoding, ReadExt,
	WriteExt,
};
use crate::vtxo::Full;
use crate::{Amount, ServerVtxo, Vtxo, VtxoId, VtxoPolicy};

use super::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};

const TRANSFERABLE_ADAPTOR_ARKOOR_PACKAGE_ENCODING_VERSION: u16 = 2;

/// An adaptor-locked arkoor package before it is safe to send to a counterparty.
pub struct PreparedAdaptorArkoorPackage {
	packages: Vec<PreparedAdaptorArkoor>,
}

/// A counterparty-safe adaptor-locked arkoor package.
///
/// This package retains public virtual transaction data, public nonces, server
/// partial signatures, adaptor pre-signatures, output details, and the adaptor
/// lock point. It does not retain VTXO private keys, secret nonces, mnemonic
/// material, or the adaptor secret.
pub struct TransferableAdaptorArkoorPackage {
	packages: Vec<TransferableAdaptorArkoor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum TransferPackageVerificationError {
	#[error("transfer package is empty")]
	EmptyPackage,
	#[error("adaptor point mismatch")]
	AdaptorPointMismatch,
	#[error("input VTXO ids mismatch")]
	InputIdsMismatch,
	#[error("duplicate transfer input VTXO {0}")]
	DuplicateInput(VtxoId),
	#[error("transfer inputs have overlapping or conflicting ancestry")]
	OverlappingInputs,
	#[error("duplicate transfer output VTXO {0}")]
	DuplicateOutput(VtxoId),
	#[error("transfer amount overflow")]
	AmountOverflow,
	#[error("Ark server pubkey mismatch")]
	ServerPubkeyMismatch,
	#[error("adaptor signature material count mismatch")]
	SignatureMaterialCountMismatch,
	#[error(
		"invalid adaptor pre-signature at package {package_index}, signature {signature_index}"
	)]
	InvalidAdaptorPreSignature {
		package_index: usize,
		signature_index: usize,
	},
	#[error("transfer package does not pay the expected Ark amount")]
	OutputAmountMismatch,
	#[error(
		"transfer package output VTXO {vtxo_id} expires at height {expiry_height}, required after height {minimum_expiry_height}"
	)]
	OutputExpiryTooSoon {
		vtxo_id: VtxoId,
		expiry_height: BlockHeight,
		minimum_expiry_height: BlockHeight,
	},
}

impl ArkoorPackageBuilder<state::Initial> {
	pub fn generate_user_adaptor_nonces(
		self,
		user_keypairs: &[Keypair],
		adaptor_point: PublicKey,
	) -> Result<ArkoorPackageBuilder<state::UserGeneratedAdaptorNonces>, ArkoorSigningError> {
		if user_keypairs.len() != self.builders.len() {
			return Err(ArkoorSigningError::InvalidNbKeypairs {
				expected: self.builders.len(),
				got: user_keypairs.len(),
			});
		}

		let mut builder = Vec::with_capacity(self.builders.len());
		for (idx, package) in self.builders.into_iter().enumerate() {
			builder.push(package.generate_user_adaptor_nonces(user_keypairs[idx], adaptor_point)?);
		}
		Ok(ArkoorPackageBuilder { builders: builder })
	}
}

impl ArkoorPackageBuilder<state::UserGeneratedAdaptorNonces> {
	pub fn user_adaptor_cosign(
		self,
		user_keypairs: &[Keypair],
		server_cosign_response: ArkoorPackageCosignResponse,
	) -> Result<PreparedAdaptorArkoorPackage, ArkoorSigningError> {
		if server_cosign_response.responses.len() != self.builders.len() {
			return Err(ArkoorSigningError::InvalidNbPackages {
				expected: self.builders.len(),
				got: server_cosign_response.responses.len(),
			});
		}

		if user_keypairs.len() != self.builders.len() {
			return Err(ArkoorSigningError::InvalidNbKeypairs {
				expected: self.builders.len(),
				got: user_keypairs.len(),
			});
		}

		let mut packages = Vec::with_capacity(self.builders.len());
		for (idx, pkg) in self.builders.into_iter().enumerate() {
			packages.push(pkg.user_adaptor_cosign(
				&user_keypairs[idx],
				&server_cosign_response.responses[idx],
			)?);
		}
		Ok(PreparedAdaptorArkoorPackage { packages })
	}
}

impl PreparedAdaptorArkoorPackage {
	pub fn pre_signatures(&self) -> impl Iterator<Item = &crate::musig::AdaptorPreSignature> {
		self.packages
			.iter()
			.flat_map(|package| package.pre_signatures())
	}

	pub fn into_transfer_package(self) -> TransferableAdaptorArkoorPackage {
		TransferableAdaptorArkoorPackage {
			packages: self
				.packages
				.into_iter()
				.map(PreparedAdaptorArkoor::into_transfer_package)
				.collect(),
		}
	}
}

impl TransferableAdaptorArkoorPackage {
	pub fn packages(&self) -> &[TransferableAdaptorArkoor] {
		&self.packages
	}

	pub fn pre_signatures(&self) -> impl Iterator<Item = &crate::musig::AdaptorPreSignature> {
		self.packages
			.iter()
			.flat_map(|package| package.pre_signatures())
	}

	pub fn input_ids<'a>(&'a self) -> impl Iterator<Item = VtxoId> + 'a {
		self.packages.iter().map(|package| package.input().id())
	}

	pub fn build_unsigned_vtxos<'a>(&'a self) -> impl Iterator<Item = Vtxo<Full>> + 'a {
		self.packages
			.iter()
			.flat_map(|package| package.build_unsigned_vtxos())
	}

	pub fn build_unsigned_internal_vtxos(&self) -> Vec<(ServerVtxo<Full>, Txid)> {
		self.packages
			.iter()
			.flat_map(|package| package.builder.build_unsigned_internal_vtxos())
			.collect()
	}

	pub fn input_spend_info<'a>(&'a self) -> impl Iterator<Item = (VtxoId, Txid)> + 'a {
		self.packages
			.iter()
			.map(|package| package.input_spend_info())
	}

	pub fn spend_info<'a>(&'a self) -> impl Iterator<Item = (VtxoId, Txid)> + 'a {
		self.packages
			.iter()
			.flat_map(|package| package.spend_info())
	}

	pub fn virtual_transactions<'a>(&'a self) -> impl Iterator<Item = Txid> + 'a {
		self.packages
			.iter()
			.flat_map(|package| package.virtual_transactions())
	}

	pub fn verify_public_transfer(
		&self,
		expected_input_ids: &[VtxoId],
		expected_receive_policy: &VtxoPolicy,
		expected_amount: Amount,
		expected_server_pubkey: PublicKey,
		expected_adaptor_point: PublicKey,
	) -> Result<(), TransferPackageVerificationError> {
		if self.packages.is_empty() {
			return Err(TransferPackageVerificationError::EmptyPackage);
		}

		let input_ids = self.input_ids().collect::<Vec<_>>();
		if input_ids != expected_input_ids {
			return Err(TransferPackageVerificationError::InputIdsMismatch);
		}
		let mut unique_inputs = HashSet::with_capacity(input_ids.len());
		for id in &input_ids {
			if !unique_inputs.insert(*id) {
				return Err(TransferPackageVerificationError::DuplicateInput(*id));
			}
		}

		// Common ancestry prefixes are legitimate; conflicting spends or spending
		// another final input would count mutually exclusive coins as payment.
		let mut ancestry_spends = HashMap::new();
		for package in &self.packages {
			package.input().chain_anchor_amount()
				.ok_or(TransferPackageVerificationError::AmountOverflow)?;
			for item in package.input().transactions() {
				let txid = item.tx.compute_txid();
				for input in &item.tx.input {
					if unique_inputs.contains(&VtxoId::from(input.previous_output)) {
						return Err(TransferPackageVerificationError::OverlappingInputs);
					}
					if let Some(previous) = ancestry_spends.insert(input.previous_output, txid) {
						if previous != txid {
							return Err(TransferPackageVerificationError::OverlappingInputs);
						}
					}
				}
			}
		}

		let mut paid_amount = Amount::ZERO;
		let mut output_ids = HashSet::new();
		for (package_index, package) in self.packages.iter().enumerate() {
			if package.adaptor_point() != expected_adaptor_point {
				return Err(TransferPackageVerificationError::AdaptorPointMismatch);
			}

			if package.input().server_pubkey() != expected_server_pubkey {
				return Err(TransferPackageVerificationError::ServerPubkeyMismatch);
			}

			let expected_sigs = package.builder.nb_sigs();
			let nb_pre_sigs = package.pre_signatures().len();
			if nb_pre_sigs != expected_sigs
				|| package.user_pub_nonces().len() != expected_sigs
				|| package.server_pub_nonces().len() != expected_sigs
				|| package.server_partial_sigs().len() != expected_sigs
			{
				return Err(TransferPackageVerificationError::SignatureMaterialCountMismatch);
			}

			for (signature_index, aggregate_key) in package.builder.signing_pubkeys().enumerate() {
				package.pre_signatures()[signature_index]
					.verify_adaptor(
						expected_adaptor_point,
						aggregate_key.x_only_public_key().0,
						package.builder.sighashes[signature_index].to_byte_array(),
					)
					.map_err(
						|_| TransferPackageVerificationError::InvalidAdaptorPreSignature {
							package_index,
							signature_index,
						},
					)?;
			}

			for output in package.build_unsigned_vtxos() {
				if !output_ids.insert(output.id()) {
					return Err(TransferPackageVerificationError::DuplicateOutput(output.id()));
				}
				if output.policy() == expected_receive_policy {
					paid_amount = paid_amount.checked_add(output.amount())
						.ok_or(TransferPackageVerificationError::AmountOverflow)?;
				}
			}
		}

		if paid_amount != expected_amount {
			return Err(TransferPackageVerificationError::OutputAmountMismatch);
		}

		Ok(())
	}

	pub fn finalize_with_secret(
		self,
		secret: crate::musig::AdaptorSecret,
	) -> Result<ArkoorPackageBuilder<state::UserSigned>, ArkoorSigningError> {
		let mut builders = Vec::with_capacity(self.packages.len());
		for package in self.packages {
			builders.push(package.finalize_with_secret(secret)?);
		}

		Ok(ArkoorPackageBuilder { builders })
	}
}

impl ProtocolEncoding for TransferableAdaptorArkoor {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		self.builder.input.encode(w)?;
		encode_vec(&self.builder.outputs, w)?;
		encode_vec(&self.builder.isolated_outputs, w)?;
		w.emit_u8(u8::from(self.builder.checkpoint_data.is_some()))?;
		encode_vec(self.builder.user_pub_nonces(), w)?;
		encode_vec(self.server_pub_nonces(), w)?;
		encode_vec(self.server_partial_sigs(), w)?;
		self.adaptor_point.encode(w)?;
		encode_vec(&self.pre_signatures, w)
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let input = Vtxo::<Full>::decode(r)?;
		let outputs: Vec<crate::arkoor::ArkoorDestination> = decode_vec(r)?;
		let isolated_outputs: Vec<crate::arkoor::ArkoorDestination> = decode_vec(r)?;
		// The builder's balancing arithmetic assumes representable amounts.
		// Reject hostile wire values before entering that trusted constructor.
		input.chain_anchor_amount().ok_or_else(|| {
			ProtocolDecodingError::invalid("transfer input ancestry amount overflow")
		})?;
		outputs.iter().chain(&isolated_outputs)
			.try_fold(Amount::ZERO, |sum, output| sum.checked_add(output.total_amount))
			.ok_or_else(|| ProtocolDecodingError::invalid("transfer output amount overflow"))?;
		let use_checkpoint = match r.read_u8()? {
			0 => false,
			1 => true,
			_ => return Err(ProtocolDecodingError::invalid("invalid checkpoint flag")),
		};
		let user_pub_nonces = decode_vec(r)?;
		let server_pub_nonces = decode_vec(r)?;
		let server_partial_sigs = decode_vec(r)?;
		let adaptor_point = PublicKey::decode(r)?;
		let pre_signatures = decode_vec(r)?;
		let builder = ArkoorBuilder::new(input, outputs, isolated_outputs, use_checkpoint)
			.map_err(|e| ProtocolDecodingError::invalid_err(
				e,
				"invalid transferable adaptor arkoor terms",
			))?;

		Ok(Self {
			builder: ArkoorBuilder {
				input: builder.input,
				outputs: builder.outputs,
				isolated_outputs: builder.isolated_outputs,
				checkpoint_data: builder.checkpoint_data,
				unsigned_arkoor_txs: builder.unsigned_arkoor_txs,
				unsigned_isolation_fanout_tx: builder.unsigned_isolation_fanout_tx,
				sighashes: builder.sighashes,
				input_tweak: builder.input_tweak,
				checkpoint_policy_tweak: builder.checkpoint_policy_tweak,
				new_vtxo_ids: builder.new_vtxo_ids,
				user_keypair: None,
				user_pub_nonces: Some(user_pub_nonces),
				user_sec_nonces: None,
				server_pub_nonces: Some(server_pub_nonces),
				server_partial_sigs: Some(server_partial_sigs),
				full_signatures: None,
				adaptor_point: Some(adaptor_point),
				_state: PhantomData::<state::UserGeneratedAdaptorNonces>,
			},
			adaptor_point,
			pre_signatures,
		})
	}
}

impl ProtocolEncoding for TransferableAdaptorArkoorPackage {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_u16(TRANSFERABLE_ADAPTOR_ARKOOR_PACKAGE_ENCODING_VERSION)?;
		w.emit_compact_size(self.packages.len() as u64)?;
		for package in &self.packages {
			package.encode(w)?;
		}
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let version = r.read_u16()?;
		if version != TRANSFERABLE_ADAPTOR_ARKOOR_PACKAGE_ENCODING_VERSION {
			return Err(ProtocolDecodingError::invalid(format_args!(
				"invalid transferable adaptor arkoor package version: {version}",
			)));
		}

		let count = r.read_compact_size()? as usize;
		OversizedVectorError::check::<TransferableAdaptorArkoor>(count)?;
		let mut packages = Vec::with_capacity(count);
		for _ in 0..count {
			packages.push(TransferableAdaptorArkoor::decode(r)?);
		}
		Ok(Self { packages })
	}
}

fn encode_vec<T: ProtocolEncoding + Clone, W: io::Write + ?Sized>(
	items: &[T],
	w: &mut W,
) -> Result<(), io::Error> {
	LengthPrefixedVector::new(items).encode(w)
}

fn decode_vec<T: ProtocolEncoding + Clone + 'static, R: io::Read + ?Sized>(
	r: &mut R,
) -> Result<Vec<T>, ProtocolDecodingError> {
	Ok(<LengthPrefixedVector<'static, T> as ProtocolEncoding>::decode(r)?.into_inner())
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use bitcoin::secp256k1::{Keypair, SecretKey, schnorr};
	use bitcoin::Transaction;
	use bitcoin_ext::P2TR_DUST;

	use crate::arkoor::{ArkoorDestination, package::ArkoorPackageBuilder};
	use crate::musig;
	use crate::test_util::dummy::DummyTestVtxoSpec;
	use crate::vtxo::Full;
	use crate::{Amount, ProtocolEncoding, PublicKey, Vtxo, VtxoPolicy};

	use super::*;

	fn server_keypair() -> Keypair {
		Keypair::from_str("f7a2a5d150afb575e98fff9caeebf6fbebbaeacfdfa7433307b208b39f1155f2")
			.expect("Invalid key")
	}

	fn server_public_key() -> PublicKey {
		server_keypair().public_key()
	}

	fn alice_keypair() -> Keypair {
		Keypair::from_str("9b4382c8985f12e4bd8d1b51e63615bf0187843630829f4c5e9c45ef2cf994a4")
			.expect("Invalid key")
	}

	fn bob_keypair() -> Keypair {
		Keypair::from_str("c86435ba7e30d7afd7c5df9f3263ce2eb86b3ff9866a16ccd22a0260496ddf0f")
			.expect("Invalid key")
	}

	fn alice_public_key() -> PublicKey {
		alice_keypair().public_key()
	}

	fn bob_public_key() -> PublicKey {
		bob_keypair().public_key()
	}

	fn dummy_vtxo_for_amount(amt: Amount) -> (Transaction, Vtxo<Full>) {
		DummyTestVtxoSpec {
			amount: amt + P2TR_DUST,
			fee: P2TR_DUST,
			expiry_height: 1000.into(),
			exit_delta: 128.into(),
			user_keypair: alice_keypair(),
			server_keypair: server_keypair(),
		}
		.build()
	}

	fn transfer_for_inputs(
		inputs: Vec<Vtxo<Full>>,
		outputs: Vec<ArkoorDestination>,
		adaptor_point: PublicKey,
	) -> TransferableAdaptorArkoorPackage {
		let keys = vec![alice_keypair(); inputs.len()];
		let builder = ArkoorPackageBuilder::new_with_checkpoints(inputs, outputs).unwrap()
			.generate_user_adaptor_nonces(&keys, adaptor_point).unwrap();
		let response = ArkoorPackageBuilder::from_cosign_request(builder.cosign_request()).unwrap()
			.server_cosign(&server_keypair()).unwrap().cosign_response();
		builder.user_adaptor_cosign(&keys, response).unwrap().into_transfer_package()
	}

	#[test]
	fn repeated_package_cannot_double_received_value() {
		let amount = Amount::from_sat(100_000);
		let (_, input) = dummy_vtxo_for_amount(amount);
		let id = input.id();
		let policy = VtxoPolicy::new_pubkey(bob_public_key());
		let point = musig::AdaptorSecret::new(SecretKey::from_slice(&[42; 32]).unwrap()).point();
		let mut transfer = transfer_for_inputs(vec![input], vec![ArkoorDestination {
			total_amount: amount, policy: policy.clone(),
		}], point);
		let copy = TransferableAdaptorArkoorPackage::deserialize(&transfer.serialize()).unwrap();
		transfer.packages.extend(copy.packages);
		assert_eq!(
			transfer.verify_public_transfer(
				&[id, id], &policy, amount + amount, server_public_key(), point,
			),
			Err(TransferPackageVerificationError::DuplicateInput(id)),
		);
	}

	#[test]
	fn shared_ancestry_is_valid_but_overlapping_or_conflicting_inputs_are_not() {
		let amount = Amount::from_sat(100_000);
		let (_, input) = dummy_vtxo_for_amount(amount);
		let secret = musig::AdaptorSecret::new(SecretKey::from_slice(&[42; 32]).unwrap());
		let alice_policy = VtxoPolicy::new_pubkey(alice_public_key());
		let bob_policy = VtxoPolicy::new_pubkey(bob_public_key());
		let split = |first: u64| transfer_for_inputs(vec![input.clone()], vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(first), policy: alice_policy.clone(),
			},
			ArkoorDestination {
				total_amount: amount - Amount::from_sat(first), policy: alice_policy.clone(),
			},
		], secret.point()).finalize_with_secret(secret).unwrap().build_signed_vtxos();
		let siblings = split(40_000);
		let sibling_ids = siblings.iter().map(|v| v.id()).collect::<Vec<_>>();
		let mut shared = transfer_for_inputs(siblings.clone(), vec![ArkoorDestination {
			total_amount: amount, policy: bob_policy.clone(),
		}], secret.point());
		shared.verify_public_transfer(
			&sibling_ids, &bob_policy, amount, server_public_key(), secret.point(),
		).expect("distinct outputs of shared ancestry are spendable together");

		let parent = transfer_for_inputs(vec![input.clone()], vec![ArkoorDestination {
			total_amount: amount, policy: bob_policy.clone(),
		}], secret.point());
		shared.packages.extend(parent.packages);
		let ids = shared.input_ids().collect::<Vec<_>>();
		assert_eq!(
			shared.verify_public_transfer(
				&ids, &bob_policy, amount + amount, server_public_key(), secret.point(),
			),
			Err(TransferPackageVerificationError::OverlappingInputs),
		);

		let alternate = split(30_000);
		let conflicting_amount = siblings[0].amount() + alternate[0].amount();
		let conflicting = transfer_for_inputs(
			vec![siblings[0].clone(), alternate[0].clone()],
			vec![ArkoorDestination {
				total_amount: conflicting_amount, policy: bob_policy.clone(),
			}],
			secret.point(),
		);
		let ids = conflicting.input_ids().collect::<Vec<_>>();
		assert_eq!(
			conflicting.verify_public_transfer(
				&ids, &bob_policy, conflicting_amount, server_public_key(), secret.point(),
			),
			Err(TransferPackageVerificationError::OverlappingInputs),
		);
	}

	#[test]
	fn received_amount_overflow_is_rejected() {
		let amount = Amount::from_sat(u64::MAX / 2 + 1);
		let policy = VtxoPolicy::new_pubkey(bob_public_key());
		let point = musig::AdaptorSecret::new(SecretKey::from_slice(&[42; 32]).unwrap()).point();
		let mut combined = TransferableAdaptorArkoorPackage { packages: Vec::new() };
		for amount in [amount, amount + Amount::ONE_SAT] {
			let (_, input) = dummy_vtxo_for_amount(amount);
			let transfer = transfer_for_inputs(vec![input], vec![ArkoorDestination {
				total_amount: amount, policy: policy.clone(),
			}], point);
			combined.packages.extend(transfer.packages);
		}
		let ids = combined.input_ids().collect::<Vec<_>>();
		assert_eq!(
			combined.verify_public_transfer(&ids, &policy, Amount::ZERO, server_public_key(), point),
			Err(TransferPackageVerificationError::AmountOverflow),
		);
	}

	#[test]
	fn wire_output_overflow_is_rejected_before_builder_arithmetic() {
		let (_, input) = dummy_vtxo_for_amount(Amount::from_sat(100_000));
		let policy = VtxoPolicy::new_pubkey(bob_public_key());
		let point = musig::AdaptorSecret::new(SecretKey::from_slice(&[42; 32]).unwrap()).point();
		let mut transfer = transfer_for_inputs(vec![input], vec![ArkoorDestination {
			total_amount: Amount::from_sat(100_000), policy: policy.clone(),
		}], point);
		transfer.packages[0].builder.outputs = vec![
			ArkoorDestination { total_amount: Amount::MAX, policy: policy.clone() },
			ArkoorDestination { total_amount: Amount::ONE_SAT, policy },
		];
		assert!(TransferableAdaptorArkoorPackage::deserialize(&transfer.serialize()).is_err());
	}

	#[test]
	fn adaptor_package_transfer_is_public_and_finalizes() {
		let (funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(100_000));
		let receive_policy = VtxoPolicy::new_pubkey(bob_public_key());
		let secret =
			musig::AdaptorSecret::new(SecretKey::from_slice(&[42; 32]).expect("valid secret"));
		let adaptor_point = secret.point();
		let expected_input_ids = vec![alice_vtxo.id()];

		let package_builder = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[alice_vtxo],
			ArkoorDestination {
				total_amount: Amount::from_sat(100_000),
				policy: receive_policy.clone(),
			},
			VtxoPolicy::new_pubkey(alice_public_key()),
		)
		.expect("valid package");

		let user_builder = package_builder
			.generate_user_adaptor_nonces(&[alice_keypair()], adaptor_point)
			.expect("valid adaptor nonces");
		let cosign_response =
			ArkoorPackageBuilder::from_cosign_request(user_builder.cosign_request())
				.expect("valid cosign request")
				.server_cosign(&server_keypair())
				.expect("server cosigns")
				.cosign_response();

		let transfer = user_builder
			.user_adaptor_cosign(&[alice_keypair()], cosign_response)
			.expect("valid adaptor cosign")
			.into_transfer_package();

		for package in transfer.packages() {
			assert!(package.builder.user_keypair.is_none());
			assert!(package.builder.user_sec_nonces.is_none());
		}

		transfer
			.verify_public_transfer(
				&expected_input_ids,
				&receive_policy,
				Amount::from_sat(100_000),
				server_public_key(),
				adaptor_point,
			)
			.expect("public transfer verifies");

		let original_virtual_transactions = transfer.virtual_transactions().collect::<Vec<_>>();
		let transfer_hex = transfer.serialize_hex();
		let mut invalid_version = transfer.serialize();
		invalid_version[0] = 0xff;
		invalid_version[1] = 0xff;
		assert!(
			TransferableAdaptorArkoorPackage::deserialize(&invalid_version).is_err(),
			"invalid transfer encoding version must be rejected",
		);

		let mut transfer = TransferableAdaptorArkoorPackage::deserialize_hex(&transfer_hex)
			.expect("transfer package round-trips through protocol encoding");
		assert_eq!(
			original_virtual_transactions,
			transfer.virtual_transactions().collect::<Vec<_>>(),
			"decoded transfer package must rebuild canonical virtual txs",
		);
		transfer
			.verify_public_transfer(
				&expected_input_ids,
				&receive_policy,
				Amount::from_sat(100_000),
				server_public_key(),
				adaptor_point,
			)
			.expect("decoded public transfer verifies");

		let mut count_mismatch =
			TransferableAdaptorArkoorPackage::deserialize_hex(&transfer_hex)
				.expect("transfer package round-trips");
		count_mismatch.packages[0].pre_signatures.clear();
		assert!(matches!(
			count_mismatch.verify_public_transfer(
				&expected_input_ids,
				&receive_policy,
				Amount::from_sat(100_000),
				server_public_key(),
				adaptor_point,
			),
			Err(TransferPackageVerificationError::SignatureMaterialCountMismatch),
		));

		let wrong_secret =
			musig::AdaptorSecret::new(SecretKey::from_slice(&[43; 32]).expect("valid secret"));
		let wrong_adaptor_point = wrong_secret.point();
		transfer.packages[0].adaptor_point = wrong_adaptor_point;
		assert!(matches!(
			transfer.verify_public_transfer(
				&expected_input_ids,
				&receive_policy,
				Amount::from_sat(100_000),
				server_public_key(),
				wrong_adaptor_point,
			),
			Err(
				TransferPackageVerificationError::InvalidAdaptorPreSignature {
					package_index: 0,
					signature_index: 0,
				}
			),
		));
		transfer.packages[0].adaptor_point = adaptor_point;

		let original_pre_sig = transfer.packages[0].pre_signatures[0];
		let mut tampered_pre_sig = original_pre_sig.as_pre_signature().serialize();
		tampered_pre_sig[63] ^= 1;
		transfer.packages[0].pre_signatures[0] = musig::AdaptorPreSignature::new(
			schnorr::Signature::from_slice(&tampered_pre_sig)
				.expect("tampered bytes remain a schnorr-shaped signature"),
		);
		assert!(matches!(
			transfer.verify_public_transfer(
				&expected_input_ids,
				&receive_policy,
				Amount::from_sat(100_000),
				server_public_key(),
				adaptor_point,
			),
			Err(
				TransferPackageVerificationError::InvalidAdaptorPreSignature {
					package_index: 0,
					signature_index: 0,
				}
			),
		));
		transfer.packages[0].pre_signatures[0] = original_pre_sig;

		let signed_vtxos = transfer
			.finalize_with_secret(secret)
			.expect("secret finalizes package")
			.build_signed_vtxos();

		for vtxo in signed_vtxos {
			vtxo.validate(&funding_tx).expect("valid signed vtxo");
		}
	}
}
