use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, bail};
use serde::{Deserialize, Deserializer, Serialize};

use ark::VtxoId;
use bark::swap::btc_ark::{SwapId, SwapRole, SwapStatus};

use crate::relay::RelayFile;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredBtcArkSwap {
	#[serde(deserialize_with = "deserialize_state_version")]
	pub(crate) version: u16,
	pub(crate) swap_id: String,
	pub(crate) role: SwapRole,
	pub(crate) status: SwapStatus,
	pub(crate) coordinator: String,
	pub(crate) claim_key_index: u32,
	pub(crate) ark_input_ids: Vec<String>,
	pub(crate) relay: RelayFile,
	pub(crate) adaptor_secret_hex: Option<String>,
	pub(crate) btc_secret_nonce: Option<ark::musig::DangerousSecretNonce>,
	pub(crate) funding_psbt_hex: Option<String>,
	pub(crate) peer_transcript_hash_hex: Option<String>,
	pub(crate) signed_claim_tx_hex: Option<String>,
	pub(crate) signed_refund_tx_hex: Option<String>,
	pub(crate) cpfp_tx_hex: Option<String>,
	pub(crate) ark_exit_claim_tx_hex: Option<String>,
	pub(crate) ark_recovery_input_ids: Vec<String>,
	pub(crate) previous_refund_txids: Vec<bitcoin::Txid>,
	pub(crate) previous_ark_exit_claim_txids: Vec<bitcoin::Txid>,
	pub(crate) funding_conflict_scan_tip: Option<bitcoin_ext::BlockRef>,
}

impl std::fmt::Debug for StoredBtcArkSwap {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("StoredBtcArkSwap")
			.field("swap_id", &self.swap_id)
			.field("role", &self.role)
			.field("status", &self.status)
			.finish_non_exhaustive()
	}
}

impl StoredBtcArkSwap {
	pub(crate) fn new(
		swap_id: SwapId,
		role: SwapRole,
		coordinator: String,
		claim_key_index: u32,
		relay: RelayFile,
	) -> Self {
		Self {
			version: 3,
			swap_id: swap_id.to_string(),
			role,
			status: relay.status,
			coordinator,
			claim_key_index,
			ark_input_ids: Vec::new(),
			relay,
			adaptor_secret_hex: None,
			btc_secret_nonce: None,
			funding_psbt_hex: None,
			peer_transcript_hash_hex: None,
			signed_claim_tx_hex: None,
			signed_refund_tx_hex: None,
			cpfp_tx_hex: None,
			ark_exit_claim_tx_hex: None,
			ark_recovery_input_ids: Vec::new(),
			previous_refund_txids: Vec::new(),
			previous_ark_exit_claim_txids: Vec::new(),
			funding_conflict_scan_tip: None,
		}
	}

	pub(crate) fn accepted_ark_input_ids(&self) -> anyhow::Result<Vec<VtxoId>> {
		if self.ark_input_ids.is_empty() {
			bail!("accepted Ark input IDs are missing from local state");
		}
		if let Some(transfer) = &self.relay.ark_transfer {
			if self.ark_input_ids != transfer.offer.ark_input_ids {
				bail!("local Ark transfer does not match the frozen input IDs");
			}
		}
		self.ark_input_ids.iter()
			.map(|id| VtxoId::from_str(id).context("invalid accepted Ark input VTXO id"))
			.collect()
	}

	fn validate(&self) -> anyhow::Result<SwapId> {
		if self.version != 3 {
			bail!("unsupported BTC-Ark state version {}; version 3 is required", self.version);
		}
		let swap_id = SwapId::from_str(&self.swap_id).context("invalid local swap id")?;
		self.relay.require_swap(swap_id)?;
		if !self.ark_input_ids.is_empty() {
			self.accepted_ark_input_ids()?;
		}
		if let Some(expected) = &self.peer_transcript_hash_hex {
			if *expected != self.relay.response_commitment_hash_hex()? {
				bail!("local BTC-Ark response does not match its accepted transcript");
			}
		}
		Ok(swap_id)
	}
}

fn deserialize_state_version<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
	let version = u16::deserialize(deserializer)?;
	if version != 3 {
		return Err(serde::de::Error::custom(format!(
			"unsupported BTC-Ark state version {version}; version 3 is required",
		)));
	}
	Ok(version)
}

pub(crate) fn swap_state_path(datadir: &Path, swap_id: &str, role: SwapRole) -> PathBuf {
	datadir.join("swap").join(format!("btc-ark-{}-{}.json", swap_id, role_slug(role)))
}

pub(crate) async fn store_swap_state(datadir: &Path, state: &StoredBtcArkSwap) -> anyhow::Result<()> {
	state.validate()?;
	let path = swap_state_path(datadir, &state.swap_id, state.role);
	atomic_write(&path, serde_json::to_vec_pretty(state)?).await
		.with_context(|| format!("failed to write swap state {}", path.display()))
}

pub(crate) async fn load_swap_state(
	datadir: &Path,
	swap_id: SwapId,
	role: SwapRole,
) -> anyhow::Result<StoredBtcArkSwap> {
	load_swap_state_if_exists(datadir, swap_id, role).await?
		.with_context(|| format!("no local BTC-Ark state for {swap_id} ({})", role_slug(role)))
}

pub(crate) async fn load_swap_state_if_exists(
	datadir: &Path,
	swap_id: SwapId,
	role: SwapRole,
) -> anyhow::Result<Option<StoredBtcArkSwap>> {
	let path = swap_state_path(datadir, &swap_id.to_string(), role);
	let bytes = match tokio::fs::read(&path).await {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error).with_context(|| {
			format!("failed to read swap state {}", path.display())
		}),
	};
	let state: StoredBtcArkSwap = serde_json::from_slice(&bytes).with_context(|| {
		format!("invalid BTC-Ark state {}; version 3 is required (legacy state is unsupported)", path.display())
	})?;
	if state.validate()? != swap_id || state.role != role {
		bail!("local BTC-Ark state does not match the requested swap and role");
	}
	Ok(Some(state))
}

/// Prevent multiple open local swaps from promising the same funding input.
/// Ordinary onchain wallet operations do not participate in this reservation.
pub(crate) async fn ensure_funding_inputs_available(
	datadir: &Path,
	funding: &bitcoin::Transaction,
	tip: u32,
) -> anyhow::Result<()> {
	let mut entries = tokio::fs::read_dir(datadir.join("swap")).await?;
	while let Some(entry) = entries.next_entry().await? {
		let name = entry.file_name();
		let Some(id) = name.to_str().and_then(|name| name.strip_prefix("btc-ark-"))
			.and_then(|name| name.strip_suffix("-btc-payer.json")) else { continue; };
		let state = load_swap_state(datadir, SwapId::from_str(id)?, SwapRole::BtcPayer).await?;
		if matches!(state.status, SwapStatus::ArkCompleted | SwapStatus::ArkReclaimed | SwapStatus::Refunded | SwapStatus::Cancelled)
			|| (state.relay.btc_claim_adaptor.is_none() && state.relay.request.refund_height <= tip) {
			continue;
		}
		let reserved: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&state.relay.request.funding_template_hex)?;
		if funding.input.iter().any(|input| reserved.input.iter().any(|other| input.previous_output == other.previous_output)) {
			bail!("funding inputs overlap open BTC-Ark swap {id}; finish it or use a separate wallet");
		}
	}
	Ok(())
}

fn role_slug(role: SwapRole) -> &'static str {
	match role {
		SwapRole::BtcPayer => "btc-payer",
		SwapRole::ArkPayer => "ark-payer",
	}
}

/// Hold the returned file for the entire command, including reads and monitoring.
/// Never unlink the lock: replacing its inode would let another process bypass it.
pub(crate) async fn acquire_swap_lock(datadir: &Path) -> anyhow::Result<File> {
	let directory = datadir.join("swap");
	tokio::task::spawn_blocking(move || {
		create_private_directory(&directory)?;
		let path = directory.join(".lock");
		let file = private_open_options()?.read(true).write(true).create(true)
			.truncate(false).open(&path)
			.with_context(|| format!("failed to open swap lock {}", path.display()))?;
		match file.try_lock() {
			Ok(()) => Ok(file),
			Err(TryLockError::WouldBlock) => {
				bail!("another BTC-Ark swap command is using this wallet; wait for it to finish")
			},
			Err(TryLockError::Error(error)) => Err(error)
				.with_context(|| format!("failed to acquire swap lock {}", path.display())),
		}
	}).await.context("swap lock task failed")?
}

fn private_open_options() -> anyhow::Result<OpenOptions> {
	#[cfg(unix)]
	{
		let mut options = OpenOptions::new();
		options.mode(0o600);
		Ok(options)
	}
	#[cfg(not(unix))]
	bail!("private BTC-Ark persistence requires Unix file permissions")
}

fn parent_directory(path: &Path) -> &Path {
	path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

/// Persist newly created directory entries as well as the eventual state file.
fn create_private_directory(path: &Path) -> anyhow::Result<()> {
	if path.as_os_str().is_empty() || path.is_dir() {
		return Ok(());
	}
	let parent = parent_directory(path);
	create_private_directory(parent)?;
	let mut builder = DirBuilder::new();
	#[cfg(unix)]
	builder.mode(0o700);
	match builder.create(path) {
		Ok(()) => {},
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {},
		Err(error) => return Err(error).with_context(|| format!("failed to create {}", path.display())),
	}
	File::open(parent)?.sync_all().context("failed to sync new swap directory")
}

/// Both private state and public relay writes use a private, durable replacement.
/// A failure after rename may have committed the new file: callers must reload
/// local state before deciding whether a secret nonce is still available.
pub(crate) async fn atomic_write(path: &Path, bytes: Vec<u8>) -> anyhow::Result<()> {
	let path = path.to_owned();
	tokio::task::spawn_blocking(move || {
		let parent = parent_directory(&path);
		create_private_directory(parent)?;
		let mut name = path.file_name().context("swap file path has no filename")?.to_os_string();
		name.push(format!(".{}.tmp", SwapId::random()));
		let tmp = parent.join(name);
		// create_new rejects an existing file or symlink; mode applies at creation,
		// before the first secret byte can be written, regardless of umask.
		let mut file = private_open_options()?.write(true).create_new(true).open(&tmp)?;
		let result = (|| -> anyhow::Result<()> {
			file.write_all(&bytes)?;
			file.sync_all()?;
			fs::rename(&tmp, &path)?;
			File::open(parent)?.sync_all()?;
			Ok(())
		})();
		if result.is_err() {
			let _ = fs::remove_file(&tmp);
		}
		result
	}).await.context("swap persistence task failed")?
}

#[cfg(all(test, unix))]
mod tests {
	use std::os::unix::fs::PermissionsExt;

	use super::*;
	use crate::relay::tests::sample_response;

	struct TestDirectory(PathBuf);

	impl TestDirectory {
		fn new() -> Self {
			Self(std::env::temp_dir().join(format!("btc-ark-state-{}", SwapId::random())))
		}
	}

	impl Drop for TestDirectory {
		fn drop(&mut self) {
			let _ = fs::remove_dir_all(&self.0);
		}
	}

	fn signed_state() -> StoredBtcArkSwap {
		let relay = sample_response();
		let mut state = StoredBtcArkSwap::new(
			relay.swap_id().unwrap(), SwapRole::BtcPayer, "relay.json".to_owned(), 0, relay,
		);
		state.ark_input_ids = state.relay.ark_transfer.as_ref().unwrap().offer.ark_input_ids.clone();
		state.adaptor_secret_hex = Some("11".repeat(32));
		state.funding_psbt_hex = Some("70736274ff".to_owned());
		state.peer_transcript_hash_hex = Some(state.relay.response_commitment_hash_hex().unwrap());
		state.signed_claim_tx_hex = Some("claim-signing-result".to_owned());
		state.signed_refund_tx_hex = Some("refund-signing-result".to_owned());
		state
	}

	#[test]
	fn debug_does_not_disclose_private_signing_material() {
		let state = signed_state();
		let formatted = format!("{state:?}");
		assert!(!formatted.contains(state.adaptor_secret_hex.as_ref().unwrap()));
		assert!(!formatted.contains(state.funding_psbt_hex.as_ref().unwrap()));
		assert!(!formatted.contains(state.signed_claim_tx_hex.as_ref().unwrap()));
	}

	#[tokio::test]
	async fn selected_ark_inputs_survive_crash_before_server_cosigning() {
		let dir = TestDirectory::new();
		let mut state = signed_state();
		let transfer = state.relay.ark_transfer.take().unwrap();
		state.peer_transcript_hash_hex = None;
		state.role = SwapRole::ArkPayer;
		let expected = state.accepted_ark_input_ids().unwrap();
		store_swap_state(&dir.0, &state).await.unwrap();
		let mut recovered = load_swap_state(
			&dir.0, state.relay.swap_id().unwrap(), state.role,
		).await.unwrap();
		assert_eq!(recovered.accepted_ark_input_ids().unwrap(), expected);
		recovered.relay.ark_transfer = Some(transfer);
		recovered.relay.ark_transfer.as_mut().unwrap().offer.ark_input_ids =
			vec![VtxoId::from_slice(&[8; 36]).unwrap().to_string()];
		assert!(store_swap_state(&dir.0, &recovered).await.is_err());
	}

	#[tokio::test]
	async fn private_state_replaces_permissive_file_and_preserves_consumed_nonce_result() {
		let dir = TestDirectory::new();
		let state = signed_state();
		let swap_id = state.relay.swap_id().unwrap();
		let path = swap_state_path(&dir.0, &state.swap_id, state.role);
		fs::create_dir_all(path.parent().unwrap()).unwrap();
		fs::write(&path, b"old public content").unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
		store_swap_state(&dir.0, &state).await.unwrap();
		assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
		let recovered = load_swap_state(&dir.0, swap_id, state.role).await.unwrap();
		assert!(recovered.btc_secret_nonce.is_none());
		assert_eq!(serde_json::to_vec(&recovered).unwrap(), serde_json::to_vec(&state).unwrap());
		assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
	}

	#[test]
	fn secret_file_is_private_before_any_secret_is_written() {
		let dir = TestDirectory::new();
		create_private_directory(&dir.0).unwrap();
		let path = dir.0.join("secret.tmp");
		let file = private_open_options().unwrap().write(true).create_new(true).open(&path).unwrap();
		assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
		assert!(private_open_options().unwrap().write(true).create_new(true).open(&path).is_err());
	}

	#[tokio::test]
	async fn swap_lock_is_exclusive_and_released_on_drop() {
		let dir = TestDirectory::new();
		let first = acquire_swap_lock(&dir.0).await.unwrap();
		assert!(acquire_swap_lock(&dir.0).await.is_err());
		assert_eq!(first.metadata().unwrap().permissions().mode() & 0o777, 0o600);
		drop(first);
		let second = acquire_swap_lock(&dir.0).await.unwrap();
		assert!(acquire_swap_lock(&dir.0).await.is_err());
		drop(second);
	}

	#[tokio::test]
	async fn missing_state_is_distinct_from_legacy_corrupt_and_misplaced_state() {
		let dir = TestDirectory::new();
		let state = signed_state();
		let id = state.relay.swap_id().unwrap();
		assert!(load_swap_state_if_exists(&dir.0, id, state.role).await.unwrap().is_none());
		let path = swap_state_path(&dir.0, &state.swap_id, state.role);
		for bytes in [b"{broken".as_slice(), br#"{"swap_id":"legacy","amount_sat":100}"#] {
			atomic_write(&path, bytes.to_vec()).await.unwrap();
			assert!(load_swap_state_if_exists(&dir.0, id, state.role).await.is_err());
		}
		let mut wrong_role = state.clone();
		wrong_role.role = SwapRole::ArkPayer;
		atomic_write(&path, serde_json::to_vec(&wrong_role).unwrap()).await.unwrap();
		assert!(load_swap_state_if_exists(&dir.0, id, state.role).await.is_err());
		let mut changed_transcript = state;
		changed_transcript.relay.request.amount_sat += 1;
		atomic_write(&path, serde_json::to_vec(&changed_transcript).unwrap()).await.unwrap();
		assert!(load_swap_state_if_exists(&dir.0, id, SwapRole::BtcPayer).await.is_err());
	}

	#[tokio::test]
	async fn failed_replace_cleans_only_its_own_temporary_file() {
		let dir = TestDirectory::new();
		let destination = dir.0.join("not-a-file");
		fs::create_dir_all(&destination).unwrap();
		let unrelated = dir.0.join("unrelated.tmp");
		fs::write(&unrelated, b"keep").unwrap();
		assert!(atomic_write(&destination, b"secret".to_vec()).await.is_err());
		assert!(destination.is_dir());
		assert_eq!(fs::read(&unrelated).unwrap(), b"keep");
		assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
	}
}
