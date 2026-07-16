//! Bounded, app-hash-verified state snapshots for CometBFT state sync.
//!
//! Snapshots contain the canonical consensus state rather than a copy of the
//! redb file. A receiving node rebuilds its local JMT and accepts the snapshot
//! only when the resulting application hash matches the light-client-verified
//! hash supplied by CometBFT.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tendermint::{abci::types::Snapshot, block::Height};

use crate::engine::{EngineState, audit_engine_state, canonical_state_bytes, compute_app_hash};

pub const STATE_SNAPSHOT_FORMAT: u32 = 1;
pub const STATE_SNAPSHOT_CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STATE_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_STATE_SNAPSHOT_METADATA_BYTES: usize = 1024 * 1024;

const SNAPSHOT_SCHEMA_VERSION: u16 = 1;
const SNAPSHOT_HASH_DOMAIN: &[u8] = b"ASTERIA_STATE_SNAPSHOT_V1\0";
const MAX_CHAIN_ID_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotMetadata {
    schema_version: u16,
    chain_id: String,
    height: u64,
    app_hash: String,
    state_bytes: u64,
    chunk_bytes: u32,
    chunk_hashes: Vec<String>,
}

/// Immutable snapshot cached by a serving node while peers fetch its chunks.
#[derive(Clone, Debug)]
pub struct StateSnapshotExport {
    descriptor: Snapshot,
    state_bytes: Bytes,
}

impl StateSnapshotExport {
    pub fn create(state: &EngineState, app_hash: [u8; 32]) -> Result<Self> {
        let computed = compute_app_hash(state).map_err(state_error)?;
        if computed != app_hash {
            return Err(StateSyncError::AppHashMismatch);
        }
        let state_bytes = canonical_state_bytes(state).map_err(state_error)?;
        validate_state_size(state_bytes.len())?;

        let chunk_hashes = state_bytes
            .chunks(STATE_SNAPSHOT_CHUNK_BYTES)
            .map(|chunk| hex::encode(Sha256::digest(chunk)))
            .collect::<Vec<_>>();
        let chunks =
            u32::try_from(chunk_hashes.len()).map_err(|_| StateSyncError::TooManyChunks)?;
        if chunks == 0 {
            return Err(StateSyncError::EmptySnapshot);
        }
        let metadata = SnapshotMetadata {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            chain_id: state.chain_id.clone(),
            height: state.height,
            app_hash: hex::encode(app_hash),
            state_bytes: u64::try_from(state_bytes.len())
                .map_err(|_| StateSyncError::SnapshotTooLarge)?,
            chunk_bytes: u32::try_from(STATE_SNAPSHOT_CHUNK_BYTES)
                .expect("snapshot chunk size fits u32"),
            chunk_hashes,
        };
        validate_metadata(&metadata, chunks)?;
        let metadata_bytes = canonical_metadata_bytes(&metadata)?;
        let snapshot_hash = snapshot_hash(&metadata_bytes, &state_bytes);
        let height = Height::try_from(state.height)
            .map_err(|_| StateSyncError::InvalidHeight(state.height))?;
        Ok(Self {
            descriptor: Snapshot {
                height,
                format: STATE_SNAPSHOT_FORMAT,
                chunks,
                hash: Bytes::copy_from_slice(&snapshot_hash),
                metadata: metadata_bytes.into(),
            },
            state_bytes: state_bytes.into(),
        })
    }

    pub fn descriptor(&self) -> Snapshot {
        self.descriptor.clone()
    }

    pub fn height(&self) -> u64 {
        self.descriptor.height.value()
    }

    pub fn app_hash(&self) -> [u8; 32] {
        let metadata = decode_metadata(&self.descriptor.metadata)
            .expect("export descriptor was validated when it was created");
        decode_hash(&metadata.app_hash, "app hash")
            .expect("export app hash was validated when it was created")
    }

    pub fn load_chunk(&self, height: u64, format: u32, index: u32) -> Option<Bytes> {
        if height != self.height()
            || format != STATE_SNAPSHOT_FORMAT
            || index >= self.descriptor.chunks
        {
            return None;
        }
        let start = usize::try_from(index)
            .ok()?
            .checked_mul(STATE_SNAPSHOT_CHUNK_BYTES)?;
        let end = start
            .checked_add(STATE_SNAPSHOT_CHUNK_BYTES)?
            .min(self.state_bytes.len());
        Some(self.state_bytes.slice(start..end))
    }
}

/// Bounded receiver state for one offered snapshot.
#[derive(Debug)]
pub struct StateSnapshotImport {
    metadata: SnapshotMetadata,
    metadata_bytes: Bytes,
    expected_snapshot_hash: [u8; 32],
    expected_app_hash: [u8; 32],
    chunks: Vec<Bytes>,
}

impl StateSnapshotImport {
    pub fn from_offer(snapshot: &Snapshot, light_client_app_hash: &[u8]) -> Result<Self> {
        if snapshot.format != STATE_SNAPSHOT_FORMAT {
            return Err(StateSyncError::UnsupportedFormat(snapshot.format));
        }
        if snapshot.hash.len() != 32 {
            return Err(StateSyncError::InvalidHash("snapshot hash"));
        }
        let expected_snapshot_hash = fixed_hash(&snapshot.hash, "snapshot hash")?;
        if expected_snapshot_hash == [0; 32] {
            return Err(StateSyncError::InvalidHash("snapshot hash"));
        }
        let expected_app_hash = fixed_hash(light_client_app_hash, "light client app hash")?;
        let metadata = decode_metadata(&snapshot.metadata)?;
        validate_metadata(&metadata, snapshot.chunks)?;
        if snapshot.height.value() != metadata.height {
            return Err(StateSyncError::HeightMismatch {
                descriptor: snapshot.height.value(),
                metadata: metadata.height,
            });
        }
        if decode_hash(&metadata.app_hash, "metadata app hash")? != expected_app_hash {
            return Err(StateSyncError::AppHashMismatch);
        }
        Ok(Self {
            metadata,
            metadata_bytes: snapshot.metadata.clone(),
            expected_snapshot_hash,
            expected_app_hash,
            chunks: Vec::with_capacity(
                usize::try_from(snapshot.chunks).map_err(|_| StateSyncError::TooManyChunks)?,
            ),
        })
    }

    pub fn expected_index(&self) -> u32 {
        u32::try_from(self.chunks.len()).expect("snapshot chunk count is bounded by u32")
    }

    pub fn chain_id(&self) -> &str {
        &self.metadata.chain_id
    }

    pub fn chunk_count(&self) -> u32 {
        u32::try_from(self.metadata.chunk_hashes.len())
            .expect("validated snapshot chunk count fits u32")
    }

    pub fn apply_chunk(&mut self, index: u32, chunk: Bytes) -> Result<bool> {
        let expected = self.expected_index();
        if index != expected {
            return Err(StateSyncError::UnexpectedChunk {
                expected,
                actual: index,
            });
        }
        if index >= self.chunk_count() {
            return Err(StateSyncError::UnexpectedChunk {
                expected,
                actual: index,
            });
        }

        let expected_len = expected_chunk_len(&self.metadata, index)?;
        if chunk.len() != expected_len {
            return Err(StateSyncError::InvalidChunkLength {
                index,
                expected: expected_len,
                actual: chunk.len(),
            });
        }
        let actual_hash = hex::encode(Sha256::digest(&chunk));
        let expected_hash = &self.metadata.chunk_hashes
            [usize::try_from(index).map_err(|_| StateSyncError::TooManyChunks)?];
        if &actual_hash != expected_hash {
            return Err(StateSyncError::InvalidChunkHash(index));
        }
        self.chunks.push(chunk);
        Ok(self.expected_index() == self.chunk_count())
    }

    pub fn finalize(&self) -> Result<EngineState> {
        if self.expected_index() != self.chunk_count() {
            return Err(StateSyncError::IncompleteSnapshot {
                expected: self.chunk_count(),
                actual: self.expected_index(),
            });
        }
        let state_len = usize::try_from(self.metadata.state_bytes)
            .map_err(|_| StateSyncError::SnapshotTooLarge)?;
        let mut bytes = Vec::with_capacity(state_len);
        for chunk in &self.chunks {
            bytes.extend_from_slice(chunk);
        }
        if bytes.len() != state_len {
            return Err(StateSyncError::InvalidStateLength {
                expected: state_len,
                actual: bytes.len(),
            });
        }
        if snapshot_hash(&self.metadata_bytes, &bytes) != self.expected_snapshot_hash {
            return Err(StateSyncError::SnapshotHashMismatch);
        }

        let state: EngineState = serde_json::from_slice(&bytes)
            .map_err(|error| StateSyncError::InvalidState(error.to_string()))?;
        if canonical_state_bytes(&state).map_err(state_error)? != bytes {
            return Err(StateSyncError::NonCanonicalState);
        }
        if state.chain_id != self.metadata.chain_id || state.height != self.metadata.height {
            return Err(StateSyncError::StateIdentityMismatch);
        }
        if compute_app_hash(&state).map_err(state_error)? != self.expected_app_hash {
            return Err(StateSyncError::AppHashMismatch);
        }
        let audit = audit_engine_state(&state);
        if !audit.healthy {
            return Err(StateSyncError::InvalidState(format!(
                "state accounting audit failed: {}",
                audit.errors.join("; ")
            )));
        }
        Ok(state)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StateSyncError {
    #[error("state snapshot is empty")]
    EmptySnapshot,
    #[error("state snapshot exceeds {MAX_STATE_SNAPSHOT_BYTES} bytes")]
    SnapshotTooLarge,
    #[error("state snapshot metadata exceeds {MAX_STATE_SNAPSHOT_METADATA_BYTES} bytes")]
    MetadataTooLarge,
    #[error("state snapshot contains too many chunks")]
    TooManyChunks,
    #[error("unsupported state snapshot format {0}")]
    UnsupportedFormat(u32),
    #[error("invalid state snapshot height {0}")]
    InvalidHeight(u64),
    #[error("invalid {0}")]
    InvalidHash(&'static str),
    #[error("state snapshot metadata is not canonical JSON")]
    NonCanonicalMetadata,
    #[error("state snapshot metadata is invalid: {0}")]
    InvalidMetadata(String),
    #[error("state snapshot height mismatch: descriptor {descriptor}, metadata {metadata}")]
    HeightMismatch { descriptor: u64, metadata: u64 },
    #[error("state snapshot application hash does not match")]
    AppHashMismatch,
    #[error("unexpected state snapshot chunk {actual}; expected {expected}")]
    UnexpectedChunk { expected: u32, actual: u32 },
    #[error("state snapshot chunk {index} is {actual} bytes; expected {expected}")]
    InvalidChunkLength {
        index: u32,
        expected: usize,
        actual: usize,
    },
    #[error("state snapshot chunk {0} hash does not match metadata")]
    InvalidChunkHash(u32),
    #[error("state snapshot is incomplete: expected {expected} chunks, got {actual}")]
    IncompleteSnapshot { expected: u32, actual: u32 },
    #[error("state snapshot body is {actual} bytes; expected {expected}")]
    InvalidStateLength { expected: usize, actual: usize },
    #[error("state snapshot hash does not match")]
    SnapshotHashMismatch,
    #[error("state snapshot body is not canonical JSON")]
    NonCanonicalState,
    #[error("state snapshot body does not match its chain or height metadata")]
    StateIdentityMismatch,
    #[error("state snapshot body is invalid: {0}")]
    InvalidState(String),
}

pub type Result<T, E = StateSyncError> = std::result::Result<T, E>;

fn validate_state_size(len: usize) -> Result<()> {
    if len == 0 {
        return Err(StateSyncError::EmptySnapshot);
    }
    if len > MAX_STATE_SNAPSHOT_BYTES {
        return Err(StateSyncError::SnapshotTooLarge);
    }
    Ok(())
}

fn validate_metadata(metadata: &SnapshotMetadata, descriptor_chunks: u32) -> Result<()> {
    if metadata.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(StateSyncError::InvalidMetadata(format!(
            "unsupported schema version {}",
            metadata.schema_version
        )));
    }
    if metadata.chain_id.is_empty()
        || metadata.chain_id.len() > MAX_CHAIN_ID_BYTES
        || metadata.chain_id.trim() != metadata.chain_id
    {
        return Err(StateSyncError::InvalidMetadata("invalid chain id".into()));
    }
    if metadata.height == 0 {
        return Err(StateSyncError::InvalidHeight(metadata.height));
    }
    decode_hash(&metadata.app_hash, "metadata app hash")?;
    let state_bytes =
        usize::try_from(metadata.state_bytes).map_err(|_| StateSyncError::SnapshotTooLarge)?;
    validate_state_size(state_bytes)?;
    if usize::try_from(metadata.chunk_bytes).ok() != Some(STATE_SNAPSHOT_CHUNK_BYTES) {
        return Err(StateSyncError::InvalidMetadata(
            "unexpected chunk size".into(),
        ));
    }
    let expected_chunks = state_bytes.div_ceil(STATE_SNAPSHOT_CHUNK_BYTES);
    if expected_chunks == 0
        || expected_chunks != metadata.chunk_hashes.len()
        || u32::try_from(expected_chunks).ok() != Some(descriptor_chunks)
    {
        return Err(StateSyncError::InvalidMetadata(
            "chunk count does not match snapshot size".into(),
        ));
    }
    for hash in &metadata.chunk_hashes {
        decode_hash(hash, "chunk hash")?;
    }
    Ok(())
}

fn canonical_metadata_bytes(metadata: &SnapshotMetadata) -> Result<Vec<u8>> {
    let bytes = serde_jcs::to_vec(metadata)
        .map_err(|error| StateSyncError::InvalidMetadata(error.to_string()))?;
    if bytes.len() > MAX_STATE_SNAPSHOT_METADATA_BYTES {
        return Err(StateSyncError::MetadataTooLarge);
    }
    Ok(bytes)
}

fn decode_metadata(bytes: &[u8]) -> Result<SnapshotMetadata> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_SNAPSHOT_METADATA_BYTES {
        return Err(StateSyncError::MetadataTooLarge);
    }
    let metadata: SnapshotMetadata = serde_json::from_slice(bytes)
        .map_err(|error| StateSyncError::InvalidMetadata(error.to_string()))?;
    if canonical_metadata_bytes(&metadata)? != bytes {
        return Err(StateSyncError::NonCanonicalMetadata);
    }
    Ok(metadata)
}

fn expected_chunk_len(metadata: &SnapshotMetadata, index: u32) -> Result<usize> {
    let index = usize::try_from(index).map_err(|_| StateSyncError::TooManyChunks)?;
    let start = index
        .checked_mul(STATE_SNAPSHOT_CHUNK_BYTES)
        .ok_or(StateSyncError::SnapshotTooLarge)?;
    let state_bytes =
        usize::try_from(metadata.state_bytes).map_err(|_| StateSyncError::SnapshotTooLarge)?;
    if start >= state_bytes {
        return Err(StateSyncError::TooManyChunks);
    }
    Ok((state_bytes - start).min(STATE_SNAPSHOT_CHUNK_BYTES))
}

fn snapshot_hash(metadata: &[u8], state: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_HASH_DOMAIN);
    hasher.update((metadata.len() as u64).to_be_bytes());
    hasher.update(metadata);
    hasher.update((state.len() as u64).to_be_bytes());
    hasher.update(state);
    hasher.finalize().into()
}

fn decode_hash(encoded: &str, label: &'static str) -> Result<[u8; 32]> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StateSyncError::InvalidHash(label));
    }
    let decoded = hex::decode(encoded).map_err(|_| StateSyncError::InvalidHash(label))?;
    fixed_hash(&decoded, label)
}

fn fixed_hash(bytes: &[u8], label: &'static str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| StateSyncError::InvalidHash(label))
}

fn state_error(error: impl std::fmt::Display) -> StateSyncError {
    StateSyncError::InvalidState(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::default_markets;

    fn state_fixture() -> (EngineState, [u8; 32]) {
        let mut state = EngineState::genesis("state-sync-test", default_markets());
        state.height = 7;
        let app_hash = compute_app_hash(&state).unwrap();
        (state, app_hash)
    }

    #[test]
    fn canonical_snapshot_round_trips_and_rebuilds_the_same_app_hash() {
        let (state, app_hash) = state_fixture();
        let export = StateSnapshotExport::create(&state, app_hash).unwrap();
        let descriptor = export.descriptor();
        let mut import = StateSnapshotImport::from_offer(&descriptor, app_hash.as_slice()).unwrap();
        for index in 0..descriptor.chunks {
            let chunk = export
                .load_chunk(state.height, STATE_SNAPSHOT_FORMAT, index)
                .unwrap();
            let complete = import.apply_chunk(index, chunk).unwrap();
            assert_eq!(complete, index + 1 == descriptor.chunks);
        }
        let restored = import.finalize().unwrap();
        assert_eq!(restored, state);
        assert_eq!(compute_app_hash(&restored).unwrap(), app_hash);
    }

    #[test]
    fn offer_rejects_wrong_light_client_hash_and_noncanonical_metadata() {
        let (state, app_hash) = state_fixture();
        let export = StateSnapshotExport::create(&state, app_hash).unwrap();
        let descriptor = export.descriptor();
        assert_eq!(
            StateSnapshotImport::from_offer(&descriptor, &[9; 32]).unwrap_err(),
            StateSyncError::AppHashMismatch
        );

        let mut noncanonical = descriptor;
        let mut metadata = noncanonical.metadata.to_vec();
        metadata.push(b' ');
        noncanonical.metadata = metadata.into();
        assert_eq!(
            StateSnapshotImport::from_offer(&noncanonical, &app_hash).unwrap_err(),
            StateSyncError::NonCanonicalMetadata
        );
    }

    #[test]
    fn receiver_rejects_wrong_order_size_and_hash() {
        let (state, app_hash) = state_fixture();
        let export = StateSnapshotExport::create(&state, app_hash).unwrap();
        let descriptor = export.descriptor();
        let chunk = export
            .load_chunk(state.height, STATE_SNAPSHOT_FORMAT, 0)
            .unwrap();

        let mut wrong_order = StateSnapshotImport::from_offer(&descriptor, &app_hash).unwrap();
        assert_eq!(
            wrong_order.apply_chunk(1, chunk.clone()).unwrap_err(),
            StateSyncError::UnexpectedChunk {
                expected: 0,
                actual: 1
            }
        );

        let mut wrong_size = StateSnapshotImport::from_offer(&descriptor, &app_hash).unwrap();
        assert!(matches!(
            wrong_size
                .apply_chunk(0, chunk.slice(..chunk.len() - 1))
                .unwrap_err(),
            StateSyncError::InvalidChunkLength { index: 0, .. }
        ));

        let mut tampered = chunk.to_vec();
        tampered[0] ^= 1;
        let mut wrong_hash = StateSnapshotImport::from_offer(&descriptor, &app_hash).unwrap();
        assert_eq!(
            wrong_hash.apply_chunk(0, tampered.into()).unwrap_err(),
            StateSyncError::InvalidChunkHash(0)
        );
    }

    #[test]
    fn export_rejects_an_app_hash_for_another_state() {
        let (state, _) = state_fixture();
        assert_eq!(
            StateSnapshotExport::create(&state, [7; 32]).unwrap_err(),
            StateSyncError::AppHashMismatch
        );
    }

    #[test]
    fn snapshots_reject_height_zero_state() {
        let state = EngineState::genesis("state-sync-height-zero", default_markets());
        let app_hash = compute_app_hash(&state).unwrap();
        assert_eq!(
            StateSnapshotExport::create(&state, app_hash).unwrap_err(),
            StateSyncError::InvalidHeight(0)
        );
    }
}
