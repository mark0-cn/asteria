//! Commitment/nullifier foundations for shielded isolated-margin notes.
//!
//! This module is deliberately **not** a zero-knowledge privacy system. The
//! [`TransparentWitnessVerifier`] used by the tests decodes every note opening,
//! so a validator using it can see the owner, collateral, position, leverage,
//! and nullifier key. A production integration must replace that verifier with
//! an audited ZK verifier whose public inputs are [`SpendStatement`]. The
//! authenticated viewing-key payload below defines a wallet crypto boundary,
//! but is not wired into wallet storage or the production ledger. The state
//! transition and Merkle/nullifier rules here are intended to be the public
//! foundation shared by those future implementations.

use std::{collections::BTreeSet, sync::OnceLock};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use imbl::{OrdMap, OrdSet, Vector};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const SHIELDED_MARGIN_VERSION: u16 = 3;
pub const MERKLE_DEPTH: usize = 32;
pub const MAX_SPEND_INPUTS: usize = 64;
pub const MAX_SPEND_OUTPUTS: usize = 64;
pub const MAX_PROOF_BYTES: usize = 1024 * 1024;
pub const DEFAULT_ROOT_HISTORY: usize = 64;
pub const BASIS_POINTS_DENOMINATOR: u128 = 10_000;

const MARKET_ID_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_MARKET_ID_V3\0";
const ASSET_ID_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_ASSET_ID_V3\0";
const NOTE_COMMITMENT_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_NOTE_COMMITMENT_V3\0";
const NULLIFIER_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_NULLIFIER_V3\0";
const POLICY_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_MARGIN_POLICY_V3\0";
const SPEND_AUTH_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_SPEND_AUTH_V3\0";
const MERKLE_LEAF_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_MERKLE_LEAF_V3\0";
const MERKLE_EMPTY_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_MERKLE_EMPTY_V3\0";
const MERKLE_NODE_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_MERKLE_NODE_V3\0";
const VIEW_TEST_NONCE_DOMAIN: &[u8] = b"ASTERIA_TEST_VIEW_NONCE_V1\0";
const VIEW_TEST_KDF_DOMAIN: &[u8] = b"ASTERIA_TEST_VIEW_KDF_V1\0";
const VIEW_AEAD_KDF_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_VIEW_KDF_V1\0";
const VIEW_AEAD_INFO_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_VIEW_XCHACHA20_V1\0";
const VIEW_AEAD_AAD_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_VIEW_AAD_V1\0";
const TEST_VIEWING_PAYLOAD_VERSION: u16 = 0;
pub const VIEWING_AAD_VERSION: u16 = 1;
pub const VIEWING_PAYLOAD_VERSION: u16 = 1;
pub const MAX_VIEWING_PLAINTEXT_BYTES: usize = 4 * 1024;
pub const VIEWING_NONCE_BYTES: usize = 24;
pub const VIEWING_AEAD_TAG_BYTES: usize = 16;
pub const VIEWING_AAD_CANONICAL_BYTES: usize = 2 + 1 + 4 + (5 * 32);
const VIEWING_PAYLOAD_HEADER_BYTES: usize = 2 + 4 + VIEWING_NONCE_BYTES + 4;
pub const MAX_VIEWING_CIPHERTEXT_BYTES: usize =
    MAX_VIEWING_PLAINTEXT_BYTES + VIEWING_AEAD_TAG_BYTES;

pub type Hash = [u8; 32];

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MarketId(pub Hash);

impl MarketId {
    pub fn from_label(label: &[u8]) -> Self {
        Self(hash_parts(MARKET_ID_DOMAIN, &[label]))
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct CollateralAssetId(pub Hash);

impl CollateralAssetId {
    pub fn from_label(label: &[u8]) -> Self {
        Self(hash_parts(ASSET_ID_DOMAIN, &[label]))
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct NoteCommitment(pub Hash);

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Nullifier(pub Hash);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShieldedMarginError {
    #[error("unsupported shielded-margin version {actual}; expected {expected}")]
    UnsupportedVersion { actual: u16, expected: u16 },
    #[error("shielded chain domain must not be zero")]
    ZeroChainDomain,
    #[error("shielded ledger id must not be zero")]
    ZeroLedgerId,
    #[error("market id must not be zero")]
    ZeroMarketId,
    #[error("collateral asset id must not be zero")]
    ZeroCollateralAssetId,
    #[error("note commitment must not be zero")]
    ZeroCommitment,
    #[error("nullifier must not be zero")]
    ZeroNullifier,
    #[error("invalid margin policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("spend must contain at least one input")]
    EmptyInputs,
    #[error("spend must contain at least one output")]
    EmptyOutputs,
    #[error("spend has {actual} inputs; maximum is {maximum}")]
    TooManyInputs { actual: usize, maximum: usize },
    #[error("spend has {actual} outputs; maximum is {maximum}")]
    TooManyOutputs { actual: usize, maximum: usize },
    #[error("input and nullifier counts differ")]
    InputNullifierCountMismatch,
    #[error("proof witness count does not match the public statement")]
    WitnessCountMismatch,
    #[error("public note {index} targets a different market or collateral asset")]
    PublicDomainMismatch { index: usize },
    #[error("margin policy hash does not match the supplied policy")]
    PolicyHashMismatch,
    #[error("duplicate input commitment in one spend")]
    DuplicateInputCommitment,
    #[error("duplicate output commitment")]
    DuplicateOutputCommitment,
    #[error("duplicate nullifier in one spend")]
    DuplicateNullifier,
    #[error("output commitment is already present in the note tree")]
    CommitmentAlreadyExists,
    #[error("nullifier has already been spent")]
    NullifierAlreadySpent,
    #[error("spend anchor is not in the accepted Merkle-root history")]
    UnknownMerkleRoot,
    #[error("Merkle leaf index {0} is out of range")]
    MerkleIndexOutOfRange(u64),
    #[error("Merkle proof must contain exactly {expected} siblings, received {actual}")]
    InvalidMerkleProofLength { expected: usize, actual: usize },
    #[error("Merkle inclusion proof is invalid")]
    InvalidMerkleProof,
    #[error("note opening does not match its public commitment")]
    CommitmentMismatch,
    #[error("note opening does not derive the declared nullifier")]
    NullifierMismatch,
    #[error("invalid owner public key: {0}")]
    InvalidOwnerKey(String),
    #[error("owner authorization signature must contain exactly 64 bytes")]
    InvalidSignatureLength,
    #[error("owner authorization signature is invalid")]
    InvalidOwnerSignature,
    #[error("note collateral must be positive")]
    ZeroCollateral,
    #[error("note leverage must be between 1 and {maximum}")]
    InvalidLeverage { maximum: u16 },
    #[error("fee {actual} is below policy minimum {minimum}")]
    FeeBelowMinimum { actual: u64, minimum: u64 },
    #[error("collateral is not conserved: inputs={inputs}, outputs={outputs}, fee={fee}")]
    ConservationViolation {
        inputs: u128,
        outputs: u128,
        fee: u64,
    },
    #[error("net position is not conserved: inputs={inputs}, outputs={outputs}")]
    PositionConservationViolation { inputs: i128, outputs: i128 },
    #[error("output {index} has collateral {actual}, below isolated-margin requirement {required}")]
    InsufficientIsolatedMargin {
        index: usize,
        actual: u64,
        required: u64,
    },
    #[error("checked arithmetic overflow while computing {0}")]
    ArithmeticOverflow(&'static str),
    #[error("computed amount does not fit the protocol amount type")]
    AmountOutOfRange,
    #[error("note tree is full")]
    MerkleTreeFull,
    #[error("root history limit must be positive")]
    InvalidRootHistoryLimit,
    #[error("invalid persisted shielded margin state: {0}")]
    InvalidPersistenceState(String),
    #[error("proof exceeds {MAX_PROOF_BYTES} bytes")]
    ProofTooLarge,
    #[error("canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error("proof is not encoded as canonical RFC 8785 JSON")]
    NonCanonicalProof,
    #[error("viewing-key ciphertext authentication failed")]
    ViewingCipherAuthentication,
    #[error("viewing key must not be all zero")]
    InvalidViewingKey,
    #[error("viewing-key randomness is unavailable")]
    ViewingKeyRandomness,
    #[error("viewing-key epoch overflow")]
    ViewingKeyEpochOverflow,
    #[error("viewing-key epoch {0} is unavailable")]
    ViewingKeyEpochUnavailable(u32),
    #[error("viewing-key payload epoch does not match its associated data")]
    ViewingKeyEpochMismatch,
    #[error("invalid viewing-key associated data: {0}")]
    InvalidViewingAssociatedData(&'static str),
    #[error("invalid viewing-key payload: {0}")]
    InvalidViewingPayload(&'static str),
    #[error("unsupported viewing-key associated-data version {actual}; expected {expected}")]
    UnsupportedViewingAadVersion { actual: u16, expected: u16 },
    #[error("unsupported viewing-key payload version {actual}; expected {expected}")]
    UnsupportedViewingPayloadVersion { actual: u16, expected: u16 },
    #[error("viewing-key plaintext is {actual} bytes; maximum is {maximum}")]
    ViewingPlaintextTooLarge { actual: usize, maximum: usize },
    #[error("viewing-key ciphertext is {actual} bytes; maximum is {maximum}")]
    ViewingCiphertextTooLarge { actual: usize, maximum: usize },
}

pub type Result<T, E = ShieldedMarginError> = std::result::Result<T, E>;

/// Public portion of a shielded isolated-margin note.
///
/// The commitment binds the public market and asset identifiers as well as all
/// fields in the corresponding [`NoteOpening`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicNote {
    pub version: u16,
    pub market_id: MarketId,
    pub collateral_asset: CollateralAssetId,
    pub commitment: NoteCommitment,
}

impl PublicNote {
    pub fn new(
        market_id: MarketId,
        collateral_asset: CollateralAssetId,
        opening: &NoteOpening,
    ) -> Self {
        Self {
            version: SHIELDED_MARGIN_VERSION,
            market_id,
            collateral_asset,
            commitment: opening.commitment(market_id, collateral_asset),
        }
    }

    fn validate_basic(&self) -> Result<()> {
        validate_version(self.version)?;
        validate_ids(self.market_id, self.collateral_asset)?;
        if self.commitment.0 == [0; 32] {
            return Err(ShieldedMarginError::ZeroCommitment);
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + 32 * 3);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.market_id.0);
        bytes.extend_from_slice(&self.collateral_asset.0);
        bytes.extend_from_slice(&self.commitment.0);
        bytes
    }
}

/// Private fields opened by the transparent test proof backend.
///
/// `owner` is an Ed25519 verifying key. `nullifier_key` and `blinding` must be
/// independently random in a real wallet. Revealing this structure destroys
/// note privacy; a future ZK circuit must keep it private.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteOpening {
    pub owner: Hash,
    pub nullifier_key: Hash,
    pub collateral: u64,
    pub position: i64,
    pub leverage: u16,
    pub blinding: Hash,
}

impl NoteOpening {
    pub fn commitment(
        &self,
        market_id: MarketId,
        collateral_asset: CollateralAssetId,
    ) -> NoteCommitment {
        NoteCommitment(hash_parts(
            NOTE_COMMITMENT_DOMAIN,
            &[
                &SHIELDED_MARGIN_VERSION.to_be_bytes(),
                &market_id.0,
                &collateral_asset.0,
                &self.owner,
                &self.nullifier_key,
                &self.collateral.to_be_bytes(),
                &self.position.to_be_bytes(),
                &self.leverage.to_be_bytes(),
                &self.blinding,
            ],
        ))
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_encode(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        canonical_decode(bytes)
    }
}

pub fn derive_nullifier(note: &PublicNote, opening: &NoteOpening, leaf_index: u64) -> Nullifier {
    Nullifier(hash_parts(
        NULLIFIER_DOMAIN,
        &[
            &note.market_id.0,
            &note.collateral_asset.0,
            &note.commitment.0,
            &leaf_index.to_be_bytes(),
            &opening.nullifier_key,
        ],
    ))
}

/// Consensus-provided public risk policy for one isolated market.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginPolicy {
    pub version: u16,
    pub market_id: MarketId,
    pub collateral_asset: CollateralAssetId,
    /// Mark price in collateral atomic units, scaled by `price_scale`.
    pub mark_price: u64,
    pub price_scale: u64,
    pub minimum_initial_margin_bps: u32,
    pub maximum_leverage: u16,
    /// Fixed public minimum fee charged by this foundational transition.
    pub minimum_fee: u64,
}

impl MarginPolicy {
    pub fn validate(&self) -> Result<()> {
        validate_version(self.version)?;
        validate_ids(self.market_id, self.collateral_asset)?;
        if self.mark_price == 0 {
            return Err(ShieldedMarginError::InvalidPolicy(
                "mark price must be positive",
            ));
        }
        if self.price_scale == 0 {
            return Err(ShieldedMarginError::InvalidPolicy(
                "price scale must be positive",
            ));
        }
        if u128::from(self.minimum_initial_margin_bps) > BASIS_POINTS_DENOMINATOR {
            return Err(ShieldedMarginError::InvalidPolicy(
                "initial margin cannot exceed 10000 basis points",
            ));
        }
        if self.maximum_leverage == 0 {
            return Err(ShieldedMarginError::InvalidPolicy(
                "maximum leverage must be positive",
            ));
        }
        Ok(())
    }

    pub fn policy_hash(&self) -> Result<Hash> {
        self.validate()?;
        Ok(hash_parts(
            POLICY_DOMAIN,
            &[
                &self.version.to_be_bytes(),
                &self.market_id.0,
                &self.collateral_asset.0,
                &self.mark_price.to_be_bytes(),
                &self.price_scale.to_be_bytes(),
                &self.minimum_initial_margin_bps.to_be_bytes(),
                &self.maximum_leverage.to_be_bytes(),
                &self.minimum_fee.to_be_bytes(),
            ],
        ))
    }

    pub fn required_margin(&self, opening: &NoteOpening) -> Result<u64> {
        self.validate()?;
        if opening.leverage == 0 || opening.leverage > self.maximum_leverage {
            return Err(ShieldedMarginError::InvalidLeverage {
                maximum: self.maximum_leverage,
            });
        }

        let quantity = u128::from(opening.position.unsigned_abs());
        let scaled_notional = quantity
            .checked_mul(u128::from(self.mark_price))
            .ok_or(ShieldedMarginError::ArithmeticOverflow("position notional"))?;
        let notional = checked_ceil_div(scaled_notional, u128::from(self.price_scale))?;
        let leverage_margin = checked_ceil_div(notional, u128::from(opening.leverage))?;
        let floor_numerator = notional
            .checked_mul(u128::from(self.minimum_initial_margin_bps))
            .ok_or(ShieldedMarginError::ArithmeticOverflow(
                "initial margin floor",
            ))?;
        let floor_margin = checked_ceil_div(floor_numerator, BASIS_POINTS_DENOMINATOR)?;
        u64::try_from(leverage_margin.max(floor_margin))
            .map_err(|_| ShieldedMarginError::AmountOutOfRange)
    }
}

/// Public inputs that a future ZK proof must bind and verify.
///
/// Input notes, leaf indices, and Merkle paths are deliberately absent. They
/// belong to the proof witness; exposing them here would link each consumed
/// commitment directly to its nullifier and outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendStatement {
    pub version: u16,
    pub chain_domain: Hash,
    pub ledger_id: Hash,
    pub anchor_root: Hash,
    pub market_id: MarketId,
    pub collateral_asset: CollateralAssetId,
    pub policy_hash: Hash,
    pub nullifiers: Vec<Nullifier>,
    pub output_commitments: Vec<NoteCommitment>,
    pub fee: u64,
}

impl SpendStatement {
    pub fn authorization_digest(&self) -> Result<Hash> {
        Ok(hash_parts(SPEND_AUTH_DOMAIN, &[&self.canonical_bytes()?]))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let nullifier_len = u32::try_from(self.nullifiers.len())
            .map_err(|_| ShieldedMarginError::ArithmeticOverflow("nullifier count"))?;
        let output_len = u32::try_from(self.output_commitments.len())
            .map_err(|_| ShieldedMarginError::ArithmeticOverflow("output count"))?;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.chain_domain);
        bytes.extend_from_slice(&self.ledger_id);
        bytes.extend_from_slice(&self.anchor_root);
        bytes.extend_from_slice(&self.market_id.0);
        bytes.extend_from_slice(&self.collateral_asset.0);
        bytes.extend_from_slice(&self.policy_hash);
        bytes.extend_from_slice(&self.fee.to_be_bytes());
        bytes.extend_from_slice(&nullifier_len.to_be_bytes());
        for nullifier in &self.nullifiers {
            bytes.extend_from_slice(&nullifier.0);
        }
        bytes.extend_from_slice(&output_len.to_be_bytes());
        for commitment in &self.output_commitments {
            bytes.extend_from_slice(&commitment.0);
        }
        Ok(bytes)
    }

    fn validate_public(&self, policy: &MarginPolicy) -> Result<()> {
        validate_version(self.version)?;
        if self.chain_domain == [0; 32] {
            return Err(ShieldedMarginError::ZeroChainDomain);
        }
        if self.ledger_id == [0; 32] {
            return Err(ShieldedMarginError::ZeroLedgerId);
        }
        validate_ids(self.market_id, self.collateral_asset)?;
        policy.validate()?;
        if policy.market_id != self.market_id || policy.collateral_asset != self.collateral_asset {
            return Err(ShieldedMarginError::InvalidPolicy(
                "policy targets a different public market domain",
            ));
        }
        if self.policy_hash != policy.policy_hash()? {
            return Err(ShieldedMarginError::PolicyHashMismatch);
        }
        if self.nullifiers.is_empty() {
            return Err(ShieldedMarginError::EmptyInputs);
        }
        if self.output_commitments.is_empty() {
            return Err(ShieldedMarginError::EmptyOutputs);
        }
        if self.nullifiers.len() > MAX_SPEND_INPUTS {
            return Err(ShieldedMarginError::TooManyInputs {
                actual: self.nullifiers.len(),
                maximum: MAX_SPEND_INPUTS,
            });
        }
        if self.output_commitments.len() > MAX_SPEND_OUTPUTS {
            return Err(ShieldedMarginError::TooManyOutputs {
                actual: self.output_commitments.len(),
                maximum: MAX_SPEND_OUTPUTS,
            });
        }
        if self.fee < policy.minimum_fee {
            return Err(ShieldedMarginError::FeeBelowMinimum {
                actual: self.fee,
                minimum: policy.minimum_fee,
            });
        }

        let mut output_commitments = BTreeSet::new();
        for commitment in &self.output_commitments {
            if commitment.0 == [0; 32] {
                return Err(ShieldedMarginError::ZeroCommitment);
            }
            if !output_commitments.insert(*commitment) {
                return Err(ShieldedMarginError::DuplicateOutputCommitment);
            }
        }

        let mut nullifiers = BTreeSet::new();
        for nullifier in &self.nullifiers {
            if nullifier.0 == [0; 32] {
                return Err(ShieldedMarginError::ZeroNullifier);
            }
            if !nullifiers.insert(*nullifier) {
                return Err(ShieldedMarginError::DuplicateNullifier);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub siblings: Vec<Hash>,
}

impl MerkleProof {
    pub fn verify(&self, note: &PublicNote, expected_root: Hash) -> Result<()> {
        if self.siblings.len() != MERKLE_DEPTH {
            return Err(ShieldedMarginError::InvalidMerkleProofLength {
                expected: MERKLE_DEPTH,
                actual: self.siblings.len(),
            });
        }
        if self.leaf_index >= merkle_capacity() {
            return Err(ShieldedMarginError::MerkleIndexOutOfRange(self.leaf_index));
        }

        let mut current = merkle_leaf_hash(note);
        let mut index = self.leaf_index;
        for sibling in &self.siblings {
            current = if index & 1 == 0 {
                merkle_node_hash(current, *sibling)
            } else {
                merkle_node_hash(*sibling, current)
            };
            index >>= 1;
        }
        if current != expected_root {
            return Err(ShieldedMarginError::InvalidMerkleProof);
        }
        Ok(())
    }
}

/// Append-only note tree with an incremental frontier and commitment index.
/// Leaves remain available so wallets or an indexer can construct proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MerkleNodePosition {
    height: u8,
    index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoteMerkleTree {
    leaves: Vector<PublicNote>,
    #[serde(skip)]
    commitment_indices: OrdMap<NoteCommitment, u64>,
    #[serde(skip)]
    nodes: OrdMap<MerkleNodePosition, Hash>,
    #[serde(skip)]
    cached_root: Hash,
}

impl Default for NoteMerkleTree {
    fn default() -> Self {
        Self {
            leaves: Vector::new(),
            commitment_indices: OrdMap::new(),
            nodes: OrdMap::new(),
            cached_root: merkle_zero_hashes()[MERKLE_DEPTH],
        }
    }
}

impl<'de> Deserialize<'de> for NoteMerkleTree {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoredNoteMerkleTree {
            leaves: Vec<PublicNote>,
        }

        let stored = StoredNoteMerkleTree::deserialize(deserializer)?;
        let mut tree = Self::default();
        for note in stored.leaves {
            tree.append(note).map_err(serde::de::Error::custom)?;
        }
        Ok(tree)
    }
}

impl NoteMerkleTree {
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn note(&self, index: u64) -> Option<&PublicNote> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.leaves.get(index))
    }

    pub fn contains(&self, commitment: NoteCommitment) -> bool {
        self.commitment_indices.contains_key(&commitment)
    }

    pub fn leaf_index(&self, commitment: NoteCommitment) -> Option<u64> {
        self.commitment_indices.get(&commitment).copied()
    }

    pub fn root(&self) -> Hash {
        self.cached_root
    }

    pub fn append(&mut self, note: PublicNote) -> Result<u64> {
        note.validate_basic()?;
        if self.contains(note.commitment) {
            return Err(ShieldedMarginError::CommitmentAlreadyExists);
        }
        if u64::try_from(self.leaves.len()).map_err(|_| ShieldedMarginError::MerkleTreeFull)?
            >= merkle_capacity()
        {
            return Err(ShieldedMarginError::MerkleTreeFull);
        }
        let index =
            u64::try_from(self.leaves.len()).map_err(|_| ShieldedMarginError::MerkleTreeFull)?;
        self.cache_append_path(merkle_leaf_hash(&note), index);
        self.commitment_indices.insert(note.commitment, index);
        self.leaves.push_back(note);
        Ok(index)
    }

    fn cache_append_path(&mut self, leaf_hash: Hash, leaf_index: u64) {
        let zero_hashes = merkle_zero_hashes();
        let mut current = leaf_hash;
        let mut index = leaf_index;
        self.nodes
            .insert(MerkleNodePosition { height: 0, index }, current);
        for (height, zero_hash) in zero_hashes.iter().take(MERKLE_DEPTH).enumerate() {
            current = if index & 1 == 0 {
                merkle_node_hash(current, *zero_hash)
            } else {
                let left = self
                    .nodes
                    .get(&MerkleNodePosition {
                        height: u8::try_from(height).expect("Merkle height fits u8"),
                        index: index - 1,
                    })
                    .copied()
                    .expect("left sibling subtree was cached by an earlier append");
                merkle_node_hash(left, current)
            };
            index >>= 1;
            self.nodes.insert(
                MerkleNodePosition {
                    height: u8::try_from(height + 1).expect("Merkle height fits u8"),
                    index,
                },
                current,
            );
        }
        self.cached_root = current;
    }

    pub fn proof(&self, leaf_index: u64) -> Result<MerkleProof> {
        let index = usize::try_from(leaf_index)
            .map_err(|_| ShieldedMarginError::MerkleIndexOutOfRange(leaf_index))?;
        if index >= self.leaves.len() {
            return Err(ShieldedMarginError::MerkleIndexOutOfRange(leaf_index));
        }

        let zero_hashes = merkle_zero_hashes();
        let mut cursor = leaf_index;
        let mut siblings = Vec::with_capacity(MERKLE_DEPTH);

        for (height, zero_hash) in zero_hashes.iter().take(MERKLE_DEPTH).enumerate() {
            let sibling = cursor ^ 1;
            siblings.push(
                self.nodes
                    .get(&MerkleNodePosition {
                        height: u8::try_from(height).expect("Merkle height fits u8"),
                        index: sibling,
                    })
                    .copied()
                    .unwrap_or(*zero_hash),
            );
            cursor >>= 1;
        }
        Ok(MerkleProof {
            leaf_index,
            siblings,
        })
    }

    fn root_at_leaf_count(&self, leaf_count: u64) -> Result<Hash> {
        let current_count =
            u64::try_from(self.leaves.len()).map_err(|_| ShieldedMarginError::MerkleTreeFull)?;
        if leaf_count > current_count {
            return Err(ShieldedMarginError::InvalidPersistenceState(format!(
                "prefix note count {leaf_count} exceeds current count {current_count}"
            )));
        }
        if leaf_count == current_count {
            return Ok(self.cached_root);
        }
        self.prefix_subtree_root(
            u8::try_from(MERKLE_DEPTH).expect("Merkle depth fits u8"),
            0,
            leaf_count,
            merkle_zero_hashes(),
        )
    }

    fn prefix_subtree_root(
        &self,
        height: u8,
        index: u64,
        leaf_count: u64,
        zero_hashes: &[Hash; MERKLE_DEPTH + 1],
    ) -> Result<Hash> {
        let span = 1_u64 << height;
        let start = index.checked_mul(span).ok_or_else(|| {
            ShieldedMarginError::InvalidPersistenceState("Merkle prefix range overflow".into())
        })?;
        let end = start.checked_add(span).ok_or_else(|| {
            ShieldedMarginError::InvalidPersistenceState("Merkle prefix range overflow".into())
        })?;
        if leaf_count <= start {
            return Ok(zero_hashes[usize::from(height)]);
        }
        if leaf_count >= end {
            return self
                .nodes
                .get(&MerkleNodePosition { height, index })
                .copied()
                .ok_or_else(|| {
                    ShieldedMarginError::InvalidPersistenceState(format!(
                        "missing cached Merkle node at height {height}, index {index}"
                    ))
                });
        }
        if height == 0 {
            return Err(ShieldedMarginError::InvalidPersistenceState(
                "partial Merkle leaf range is impossible".into(),
            ));
        }
        let child_height = height - 1;
        let left_index = index.checked_mul(2).ok_or_else(|| {
            ShieldedMarginError::InvalidPersistenceState("Merkle child index overflow".into())
        })?;
        let right_index = left_index.checked_add(1).ok_or_else(|| {
            ShieldedMarginError::InvalidPersistenceState("Merkle child index overflow".into())
        })?;
        let left = self.prefix_subtree_root(child_height, left_index, leaf_count, zero_hashes)?;
        let right = self.prefix_subtree_root(child_height, right_index, leaf_count, zero_hashes)?;
        Ok(merkle_node_hash(left, right))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInputWitness {
    pub note: PublicNote,
    pub opening: NoteOpening,
    pub merkle_proof: MerkleProof,
    pub authorization_signature: Vec<u8>,
}

/// Canonical transparent witness used only until an actual ZK proof system is
/// integrated. Serializing this value reveals every supposedly hidden field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentSpendProof {
    pub inputs: Vec<TransparentInputWitness>,
    pub output_openings: Vec<NoteOpening>,
}

impl TransparentSpendProof {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_encode(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        canonical_decode(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedSpend {
    pub statement: SpendStatement,
    pub proof: Vec<u8>,
}

/// Verification boundary for the future zero-knowledge implementation.
///
/// A production node must only use a trusted implementation that proves note
/// ownership, Merkle inclusion, nullifier derivation, balance conservation,
/// output margin, and fee constraints. Returning `Ok(())` without those checks
/// would permit inflation.
pub trait SpendProofVerifier {
    fn verify(&self, statement: &SpendStatement, policy: &MarginPolicy, proof: &[u8])
    -> Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TransparentWitnessVerifier;

impl SpendProofVerifier for TransparentWitnessVerifier {
    fn verify(
        &self,
        statement: &SpendStatement,
        policy: &MarginPolicy,
        proof_bytes: &[u8],
    ) -> Result<()> {
        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(ShieldedMarginError::ProofTooLarge);
        }
        statement.validate_public(policy)?;
        let proof = TransparentSpendProof::from_canonical_bytes(proof_bytes)?;
        if proof.inputs.len() != statement.nullifiers.len()
            || proof.output_openings.len() != statement.output_commitments.len()
        {
            return Err(ShieldedMarginError::WitnessCountMismatch);
        }

        let authorization_digest = statement.authorization_digest()?;
        let mut input_total = 0_u128;
        let mut input_position = 0_i128;
        let mut input_commitments = BTreeSet::new();
        for (index, witness) in proof.inputs.iter().enumerate() {
            let public_note = &witness.note;
            public_note.validate_basic()?;
            if public_note.market_id != statement.market_id
                || public_note.collateral_asset != statement.collateral_asset
            {
                return Err(ShieldedMarginError::PublicDomainMismatch { index });
            }
            if !input_commitments.insert(public_note.commitment) {
                return Err(ShieldedMarginError::DuplicateInputCommitment);
            }
            let expected_commitment = witness
                .opening
                .commitment(public_note.market_id, public_note.collateral_asset);
            if expected_commitment != public_note.commitment {
                return Err(ShieldedMarginError::CommitmentMismatch);
            }
            witness
                .merkle_proof
                .verify(public_note, statement.anchor_root)?;
            let expected_nullifier = derive_nullifier(
                public_note,
                &witness.opening,
                witness.merkle_proof.leaf_index,
            );
            if expected_nullifier != statement.nullifiers[index] {
                return Err(ShieldedMarginError::NullifierMismatch);
            }
            verify_owner_authorization(
                &witness.opening.owner,
                &authorization_digest,
                &witness.authorization_signature,
            )?;
            if witness.opening.collateral == 0 {
                return Err(ShieldedMarginError::ZeroCollateral);
            }
            input_total = input_total
                .checked_add(u128::from(witness.opening.collateral))
                .ok_or(ShieldedMarginError::ArithmeticOverflow(
                    "input collateral total",
                ))?;
            input_position = input_position
                .checked_add(i128::from(witness.opening.position))
                .ok_or(ShieldedMarginError::ArithmeticOverflow(
                    "input position total",
                ))?;
        }

        let mut output_total = 0_u128;
        let mut output_position = 0_i128;
        for (index, opening) in proof.output_openings.iter().enumerate() {
            let expected_commitment =
                opening.commitment(statement.market_id, statement.collateral_asset);
            if expected_commitment != statement.output_commitments[index] {
                return Err(ShieldedMarginError::CommitmentMismatch);
            }
            if opening.collateral == 0 {
                return Err(ShieldedMarginError::ZeroCollateral);
            }
            let required = policy.required_margin(opening)?;
            if opening.collateral < required {
                return Err(ShieldedMarginError::InsufficientIsolatedMargin {
                    index,
                    actual: opening.collateral,
                    required,
                });
            }
            output_total = output_total
                .checked_add(u128::from(opening.collateral))
                .ok_or(ShieldedMarginError::ArithmeticOverflow(
                    "output collateral total",
                ))?;
            output_position = output_position
                .checked_add(i128::from(opening.position))
                .ok_or(ShieldedMarginError::ArithmeticOverflow(
                    "output position total",
                ))?;
        }

        let outputs_and_fee = output_total
            .checked_add(u128::from(statement.fee))
            .ok_or(ShieldedMarginError::ArithmeticOverflow("outputs plus fee"))?;
        if input_total != outputs_and_fee {
            return Err(ShieldedMarginError::ConservationViolation {
                inputs: input_total,
                outputs: output_total,
                fee: statement.fee,
            });
        }
        if input_position != output_position {
            return Err(ShieldedMarginError::PositionConservationViolation {
                inputs: input_position,
                outputs: output_position,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendReceipt {
    pub previous_root: Hash,
    pub new_root: Hash,
    pub output_leaf_indices: Vec<u64>,
    pub nullifiers: Vec<Nullifier>,
    pub fee: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShieldedMarginPersistenceHeader {
    pub note_count: u64,
    pub nullifier_count: u64,
    pub current_root: Hash,
    pub accepted_roots: Vec<Hash>,
    pub root_history_limit: usize,
}

pub(crate) struct ShieldedMarginPersistenceParts<'a> {
    pub header: ShieldedMarginPersistenceHeader,
    pub notes: &'a Vector<PublicNote>,
    pub spent_nullifiers: &'a OrdSet<Nullifier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedMarginState {
    note_tree: NoteMerkleTree,
    spent_nullifiers: OrdSet<Nullifier>,
    accepted_roots: Vector<Hash>,
    root_history_limit: usize,
}

impl Default for ShieldedMarginState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldedMarginState {
    pub fn new() -> Self {
        let note_tree = NoteMerkleTree::default();
        let mut accepted_roots = Vector::new();
        accepted_roots.push_back(note_tree.root());
        Self {
            note_tree,
            spent_nullifiers: OrdSet::new(),
            accepted_roots,
            root_history_limit: DEFAULT_ROOT_HISTORY,
        }
    }

    pub fn with_root_history_limit(root_history_limit: usize) -> Result<Self> {
        if root_history_limit == 0 {
            return Err(ShieldedMarginError::InvalidRootHistoryLimit);
        }
        let mut state = Self::new();
        state.root_history_limit = root_history_limit;
        Ok(state)
    }

    pub(crate) fn persistence_parts(&self) -> ShieldedMarginPersistenceParts<'_> {
        ShieldedMarginPersistenceParts {
            header: ShieldedMarginPersistenceHeader {
                note_count: u64::try_from(self.note_tree.len())
                    .expect("Merkle capacity guarantees note count fits u64"),
                nullifier_count: u64::try_from(self.spent_nullifiers.len())
                    .expect("in-memory nullifier count fits u64"),
                current_root: self.note_tree.root(),
                accepted_roots: self.accepted_roots.iter().copied().collect(),
                root_history_limit: self.root_history_limit,
            },
            notes: &self.note_tree.leaves,
            spent_nullifiers: &self.spent_nullifiers,
        }
    }

    pub(crate) fn rebuild_from_persistence(
        header: ShieldedMarginPersistenceHeader,
        notes: impl IntoIterator<Item = (u64, PublicNote)>,
        spent_nullifiers: OrdSet<Nullifier>,
    ) -> Result<Self> {
        if header.root_history_limit == 0 {
            return Err(ShieldedMarginError::InvalidRootHistoryLimit);
        }
        let mut note_tree = NoteMerkleTree::default();
        let mut prefix_roots = Vec::new();
        prefix_roots.push(note_tree.root());
        for (leaf_index, note) in notes {
            let expected_index =
                u64::try_from(note_tree.len()).map_err(|_| ShieldedMarginError::MerkleTreeFull)?;
            if leaf_index != expected_index {
                return Err(ShieldedMarginError::InvalidPersistenceState(format!(
                    "note indices must be continuous: expected {expected_index}, received {leaf_index}"
                )));
            }
            note_tree.append(note)?;
            prefix_roots.push(note_tree.root());
        }
        let actual_note_count =
            u64::try_from(note_tree.len()).map_err(|_| ShieldedMarginError::MerkleTreeFull)?;
        if actual_note_count != header.note_count {
            return Err(ShieldedMarginError::InvalidPersistenceState(format!(
                "header declares {} notes but {actual_note_count} were loaded",
                header.note_count
            )));
        }
        if note_tree.root() != header.current_root {
            return Err(ShieldedMarginError::InvalidPersistenceState(
                "header root does not match the rebuilt note tree".into(),
            ));
        }
        let actual_nullifier_count = u64::try_from(spent_nullifiers.len()).map_err(|_| {
            ShieldedMarginError::InvalidPersistenceState(
                "nullifier count cannot be represented as u64".into(),
            )
        })?;
        if actual_nullifier_count != header.nullifier_count {
            return Err(ShieldedMarginError::InvalidPersistenceState(format!(
                "header declares {} nullifiers but {actual_nullifier_count} were loaded",
                header.nullifier_count
            )));
        }
        if actual_nullifier_count > actual_note_count
            || spent_nullifiers
                .iter()
                .any(|nullifier| nullifier.0 == [0; 32])
        {
            return Err(ShieldedMarginError::InvalidPersistenceState(
                "persisted nullifier set is inconsistent with the note set".into(),
            ));
        }
        if header.accepted_roots.is_empty()
            || header.accepted_roots.len() > header.root_history_limit
            || header.accepted_roots.last().copied() != Some(header.current_root)
        {
            return Err(ShieldedMarginError::InvalidPersistenceState(
                "accepted root history has invalid bounds or current root".into(),
            ));
        }
        let mut prefix_cursor = 0_usize;
        for accepted_root in &header.accepted_roots {
            let relative = prefix_roots[prefix_cursor..]
                .iter()
                .position(|root| root == accepted_root)
                .ok_or_else(|| {
                    ShieldedMarginError::InvalidPersistenceState(
                        "accepted root is not an ordered note-tree prefix".into(),
                    )
                })?;
            prefix_cursor = prefix_cursor.checked_add(relative + 1).ok_or_else(|| {
                ShieldedMarginError::InvalidPersistenceState(
                    "accepted root history index overflow".into(),
                )
            })?;
        }

        Ok(Self {
            note_tree,
            spent_nullifiers,
            accepted_roots: header.accepted_roots.into_iter().collect(),
            root_history_limit: header.root_history_limit,
        })
    }

    pub(crate) fn root_at_note_count(&self, note_count: u64) -> Result<Hash> {
        self.note_tree.root_at_leaf_count(note_count)
    }

    pub fn root(&self) -> Hash {
        self.note_tree.root()
    }

    pub fn note_count(&self) -> usize {
        self.note_tree.len()
    }

    pub fn note(&self, leaf_index: u64) -> Option<&PublicNote> {
        self.note_tree.note(leaf_index)
    }

    pub fn leaf_index(&self, commitment: NoteCommitment) -> Option<u64> {
        self.note_tree.leaf_index(commitment)
    }

    pub fn merkle_proof(&self, leaf_index: u64) -> Result<MerkleProof> {
        self.note_tree.proof(leaf_index)
    }

    pub fn is_spent(&self, nullifier: Nullifier) -> bool {
        self.spent_nullifiers.contains(&nullifier)
    }

    pub fn accepts_root(&self, root: Hash) -> bool {
        self.accepted_roots.contains(&root)
    }

    /// Appends a commitment created by an external deposit/mint authority.
    /// Calling this method alone does not prove that backing collateral exists;
    /// consensus integration must authorize and account for that deposit.
    pub fn append_deposit_commitment(&mut self, note: PublicNote) -> Result<u64> {
        note.validate_basic()?;
        if self.note_tree.contains(note.commitment) {
            return Err(ShieldedMarginError::CommitmentAlreadyExists);
        }
        let index = self.note_tree.append(note)?;
        self.remember_current_root();
        Ok(index)
    }

    pub fn apply_spend<V: SpendProofVerifier>(
        &mut self,
        spend: &ShieldedSpend,
        policy: &MarginPolicy,
        verifier: &V,
    ) -> Result<SpendReceipt> {
        spend.statement.validate_public(policy)?;

        // Check spent nullifiers before the anchor so replay is reported as a
        // double spend even if later appends have moved the current tree root.
        for nullifier in &spend.statement.nullifiers {
            if self.spent_nullifiers.contains(nullifier) {
                return Err(ShieldedMarginError::NullifierAlreadySpent);
            }
        }
        if !self.accepts_root(spend.statement.anchor_root) {
            return Err(ShieldedMarginError::UnknownMerkleRoot);
        }
        for commitment in &spend.statement.output_commitments {
            if self.note_tree.contains(*commitment) {
                return Err(ShieldedMarginError::CommitmentAlreadyExists);
            }
        }
        let final_count = self
            .note_tree
            .len()
            .checked_add(spend.statement.output_commitments.len())
            .ok_or(ShieldedMarginError::MerkleTreeFull)?;
        if u64::try_from(final_count).map_err(|_| ShieldedMarginError::MerkleTreeFull)?
            > merkle_capacity()
        {
            return Err(ShieldedMarginError::MerkleTreeFull);
        }

        // No state is mutated before the complete proof succeeds.
        verifier.verify(&spend.statement, policy, &spend.proof)?;

        let previous_root = self.root();
        let mut output_leaf_indices = Vec::with_capacity(spend.statement.output_commitments.len());
        for commitment in &spend.statement.output_commitments {
            output_leaf_indices.push(self.note_tree.append(PublicNote {
                version: spend.statement.version,
                market_id: spend.statement.market_id,
                collateral_asset: spend.statement.collateral_asset,
                commitment: *commitment,
            })?);
        }
        for nullifier in &spend.statement.nullifiers {
            self.spent_nullifiers.insert(*nullifier);
        }
        self.remember_current_root();
        Ok(SpendReceipt {
            previous_root,
            new_root: self.root(),
            output_leaf_indices,
            nullifiers: spend.statement.nullifiers.clone(),
            fee: spend.statement.fee,
        })
    }

    fn remember_current_root(&mut self) {
        let root = self.root();
        if self.accepted_roots.back().copied() != Some(root) {
            self.accepted_roots.push_back(root);
        }
        while self.accepted_roots.len() > self.root_history_limit {
            self.accepted_roots.pop_front();
        }
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ViewingKeyEpoch(pub u32);

impl ViewingKeyEpoch {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u32 {
        self.0
    }

    pub fn next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ShieldedMarginError::ViewingKeyEpochOverflow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewingKeyPurpose {
    NoteOpening,
}

impl ViewingKeyPurpose {
    const fn code(self) -> u8 {
        match self {
            Self::NoteOpening => 1,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::NoteOpening),
            _ => Err(ShieldedMarginError::InvalidViewingAssociatedData(
                "unknown purpose",
            )),
        }
    }
}

/// Authenticated context for one encrypted note opening.
///
/// The canonical byte layout is version, purpose, key epoch, chain domain,
/// ledger id, market id, collateral asset id, and note commitment. Keeping
/// these fixed-width fields in the AEAD context prevents a ciphertext from
/// being moved between chains, ledgers, markets, notes, or key epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewingKeyAad {
    pub version: u16,
    pub purpose: ViewingKeyPurpose,
    pub key_epoch: ViewingKeyEpoch,
    pub chain_domain: Hash,
    pub ledger_id: Hash,
    pub market_id: MarketId,
    pub collateral_asset: CollateralAssetId,
    pub note_commitment: NoteCommitment,
}

impl ViewingKeyAad {
    pub fn for_note_opening(
        chain_domain: Hash,
        ledger_id: Hash,
        key_epoch: ViewingKeyEpoch,
        note: PublicNote,
    ) -> Result<Self> {
        note.validate_basic()?;
        let aad = Self {
            version: VIEWING_AAD_VERSION,
            purpose: ViewingKeyPurpose::NoteOpening,
            key_epoch,
            chain_domain,
            ledger_id,
            market_id: note.market_id,
            collateral_asset: note.collateral_asset,
            note_commitment: note.commitment,
        };
        aad.validate()?;
        Ok(aad)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != VIEWING_AAD_VERSION {
            return Err(ShieldedMarginError::UnsupportedViewingAadVersion {
                actual: self.version,
                expected: VIEWING_AAD_VERSION,
            });
        }
        if self.chain_domain == [0; 32] {
            return Err(ShieldedMarginError::InvalidViewingAssociatedData(
                "chain domain must not be zero",
            ));
        }
        if self.ledger_id == [0; 32] {
            return Err(ShieldedMarginError::InvalidViewingAssociatedData(
                "ledger id must not be zero",
            ));
        }
        validate_ids(self.market_id, self.collateral_asset)?;
        if self.note_commitment.0 == [0; 32] {
            return Err(ShieldedMarginError::ZeroCommitment);
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(VIEWING_AAD_CANONICAL_BYTES);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.push(self.purpose.code());
        bytes.extend_from_slice(&self.key_epoch.0.to_be_bytes());
        bytes.extend_from_slice(&self.chain_domain);
        bytes.extend_from_slice(&self.ledger_id);
        bytes.extend_from_slice(&self.market_id.0);
        bytes.extend_from_slice(&self.collateral_asset.0);
        bytes.extend_from_slice(&self.note_commitment.0);
        debug_assert_eq!(bytes.len(), VIEWING_AAD_CANONICAL_BYTES);
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != VIEWING_AAD_CANONICAL_BYTES {
            return Err(ShieldedMarginError::InvalidViewingAssociatedData(
                "wrong canonical length",
            ));
        }
        let version = u16::from_be_bytes(
            bytes[0..2]
                .try_into()
                .expect("viewing AAD version has fixed length"),
        );
        let purpose = ViewingKeyPurpose::from_code(bytes[2])?;
        let key_epoch = ViewingKeyEpoch(u32::from_be_bytes(
            bytes[3..7]
                .try_into()
                .expect("viewing AAD epoch has fixed length"),
        ));
        let aad = Self {
            version,
            purpose,
            key_epoch,
            chain_domain: viewing_hash(&bytes[7..39]),
            ledger_id: viewing_hash(&bytes[39..71]),
            market_id: MarketId(viewing_hash(&bytes[71..103])),
            collateral_asset: CollateralAssetId(viewing_hash(&bytes[103..135])),
            note_commitment: NoteCommitment(viewing_hash(&bytes[135..167])),
        };
        aad.validate()?;
        Ok(aad)
    }
}

/// Versioned XChaCha20-Poly1305 payload. The authentication tag is the final
/// 16 bytes of `ciphertext`, as defined by the AEAD implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedViewingPayload {
    pub version: u16,
    pub key_epoch: ViewingKeyEpoch,
    pub nonce: [u8; VIEWING_NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

impl EncryptedViewingPayload {
    pub fn validate(&self) -> Result<()> {
        self.validate_for_version(VIEWING_PAYLOAD_VERSION)
    }

    fn validate_for_version(&self, expected_version: u16) -> Result<()> {
        if self.version != expected_version {
            return Err(ShieldedMarginError::UnsupportedViewingPayloadVersion {
                actual: self.version,
                expected: expected_version,
            });
        }
        if self.nonce == [0; VIEWING_NONCE_BYTES] {
            return Err(ShieldedMarginError::InvalidViewingPayload(
                "nonce must not be zero",
            ));
        }
        if self.ciphertext.len() < VIEWING_AEAD_TAG_BYTES {
            return Err(ShieldedMarginError::InvalidViewingPayload(
                "ciphertext is shorter than the authentication tag",
            ));
        }
        if self.ciphertext.len() > MAX_VIEWING_CIPHERTEXT_BYTES {
            return Err(ShieldedMarginError::ViewingCiphertextTooLarge {
                actual: self.ciphertext.len(),
                maximum: MAX_VIEWING_CIPHERTEXT_BYTES,
            });
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let ciphertext_len = u32::try_from(self.ciphertext.len()).map_err(|_| {
            ShieldedMarginError::ViewingCiphertextTooLarge {
                actual: self.ciphertext.len(),
                maximum: MAX_VIEWING_CIPHERTEXT_BYTES,
            }
        })?;
        let mut bytes = Vec::with_capacity(VIEWING_PAYLOAD_HEADER_BYTES + self.ciphertext.len());
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.key_epoch.0.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&ciphertext_len.to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < VIEWING_PAYLOAD_HEADER_BYTES {
            return Err(ShieldedMarginError::InvalidViewingPayload(
                "canonical payload is truncated",
            ));
        }
        let version = u16::from_be_bytes(
            bytes[0..2]
                .try_into()
                .expect("viewing payload version has fixed length"),
        );
        let key_epoch = ViewingKeyEpoch(u32::from_be_bytes(
            bytes[2..6]
                .try_into()
                .expect("viewing payload epoch has fixed length"),
        ));
        let mut nonce = [0_u8; VIEWING_NONCE_BYTES];
        nonce.copy_from_slice(&bytes[6..6 + VIEWING_NONCE_BYTES]);
        let length_offset = 6 + VIEWING_NONCE_BYTES;
        let ciphertext_len = usize::try_from(u32::from_be_bytes(
            bytes[length_offset..length_offset + 4]
                .try_into()
                .expect("viewing payload length has fixed length"),
        ))
        .expect("u32 ciphertext length fits usize");
        if ciphertext_len > MAX_VIEWING_CIPHERTEXT_BYTES {
            return Err(ShieldedMarginError::ViewingCiphertextTooLarge {
                actual: ciphertext_len,
                maximum: MAX_VIEWING_CIPHERTEXT_BYTES,
            });
        }
        let expected_len = VIEWING_PAYLOAD_HEADER_BYTES
            .checked_add(ciphertext_len)
            .ok_or(ShieldedMarginError::InvalidViewingPayload(
                "canonical payload length overflow",
            ))?;
        if bytes.len() != expected_len {
            return Err(ShieldedMarginError::InvalidViewingPayload(
                "canonical payload length does not match its header",
            ));
        }
        let payload = Self {
            version,
            key_epoch,
            nonce,
            ciphertext: bytes[VIEWING_PAYLOAD_HEADER_BYTES..].to_vec(),
        };
        payload.validate()?;
        Ok(payload)
    }
}

pub type AuthenticatedViewingPayload = EncryptedViewingPayload;

/// Wallet/key-custody boundary for rotation and historical recovery. Returned
/// key bytes are zeroized on drop; implementations decide how epochs are
/// stored, backed up, recovered, and access-controlled.
pub trait ViewingKeyResolver {
    fn current_epoch(&self) -> Result<ViewingKeyEpoch>;
    fn key_for_epoch(&self, epoch: ViewingKeyEpoch) -> Result<Zeroizing<Hash>>;
}

/// Interface for encrypting note openings to a wallet viewing key.
pub trait ViewingKeyEncryption {
    fn seal(
        &self,
        viewing_key: &Hash,
        aad: &ViewingKeyAad,
        plaintext: &[u8],
    ) -> Result<EncryptedViewingPayload>;

    fn open(
        &self,
        viewing_key: &Hash,
        aad: &ViewingKeyAad,
        payload: &EncryptedViewingPayload,
    ) -> Result<Zeroizing<Vec<u8>>>;
}

/// Deterministic XChaCha adapter for reproducible tests only. Its nonce is
/// derived from secret and plaintext data, so repeated messages repeat nonces.
/// It must never protect wallet data.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeterministicTestViewingCipher;

impl ViewingKeyEncryption for DeterministicTestViewingCipher {
    fn seal(
        &self,
        viewing_key: &Hash,
        aad: &ViewingKeyAad,
        plaintext: &[u8],
    ) -> Result<EncryptedViewingPayload> {
        validate_viewing_plaintext_size(plaintext)?;
        let aad_bytes = aad.to_canonical_bytes()?;
        let digest = hash_parts(
            VIEW_TEST_NONCE_DOMAIN,
            &[viewing_key, &aad_bytes, plaintext],
        );
        let mut nonce = [0_u8; VIEWING_NONCE_BYTES];
        nonce.copy_from_slice(&digest[..VIEWING_NONCE_BYTES]);
        if nonce == [0; VIEWING_NONCE_BYTES] {
            nonce[VIEWING_NONCE_BYTES - 1] = 1;
        }
        seal_viewing_payload(
            TEST_VIEWING_PAYLOAD_VERSION,
            VIEW_TEST_KDF_DOMAIN,
            viewing_key,
            aad,
            nonce,
            plaintext,
        )
    }

    fn open(
        &self,
        viewing_key: &Hash,
        aad: &ViewingKeyAad,
        payload: &EncryptedViewingPayload,
    ) -> Result<Zeroizing<Vec<u8>>> {
        open_viewing_payload(
            TEST_VIEWING_PAYLOAD_VERSION,
            VIEW_TEST_KDF_DOMAIN,
            viewing_key,
            aad,
            payload,
        )
    }
}

/// XChaCha20-Poly1305 primitive for wallet viewing-key payloads. This does not
/// provide wallet storage, custody, recovery, or ledger integration.
#[derive(Debug, Clone, Copy, Default)]
pub struct XChaChaViewingKeyCipher;

impl XChaChaViewingKeyCipher {
    /// Encrypt one payload using an already-resolved epoch key.
    pub fn seal(
        &self,
        viewing_key: &Hash,
        aad: &ViewingKeyAad,
        plaintext: &[u8],
    ) -> Result<EncryptedViewingPayload> {
        <Self as ViewingKeyEncryption>::seal(self, viewing_key, aad, plaintext)
    }

    /// Decrypt one payload using an already-resolved epoch key.
    pub fn open(
        &self,
        viewing_key: &Hash,
        aad: &ViewingKeyAad,
        payload: &EncryptedViewingPayload,
    ) -> Result<Zeroizing<Vec<u8>>> {
        <Self as ViewingKeyEncryption>::open(self, viewing_key, aad, payload)
    }

    pub fn seal_with_resolver<R: ViewingKeyResolver>(
        &self,
        resolver: &R,
        aad: &ViewingKeyAad,
        plaintext: &[u8],
    ) -> Result<EncryptedViewingPayload> {
        if resolver.current_epoch()? != aad.key_epoch {
            return Err(ShieldedMarginError::ViewingKeyEpochMismatch);
        }
        let key = resolver.key_for_epoch(aad.key_epoch)?;
        ViewingKeyEncryption::seal(self, &key, aad, plaintext)
    }

    pub fn open_with_resolver<R: ViewingKeyResolver>(
        &self,
        resolver: &R,
        aad: &ViewingKeyAad,
        payload: &EncryptedViewingPayload,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if payload.key_epoch != aad.key_epoch {
            return Err(ShieldedMarginError::ViewingKeyEpochMismatch);
        }
        let key = resolver.key_for_epoch(payload.key_epoch)?;
        ViewingKeyEncryption::open(self, &key, aad, payload)
    }
}

impl ViewingKeyEncryption for XChaChaViewingKeyCipher {
    fn seal(
        &self,
        viewing_key: &Hash,
        aad: &ViewingKeyAad,
        plaintext: &[u8],
    ) -> Result<EncryptedViewingPayload> {
        validate_viewing_plaintext_size(plaintext)?;
        let mut nonce = [0_u8; VIEWING_NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| ShieldedMarginError::ViewingKeyRandomness)?;
        if nonce == [0; VIEWING_NONCE_BYTES] {
            return Err(ShieldedMarginError::ViewingKeyRandomness);
        }
        seal_viewing_payload(
            VIEWING_PAYLOAD_VERSION,
            VIEW_AEAD_KDF_DOMAIN,
            viewing_key,
            aad,
            nonce,
            plaintext,
        )
    }

    fn open(
        &self,
        viewing_key: &Hash,
        aad: &ViewingKeyAad,
        payload: &EncryptedViewingPayload,
    ) -> Result<Zeroizing<Vec<u8>>> {
        open_viewing_payload(
            VIEWING_PAYLOAD_VERSION,
            VIEW_AEAD_KDF_DOMAIN,
            viewing_key,
            aad,
            payload,
        )
    }
}

fn seal_viewing_payload(
    version: u16,
    kdf_domain: &[u8],
    viewing_key: &Hash,
    aad: &ViewingKeyAad,
    nonce: [u8; VIEWING_NONCE_BYTES],
    plaintext: &[u8],
) -> Result<EncryptedViewingPayload> {
    aad.validate()?;
    validate_viewing_plaintext_size(plaintext)?;
    let key = viewing_aead_key(version, kdf_domain, viewing_key, aad)?;
    let associated_data = viewing_aead_associated_data(version, aad)?;
    let ciphertext = {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
        cipher.encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &associated_data,
            },
        )
    }
    .map_err(|_| ShieldedMarginError::ViewingCipherAuthentication)?;
    let payload = EncryptedViewingPayload {
        version,
        key_epoch: aad.key_epoch,
        nonce,
        ciphertext,
    };
    payload.validate_for_version(version)?;
    Ok(payload)
}

fn open_viewing_payload(
    version: u16,
    kdf_domain: &[u8],
    viewing_key: &Hash,
    aad: &ViewingKeyAad,
    payload: &EncryptedViewingPayload,
) -> Result<Zeroizing<Vec<u8>>> {
    aad.validate()?;
    payload.validate_for_version(version)?;
    if payload.key_epoch != aad.key_epoch {
        return Err(ShieldedMarginError::ViewingKeyEpochMismatch);
    }
    let key = viewing_aead_key(version, kdf_domain, viewing_key, aad)?;
    let associated_data = viewing_aead_associated_data(version, aad)?;
    let plaintext = {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
        cipher.decrypt(
            XNonce::from_slice(&payload.nonce),
            Payload {
                msg: &payload.ciphertext,
                aad: &associated_data,
            },
        )
    }
    .map_err(|_| ShieldedMarginError::ViewingCipherAuthentication)?;
    if plaintext.len() > MAX_VIEWING_PLAINTEXT_BYTES {
        return Err(ShieldedMarginError::ViewingPlaintextTooLarge {
            actual: plaintext.len(),
            maximum: MAX_VIEWING_PLAINTEXT_BYTES,
        });
    }
    Ok(Zeroizing::new(plaintext))
}

fn viewing_aead_key(
    version: u16,
    kdf_domain: &[u8],
    viewing_key: &Hash,
    aad: &ViewingKeyAad,
) -> Result<Zeroizing<Hash>> {
    if bool::from(viewing_key.ct_eq(&[0; 32])) {
        return Err(ShieldedMarginError::InvalidViewingKey);
    }
    let aad_bytes = aad.to_canonical_bytes()?;
    let mut info = Vec::with_capacity(VIEW_AEAD_INFO_DOMAIN.len() + 2 + 4 + aad_bytes.len());
    info.extend_from_slice(VIEW_AEAD_INFO_DOMAIN);
    info.extend_from_slice(&version.to_be_bytes());
    info.extend_from_slice(
        &u32::try_from(aad_bytes.len())
            .expect("fixed viewing AAD length fits u32")
            .to_be_bytes(),
    );
    info.extend_from_slice(&aad_bytes);
    let hkdf = Hkdf::<Sha256>::new(Some(kdf_domain), viewing_key);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, &mut key[..])
        .map_err(|_| ShieldedMarginError::ViewingCipherAuthentication)?;
    Ok(key)
}

fn viewing_aead_associated_data(version: u16, aad: &ViewingKeyAad) -> Result<Vec<u8>> {
    let aad_bytes = aad.to_canonical_bytes()?;
    let mut bytes = Vec::with_capacity(VIEW_AEAD_AAD_DOMAIN.len() + 2 + 4 + aad_bytes.len());
    bytes.extend_from_slice(VIEW_AEAD_AAD_DOMAIN);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(aad_bytes.len())
            .expect("fixed viewing AAD length fits u32")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&aad_bytes);
    Ok(bytes)
}

fn validate_viewing_plaintext_size(plaintext: &[u8]) -> Result<()> {
    if plaintext.len() > MAX_VIEWING_PLAINTEXT_BYTES {
        return Err(ShieldedMarginError::ViewingPlaintextTooLarge {
            actual: plaintext.len(),
            maximum: MAX_VIEWING_PLAINTEXT_BYTES,
        });
    }
    Ok(())
}

fn viewing_hash(bytes: &[u8]) -> Hash {
    bytes
        .try_into()
        .expect("viewing-key canonical hash field has fixed length")
}

fn validate_version(version: u16) -> Result<()> {
    if version != SHIELDED_MARGIN_VERSION {
        return Err(ShieldedMarginError::UnsupportedVersion {
            actual: version,
            expected: SHIELDED_MARGIN_VERSION,
        });
    }
    Ok(())
}

fn validate_ids(market_id: MarketId, collateral_asset: CollateralAssetId) -> Result<()> {
    if market_id.0 == [0; 32] {
        return Err(ShieldedMarginError::ZeroMarketId);
    }
    if collateral_asset.0 == [0; 32] {
        return Err(ShieldedMarginError::ZeroCollateralAssetId);
    }
    Ok(())
}

fn verify_owner_authorization(owner: &Hash, message: &Hash, signature: &[u8]) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(owner)
        .map_err(|error| ShieldedMarginError::InvalidOwnerKey(error.to_string()))?;
    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| ShieldedMarginError::InvalidSignatureLength)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| ShieldedMarginError::InvalidOwnerSignature)
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value)
        .map_err(|error| ShieldedMarginError::CanonicalEncoding(error.to_string()))
}

fn canonical_decode<T>(bytes: &[u8]) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice(bytes)
        .map_err(|error| ShieldedMarginError::CanonicalEncoding(error.to_string()))?;
    if canonical_encode(&value)? != bytes {
        return Err(ShieldedMarginError::NonCanonicalProof);
    }
    Ok(value)
}

fn checked_ceil_div(numerator: u128, denominator: u128) -> Result<u128> {
    if denominator == 0 {
        return Err(ShieldedMarginError::ArithmeticOverflow("division by zero"));
    }
    let quotient = numerator / denominator;
    if numerator.is_multiple_of(denominator) {
        Ok(quotient)
    } else {
        quotient
            .checked_add(1)
            .ok_or(ShieldedMarginError::ArithmeticOverflow("ceiling division"))
    }
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).expect("byte slice length fits u64");
        hasher.update(length.to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn merkle_capacity() -> u64 {
    1_u64 << MERKLE_DEPTH
}

fn merkle_leaf_hash(note: &PublicNote) -> Hash {
    hash_parts(MERKLE_LEAF_DOMAIN, &[&note.to_canonical_bytes()])
}

fn merkle_node_hash(left: Hash, right: Hash) -> Hash {
    hash_parts(MERKLE_NODE_DOMAIN, &[&left, &right])
}

fn merkle_zero_hashes() -> &'static [Hash; MERKLE_DEPTH + 1] {
    static ZERO_HASHES: OnceLock<[Hash; MERKLE_DEPTH + 1]> = OnceLock::new();
    ZERO_HASHES.get_or_init(|| {
        let mut zero_hashes = [[0; 32]; MERKLE_DEPTH + 1];
        zero_hashes[0] = hash_parts(MERKLE_EMPTY_DOMAIN, &[]);
        for height in 0..MERKLE_DEPTH {
            let child = zero_hashes[height];
            zero_hashes[height + 1] = merkle_node_hash(child, child);
        }
        zero_hashes
    })
}

#[cfg(test)]
fn next_merkle_level(level: &[Hash], empty: Hash) -> Vec<Hash> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    for pair in level.chunks(2) {
        let left = pair[0];
        let right = pair.get(1).copied().unwrap_or(empty);
        next.push(merkle_node_hash(left, right));
    }
    next
}

#[cfg(test)]
fn merkle_root<'a>(leaves: impl Iterator<Item = &'a PublicNote>) -> Hash {
    let zero_hashes = merkle_zero_hashes();
    let mut level: Vec<Hash> = leaves.map(merkle_leaf_hash).collect();
    if level.is_empty() {
        return zero_hashes[MERKLE_DEPTH];
    }
    for empty in zero_hashes.iter().take(MERKLE_DEPTH) {
        level = next_merkle_level(&level, *empty);
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::{Signer as _, SigningKey};
    use zeroize::Zeroize;

    use super::*;

    fn market_id() -> MarketId {
        MarketId::from_label(b"BTC-PERP")
    }

    fn asset_id() -> CollateralAssetId {
        CollateralAssetId::from_label(b"USDC")
    }

    fn policy() -> MarginPolicy {
        MarginPolicy {
            version: SHIELDED_MARGIN_VERSION,
            market_id: market_id(),
            collateral_asset: asset_id(),
            mark_price: 100,
            price_scale: 1,
            minimum_initial_margin_bps: 1_000,
            maximum_leverage: 20,
            minimum_fee: 10,
        }
    }

    fn opening(
        signing_key: &SigningKey,
        seed: u8,
        collateral: u64,
        position: i64,
        leverage: u16,
    ) -> NoteOpening {
        NoteOpening {
            owner: signing_key.verifying_key().to_bytes(),
            nullifier_key: [seed; 32],
            collateral,
            position,
            leverage,
            blinding: [seed.wrapping_add(1); 32],
        }
    }

    fn indexed_note(signing_key: &SigningKey, index: u64) -> PublicNote {
        let unique = index.checked_add(1).unwrap();
        let mut nullifier_key = [0_u8; 32];
        nullifier_key[..8].copy_from_slice(&unique.to_be_bytes());
        let mut blinding = [0_u8; 32];
        blinding[..8].copy_from_slice(&unique.rotate_left(17).to_be_bytes());
        blinding[31] = 1;
        PublicNote::new(
            market_id(),
            asset_id(),
            &NoteOpening {
                owner: signing_key.verifying_key().to_bytes(),
                nullifier_key,
                collateral: unique,
                position: 0,
                leverage: 1,
                blinding,
            },
        )
    }

    fn initialized_state(
        signing_key: &SigningKey,
        input_opening: &NoteOpening,
    ) -> (ShieldedMarginState, u64, PublicNote) {
        let mut state = ShieldedMarginState::new();
        let note = PublicNote::new(market_id(), asset_id(), input_opening);
        let index = state.append_deposit_commitment(note).unwrap();
        assert_eq!(input_opening.owner, signing_key.verifying_key().to_bytes());
        (state, index, note)
    }

    fn build_spend(
        state: &ShieldedMarginState,
        policy: &MarginPolicy,
        signing_key: &SigningKey,
        input_opening: NoteOpening,
        input_index: u64,
        output_openings: Vec<NoteOpening>,
        fee: u64,
    ) -> ShieldedSpend {
        let input_note = *state.note(input_index).unwrap();
        let merkle_proof = state.merkle_proof(input_index).unwrap();
        let nullifier = derive_nullifier(&input_note, &input_opening, input_index);
        let output_commitments = output_openings
            .iter()
            .map(|opening| {
                PublicNote::new(policy.market_id, policy.collateral_asset, opening).commitment
            })
            .collect();
        let statement = SpendStatement {
            version: SHIELDED_MARGIN_VERSION,
            chain_domain: [7; 32],
            ledger_id: [8; 32],
            anchor_root: state.root(),
            market_id: policy.market_id,
            collateral_asset: policy.collateral_asset,
            policy_hash: policy.policy_hash().unwrap(),
            nullifiers: vec![nullifier],
            output_commitments,
            fee,
        };
        let signature = signing_key
            .sign(&statement.authorization_digest().unwrap())
            .to_bytes()
            .to_vec();
        let proof = TransparentSpendProof {
            inputs: vec![TransparentInputWitness {
                note: input_note,
                opening: input_opening,
                merkle_proof,
                authorization_signature: signature,
            }],
            output_openings,
        }
        .to_canonical_bytes()
        .unwrap();
        ShieldedSpend { statement, proof }
    }

    #[test]
    fn merkle_append_and_proofs_cover_every_leaf() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut tree = NoteMerkleTree::default();
        for seed in 1..=5 {
            let note = PublicNote::new(
                market_id(),
                asset_id(),
                &opening(&signing_key, seed, u64::from(seed) * 100, 0, 1),
            );
            tree.append(note).unwrap();
        }

        let root = tree.root();
        for index in 0..tree.len() {
            let index = u64::try_from(index).unwrap();
            let proof = tree.proof(index).unwrap();
            proof.verify(tree.note(index).unwrap(), root).unwrap();
        }

        let mut tampered = tree.proof(2).unwrap();
        tampered.siblings[0][0] ^= 1;
        assert_eq!(
            tampered.verify(tree.note(2).unwrap(), root),
            Err(ShieldedMarginError::InvalidMerkleProof)
        );
    }

    #[test]
    fn incremental_root_matches_reference_after_many_appends() {
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        let mut tree = NoteMerkleTree::default();
        assert_eq!(tree.root(), merkle_root(std::iter::empty()));

        for index in 0..4_096 {
            tree.append(indexed_note(&signing_key, index)).unwrap();
            let count = index + 1;
            if count.is_power_of_two() || count.is_multiple_of(257) {
                assert_eq!(tree.root(), merkle_root(tree.leaves.iter()));
            }
        }
        assert_eq!(tree.root(), merkle_root(tree.leaves.iter()));
    }

    #[test]
    fn large_tree_clone_isolated_and_cached_proofs_stay_depth_bounded() {
        let signing_key = SigningKey::from_bytes(&[33; 32]);
        let mut tree = NoteMerkleTree::default();
        for index in 0..8_192 {
            tree.append(indexed_note(&signing_key, index)).unwrap();
        }
        assert!(tree.nodes.len() <= tree.len() * 2 + MERKLE_DEPTH);

        let original_root = tree.root();
        let original_nodes = tree.nodes.len();
        let mut cloned = tree.clone();
        cloned
            .append(indexed_note(
                &signing_key,
                u64::try_from(tree.len()).unwrap(),
            ))
            .unwrap();
        assert_eq!(tree.len(), 8_192);
        assert_eq!(tree.root(), original_root);
        assert_eq!(tree.nodes.len(), original_nodes);
        assert_ne!(cloned.root(), original_root);

        for index in [0, 1, 4_095, 8_191] {
            let proof = tree.proof(index).unwrap();
            assert_eq!(proof.siblings.len(), MERKLE_DEPTH);
            proof
                .verify(tree.note(index).unwrap(), original_root)
                .unwrap();
        }
    }

    #[test]
    fn duplicate_commitment_does_not_mutate_incremental_tree() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let mut tree = NoteMerkleTree::default();
        let note = indexed_note(&signing_key, 0);
        tree.append(note).unwrap();
        let before = tree.clone();

        assert_eq!(
            tree.append(note),
            Err(ShieldedMarginError::CommitmentAlreadyExists)
        );
        assert_eq!(tree, before);
    }

    #[test]
    fn note_tree_serde_rebuilds_caches_and_rejects_tampering() {
        let signing_key = SigningKey::from_bytes(&[10; 32]);
        let mut tree = NoteMerkleTree::default();
        for index in 0..32 {
            tree.append(indexed_note(&signing_key, index)).unwrap();
        }

        let encoded = serde_json::to_vec(&tree).unwrap();
        let decoded: NoteMerkleTree = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, tree);
        assert_eq!(decoded.root(), merkle_root(decoded.leaves.iter()));

        let mut forged_cache: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        forged_cache
            .as_object_mut()
            .unwrap()
            .insert("cached_root".into(), serde_json::json!([0, 1, 2]));
        assert!(serde_json::from_value::<NoteMerkleTree>(forged_cache).is_err());

        let mut duplicate_leaf: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let leaves = duplicate_leaf
            .get_mut("leaves")
            .and_then(serde_json::Value::as_array_mut)
            .unwrap();
        let duplicate = leaves[0].clone();
        leaves.push(duplicate);
        assert!(serde_json::from_value::<NoteMerkleTree>(duplicate_leaf).is_err());
    }

    #[test]
    fn valid_spend_conserves_collateral_charges_fee_and_appends_output() {
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let input = opening(&signing_key, 1, 1_000, 50, 10);
        let output = opening(&signing_key, 2, 990, 50, 10);
        let (mut state, input_index, _) = initialized_state(&signing_key, &input);
        let spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            input,
            input_index,
            vec![output],
            10,
        );

        let receipt = state
            .apply_spend(&spend, &policy(), &TransparentWitnessVerifier)
            .unwrap();

        assert_eq!(receipt.fee, 10);
        assert_eq!(receipt.output_leaf_indices, vec![1]);
        assert_ne!(receipt.previous_root, receipt.new_root);
        assert!(state.is_spent(spend.statement.nullifiers[0]));
        assert_eq!(state.note_count(), 2);
    }

    #[test]
    fn public_statement_does_not_link_consumed_note_or_merkle_path() {
        let signing_key = SigningKey::from_bytes(&[12; 32]);
        let input = opening(&signing_key, 31, 1_000, 20, 5);
        let output = opening(&signing_key, 32, 990, 20, 5);
        let (state, input_index, input_note) = initialized_state(&signing_key, &input);
        let spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            input,
            input_index,
            vec![output],
            10,
        );

        let public_json = serde_json::to_value(&spend.statement).unwrap();
        assert!(public_json.get("inputs").is_none());
        assert!(public_json.get("outputs").is_none());
        assert_eq!(
            public_json["output_commitments"].as_array().unwrap().len(),
            1
        );
        assert!(
            !public_json
                .to_string()
                .contains(&hex::encode(input_note.commitment.0))
        );

        let proof = TransparentSpendProof::from_canonical_bytes(&spend.proof).unwrap();
        assert_eq!(proof.inputs[0].note, input_note);
        assert_eq!(proof.inputs[0].merkle_proof.leaf_index, input_index);

        let mut legacy_statement = public_json;
        legacy_statement
            .as_object_mut()
            .unwrap()
            .insert("inputs".into(), serde_json::json!([input_note]));
        assert!(serde_json::from_value::<SpendStatement>(legacy_statement).is_err());
    }

    #[test]
    fn a_nullifier_cannot_be_spent_twice() {
        let signing_key = SigningKey::from_bytes(&[13; 32]);
        let input = opening(&signing_key, 3, 1_000, 20, 5);
        let output = opening(&signing_key, 4, 990, 20, 5);
        let (mut state, input_index, _) = initialized_state(&signing_key, &input);
        let spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            input,
            input_index,
            vec![output],
            10,
        );
        state
            .apply_spend(&spend, &policy(), &TransparentWitnessVerifier)
            .unwrap();

        assert_eq!(
            state.apply_spend(&spend, &policy(), &TransparentWitnessVerifier),
            Err(ShieldedMarginError::NullifierAlreadySpent)
        );
    }

    #[test]
    fn tampered_merkle_witness_is_rejected_without_mutating_state() {
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let input = opening(&signing_key, 5, 1_000, 20, 5);
        let output = opening(&signing_key, 6, 990, 20, 5);
        let (mut state, input_index, _) = initialized_state(&signing_key, &input);
        let mut spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            input,
            input_index,
            vec![output],
            10,
        );
        let mut proof = TransparentSpendProof::from_canonical_bytes(&spend.proof).unwrap();
        proof.inputs[0].merkle_proof.siblings[0][0] ^= 1;
        spend.proof = proof.to_canonical_bytes().unwrap();
        let root_before = state.root();

        assert_eq!(
            state.apply_spend(&spend, &policy(), &TransparentWitnessVerifier),
            Err(ShieldedMarginError::InvalidMerkleProof)
        );
        assert_eq!(state.root(), root_before);
        assert!(!state.is_spent(spend.statement.nullifiers[0]));
    }

    #[test]
    fn tampered_owner_signature_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[18; 32]);
        let input = opening(&signing_key, 15, 1_000, 20, 5);
        let output = opening(&signing_key, 16, 990, 20, 5);
        let (mut state, input_index, _) = initialized_state(&signing_key, &input);
        let mut spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            input,
            input_index,
            vec![output],
            10,
        );
        let mut proof = TransparentSpendProof::from_canonical_bytes(&spend.proof).unwrap();
        proof.inputs[0].authorization_signature[0] ^= 1;
        spend.proof = proof.to_canonical_bytes().unwrap();

        assert_eq!(
            state.apply_spend(&spend, &policy(), &TransparentWitnessVerifier),
            Err(ShieldedMarginError::InvalidOwnerSignature)
        );
    }

    #[test]
    fn recent_anchor_history_allows_independent_spends_from_one_root() {
        let signing_key = SigningKey::from_bytes(&[20; 32]);
        let first_input = opening(&signing_key, 17, 1_000, 20, 5);
        let second_input = opening(&signing_key, 19, 1_000, -20, 5);
        let mut state = ShieldedMarginState::new();
        let first_index = state
            .append_deposit_commitment(PublicNote::new(market_id(), asset_id(), &first_input))
            .unwrap();
        let second_index = state
            .append_deposit_commitment(PublicNote::new(market_id(), asset_id(), &second_input))
            .unwrap();
        let shared_anchor = state.root();
        let first_spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            first_input,
            first_index,
            vec![opening(&signing_key, 21, 990, 20, 5)],
            10,
        );
        let second_spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            second_input,
            second_index,
            vec![opening(&signing_key, 23, 990, -20, 5)],
            10,
        );

        state
            .apply_spend(&first_spend, &policy(), &TransparentWitnessVerifier)
            .unwrap();
        assert!(state.accepts_root(shared_anchor));
        state
            .apply_spend(&second_spend, &policy(), &TransparentWitnessVerifier)
            .unwrap();

        assert!(state.is_spent(first_spend.statement.nullifiers[0]));
        assert!(state.is_spent(second_spend.statement.nullifiers[0]));
    }

    #[test]
    fn insufficient_isolated_margin_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[19; 32]);
        let input = opening(&signing_key, 7, 1_000, 1_000, 20);
        // Notional is 100_000 and the 10% policy floor requires 10_000.
        let output = opening(&signing_key, 8, 990, 1_000, 20);
        let (mut state, input_index, _) = initialized_state(&signing_key, &input);
        let spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            input,
            input_index,
            vec![output],
            10,
        );

        assert_eq!(
            state.apply_spend(&spend, &policy(), &TransparentWitnessVerifier),
            Err(ShieldedMarginError::InsufficientIsolatedMargin {
                index: 0,
                actual: 990,
                required: 10_000,
            })
        );
    }

    #[test]
    fn collateral_conservation_is_enforced() {
        let signing_key = SigningKey::from_bytes(&[23; 32]);
        let input = opening(&signing_key, 9, 1_000, 20, 5);
        let output = opening(&signing_key, 10, 989, 20, 5);
        let (mut state, input_index, _) = initialized_state(&signing_key, &input);
        let spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            input,
            input_index,
            vec![output],
            10,
        );

        assert_eq!(
            state.apply_spend(&spend, &policy(), &TransparentWitnessVerifier),
            Err(ShieldedMarginError::ConservationViolation {
                inputs: 1_000,
                outputs: 989,
                fee: 10,
            })
        );
    }

    #[test]
    fn public_minimum_fee_is_enforced() {
        let signing_key = SigningKey::from_bytes(&[29; 32]);
        let input = opening(&signing_key, 11, 1_000, 20, 5);
        let output = opening(&signing_key, 12, 991, 20, 5);
        let (mut state, input_index, _) = initialized_state(&signing_key, &input);
        let spend = build_spend(
            &state,
            &policy(),
            &signing_key,
            input,
            input_index,
            vec![output],
            9,
        );

        assert_eq!(
            state.apply_spend(&spend, &policy(), &TransparentWitnessVerifier),
            Err(ShieldedMarginError::FeeBelowMinimum {
                actual: 9,
                minimum: 10,
            })
        );
    }

    #[test]
    fn proof_encoding_is_canonical() {
        let proof = TransparentSpendProof {
            inputs: Vec::new(),
            output_openings: Vec::new(),
        };
        let canonical = proof.to_canonical_bytes().unwrap();
        assert_eq!(
            TransparentSpendProof::from_canonical_bytes(&canonical).unwrap(),
            proof
        );
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(&canonical);
        assert_eq!(
            TransparentSpendProof::from_canonical_bytes(&noncanonical),
            Err(ShieldedMarginError::NonCanonicalProof)
        );
    }

    fn viewing_aad(opening: &NoteOpening, epoch: u32) -> ViewingKeyAad {
        let note = PublicNote::new(market_id(), asset_id(), opening);
        ViewingKeyAad::for_note_opening([7; 32], [8; 32], ViewingKeyEpoch::new(epoch), note)
            .unwrap()
    }

    #[test]
    fn viewing_aad_and_payload_have_strict_canonical_binary_encodings() {
        let signing_key = SigningKey::from_bytes(&[30; 32]);
        let opening = opening(&signing_key, 13, 1_000, -20, 5);
        let aad = viewing_aad(&opening, 4);
        let aad_bytes = aad.to_canonical_bytes().unwrap();
        assert_eq!(aad_bytes.len(), VIEWING_AAD_CANONICAL_BYTES);
        assert_eq!(
            ViewingKeyAad::from_canonical_bytes(&aad_bytes).unwrap(),
            aad
        );
        let mut wrong_aad_version = aad_bytes.clone();
        wrong_aad_version[1] = 2;
        assert_eq!(
            ViewingKeyAad::from_canonical_bytes(&wrong_aad_version),
            Err(ShieldedMarginError::UnsupportedViewingAadVersion {
                actual: 2,
                expected: VIEWING_AAD_VERSION,
            })
        );
        let mut zero_chain = aad_bytes.clone();
        zero_chain[7..39].fill(0);
        assert_eq!(
            ViewingKeyAad::from_canonical_bytes(&zero_chain),
            Err(ShieldedMarginError::InvalidViewingAssociatedData(
                "chain domain must not be zero"
            ))
        );
        assert_eq!(
            ViewingKeyAad::from_canonical_bytes(&aad_bytes[..aad_bytes.len() - 1]),
            Err(ShieldedMarginError::InvalidViewingAssociatedData(
                "wrong canonical length"
            ))
        );

        let plaintext = opening.to_canonical_bytes().unwrap();
        let payload = XChaChaViewingKeyCipher
            .seal(&[41; 32], &aad, &plaintext)
            .unwrap();
        let payload_bytes = payload.to_canonical_bytes().unwrap();
        assert_eq!(
            EncryptedViewingPayload::from_canonical_bytes(&payload_bytes).unwrap(),
            payload
        );
        let mut trailing = payload_bytes.clone();
        trailing.push(0);
        assert_eq!(
            EncryptedViewingPayload::from_canonical_bytes(&trailing),
            Err(ShieldedMarginError::InvalidViewingPayload(
                "canonical payload length does not match its header"
            ))
        );
        let mut wrong_version = payload_bytes;
        wrong_version[1] = 2;
        assert_eq!(
            EncryptedViewingPayload::from_canonical_bytes(&wrong_version),
            Err(ShieldedMarginError::UnsupportedViewingPayloadVersion {
                actual: 2,
                expected: VIEWING_PAYLOAD_VERSION,
            })
        );
    }

    #[test]
    fn deterministic_test_cipher_is_authenticated_but_not_production_format() {
        let signing_key = SigningKey::from_bytes(&[31; 32]);
        let opening = opening(&signing_key, 13, 1_000, -20, 5);
        let plaintext = opening.to_canonical_bytes().unwrap();
        let aad = viewing_aad(&opening, 0);
        let viewing_key = [41; 32];
        let cipher = DeterministicTestViewingCipher;
        let first = cipher.seal(&viewing_key, &aad, &plaintext).unwrap();
        let second = cipher.seal(&viewing_key, &aad, &plaintext).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.version, TEST_VIEWING_PAYLOAD_VERSION);
        assert_eq!(
            NoteOpening::from_canonical_bytes(&cipher.open(&viewing_key, &aad, &first).unwrap())
                .unwrap(),
            opening
        );

        let mut tampered = first;
        tampered.ciphertext[0] ^= 1;
        assert_eq!(
            cipher.open(&viewing_key, &aad, &tampered),
            Err(ShieldedMarginError::ViewingCipherAuthentication)
        );
    }

    #[test]
    fn xchacha_viewing_cipher_is_randomized_and_binds_wallet_context() {
        let signing_key = SigningKey::from_bytes(&[32; 32]);
        let opening = opening(&signing_key, 14, 2_000, 25, 4);
        let plaintext = opening.to_canonical_bytes().unwrap();
        let aad = viewing_aad(&opening, 1);
        let viewing_key = [42; 32];
        let cipher = XChaChaViewingKeyCipher;
        let first = cipher.seal(&viewing_key, &aad, &plaintext).unwrap();
        let second = cipher.seal(&viewing_key, &aad, &plaintext).unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(
            &*cipher.open(&viewing_key, &aad, &first).unwrap(),
            plaintext.as_slice()
        );

        let mut wrong_context = aad;
        wrong_context.ledger_id[0] ^= 1;
        assert_eq!(
            cipher.open(&viewing_key, &wrong_context, &first),
            Err(ShieldedMarginError::ViewingCipherAuthentication)
        );
        let mut tampered_epoch = first.clone();
        tampered_epoch.key_epoch = ViewingKeyEpoch::new(2);
        assert_eq!(
            cipher.open(&viewing_key, &aad, &tampered_epoch),
            Err(ShieldedMarginError::ViewingKeyEpochMismatch)
        );
        let mut tampered_nonce = first.clone();
        tampered_nonce.nonce[0] ^= 1;
        assert_eq!(
            cipher.open(&viewing_key, &aad, &tampered_nonce),
            Err(ShieldedMarginError::ViewingCipherAuthentication)
        );
        let mut tampered_ciphertext = first;
        tampered_ciphertext.ciphertext[0] ^= 1;
        assert_eq!(
            cipher.open(&viewing_key, &aad, &tampered_ciphertext),
            Err(ShieldedMarginError::ViewingCipherAuthentication)
        );
        assert_eq!(
            cipher.open(&[0; 32], &aad, &tampered_ciphertext),
            Err(ShieldedMarginError::InvalidViewingKey)
        );
    }

    #[test]
    fn viewing_cipher_enforces_bounds_and_zeroizes_decrypted_material() {
        let signing_key = SigningKey::from_bytes(&[34; 32]);
        let opening = opening(&signing_key, 15, 2_000, 25, 4);
        let aad = viewing_aad(&opening, 1);
        let cipher = XChaChaViewingKeyCipher;
        let maximum = vec![7_u8; MAX_VIEWING_PLAINTEXT_BYTES];
        let payload = cipher.seal(&[43; 32], &aad, &maximum).unwrap();
        let mut opened = cipher.open(&[43; 32], &aad, &payload).unwrap();
        assert_eq!(&*opened, maximum.as_slice());
        opened.zeroize();
        assert!(opened.iter().all(|byte| *byte == 0));
        assert_eq!(
            cipher.seal(
                &[43; 32],
                &aad,
                &vec![0_u8; MAX_VIEWING_PLAINTEXT_BYTES + 1]
            ),
            Err(ShieldedMarginError::ViewingPlaintextTooLarge {
                actual: MAX_VIEWING_PLAINTEXT_BYTES + 1,
                maximum: MAX_VIEWING_PLAINTEXT_BYTES,
            })
        );

        let mut oversized = payload;
        oversized.ciphertext.push(0);
        assert_eq!(
            cipher.open(&[43; 32], &aad, &oversized),
            Err(ShieldedMarginError::ViewingCiphertextTooLarge {
                actual: MAX_VIEWING_CIPHERTEXT_BYTES + 1,
                maximum: MAX_VIEWING_CIPHERTEXT_BYTES,
            })
        );

        let mut derived = viewing_aead_key(
            VIEWING_PAYLOAD_VERSION,
            VIEW_AEAD_KDF_DOMAIN,
            &[43; 32],
            &aad,
        )
        .unwrap();
        let next_aad = ViewingKeyAad {
            key_epoch: ViewingKeyEpoch::new(2),
            ..aad
        };
        let next_derived = viewing_aead_key(
            VIEWING_PAYLOAD_VERSION,
            VIEW_AEAD_KDF_DOMAIN,
            &[43; 32],
            &next_aad,
        )
        .unwrap();
        assert_ne!(*derived, *next_derived);
        derived.zeroize();
        assert_eq!(*derived, [0; 32]);
    }

    struct TestViewingKeyResolver {
        current: ViewingKeyEpoch,
        keys: BTreeMap<ViewingKeyEpoch, Hash>,
    }

    impl ViewingKeyResolver for TestViewingKeyResolver {
        fn current_epoch(&self) -> Result<ViewingKeyEpoch> {
            Ok(self.current)
        }

        fn key_for_epoch(&self, epoch: ViewingKeyEpoch) -> Result<Zeroizing<Hash>> {
            self.keys
                .get(&epoch)
                .copied()
                .map(Zeroizing::new)
                .ok_or(ShieldedMarginError::ViewingKeyEpochUnavailable(epoch.0))
        }
    }

    #[test]
    fn viewing_key_resolver_supports_rotation_and_historical_recovery() {
        let signing_key = SigningKey::from_bytes(&[35; 32]);
        let opening = opening(&signing_key, 16, 2_000, 25, 4);
        let epoch_one = ViewingKeyEpoch::new(1);
        let epoch_two = epoch_one.next().unwrap();
        let aad_one = viewing_aad(&opening, epoch_one.0);
        let aad_two = viewing_aad(&opening, epoch_two.0);
        let mut resolver = TestViewingKeyResolver {
            current: epoch_one,
            keys: BTreeMap::from([(epoch_one, [51; 32]), (epoch_two, [52; 32])]),
        };
        let cipher = XChaChaViewingKeyCipher;
        let payload_one = cipher
            .seal_with_resolver(&resolver, &aad_one, b"old epoch")
            .unwrap();
        resolver.current = epoch_two;
        assert_eq!(
            cipher
                .open_with_resolver(&resolver, &aad_one, &payload_one)
                .unwrap()
                .as_slice(),
            b"old epoch"
        );
        assert_eq!(
            cipher
                .seal_with_resolver(&resolver, &aad_one, b"stale")
                .unwrap_err(),
            ShieldedMarginError::ViewingKeyEpochMismatch
        );
        let payload_two = cipher
            .seal_with_resolver(&resolver, &aad_two, b"new epoch")
            .unwrap();
        assert_eq!(
            cipher
                .open_with_resolver(&resolver, &aad_two, &payload_two)
                .unwrap()
                .as_slice(),
            b"new epoch"
        );
        resolver.keys.remove(&epoch_one);
        assert_eq!(
            cipher
                .open_with_resolver(&resolver, &aad_one, &payload_one)
                .unwrap_err(),
            ShieldedMarginError::ViewingKeyEpochUnavailable(epoch_one.0)
        );
        assert_eq!(epoch_two.next().unwrap().value(), 3);
        assert_eq!(
            ViewingKeyEpoch::new(u32::MAX).next(),
            Err(ShieldedMarginError::ViewingKeyEpochOverflow)
        );
    }

    #[test]
    fn margin_math_fails_closed_on_out_of_range_result() {
        let extreme_policy = MarginPolicy {
            mark_price: u64::MAX,
            price_scale: 1,
            minimum_initial_margin_bps: 10_000,
            maximum_leverage: 1,
            minimum_fee: 0,
            ..policy()
        };
        let signing_key = SigningKey::from_bytes(&[37; 32]);
        let extreme = opening(&signing_key, 14, u64::MAX, i64::MIN, 1);

        assert!(matches!(
            extreme_policy.required_margin(&extreme),
            Err(ShieldedMarginError::ArithmeticOverflow(_))
                | Err(ShieldedMarginError::AmountOutOfRange)
        ));
    }
}
