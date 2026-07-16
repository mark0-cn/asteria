//! Research-only protocol framing for encrypted private orders.
//!
//! The cryptographic envelope lives in `private_order`. This module adds the
//! protocol objects that may cross an application/consensus boundary without
//! integrating them into either boundary:
//!
//! - a fee-payer-signed v3 submission with explicit replay and expiry fields;
//! - a canonical, encrypted order payload;
//! - validator vote extensions carrying verifiable decryption shares; and
//! - an unsigned system bundle that is accepted only after every included
//!   threshold share and decrypted payload has been verified.
//!
//! Consensus remains responsible for authenticating the validator that supplied
//! a vote extension, reserving and consuming payer nonces, choosing the pending
//! ciphertext set, and enforcing that shares are released only after ordering is
//! final. In particular, self-contained signature verification cannot determine
//! whether a correctly signed nonce has already been consumed.

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned, de::Error as _,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::private_order::{
    ENCRYPTED_PRIVATE_ORDER_BYTES, MAX_PRIVATE_ORDER_PAYLOAD_BYTES, PRIVATE_ORDER_FORMAT_VERSION,
    PRIVATE_ORDER_THRESHOLD, PRIVATE_ORDER_VALIDATOR_COUNT, PrivateOrderContext,
    PrivateOrderEnvelope, PrivateOrderError, ThresholdPublicKeySet, ValidatorSecretShare,
    VerifiableBeaconShare, VerifiableDecryptionShare, aggregate_beacon_shares, create_beacon_share,
    create_decryption_share, decrypt_private_order, verify_beacon_share, verify_decryption_share,
};

pub const PRIVATE_PROTOCOL_VERSION: u16 = 3;
pub const MAX_PRIVATE_PROTOCOL_CHAIN_ID_BYTES: usize = 128;
pub const MAX_PRIVATE_CLIENT_ID_BYTES: usize = 64;
pub const MAX_PRIVATE_ORDER_VALIDITY_WINDOW: u64 = 64;
pub const MAX_PRIVATE_ORDER_SUBMISSION_BYTES: usize = 4 * 1024;
pub const MAX_PENDING_PRIVATE_ORDERS: usize = 128;
pub const MAX_VOTE_EXTENSION_SHARES: usize = MAX_PENDING_PRIVATE_ORDERS;
pub const MAX_VOTE_EXTENSION_BYTES: usize = 128 * 1024;
pub const MAX_DECRYPTION_BUNDLE_ENTRIES: usize = MAX_PENDING_PRIVATE_ORDERS;
pub const MAX_DECRYPTION_BUNDLE_BYTES: usize = 256 * 1024;
/// A batch committed at H is shared at H+1 and executed at H+2. Validators
/// never release a share for a proposal that has not already committed.
pub const PRIVATE_ORDER_DECRYPTION_DELAY_BLOCKS: u64 = 2;

const SUBMISSION_SIGNING_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_SUBMISSION_V3\0";
const SUBMISSION_ID_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_SUBMISSION_ID_V3\0";
const ANTI_SPAM_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_ANTI_SPAM_V3\0";
const PRIVATE_BATCH_EXECUTION_ID_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_BATCH_EXECUTION_ID_V1\0";

#[derive(Debug, thiserror::Error)]
pub enum PrivateProtocolError {
    #[error("private-order canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error("{object} is not encoded as canonical RFC 8785 JSON")]
    NonCanonicalEncoding { object: &'static str },
    #[error("{object} is {actual} bytes; maximum is {maximum}")]
    EncodedSizeLimit {
        object: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("invalid private-order payload: {0}")]
    InvalidPayload(String),
    #[error("invalid private-order submission: {0}")]
    InvalidSubmission(String),
    #[error("private-order submission is for chain {actual}, expected {expected}")]
    WrongChain { expected: String, actual: String },
    #[error("private-order nonce mismatch: expected {expected}, received {actual}")]
    WrongNonce { expected: u64, actual: u64 },
    #[error("private-order target height mismatch: expected {expected}, received {actual}")]
    WrongHeight { expected: u64, actual: u64 },
    #[error(
        "private-order submission expired at height {valid_until}; current height is {current}"
    )]
    Expired { valid_until: u64, current: u64 },
    #[error("private-order anti-spam commitment does not bind the chain, payer, and nonce")]
    InvalidAntiSpamCommitment,
    #[error("private-order fee-payer public key is invalid: {0}")]
    InvalidFeePayer(String),
    #[error("private-order fee-payer signature is invalid")]
    InvalidSignature,
    #[error("invalid private-order vote extension: {0}")]
    InvalidVoteExtension(String),
    #[error("invalid private-order decryption bundle: {0}")]
    InvalidDecryptionBundle(String),
    #[error("pending private-order set contains duplicate submission id {0}")]
    DuplicateSubmissionId(String),
    #[error("pending private-order set reuses payer nonce {nonce}")]
    ReplayedPayerNonce { nonce: u64 },
    #[error("received {provided} validator vote extensions; {required} are required")]
    InsufficientVoteExtensions { provided: usize, required: usize },
    #[error(transparent)]
    Threshold(#[from] PrivateOrderError),
}

pub type Result<T, E = PrivateProtocolError> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOrderSide {
    Buy,
    Sell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOrderKind {
    Market,
    Limit,
}

/// The entire value is serialized canonically and encrypted inside the fixed
/// 1,024-byte plaintext area. None of these fields belongs in the public header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOrderPayload {
    pub client_id: String,
    pub side: PrivateOrderSide,
    pub kind: PrivateOrderKind,
    pub price_ticks: u64,
    pub quantity_lots: u64,
    pub leverage: u16,
    pub ioc: bool,
    pub fok: bool,
    pub reduce_only: bool,
}

impl PrivateOrderPayload {
    pub fn validate(&self) -> Result<()> {
        validate_printable_identifier("client_id", &self.client_id, MAX_PRIVATE_CLIENT_ID_BYTES)
            .map_err(PrivateProtocolError::InvalidPayload)?;
        if self.quantity_lots == 0 {
            return Err(PrivateProtocolError::InvalidPayload(
                "quantity_lots must be greater than zero".into(),
            ));
        }
        if !(1..=125).contains(&self.leverage) {
            return Err(PrivateProtocolError::InvalidPayload(
                "leverage must be between 1 and 125".into(),
            ));
        }
        match self.kind {
            PrivateOrderKind::Market if self.price_ticks != 0 => {
                return Err(PrivateProtocolError::InvalidPayload(
                    "market orders must encode price_ticks as zero".into(),
                ));
            }
            PrivateOrderKind::Limit if self.price_ticks == 0 => {
                return Err(PrivateProtocolError::InvalidPayload(
                    "limit orders require a non-zero price_ticks".into(),
                ));
            }
            PrivateOrderKind::Market | PrivateOrderKind::Limit => {}
        }
        if self.ioc == self.fok {
            return Err(PrivateProtocolError::InvalidPayload(
                "exactly one of ioc or fok must be true for single-batch execution".into(),
            ));
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_encode(
            self,
            MAX_PRIVATE_ORDER_PAYLOAD_BYTES,
            "private-order payload",
        )
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let payload: Self = canonical_decode(
            bytes,
            MAX_PRIVATE_ORDER_PAYLOAD_BYTES,
            "private-order payload",
        )?;
        payload.validate()?;
        Ok(payload)
    }
}

impl Drop for PrivateOrderPayload {
    fn drop(&mut self) {
        self.client_id.zeroize();
        self.price_ticks.zeroize();
        self.quantity_lots.zeroize();
        self.leverage.zeroize();
        self.ioc.zeroize();
        self.fok.zeroize();
        self.reduce_only.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOrderSubmission {
    pub version: u16,
    pub chain_id: String,
    pub nonce: u64,
    pub valid_until_height: u64,
    pub envelope: PrivateOrderEnvelope,
    #[serde(with = "base64_64")]
    pub fee_payer_signature: [u8; 64],
}

#[derive(Serialize)]
struct SubmissionSigningPayload<'a> {
    version: u16,
    chain_id: &'a str,
    nonce: u64,
    valid_until_height: u64,
    envelope: &'a PrivateOrderEnvelope,
}

impl PrivateOrderSubmission {
    pub fn sign(
        chain_id: String,
        nonce: u64,
        valid_until_height: u64,
        envelope: PrivateOrderEnvelope,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let fee_payer = signing_key.verifying_key().to_bytes();
        if envelope.header.fee_payer != fee_payer {
            return Err(PrivateProtocolError::InvalidSubmission(
                "envelope fee_payer does not match the signing key".into(),
            ));
        }
        let expected_commitment = anti_spam_commitment(&chain_id, &fee_payer, nonce)?;
        if envelope.header.anti_spam_commitment != expected_commitment {
            return Err(PrivateProtocolError::InvalidAntiSpamCommitment);
        }

        let mut submission = Self {
            version: PRIVATE_PROTOCOL_VERSION,
            chain_id,
            nonce,
            valid_until_height,
            envelope,
            fee_payer_signature: [0; 64],
        };
        submission.validate_self_contained(false)?;
        submission.fee_payer_signature =
            signing_key.sign(&submission.signing_message()?).to_bytes();
        submission.validate_self_contained(true)?;
        Ok(submission)
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_self_contained(true)?;
        self.canonical_bytes_after_validation()
    }

    fn canonical_bytes_after_validation(&self) -> Result<Vec<u8>> {
        canonical_encode(
            self,
            MAX_PRIVATE_ORDER_SUBMISSION_BYTES,
            "private-order submission",
        )
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let submission: Self = canonical_decode(
            bytes,
            MAX_PRIVATE_ORDER_SUBMISSION_BYTES,
            "private-order submission",
        )?;
        submission.validate_self_contained(true)?;
        Ok(submission)
    }

    pub fn submission_id(&self) -> Result<[u8; 32]> {
        self.validate_self_contained(true)?;
        self.submission_id_after_validation()
    }

    fn submission_id_after_validation(&self) -> Result<[u8; 32]> {
        let canonical = self.canonical_bytes_after_validation()?;
        Ok(hash_parts(SUBMISSION_ID_DOMAIN, &[&canonical]))
    }

    fn signing_message(&self) -> Result<Vec<u8>> {
        let payload = SubmissionSigningPayload {
            version: self.version,
            chain_id: &self.chain_id,
            nonce: self.nonce,
            valid_until_height: self.valid_until_height,
            envelope: &self.envelope,
        };
        let canonical = canonical_encode(
            &payload,
            MAX_PRIVATE_ORDER_SUBMISSION_BYTES,
            "private-order signing payload",
        )?;
        let mut message = Vec::with_capacity(SUBMISSION_SIGNING_DOMAIN.len() + canonical.len());
        message.extend_from_slice(SUBMISSION_SIGNING_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    fn validate_self_contained(&self, verify_signature: bool) -> Result<()> {
        if self.version != PRIVATE_PROTOCOL_VERSION {
            return Err(PrivateProtocolError::InvalidSubmission(format!(
                "unsupported protocol version {}",
                self.version
            )));
        }
        validate_chain_id(&self.chain_id)?;
        if self.nonce == u64::MAX {
            return Err(PrivateProtocolError::InvalidSubmission(
                "nonce must leave room for the next account nonce".into(),
            ));
        }
        if self.valid_until_height == 0 {
            return Err(PrivateProtocolError::InvalidSubmission(
                "valid_until_height must be greater than zero".into(),
            ));
        }
        validate_envelope_wire_shape(&self.envelope)?;
        if self.valid_until_height < self.envelope.header.batch_height {
            return Err(PrivateProtocolError::Expired {
                valid_until: self.valid_until_height,
                current: self.envelope.header.batch_height,
            });
        }
        if self.valid_until_height - self.envelope.header.batch_height
            > MAX_PRIVATE_ORDER_VALIDITY_WINDOW
        {
            return Err(PrivateProtocolError::InvalidSubmission(format!(
                "validity window exceeds {MAX_PRIVATE_ORDER_VALIDITY_WINDOW} blocks"
            )));
        }
        let expected =
            anti_spam_commitment(&self.chain_id, &self.envelope.header.fee_payer, self.nonce)?;
        if self.envelope.header.anti_spam_commitment != expected {
            return Err(PrivateProtocolError::InvalidAntiSpamCommitment);
        }
        if verify_signature {
            let verifying_key = verifying_key(&self.envelope.header.fee_payer)?;
            let signature = Signature::from_bytes(&self.fee_payer_signature);
            verifying_key
                .verify_strict(&self.signing_message()?, &signature)
                .map_err(|_| PrivateProtocolError::InvalidSignature)?;
        }
        Ok(())
    }
}

/// Deterministically commits the public anti-spam identity to its nonce while
/// including the chain domain to avoid unnecessary cross-chain linkability.
pub fn anti_spam_commitment(chain_id: &str, fee_payer: &[u8; 32], nonce: u64) -> Result<[u8; 32]> {
    validate_chain_id(chain_id)?;
    if *fee_payer == [0; 32] {
        return Err(PrivateProtocolError::InvalidFeePayer(
            "public key must not be all zeroes".into(),
        ));
    }
    let chain_len = u16::try_from(chain_id.len()).expect("validated chain id fits in u16");
    Ok(hash_parts(
        ANTI_SPAM_DOMAIN,
        &[
            &chain_len.to_be_bytes(),
            chain_id.as_bytes(),
            fee_payer,
            &nonce.to_be_bytes(),
        ],
    ))
}

/// Verifies admission-time fields whose truth depends on consensus state.
/// A successful result still requires the caller to atomically reserve/consume
/// `expected_nonce`; calling this function twice does not itself prevent replay.
pub fn verify_submission(
    submission: &PrivateOrderSubmission,
    expected_chain_id: &str,
    expected_nonce: u64,
    current_height: u64,
    expected_batch_height: u64,
    public_keys: &ThresholdPublicKeySet,
) -> Result<PrivateOrderContext> {
    if expected_batch_height != current_height {
        return Err(PrivateProtocolError::WrongHeight {
            expected: current_height,
            actual: expected_batch_height,
        });
    }
    if submission.chain_id != expected_chain_id {
        return Err(PrivateProtocolError::WrongChain {
            expected: expected_chain_id.into(),
            actual: submission.chain_id.clone(),
        });
    }
    if submission.envelope.header.batch_height != current_height {
        return Err(PrivateProtocolError::WrongHeight {
            expected: current_height,
            actual: submission.envelope.header.batch_height,
        });
    }
    if submission.nonce != expected_nonce {
        return Err(PrivateProtocolError::WrongNonce {
            expected: expected_nonce,
            actual: submission.nonce,
        });
    }
    if current_height > submission.valid_until_height {
        return Err(PrivateProtocolError::Expired {
            valid_until: submission.valid_until_height,
            current: current_height,
        });
    }
    verify_pending_submission(
        submission,
        expected_chain_id,
        expected_batch_height,
        public_keys,
    )
}

/// Verifies a submission already selected into the pending set for a height.
/// Account nonce state is deliberately not available here and must have been
/// checked when the pending set was formed.
pub fn verify_pending_submission(
    submission: &PrivateOrderSubmission,
    expected_chain_id: &str,
    expected_batch_height: u64,
    public_keys: &ThresholdPublicKeySet,
) -> Result<PrivateOrderContext> {
    public_keys.validate()?;
    verify_pending_submission_with_validated_keyset(
        submission,
        expected_chain_id,
        expected_batch_height,
        public_keys,
    )
}

fn verify_pending_submission_with_validated_keyset(
    submission: &PrivateOrderSubmission,
    expected_chain_id: &str,
    expected_batch_height: u64,
    public_keys: &ThresholdPublicKeySet,
) -> Result<PrivateOrderContext> {
    if submission.chain_id != expected_chain_id {
        return Err(PrivateProtocolError::WrongChain {
            expected: expected_chain_id.into(),
            actual: submission.chain_id.clone(),
        });
    }
    if submission.envelope.header.batch_height != expected_batch_height {
        return Err(PrivateProtocolError::WrongHeight {
            expected: expected_batch_height,
            actual: submission.envelope.header.batch_height,
        });
    }
    if submission.envelope.header.epoch != public_keys.epoch
        || submission.envelope.header.key_id != public_keys.key_id
    {
        return Err(PrivateProtocolError::InvalidSubmission(
            "envelope epoch key does not match the expected key set".into(),
        ));
    }
    submission.validate_self_contained(true)?;

    let context = PrivateOrderContext {
        chain_id: submission.chain_id.clone(),
        market_id: submission.envelope.header.market_id.clone(),
        epoch: submission.envelope.header.epoch,
        batch_height: submission.envelope.header.batch_height,
    };
    context.validate()?;
    Ok(context)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoteExtensionShare {
    #[serde(with = "base64_32")]
    pub submission_id: [u8; 32],
    pub share: VerifiableDecryptionShare,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoteExtension {
    pub version: u16,
    pub height: u64,
    #[serde(with = "base64_32")]
    pub committed_app_hash: [u8; 32],
    pub validator_id: u16,
    pub beacon_share: VerifiableBeaconShare,
    pub shares: Vec<VoteExtensionShare>,
}

impl VoteExtension {
    pub fn build<R>(
        chain_id: &str,
        height: u64,
        committed_app_hash: [u8; 32],
        public_keys: &ThresholdPublicKeySet,
        secret_share: &ValidatorSecretShare,
        pending: &[PrivateOrderSubmission],
        rng: &mut R,
    ) -> Result<Self>
    where
        R: CryptoRng + RngCore,
    {
        let index = pending_index(chain_id, height, public_keys, pending)?;
        let beacon_share = create_beacon_share(
            public_keys,
            secret_share,
            chain_id,
            height,
            committed_app_hash,
            rng,
        )?;
        let mut shares = Vec::with_capacity(index.len());
        for (submission_id, record) in index {
            let share = create_decryption_share(
                public_keys,
                secret_share,
                &record.context,
                &record.submission.envelope,
                rng,
            )?;
            shares.push(VoteExtensionShare {
                submission_id,
                share,
            });
        }
        let extension = Self {
            version: PRIVATE_PROTOCOL_VERSION,
            height,
            committed_app_hash,
            validator_id: secret_share.validator_id(),
            beacon_share,
            shares,
        };
        extension.validate_shape()?;
        if !public_keys
            .validators
            .iter()
            .any(|validator| validator.validator_id == secret_share.validator_id())
        {
            return Err(PrivateProtocolError::InvalidVoteExtension(format!(
                "validator {} is not in the epoch key set",
                secret_share.validator_id()
            )));
        }
        Ok(extension)
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        canonical_encode(
            self,
            MAX_VOTE_EXTENSION_BYTES,
            "private-order vote extension",
        )
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let extension: Self = canonical_decode(
            bytes,
            MAX_VOTE_EXTENSION_BYTES,
            "private-order vote extension",
        )?;
        extension.validate_shape()?;
        Ok(extension)
    }

    fn validate_shape(&self) -> Result<()> {
        if self.version != PRIVATE_PROTOCOL_VERSION {
            return Err(PrivateProtocolError::InvalidVoteExtension(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.height == 0 || self.validator_id == 0 {
            return Err(PrivateProtocolError::InvalidVoteExtension(
                "height and validator_id must be non-zero".into(),
            ));
        }
        if self.beacon_share.validator_id != self.validator_id
            || self.beacon_share.height != self.height
            || self.beacon_share.committed_app_hash != self.committed_app_hash
        {
            return Err(PrivateProtocolError::InvalidVoteExtension(
                "beacon share does not match the extension context".into(),
            ));
        }
        if self.shares.len() > MAX_VOTE_EXTENSION_SHARES {
            return Err(PrivateProtocolError::InvalidVoteExtension(format!(
                "share count exceeds {MAX_VOTE_EXTENSION_SHARES}"
            )));
        }
        let mut previous = None;
        for item in &self.shares {
            if item.submission_id == [0; 32] {
                return Err(PrivateProtocolError::InvalidVoteExtension(
                    "submission_id must not be all zeroes".into(),
                ));
            }
            if previous.is_some_and(|id| id >= item.submission_id) {
                return Err(PrivateProtocolError::InvalidVoteExtension(
                    "shares must be strictly ordered by submission_id".into(),
                ));
            }
            if item.share.validator_id != self.validator_id {
                return Err(PrivateProtocolError::InvalidVoteExtension(
                    "all shares must belong to validator_id".into(),
                ));
            }
            previous = Some(item.submission_id);
        }
        Ok(())
    }
}

pub fn validate_vote_extension(
    extension: &VoteExtension,
    chain_id: &str,
    expected_height: u64,
    committed_app_hash: [u8; 32],
    expected_validator_id: u16,
    public_keys: &ThresholdPublicKeySet,
    pending: &[PrivateOrderSubmission],
) -> Result<()> {
    let index = pending_index(chain_id, expected_height, public_keys, pending)?;
    validate_vote_extension_against_index(
        extension,
        chain_id,
        expected_height,
        committed_app_hash,
        expected_validator_id,
        public_keys,
        &index,
    )
}

fn validate_vote_extension_against_index(
    extension: &VoteExtension,
    chain_id: &str,
    expected_height: u64,
    committed_app_hash: [u8; 32],
    expected_validator_id: u16,
    public_keys: &ThresholdPublicKeySet,
    index: &BTreeMap<[u8; 32], PendingRecord<'_>>,
) -> Result<()> {
    if extension.height != expected_height {
        return Err(PrivateProtocolError::WrongHeight {
            expected: expected_height,
            actual: extension.height,
        });
    }
    extension.validate_shape()?;
    if extension.committed_app_hash != committed_app_hash {
        return Err(PrivateProtocolError::InvalidVoteExtension(
            "extension app hash does not match the committed batch".into(),
        ));
    }
    if extension.validator_id != expected_validator_id {
        return Err(PrivateProtocolError::InvalidVoteExtension(format!(
            "validator id mismatch: expected {expected_validator_id}, received {}",
            extension.validator_id
        )));
    }
    if !public_keys
        .validators
        .iter()
        .any(|validator| validator.validator_id == expected_validator_id)
    {
        return Err(PrivateProtocolError::InvalidVoteExtension(format!(
            "validator {expected_validator_id} is not in the epoch key set"
        )));
    }
    verify_beacon_share(
        public_keys,
        chain_id,
        expected_height,
        committed_app_hash,
        &extension.beacon_share,
    )?;

    if extension.shares.len() != index.len() {
        return Err(PrivateProtocolError::InvalidVoteExtension(format!(
            "extension contains {} shares for {} pending ciphertexts",
            extension.shares.len(),
            index.len()
        )));
    }
    for (item, (expected_id, record)) in extension.shares.iter().zip(index) {
        if &item.submission_id != expected_id {
            return Err(PrivateProtocolError::InvalidVoteExtension(
                "extension does not exactly cover the canonical pending set".into(),
            ));
        }
        verify_decryption_share(
            public_keys,
            &record.context,
            &record.submission.envelope,
            &item.share,
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiphertextDecryption {
    #[serde(with = "base64_32")]
    pub submission_id: [u8; 32],
    pub shares: Vec<VerifiableDecryptionShare>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptionBundle {
    pub version: u16,
    pub height: u64,
    #[serde(with = "base64_32")]
    pub committed_app_hash: [u8; 32],
    pub beacon_shares: Vec<VerifiableBeaconShare>,
    #[serde(with = "base64_32")]
    pub beacon_output: [u8; 32],
    pub ciphertexts: Vec<CiphertextDecryption>,
}

impl DecryptionBundle {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        canonical_encode(
            self,
            MAX_DECRYPTION_BUNDLE_BYTES,
            "private-order decryption bundle",
        )
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let bundle: Self = canonical_decode(
            bytes,
            MAX_DECRYPTION_BUNDLE_BYTES,
            "private-order decryption bundle",
        )?;
        bundle.validate_shape()?;
        Ok(bundle)
    }

    fn validate_shape(&self) -> Result<()> {
        if self.version != PRIVATE_PROTOCOL_VERSION {
            return Err(PrivateProtocolError::InvalidDecryptionBundle(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.height == 0 {
            return Err(PrivateProtocolError::InvalidDecryptionBundle(
                "height must be non-zero".into(),
            ));
        }
        if self.beacon_shares.len() != PRIVATE_ORDER_THRESHOLD {
            return Err(PrivateProtocolError::InvalidDecryptionBundle(format!(
                "beacon requires exactly {PRIVATE_ORDER_THRESHOLD} shares"
            )));
        }
        let mut previous_beacon_validator = 0_u16;
        for share in &self.beacon_shares {
            if share.validator_id <= previous_beacon_validator {
                return Err(PrivateProtocolError::InvalidDecryptionBundle(
                    "beacon shares must be strictly ordered by validator_id".into(),
                ));
            }
            if share.height != self.height || share.committed_app_hash != self.committed_app_hash {
                return Err(PrivateProtocolError::InvalidDecryptionBundle(
                    "beacon share does not match the bundle context".into(),
                ));
            }
            previous_beacon_validator = share.validator_id;
        }
        if self.beacon_output == [0; 32] {
            return Err(PrivateProtocolError::InvalidDecryptionBundle(
                "beacon output must not be the identity encoding".into(),
            ));
        }
        if self.ciphertexts.len() > MAX_DECRYPTION_BUNDLE_ENTRIES {
            return Err(PrivateProtocolError::InvalidDecryptionBundle(format!(
                "ciphertext count exceeds {MAX_DECRYPTION_BUNDLE_ENTRIES}"
            )));
        }
        let mut previous = None;
        for ciphertext in &self.ciphertexts {
            if ciphertext.submission_id == [0; 32] {
                return Err(PrivateProtocolError::InvalidDecryptionBundle(
                    "submission_id must not be all zeroes".into(),
                ));
            }
            if previous.is_some_and(|id| id >= ciphertext.submission_id) {
                return Err(PrivateProtocolError::InvalidDecryptionBundle(
                    "ciphertexts must be strictly ordered by submission_id".into(),
                ));
            }
            if ciphertext.shares.len() != PRIVATE_ORDER_THRESHOLD {
                return Err(PrivateProtocolError::InvalidDecryptionBundle(format!(
                    "each ciphertext requires exactly {PRIVATE_ORDER_THRESHOLD} shares"
                )));
            }
            let mut previous_validator = 0;
            for share in &ciphertext.shares {
                if share.validator_id <= previous_validator {
                    return Err(PrivateProtocolError::InvalidDecryptionBundle(
                        "decryption shares must be strictly ordered by validator_id".into(),
                    ));
                }
                previous_validator = share.validator_id;
            }
            if !ciphertext
                .shares
                .iter()
                .map(|share| share.validator_id)
                .eq(self.beacon_shares.iter().map(|share| share.validator_id))
            {
                return Err(PrivateProtocolError::InvalidDecryptionBundle(
                    "beacon and ciphertext shares must use the same validator set".into(),
                ));
            }
            previous = Some(ciphertext.submission_id);
        }
        Ok(())
    }
}

/// Derives the state-execution identity from immutable batch semantics. Share
/// proofs and the particular valid threshold subset are deliberately excluded.
pub fn private_batch_execution_id(chain_id: &str, bundle: &DecryptionBundle) -> Result<[u8; 32]> {
    validate_chain_id(chain_id)?;
    bundle.validate_shape()?;
    let chain_length =
        u16::try_from(chain_id.len()).expect("validated chain id length fits in u16");
    let ciphertext_count = u32::try_from(bundle.ciphertexts.len()).map_err(|_| {
        PrivateProtocolError::InvalidDecryptionBundle(
            "ciphertext count does not fit the execution identity".into(),
        )
    })?;

    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_BATCH_EXECUTION_ID_DOMAIN);
    hasher.update(bundle.version.to_be_bytes());
    hasher.update(chain_length.to_be_bytes());
    hasher.update(chain_id.as_bytes());
    hasher.update(bundle.height.to_be_bytes());
    hasher.update(bundle.committed_app_hash);
    hasher.update(bundle.beacon_output);
    hasher.update(ciphertext_count.to_be_bytes());
    for ciphertext in &bundle.ciphertexts {
        hasher.update(ciphertext.submission_id);
    }
    Ok(hasher.finalize().into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedPrivateOrder {
    pub submission_id: [u8; 32],
    pub fee_payer: [u8; 32],
    pub nonce: u64,
    pub market_id: String,
    pub payload: PrivateOrderPayload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidPrivateOrderReason {
    CiphertextAuthenticationFailed,
    InvalidPlaintextLength,
    MalformedPayload,
    NonCanonicalPayload,
    InvalidPayloadSemantics,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateOrderDecryptionOutcome {
    Valid(DecryptedPrivateOrder),
    Invalid {
        submission_id: [u8; 32],
        fee_payer: [u8; 32],
        nonce: u64,
        reason: InvalidPrivateOrderReason,
    },
}

/// Deterministically chooses the lowest three validator IDs from a set of
/// already verifiable vote extensions and emits an unsigned system object.
pub fn aggregate_vote_extensions(
    chain_id: &str,
    height: u64,
    committed_app_hash: [u8; 32],
    public_keys: &ThresholdPublicKeySet,
    pending: &[PrivateOrderSubmission],
    extensions: &[VoteExtension],
) -> Result<DecryptionBundle> {
    if extensions.len() < PRIVATE_ORDER_THRESHOLD {
        return Err(PrivateProtocolError::InsufficientVoteExtensions {
            provided: extensions.len(),
            required: PRIVATE_ORDER_THRESHOLD,
        });
    }
    if extensions.len() > PRIVATE_ORDER_VALIDATOR_COUNT {
        return Err(PrivateProtocolError::InvalidDecryptionBundle(format!(
            "received more than {PRIVATE_ORDER_VALIDATOR_COUNT} validator extensions"
        )));
    }

    let index = pending_index(chain_id, height, public_keys, pending)?;
    let mut ordered = BTreeMap::new();
    for extension in extensions {
        if validate_vote_extension_against_index(
            extension,
            chain_id,
            height,
            committed_app_hash,
            extension.validator_id,
            public_keys,
            &index,
        )
        .is_err()
        {
            continue;
        }
        if ordered.insert(extension.validator_id, extension).is_some() {
            return Err(PrivateProtocolError::InvalidDecryptionBundle(format!(
                "duplicate vote extension from validator {}",
                extension.validator_id
            )));
        }
    }
    if ordered.len() < PRIVATE_ORDER_THRESHOLD {
        return Err(PrivateProtocolError::InsufficientVoteExtensions {
            provided: ordered.len(),
            required: PRIVATE_ORDER_THRESHOLD,
        });
    }
    let selected: Vec<_> = ordered
        .values()
        .take(PRIVATE_ORDER_THRESHOLD)
        .copied()
        .collect();
    let beacon_shares = selected
        .iter()
        .map(|extension| extension.beacon_share.clone())
        .collect::<Vec<_>>();
    let beacon_output = aggregate_beacon_shares(
        public_keys,
        chain_id,
        height,
        committed_app_hash,
        &beacon_shares,
    )?;
    let mut ciphertexts = Vec::with_capacity(index.len());
    for (item_index, submission_id) in index.keys().enumerate() {
        let mut shares = Vec::with_capacity(PRIVATE_ORDER_THRESHOLD);
        for extension in &selected {
            let item = &extension.shares[item_index];
            debug_assert_eq!(&item.submission_id, submission_id);
            shares.push(item.share.clone());
        }
        shares.sort_by_key(|share| share.validator_id);
        ciphertexts.push(CiphertextDecryption {
            submission_id: *submission_id,
            shares,
        });
    }
    let bundle = DecryptionBundle {
        version: PRIVATE_PROTOCOL_VERSION,
        height,
        committed_app_hash,
        beacon_shares,
        beacon_output,
        ciphertexts,
    };
    bundle.validate_shape()?;
    Ok(bundle)
}

/// Fully verifies an unsigned system bundle against the exact pending set and
/// verifies every DLEQ proof. Once those block-validity checks pass, ciphertext
/// authentication and payload parsing are reported per entry so a malicious
/// paid submission cannot make the entire pending height undecryptable.
pub fn validate_and_decrypt_bundle(
    chain_id: &str,
    expected_height: u64,
    committed_app_hash: [u8; 32],
    public_keys: &ThresholdPublicKeySet,
    pending: &[PrivateOrderSubmission],
    bundle: &DecryptionBundle,
) -> Result<Vec<PrivateOrderDecryptionOutcome>> {
    if bundle.height != expected_height {
        return Err(PrivateProtocolError::WrongHeight {
            expected: expected_height,
            actual: bundle.height,
        });
    }
    bundle.validate_shape()?;
    if bundle.committed_app_hash != committed_app_hash {
        return Err(PrivateProtocolError::InvalidDecryptionBundle(
            "bundle app hash does not match the committed batch".into(),
        ));
    }
    let beacon_output = aggregate_beacon_shares(
        public_keys,
        chain_id,
        expected_height,
        committed_app_hash,
        &bundle.beacon_shares,
    )?;
    if beacon_output != bundle.beacon_output {
        return Err(PrivateProtocolError::InvalidDecryptionBundle(
            "bundle beacon output does not match its verified shares".into(),
        ));
    }
    let index = pending_index(chain_id, expected_height, public_keys, pending)?;
    if bundle.ciphertexts.len() != index.len() {
        return Err(PrivateProtocolError::InvalidDecryptionBundle(format!(
            "bundle contains {} ciphertexts for {} pending submissions",
            bundle.ciphertexts.len(),
            index.len()
        )));
    }

    let mut decrypted = Vec::with_capacity(index.len());
    for (ciphertext, (expected_id, record)) in bundle.ciphertexts.iter().zip(index.iter()) {
        if &ciphertext.submission_id != expected_id {
            return Err(PrivateProtocolError::InvalidDecryptionBundle(
                "bundle does not exactly cover the canonical pending set".into(),
            ));
        }
        for share in &ciphertext.shares {
            verify_decryption_share(
                public_keys,
                &record.context,
                &record.submission.envelope,
                share,
            )?;
        }
        let mut plaintext = match decrypt_private_order(
            public_keys,
            &record.context,
            &record.submission.envelope,
            &ciphertext.shares,
        ) {
            Ok(plaintext) => plaintext,
            Err(PrivateOrderError::AuthenticationFailed) => {
                decrypted.push(invalid_outcome(
                    *expected_id,
                    record.submission,
                    InvalidPrivateOrderReason::CiphertextAuthenticationFailed,
                ));
                continue;
            }
            Err(PrivateOrderError::InvalidPayloadLength) => {
                decrypted.push(invalid_outcome(
                    *expected_id,
                    record.submission,
                    InvalidPrivateOrderReason::InvalidPlaintextLength,
                ));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let parsed_payload = PrivateOrderPayload::from_canonical_bytes(&plaintext);
        plaintext.zeroize();
        match parsed_payload {
            Ok(payload) => decrypted.push(PrivateOrderDecryptionOutcome::Valid(
                DecryptedPrivateOrder {
                    submission_id: *expected_id,
                    fee_payer: record.submission.envelope.header.fee_payer,
                    nonce: record.submission.nonce,
                    market_id: record.submission.envelope.header.market_id.clone(),
                    payload,
                },
            )),
            Err(error) => decrypted.push(invalid_outcome(
                *expected_id,
                record.submission,
                payload_error_reason(&error),
            )),
        }
    }
    Ok(decrypted)
}

fn invalid_outcome(
    submission_id: [u8; 32],
    submission: &PrivateOrderSubmission,
    reason: InvalidPrivateOrderReason,
) -> PrivateOrderDecryptionOutcome {
    PrivateOrderDecryptionOutcome::Invalid {
        submission_id,
        fee_payer: submission.envelope.header.fee_payer,
        nonce: submission.nonce,
        reason,
    }
}

fn payload_error_reason(error: &PrivateProtocolError) -> InvalidPrivateOrderReason {
    match error {
        PrivateProtocolError::NonCanonicalEncoding { .. } => {
            InvalidPrivateOrderReason::NonCanonicalPayload
        }
        PrivateProtocolError::InvalidPayload(_) => {
            InvalidPrivateOrderReason::InvalidPayloadSemantics
        }
        PrivateProtocolError::CanonicalEncoding(_)
        | PrivateProtocolError::EncodedSizeLimit { .. } => {
            InvalidPrivateOrderReason::MalformedPayload
        }
        _ => InvalidPrivateOrderReason::MalformedPayload,
    }
}

struct PendingRecord<'a> {
    submission: &'a PrivateOrderSubmission,
    context: PrivateOrderContext,
}

fn pending_index<'a>(
    chain_id: &str,
    height: u64,
    public_keys: &ThresholdPublicKeySet,
    pending: &'a [PrivateOrderSubmission],
) -> Result<BTreeMap<[u8; 32], PendingRecord<'a>>> {
    if pending.len() > MAX_PENDING_PRIVATE_ORDERS {
        return Err(PrivateProtocolError::InvalidDecryptionBundle(format!(
            "pending ciphertext count exceeds {MAX_PENDING_PRIVATE_ORDERS}"
        )));
    }
    public_keys.validate()?;
    let mut index = BTreeMap::new();
    let mut payer_nonces = BTreeSet::new();
    for submission in pending {
        let context = verify_pending_submission_with_validated_keyset(
            submission,
            chain_id,
            height,
            public_keys,
        )?;
        let submission_id = submission.submission_id_after_validation()?;
        if index.contains_key(&submission_id) {
            return Err(PrivateProtocolError::DuplicateSubmissionId(hex::encode(
                submission_id,
            )));
        }
        let payer_nonce = (submission.envelope.header.fee_payer, submission.nonce);
        if !payer_nonces.insert(payer_nonce) {
            return Err(PrivateProtocolError::ReplayedPayerNonce {
                nonce: submission.nonce,
            });
        }
        index.insert(
            submission_id,
            PendingRecord {
                submission,
                context,
            },
        );
    }
    Ok(index)
}

fn validate_envelope_wire_shape(envelope: &PrivateOrderEnvelope) -> Result<()> {
    if envelope.header.version != PRIVATE_ORDER_FORMAT_VERSION {
        return Err(PrivateProtocolError::InvalidSubmission(format!(
            "unsupported envelope version {}",
            envelope.header.version
        )));
    }
    if envelope.header.batch_height == 0 {
        return Err(PrivateProtocolError::InvalidSubmission(
            "envelope batch_height must be greater than zero".into(),
        ));
    }
    if envelope.header.fee_payer == [0; 32]
        || envelope.header.anti_spam_commitment == [0; 32]
        || envelope.header.key_id == [0; 32]
    {
        return Err(PrivateProtocolError::InvalidSubmission(
            "fee_payer, anti_spam_commitment, and key_id must be non-zero".into(),
        ));
    }
    if envelope.encrypted_payload.len() != ENCRYPTED_PRIVATE_ORDER_BYTES {
        return Err(PrivateProtocolError::InvalidSubmission(format!(
            "encrypted payload must contain exactly {ENCRYPTED_PRIVATE_ORDER_BYTES} bytes"
        )));
    }
    validate_printable_identifier("market_id", &envelope.header.market_id, 64)
        .map_err(PrivateProtocolError::InvalidSubmission)?;
    let ephemeral = CompressedRistretto(envelope.ephemeral_public_key)
        .decompress()
        .ok_or_else(|| {
            PrivateProtocolError::InvalidSubmission(
                "ephemeral_public_key is not a canonical Ristretto point".into(),
            )
        })?;
    if ephemeral == curve25519_dalek::ristretto::RistrettoPoint::identity() {
        return Err(PrivateProtocolError::InvalidSubmission(
            "ephemeral_public_key must not be the identity point".into(),
        ));
    }
    Ok(())
}

fn verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(bytes)
        .map_err(|error| PrivateProtocolError::InvalidFeePayer(error.to_string()))?;
    if key.is_weak() {
        return Err(PrivateProtocolError::InvalidFeePayer(
            "weak Ed25519 public keys are not accepted".into(),
        ));
    }
    Ok(key)
}

fn validate_chain_id(chain_id: &str) -> Result<()> {
    validate_printable_identifier("chain_id", chain_id, MAX_PRIVATE_PROTOCOL_CHAIN_ID_BYTES)
        .map_err(PrivateProtocolError::InvalidSubmission)
}

fn validate_printable_identifier(
    name: &str,
    value: &str,
    maximum: usize,
) -> std::result::Result<(), String> {
    if value.is_empty() || value.len() > maximum {
        return Err(format!("{name} must contain between 1 and {maximum} bytes"));
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(format!(
            "{name} must contain only non-whitespace printable ASCII"
        ));
    }
    Ok(())
}

fn canonical_encode<T: Serialize>(
    value: &T,
    maximum: usize,
    object: &'static str,
) -> Result<Vec<u8>> {
    let bytes = serde_jcs::to_vec(value)
        .map_err(|error| PrivateProtocolError::CanonicalEncoding(error.to_string()))?;
    check_encoded_size(bytes.len(), maximum, object)?;
    Ok(bytes)
}

fn canonical_decode<T>(bytes: &[u8], maximum: usize, object: &'static str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    check_encoded_size(bytes.len(), maximum, object)?;
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| PrivateProtocolError::CanonicalEncoding(error.to_string()))?;
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|error| PrivateProtocolError::CanonicalEncoding(error.to_string()))?;
    if canonical != bytes {
        return Err(PrivateProtocolError::NonCanonicalEncoding { object });
    }
    Ok(value)
}

fn check_encoded_size(actual: usize, maximum: usize, object: &'static str) -> Result<()> {
    if actual > maximum {
        return Err(PrivateProtocolError::EncodedSizeLimit {
            object,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn serialize_fixed<const N: usize, S>(
    bytes: &[u8; N],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&STANDARD.encode(bytes))
}

fn deserialize_fixed<'de, const N: usize, D>(
    deserializer: D,
) -> std::result::Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let expected_encoded_len = N.div_ceil(3) * 4;
    if encoded.len() != expected_encoded_len {
        return Err(D::Error::custom(format!(
            "expected {expected_encoded_len} base64 characters, received {}",
            encoded.len()
        )));
    }
    let decoded = STANDARD.decode(&encoded).map_err(D::Error::custom)?;
    let bytes: [u8; N] = decoded.try_into().map_err(|decoded: Vec<u8>| {
        D::Error::custom(format!(
            "expected {N} decoded bytes, received {}",
            decoded.len()
        ))
    })?;
    if STANDARD.encode(bytes) != encoded {
        return Err(D::Error::custom("non-canonical base64 encoding"));
    }
    Ok(bytes)
}

mod base64_32 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_fixed(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_fixed(deserializer)
    }
}

mod base64_64 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_fixed(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_fixed(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_order::{encrypt_private_order, generate_dealer_key_set};
    use rand_core::OsRng;
    use zeroize::Zeroize;

    const CHAIN_ID: &str = "asteria-private-devnet";
    const MARKET_ID: &str = "BTC-USDT-PERP";
    const EPOCH: u64 = 17;
    const HEIGHT: u64 = 100;
    const APP_HASH: [u8; 32] = [0xA5; 32];

    struct Fixture {
        signing_key: SigningKey,
        public_keys: ThresholdPublicKeySet,
        secret_shares: Vec<ValidatorSecretShare>,
        pending: Vec<PrivateOrderSubmission>,
        payloads: Vec<PrivateOrderPayload>,
    }

    impl Fixture {
        fn new(count: usize) -> Self {
            let signing_key = SigningKey::from_bytes(&[41; 32]);
            let (public_keys, secret_shares) = generate_dealer_key_set(EPOCH, &mut OsRng).unwrap();
            let mut pending = Vec::with_capacity(count);
            let mut payloads = Vec::with_capacity(count);
            for index in 0..count {
                let payload = sample_payload(index);
                pending.push(make_submission(
                    &signing_key,
                    &public_keys,
                    u64::try_from(index).unwrap(),
                    HEIGHT,
                    HEIGHT + 10,
                    &payload,
                ));
                payloads.push(payload);
            }
            Self {
                signing_key,
                public_keys,
                secret_shares,
                pending,
                payloads,
            }
        }

        fn votes(&self) -> Vec<VoteExtension> {
            self.secret_shares
                .iter()
                .map(|secret_share| {
                    VoteExtension::build(
                        CHAIN_ID,
                        HEIGHT,
                        APP_HASH,
                        &self.public_keys,
                        secret_share,
                        &self.pending,
                        &mut OsRng,
                    )
                    .unwrap()
                })
                .collect()
        }
    }

    fn sample_payload(index: usize) -> PrivateOrderPayload {
        PrivateOrderPayload {
            client_id: format!("private-{index}"),
            side: if index.is_multiple_of(2) {
                PrivateOrderSide::Buy
            } else {
                PrivateOrderSide::Sell
            },
            kind: PrivateOrderKind::Limit,
            price_ticks: 42_000 + u64::try_from(index).unwrap(),
            quantity_lots: 5 + u64::try_from(index).unwrap(),
            leverage: 10,
            ioc: index.is_multiple_of(2),
            fok: !index.is_multiple_of(2),
            reduce_only: !index.is_multiple_of(2),
        }
    }

    fn make_submission(
        signing_key: &SigningKey,
        public_keys: &ThresholdPublicKeySet,
        nonce: u64,
        batch_height: u64,
        valid_until_height: u64,
        payload: &PrivateOrderPayload,
    ) -> PrivateOrderSubmission {
        let plaintext = payload.to_canonical_bytes().unwrap();
        make_raw_submission(
            signing_key,
            public_keys,
            nonce,
            batch_height,
            valid_until_height,
            &plaintext,
        )
    }

    fn make_raw_submission(
        signing_key: &SigningKey,
        public_keys: &ThresholdPublicKeySet,
        nonce: u64,
        batch_height: u64,
        valid_until_height: u64,
        plaintext: &[u8],
    ) -> PrivateOrderSubmission {
        let payer = signing_key.verifying_key().to_bytes();
        let commitment = anti_spam_commitment(CHAIN_ID, &payer, nonce).unwrap();
        let context = PrivateOrderContext {
            chain_id: CHAIN_ID.into(),
            market_id: MARKET_ID.into(),
            epoch: EPOCH,
            batch_height,
        };
        let envelope = encrypt_private_order(
            public_keys,
            &context,
            payer,
            commitment,
            plaintext,
            &mut OsRng,
        )
        .unwrap();
        PrivateOrderSubmission::sign(
            CHAIN_ID.into(),
            nonce,
            valid_until_height,
            envelope,
            signing_key,
        )
        .unwrap()
    }

    #[test]
    fn payload_is_canonical_private_and_single_batch_only() {
        let payload = sample_payload(0);
        let canonical = payload.to_canonical_bytes().unwrap();
        assert_eq!(
            PrivateOrderPayload::from_canonical_bytes(&canonical).unwrap(),
            payload
        );
        assert!(canonical.len() < MAX_PRIVATE_ORDER_PAYLOAD_BYTES);

        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(&canonical);
        assert!(matches!(
            PrivateOrderPayload::from_canonical_bytes(&noncanonical),
            Err(PrivateProtocolError::NonCanonicalEncoding { .. })
        ));

        let mut neither = payload.clone();
        neither.ioc = false;
        neither.fok = false;
        assert!(matches!(
            neither.validate(),
            Err(PrivateProtocolError::InvalidPayload(_))
        ));
        let mut both = payload.clone();
        both.ioc = true;
        both.fok = true;
        assert!(matches!(
            both.validate(),
            Err(PrivateProtocolError::InvalidPayload(_))
        ));

        let mut market = payload;
        market.kind = PrivateOrderKind::Market;
        market.price_ticks = 0;
        market.validate().unwrap();
    }

    #[test]
    fn submission_signature_binds_envelope_chain_nonce_and_expiry() {
        let fixture = Fixture::new(1);
        let submission = &fixture.pending[0];
        verify_submission(
            submission,
            CHAIN_ID,
            0,
            HEIGHT,
            HEIGHT,
            &fixture.public_keys,
        )
        .unwrap();

        let canonical = submission.to_canonical_bytes().unwrap();
        assert_eq!(
            PrivateOrderSubmission::from_canonical_bytes(&canonical).unwrap(),
            *submission
        );
        let mut noncanonical = b"\n".to_vec();
        noncanonical.extend_from_slice(&canonical);
        assert!(matches!(
            PrivateOrderSubmission::from_canonical_bytes(&noncanonical),
            Err(PrivateProtocolError::NonCanonicalEncoding { .. })
        ));

        let mut tampered_ciphertext = submission.clone();
        tampered_ciphertext.envelope.encrypted_payload[0] ^= 1;
        assert!(matches!(
            verify_submission(
                &tampered_ciphertext,
                CHAIN_ID,
                0,
                HEIGHT,
                HEIGHT,
                &fixture.public_keys,
            ),
            Err(PrivateProtocolError::InvalidSignature)
        ));

        let mut tampered_expiry = submission.clone();
        tampered_expiry.valid_until_height += 1;
        assert!(matches!(
            verify_submission(
                &tampered_expiry,
                CHAIN_ID,
                0,
                HEIGHT,
                HEIGHT,
                &fixture.public_keys,
            ),
            Err(PrivateProtocolError::InvalidSignature)
        ));

        assert!(matches!(
            verify_submission(
                submission,
                "another-chain",
                0,
                HEIGHT,
                HEIGHT,
                &fixture.public_keys,
            ),
            Err(PrivateProtocolError::WrongChain { .. })
        ));
    }

    #[test]
    fn admission_rejects_replay_future_height_nonce_and_header_mismatch() {
        let fixture = Fixture::new(1);
        let submission = &fixture.pending[0];

        assert!(matches!(
            verify_submission(
                submission,
                CHAIN_ID,
                1,
                HEIGHT,
                HEIGHT,
                &fixture.public_keys,
            ),
            Err(PrivateProtocolError::WrongNonce {
                expected: 1,
                actual: 0
            })
        ));
        assert!(matches!(
            verify_submission(
                submission,
                CHAIN_ID,
                0,
                HEIGHT,
                HEIGHT + 1,
                &fixture.public_keys,
            ),
            Err(PrivateProtocolError::WrongHeight { .. })
        ));

        let mut tampered_nonce = submission.clone();
        tampered_nonce.nonce += 1;
        assert!(matches!(
            verify_submission(
                &tampered_nonce,
                CHAIN_ID,
                1,
                HEIGHT,
                HEIGHT,
                &fixture.public_keys,
            ),
            Err(PrivateProtocolError::InvalidAntiSpamCommitment)
        ));

        let mut tampered_header = submission.clone();
        tampered_header.envelope.header.anti_spam_commitment[0] ^= 1;
        assert!(matches!(
            verify_submission(
                &tampered_header,
                CHAIN_ID,
                0,
                HEIGHT,
                HEIGHT,
                &fixture.public_keys,
            ),
            Err(PrivateProtocolError::InvalidAntiSpamCommitment)
        ));

        let future = make_submission(
            &fixture.signing_key,
            &fixture.public_keys,
            0,
            HEIGHT + 1,
            HEIGHT + 2,
            &fixture.payloads[0],
        );
        assert!(matches!(
            verify_submission(&future, CHAIN_ID, 0, HEIGHT, HEIGHT, &fixture.public_keys,),
            Err(PrivateProtocolError::WrongHeight { .. })
        ));
    }

    #[test]
    fn wrong_keyset_and_invalid_fee_payer_are_rejected() {
        let fixture = Fixture::new(1);
        let (wrong_keys, _) = generate_dealer_key_set(EPOCH, &mut OsRng).unwrap();
        assert!(matches!(
            verify_submission(
                &fixture.pending[0],
                CHAIN_ID,
                0,
                HEIGHT,
                HEIGHT,
                &wrong_keys,
            ),
            Err(PrivateProtocolError::InvalidSubmission(_))
        ));

        let mut wrong_payer = fixture.pending[0].clone();
        wrong_payer.envelope.header.fee_payer = [0; 32];
        assert!(matches!(
            verify_submission(
                &wrong_payer,
                CHAIN_ID,
                0,
                HEIGHT,
                HEIGHT,
                &fixture.public_keys,
            ),
            Err(PrivateProtocolError::InvalidSubmission(_))
                | Err(PrivateProtocolError::InvalidFeePayer(_))
        ));
    }

    #[test]
    fn vote_extension_requires_exact_pending_set_height_and_validator() {
        let fixture = Fixture::new(2);
        let extension = VoteExtension::build(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &fixture.secret_shares[0],
            &fixture.pending,
            &mut OsRng,
        )
        .unwrap();
        validate_vote_extension(
            &extension,
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            1,
            &fixture.public_keys,
            &fixture.pending,
        )
        .unwrap();

        let canonical = extension.to_canonical_bytes().unwrap();
        assert_eq!(
            VoteExtension::from_canonical_bytes(&canonical).unwrap(),
            extension
        );
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(&canonical);
        assert!(matches!(
            VoteExtension::from_canonical_bytes(&noncanonical),
            Err(PrivateProtocolError::NonCanonicalEncoding { .. })
        ));

        let mut wrong_height = extension.clone();
        wrong_height.height += 1;
        assert!(matches!(
            validate_vote_extension(
                &wrong_height,
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                1,
                &fixture.public_keys,
                &fixture.pending,
            ),
            Err(PrivateProtocolError::WrongHeight { .. })
        ));
        assert!(matches!(
            validate_vote_extension(
                &extension,
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                2,
                &fixture.public_keys,
                &fixture.pending,
            ),
            Err(PrivateProtocolError::InvalidVoteExtension(_))
        ));

        let mut missing = extension.clone();
        missing.shares.pop();
        assert!(matches!(
            validate_vote_extension(
                &missing,
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                1,
                &fixture.public_keys,
                &fixture.pending,
            ),
            Err(PrivateProtocolError::InvalidVoteExtension(_))
        ));

        let mut duplicate = extension;
        duplicate.shares[1] = duplicate.shares[0].clone();
        assert!(matches!(
            validate_vote_extension(
                &duplicate,
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                1,
                &fixture.public_keys,
                &fixture.pending,
            ),
            Err(PrivateProtocolError::InvalidVoteExtension(_))
        ));
    }

    #[test]
    fn vote_extension_rejects_tampered_decryption_proof() {
        let fixture = Fixture::new(1);
        let mut extension = fixture.votes().remove(0);
        extension.shares[0].share.proof.response[0] ^= 1;
        assert!(matches!(
            validate_vote_extension(
                &extension,
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                1,
                &fixture.public_keys,
                &fixture.pending,
            ),
            Err(PrivateProtocolError::Threshold(
                PrivateOrderError::InvalidDecryptionShare { .. }
            ))
        ));
    }

    #[test]
    fn unsigned_bundle_is_complete_canonical_and_decrypts() {
        let fixture = Fixture::new(2);
        let votes = fixture.votes();
        let bundle = aggregate_vote_extensions(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &fixture.pending,
            &votes,
        )
        .unwrap();
        let mut reversed_votes = votes.clone();
        reversed_votes.reverse();
        let mut reversed_pending = fixture.pending.clone();
        reversed_pending.reverse();
        assert_eq!(
            aggregate_vote_extensions(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &reversed_pending,
                &reversed_votes,
            )
            .unwrap(),
            bundle
        );
        assert_eq!(bundle.ciphertexts.len(), 2);
        for ciphertext in &bundle.ciphertexts {
            assert_eq!(ciphertext.shares.len(), PRIVATE_ORDER_THRESHOLD);
            assert_eq!(
                ciphertext
                    .shares
                    .iter()
                    .map(|share| share.validator_id)
                    .collect::<Vec<_>>(),
                vec![1, 2, 3]
            );
        }

        let decrypted = validate_and_decrypt_bundle(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &fixture.pending,
            &bundle,
        )
        .unwrap();
        let payloads: BTreeSet<_> = decrypted
            .iter()
            .filter_map(|outcome| match outcome {
                PrivateOrderDecryptionOutcome::Valid(order) => {
                    Some(order.payload.client_id.as_str())
                }
                PrivateOrderDecryptionOutcome::Invalid { .. } => None,
            })
            .collect();
        assert_eq!(payloads, BTreeSet::from(["private-0", "private-1"]));

        let canonical = bundle.to_canonical_bytes().unwrap();
        assert!(!String::from_utf8_lossy(&canonical).contains("signature"));
        assert_eq!(
            DecryptionBundle::from_canonical_bytes(&canonical).unwrap(),
            bundle
        );
    }

    #[test]
    fn every_three_validator_subset_produces_the_same_beacon_output() {
        let fixture = Fixture::new(2);
        let votes = fixture.votes();
        let mut expected = None;
        let mut expected_execution_id = None;

        for omitted in 0..PRIVATE_ORDER_VALIDATOR_COUNT {
            let subset = votes
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, extension)| extension.clone())
                .collect::<Vec<_>>();
            let bundle = aggregate_vote_extensions(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.pending,
                &subset,
            )
            .unwrap();
            assert_eq!(
                *expected.get_or_insert(bundle.beacon_output),
                bundle.beacon_output
            );
            let execution_id = private_batch_execution_id(CHAIN_ID, &bundle).unwrap();
            assert_eq!(
                *expected_execution_id.get_or_insert(execution_id),
                execution_id
            );
        }
    }

    #[test]
    fn bundle_rejects_ciphertext_shares_from_a_different_threshold_subset() {
        let fixture = Fixture::new(2);
        let votes = fixture.votes();
        let mut first_subset = aggregate_vote_extensions(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &fixture.pending,
            &votes[..PRIVATE_ORDER_THRESHOLD],
        )
        .unwrap();
        let second_subset = aggregate_vote_extensions(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &fixture.pending,
            &votes[1..],
        )
        .unwrap();
        first_subset.ciphertexts[0].shares = second_subset.ciphertexts[0].shares.clone();

        assert!(matches!(
            first_subset.to_canonical_bytes(),
            Err(PrivateProtocolError::InvalidDecryptionBundle(message))
                if message.contains("same validator set")
        ));
        assert!(matches!(
            validate_and_decrypt_bundle(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.pending,
                &first_subset,
            ),
            Err(PrivateProtocolError::InvalidDecryptionBundle(message))
                if message.contains("same validator set")
        ));
    }

    #[test]
    fn proof_bytes_do_not_change_the_private_batch_execution_id() {
        let fixture = Fixture::new(1);
        let votes = fixture.votes();
        let bundle = aggregate_vote_extensions(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &fixture.pending,
            &votes,
        )
        .unwrap();
        let mut proof_variant = bundle.clone();
        proof_variant.beacon_shares[0].proof.response[0] ^= 1;
        proof_variant.ciphertexts[0].shares[0].proof.commitment_base[0] ^= 1;

        assert_ne!(proof_variant, bundle);
        assert_eq!(
            private_batch_execution_id(CHAIN_ID, &proof_variant).unwrap(),
            private_batch_execution_id(CHAIN_ID, &bundle).unwrap()
        );
    }

    #[test]
    fn vote_and_bundle_reject_tampered_app_hash_or_beacon_output() {
        let fixture = Fixture::new(1);
        let votes = fixture.votes();
        let mut wrong_app_hash = APP_HASH;
        wrong_app_hash[0] ^= 1;

        assert!(matches!(
            validate_vote_extension(
                &votes[0],
                CHAIN_ID,
                HEIGHT,
                wrong_app_hash,
                1,
                &fixture.public_keys,
                &fixture.pending,
            ),
            Err(PrivateProtocolError::InvalidVoteExtension(_))
        ));

        let bundle = aggregate_vote_extensions(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &fixture.pending,
            &votes,
        )
        .unwrap();
        assert!(matches!(
            validate_and_decrypt_bundle(
                CHAIN_ID,
                HEIGHT,
                wrong_app_hash,
                &fixture.public_keys,
                &fixture.pending,
                &bundle,
            ),
            Err(PrivateProtocolError::InvalidDecryptionBundle(_))
        ));

        let mut tampered_output = bundle;
        tampered_output.beacon_output[0] ^= 1;
        assert!(matches!(
            validate_and_decrypt_bundle(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.pending,
                &tampered_output,
            ),
            Err(PrivateProtocolError::InvalidDecryptionBundle(_))
        ));
    }

    #[test]
    fn invalid_ciphertext_and_payload_do_not_block_valid_orders() {
        let fixture = Fixture::new(1);
        let mut pending = fixture.pending.clone();

        let mut invalid_payload = sample_payload(1);
        invalid_payload.ioc = false;
        invalid_payload.fok = false;
        let invalid_payload_bytes = serde_jcs::to_vec(&invalid_payload).unwrap();
        pending.push(make_raw_submission(
            &fixture.signing_key,
            &fixture.public_keys,
            1,
            HEIGHT,
            HEIGHT + 10,
            &invalid_payload_bytes,
        ));

        let mut bad_authentication = make_submission(
            &fixture.signing_key,
            &fixture.public_keys,
            2,
            HEIGHT,
            HEIGHT + 10,
            &sample_payload(2),
        );
        bad_authentication.envelope.encrypted_payload[0] ^= 1;
        bad_authentication = PrivateOrderSubmission::sign(
            CHAIN_ID.into(),
            2,
            HEIGHT + 10,
            bad_authentication.envelope,
            &fixture.signing_key,
        )
        .unwrap();
        pending.push(bad_authentication);

        let votes: Vec<_> = fixture
            .secret_shares
            .iter()
            .map(|secret_share| {
                VoteExtension::build(
                    CHAIN_ID,
                    HEIGHT,
                    APP_HASH,
                    &fixture.public_keys,
                    secret_share,
                    &pending,
                    &mut OsRng,
                )
                .unwrap()
            })
            .collect();
        let bundle = aggregate_vote_extensions(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &pending,
            &votes,
        )
        .unwrap();
        let outcomes = validate_and_decrypt_bundle(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &pending,
            &bundle,
        )
        .unwrap();

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PrivateOrderDecryptionOutcome::Valid(_)))
                .count(),
            1
        );
        let reasons: BTreeSet<_> = outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                PrivateOrderDecryptionOutcome::Invalid { reason, .. } => Some(*reason),
                PrivateOrderDecryptionOutcome::Valid(_) => None,
            })
            .collect();
        assert_eq!(
            reasons,
            BTreeSet::from([
                InvalidPrivateOrderReason::CiphertextAuthenticationFailed,
                InvalidPrivateOrderReason::InvalidPayloadSemantics,
            ])
        );
    }

    #[test]
    fn bundle_rejects_missing_duplicate_tampered_and_wrong_height_shares() {
        let fixture = Fixture::new(2);
        let votes = fixture.votes();
        let mut one_faulty_validator = votes.clone();
        one_faulty_validator[0].shares[0].share.proof.response[0] ^= 1;
        let fault_tolerant_bundle = aggregate_vote_extensions(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &fixture.pending,
            &one_faulty_validator,
        )
        .unwrap();
        assert_eq!(
            fault_tolerant_bundle.ciphertexts[0]
                .shares
                .iter()
                .map(|share| share.validator_id)
                .collect::<Vec<_>>(),
            vec![2, 3, 4]
        );

        let bundle = aggregate_vote_extensions(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &fixture.pending,
            &votes,
        )
        .unwrap();

        let mut missing_share = bundle.clone();
        missing_share.ciphertexts[0].shares.pop();
        assert!(matches!(
            validate_and_decrypt_bundle(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.pending,
                &missing_share,
            ),
            Err(PrivateProtocolError::InvalidDecryptionBundle(_))
        ));

        let mut duplicate_share = bundle.clone();
        duplicate_share.ciphertexts[0].shares[1] = duplicate_share.ciphertexts[0].shares[0].clone();
        assert!(matches!(
            validate_and_decrypt_bundle(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.pending,
                &duplicate_share,
            ),
            Err(PrivateProtocolError::InvalidDecryptionBundle(_))
        ));

        let mut missing_ciphertext = bundle.clone();
        missing_ciphertext.ciphertexts.pop();
        assert!(matches!(
            validate_and_decrypt_bundle(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.pending,
                &missing_ciphertext,
            ),
            Err(PrivateProtocolError::InvalidDecryptionBundle(_))
        ));

        let mut tampered = bundle.clone();
        tampered.ciphertexts[0].shares[0].proof.response[0] ^= 1;
        assert!(matches!(
            validate_and_decrypt_bundle(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.pending,
                &tampered,
            ),
            Err(PrivateProtocolError::Threshold(
                PrivateOrderError::InvalidDecryptionShare { .. }
            ))
        ));

        let mut wrong_height = bundle;
        wrong_height.height += 1;
        assert!(matches!(
            validate_and_decrypt_bundle(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.pending,
                &wrong_height,
            ),
            Err(PrivateProtocolError::WrongHeight { .. })
        ));

        assert!(matches!(
            aggregate_vote_extensions(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.pending,
                &votes[..2],
            ),
            Err(PrivateProtocolError::InsufficientVoteExtensions {
                provided: 2,
                required: PRIVATE_ORDER_THRESHOLD
            })
        ));
    }

    #[test]
    fn pending_set_rejects_same_payer_nonce_replay() {
        let fixture = Fixture::new(1);
        let replay = make_submission(
            &fixture.signing_key,
            &fixture.public_keys,
            0,
            HEIGHT,
            HEIGHT + 10,
            &sample_payload(99),
        );
        let pending = vec![fixture.pending[0].clone(), replay];
        assert!(matches!(
            VoteExtension::build(
                CHAIN_ID,
                HEIGHT,
                APP_HASH,
                &fixture.public_keys,
                &fixture.secret_shares[0],
                &pending,
                &mut OsRng,
            ),
            Err(PrivateProtocolError::ReplayedPayerNonce { nonce: 0 })
        ));
    }

    #[test]
    fn provisioned_secret_share_must_match_public_commitment() {
        let fixture = Fixture::new(1);
        let mut provisioned = fixture.secret_shares[0].export_scalar_for_provisioning();
        let imported = ValidatorSecretShare::from_provisioned_scalar(
            &fixture.public_keys,
            fixture.secret_shares[0].validator_id(),
            provisioned,
        )
        .unwrap();
        let extension = VoteExtension::build(
            CHAIN_ID,
            HEIGHT,
            APP_HASH,
            &fixture.public_keys,
            &imported,
            &fixture.pending,
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(extension.validator_id, 1);

        provisioned[0] ^= 1;
        assert!(matches!(
            ValidatorSecretShare::from_provisioned_scalar(&fixture.public_keys, 1, provisioned),
            Err(PrivateOrderError::InvalidSecretShare(_))
        ));
        provisioned.zeroize();
    }
}
