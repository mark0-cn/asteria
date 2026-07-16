//! Auditable research backend for 3-of-4 encrypted private-order envelopes.
//!
//! This module implements hybrid threshold ElGamal over Ristretto255. A dealer
//! samples a degree-two polynomial whose constant term is the epoch secret key.
//! Validators receive scalar evaluations; the public key set contains matching
//! group commitments. Encryption derives an XChaCha20-Poly1305 key from an
//! ephemeral Diffie-Hellman point. Validators publish Chaum-Pedersen proofs that
//! their partial decryptions use the scalar committed by their public share.
//!
//! This is deliberately an **audit-before-use research backend**, not a
//! production threshold-encryption protocol:
//!
//! - Key generation is dealer based. It has no distributed key generation,
//!   complaint protocol, proactive refresh, HSM integration, or forward secrecy.
//! - Three validators can decrypt every envelope for an epoch. Consensus must
//!   prevent them from releasing shares before ciphertext ordering is final.
//!   Exposing an unrestricted share-generation endpoint would create a
//!   decryption oracle; this module intentionally does not define release policy.
//! - The proof establishes share correctness, not the validator's consensus
//!   identity or authorization to release a share.
//! - The public fee payer and anti-spam commitment are opaque here. Consensus
//!   must validate their economic meaning before accepting an envelope.
//! - Fixed padding hides payload length within the encrypted body, but traffic
//!   timing, the public header, network identity, and the existence of an order
//!   remain observable.
//!
//! Unlike an unsafe construction that Shamir-splits an AEAD key, the threshold
//! operation here is a publicly verifiable partial Diffie-Hellman decryption.

use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{Key, KeyInit, Tag, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

pub const PRIVATE_ORDER_FORMAT_VERSION: u16 = 2;
pub const PRIVATE_ORDER_THRESHOLD: usize = 3;
pub const PRIVATE_ORDER_VALIDATOR_COUNT: usize = 4;
pub const MAX_PRIVATE_ORDER_PAYLOAD_BYTES: usize = 1_024;
pub const PADDED_PRIVATE_ORDER_BYTES: usize = 2 + MAX_PRIVATE_ORDER_PAYLOAD_BYTES;
pub const ENCRYPTED_PRIVATE_ORDER_BYTES: usize = PADDED_PRIVATE_ORDER_BYTES + 16;
pub const FIXED_CRYPTO_ENVELOPE_BYTES: usize = 32 + 24 + ENCRYPTED_PRIVATE_ORDER_BYTES;
const ENCRYPTED_PRIVATE_ORDER_BASE64_BYTES: usize = ENCRYPTED_PRIVATE_ORDER_BYTES.div_ceil(3) * 4;

const MAX_CHAIN_ID_BYTES: usize = 128;
const MAX_MARKET_ID_BYTES: usize = 64;

const KEY_ID_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_KEY_ID_V2\0";
const AAD_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_AAD_V2\0";
const KDF_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_KDF_V2\0";
const CIPHERTEXT_ID_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_CIPHERTEXT_ID_V2\0";
const DLEQ_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_DLEQ_V2\0";
const BEACON_BASE_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_BEACON_BASE_V2\0";
const BEACON_DLEQ_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_BEACON_DLEQ_V2\0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PrivateOrderError {
    #[error("invalid private-order context: {0}")]
    InvalidContext(String),
    #[error("invalid threshold public key set: {0}")]
    InvalidKeySet(String),
    #[error("invalid validator secret share: {0}")]
    InvalidSecretShare(String),
    #[error("invalid private-order envelope: {0}")]
    InvalidEnvelope(String),
    #[error("private-order payload must not be empty")]
    EmptyPayload,
    #[error("private-order payload is {actual} bytes; maximum is {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("received {provided} decryption shares; {required} are required")]
    InsufficientShares { provided: usize, required: usize },
    #[error("duplicate decryption share from validator {0}")]
    DuplicateValidator(u16),
    #[error("validator {0} is not in this threshold public key set")]
    UnknownValidator(u16),
    #[error("invalid decryption share from validator {validator_id}: {reason}")]
    InvalidDecryptionShare { validator_id: u16, reason: String },
    #[error("invalid threshold beacon: {0}")]
    InvalidBeacon(String),
    #[error("private-order ciphertext authentication failed")]
    AuthenticationFailed,
    #[error("decrypted private-order payload length is invalid")]
    InvalidPayloadLength,
    #[error("private-order key derivation failed")]
    KeyDerivationFailed,
}

pub type Result<T, E = PrivateOrderError> = std::result::Result<T, E>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOrderContext {
    pub chain_id: String,
    pub market_id: String,
    pub epoch: u64,
    pub batch_height: u64,
}

impl PrivateOrderContext {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("chain_id", &self.chain_id, MAX_CHAIN_ID_BYTES)?;
        validate_identifier("market_id", &self.market_id, MAX_MARKET_ID_BYTES)?;
        if self.batch_height == 0 {
            return Err(PrivateOrderError::InvalidContext(
                "batch_height must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOrderHeader {
    pub version: u16,
    pub market_id: String,
    pub epoch: u64,
    pub batch_height: u64,
    #[serde(with = "base64_32")]
    pub fee_payer: [u8; 32],
    #[serde(with = "base64_32")]
    pub anti_spam_commitment: [u8; 32],
    #[serde(with = "base64_32")]
    pub key_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorPublicShare {
    pub validator_id: u16,
    #[serde(with = "base64_32")]
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdPublicKeySet {
    pub version: u16,
    pub threshold: u8,
    pub validator_count: u8,
    pub epoch: u64,
    #[serde(with = "base64_32")]
    pub public_key: [u8; 32],
    pub validators: Vec<ValidatorPublicShare>,
    #[serde(with = "base64_32")]
    pub key_id: [u8; 32],
}

impl ThresholdPublicKeySet {
    /// Constructs an epoch key set from public material produced by an
    /// authenticated DKG provisioning flow.
    ///
    /// The validator commitments must use IDs 1 through 4. This constructor
    /// computes the key ID locally and verifies that every three-share subset
    /// interpolates to the supplied group public key before returning it.
    pub fn from_provisioned_public_shares(
        epoch: u64,
        public_key: [u8; 32],
        validators: Vec<ValidatorPublicShare>,
    ) -> Result<Self> {
        let mut public_keys = Self {
            version: PRIVATE_ORDER_FORMAT_VERSION,
            threshold: u8::try_from(PRIVATE_ORDER_THRESHOLD).expect("threshold fits in u8"),
            validator_count: u8::try_from(PRIVATE_ORDER_VALIDATOR_COUNT)
                .expect("validator count fits in u8"),
            epoch,
            public_key,
            validators,
            key_id: [0; 32],
        };
        public_keys.key_id = compute_key_id(&public_keys);
        public_keys.validate()?;
        Ok(public_keys)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != PRIVATE_ORDER_FORMAT_VERSION {
            return Err(PrivateOrderError::InvalidKeySet(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if usize::from(self.threshold) != PRIVATE_ORDER_THRESHOLD
            || usize::from(self.validator_count) != PRIVATE_ORDER_VALIDATOR_COUNT
        {
            return Err(PrivateOrderError::InvalidKeySet(
                "this backend requires exactly 3-of-4 keys".into(),
            ));
        }
        if self.validators.len() != PRIVATE_ORDER_VALIDATOR_COUNT {
            return Err(PrivateOrderError::InvalidKeySet(format!(
                "expected {} validator commitments, received {}",
                PRIVATE_ORDER_VALIDATOR_COUNT,
                self.validators.len()
            )));
        }

        let public_key = decompress_non_identity(self.public_key, "epoch public key")
            .map_err(PrivateOrderError::InvalidKeySet)?;
        let mut public_shares = Vec::with_capacity(PRIVATE_ORDER_VALIDATOR_COUNT);
        for (offset, validator) in self.validators.iter().enumerate() {
            let expected_id = u16::try_from(offset + 1).expect("four validator IDs fit in u16");
            if validator.validator_id != expected_id {
                return Err(PrivateOrderError::InvalidKeySet(
                    "validator commitments must be ordered with IDs 1 through 4".into(),
                ));
            }
            let point = decompress_non_identity(
                validator.public_key,
                &format!("validator {} public share", validator.validator_id),
            )
            .map_err(PrivateOrderError::InvalidKeySet)?;
            public_shares.push((validator.validator_id, point));
        }

        // Every 3-share combination must interpolate to the advertised epoch key.
        // This detects a malformed fourth commitment rather than validating only
        // the first three entries.
        for omitted in 0..PRIVATE_ORDER_VALIDATOR_COUNT {
            let subset: Vec<_> = public_shares
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, value)| *value)
                .collect();
            if interpolate_points_at_zero(&subset)? != public_key {
                return Err(PrivateOrderError::InvalidKeySet(
                    "validator commitments are not evaluations of one degree-two polynomial".into(),
                ));
            }
        }

        if compute_key_id(self) != self.key_id {
            return Err(PrivateOrderError::InvalidKeySet(
                "key_id does not match the public key material".into(),
            ));
        }
        Ok(())
    }

    fn validator(&self, validator_id: u16) -> Result<&ValidatorPublicShare> {
        self.validators
            .iter()
            .find(|validator| validator.validator_id == validator_id)
            .ok_or(PrivateOrderError::UnknownValidator(validator_id))
    }
}

/// A validator's scalar key share.
///
/// It intentionally has no `Clone`, `Debug`, `Serialize`, or `Deserialize`
/// implementation. Production deployments must replace this in-memory value
/// with protected key storage and a DKG-produced share.
pub struct ValidatorSecretShare {
    version: u16,
    epoch: u64,
    validator_id: u16,
    scalar: [u8; 32],
}

impl ValidatorSecretShare {
    pub fn validator_id(&self) -> u16 {
        self.validator_id
    }

    /// Imports scalar material delivered by an authenticated provisioning
    /// channel and verifies it against the validator's public commitment.
    ///
    /// This is intentionally not a general deserializer: callers must already
    /// have an authenticated epoch key set, and must zeroize any additional
    /// copies of `scalar` they retain.
    pub fn from_provisioned_scalar(
        public_keys: &ThresholdPublicKeySet,
        validator_id: u16,
        scalar: [u8; 32],
    ) -> Result<Self> {
        public_keys.validate()?;
        let share = Self {
            version: PRIVATE_ORDER_FORMAT_VERSION,
            epoch: public_keys.epoch,
            validator_id,
            scalar,
        };
        let mut validated_scalar = validate_secret_share(public_keys, &share)?;
        validated_scalar.zeroize();
        Ok(share)
    }

    /// Exports scalar material solely for an authenticated provisioning or
    /// backup channel.
    ///
    /// The returned copy is secret and cannot be zeroized by this object. It
    /// must never be logged or sent through ordinary application serialization,
    /// and the caller is responsible for zeroizing it promptly.
    pub fn export_scalar_for_provisioning(&self) -> [u8; 32] {
        self.scalar
    }
}

impl Drop for ValidatorSecretShare {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOrderEnvelope {
    pub header: PrivateOrderHeader,
    #[serde(with = "base64_32")]
    pub ephemeral_public_key: [u8; 32],
    #[serde(with = "base64_24")]
    pub nonce: [u8; 24],
    #[serde(with = "base64_vec")]
    pub encrypted_payload: Vec<u8>,
}

impl PrivateOrderEnvelope {
    pub fn fixed_crypto_size(&self) -> Result<usize> {
        if self.encrypted_payload.len() != ENCRYPTED_PRIVATE_ORDER_BYTES {
            return Err(PrivateOrderError::InvalidEnvelope(format!(
                "encrypted payload must be exactly {ENCRYPTED_PRIVATE_ORDER_BYTES} bytes"
            )));
        }
        Ok(FIXED_CRYPTO_ENVELOPE_BYTES)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChaumPedersenProof {
    #[serde(with = "base64_32")]
    pub commitment_base: [u8; 32],
    #[serde(with = "base64_32")]
    pub commitment_ephemeral: [u8; 32],
    #[serde(with = "base64_32")]
    pub response: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiableDecryptionShare {
    pub version: u16,
    pub epoch: u64,
    pub validator_id: u16,
    #[serde(with = "base64_32")]
    pub key_id: [u8; 32],
    #[serde(with = "base64_32")]
    pub ciphertext_id: [u8; 32],
    #[serde(with = "base64_32")]
    pub shared_point: [u8; 32],
    pub proof: ChaumPedersenProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiableBeaconShare {
    pub version: u16,
    pub epoch: u64,
    pub height: u64,
    pub validator_id: u16,
    #[serde(with = "base64_32")]
    pub key_id: [u8; 32],
    #[serde(with = "base64_32")]
    pub committed_app_hash: [u8; 32],
    #[serde(with = "base64_32")]
    pub beacon_point: [u8; 32],
    pub proof: ChaumPedersenProof,
}

/// Generates a dealer-based epoch key and four validator shares.
///
/// This exists for the research prototype and tests. A production network must
/// replace it with an audited verifiable DKG so no dealer ever learns the epoch
/// secret.
pub fn generate_dealer_key_set<R>(
    epoch: u64,
    rng: &mut R,
) -> Result<(ThresholdPublicKeySet, Vec<ValidatorSecretShare>)>
where
    R: CryptoRng + RngCore,
{
    loop {
        let mut secret = random_nonzero_scalar(rng);
        let mut coefficient_1 = random_scalar(rng);
        let mut coefficient_2 = random_scalar(rng);

        let mut scalar_shares = Vec::with_capacity(PRIVATE_ORDER_VALIDATOR_COUNT);
        let mut validators = Vec::with_capacity(PRIVATE_ORDER_VALIDATOR_COUNT);
        let mut has_zero_share = false;
        for validator_id in 1..=PRIVATE_ORDER_VALIDATOR_COUNT {
            let x = Scalar::from(u64::try_from(validator_id).expect("validator ID fits in u64"));
            let mut share = secret + coefficient_1 * x + coefficient_2 * x * x;
            if share == Scalar::ZERO {
                has_zero_share = true;
                share.zeroize();
                break;
            }
            let validator_id = u16::try_from(validator_id).expect("four IDs fit in u16");
            validators.push(ValidatorPublicShare {
                validator_id,
                public_key: (share * RISTRETTO_BASEPOINT_POINT).compress().to_bytes(),
            });
            scalar_shares.push((validator_id, share.to_bytes()));
            share.zeroize();
        }
        if has_zero_share {
            for (_, scalar_bytes) in &mut scalar_shares {
                scalar_bytes.zeroize();
            }
            secret.zeroize();
            coefficient_1.zeroize();
            coefficient_2.zeroize();
            continue;
        }

        let mut public_keys = ThresholdPublicKeySet {
            version: PRIVATE_ORDER_FORMAT_VERSION,
            threshold: u8::try_from(PRIVATE_ORDER_THRESHOLD).expect("threshold fits in u8"),
            validator_count: u8::try_from(PRIVATE_ORDER_VALIDATOR_COUNT)
                .expect("validator count fits in u8"),
            epoch,
            public_key: (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes(),
            validators,
            key_id: [0; 32],
        };
        public_keys.key_id = compute_key_id(&public_keys);
        secret.zeroize();
        coefficient_1.zeroize();
        coefficient_2.zeroize();
        if let Err(error) = public_keys.validate() {
            for (_, scalar_bytes) in &mut scalar_shares {
                scalar_bytes.zeroize();
            }
            return Err(error);
        }

        let secret_shares = scalar_shares
            .into_iter()
            .map(|(validator_id, scalar)| ValidatorSecretShare {
                version: PRIVATE_ORDER_FORMAT_VERSION,
                epoch,
                validator_id,
                scalar,
            })
            .collect();
        return Ok((public_keys, secret_shares));
    }
}

pub fn encrypt_private_order<R>(
    public_keys: &ThresholdPublicKeySet,
    context: &PrivateOrderContext,
    fee_payer: [u8; 32],
    anti_spam_commitment: [u8; 32],
    payload: &[u8],
    rng: &mut R,
) -> Result<PrivateOrderEnvelope>
where
    R: CryptoRng + RngCore,
{
    public_keys.validate()?;
    context.validate()?;
    if context.epoch != public_keys.epoch {
        return Err(PrivateOrderError::InvalidContext(
            "context epoch does not match the threshold key epoch".into(),
        ));
    }
    if payload.is_empty() {
        return Err(PrivateOrderError::EmptyPayload);
    }
    if payload.len() > MAX_PRIVATE_ORDER_PAYLOAD_BYTES {
        return Err(PrivateOrderError::PayloadTooLarge {
            actual: payload.len(),
            maximum: MAX_PRIVATE_ORDER_PAYLOAD_BYTES,
        });
    }
    if fee_payer == [0; 32] {
        return Err(PrivateOrderError::InvalidContext(
            "fee_payer must not be all zeroes".into(),
        ));
    }
    if anti_spam_commitment == [0; 32] {
        return Err(PrivateOrderError::InvalidContext(
            "anti_spam_commitment must not be all zeroes".into(),
        ));
    }

    let header = PrivateOrderHeader {
        version: PRIVATE_ORDER_FORMAT_VERSION,
        market_id: context.market_id.clone(),
        epoch: context.epoch,
        batch_height: context.batch_height,
        fee_payer,
        anti_spam_commitment,
        key_id: public_keys.key_id,
    };
    let aad = encode_and_validate_aad(public_keys, context, &header)?;

    let mut ephemeral_secret = random_nonzero_scalar(rng);
    let ephemeral_public = ephemeral_secret * RISTRETTO_BASEPOINT_POINT;
    let epoch_public = decompress_non_identity(public_keys.public_key, "epoch public key")
        .map_err(PrivateOrderError::InvalidKeySet)?;
    let shared_point = ephemeral_secret * epoch_public;
    ephemeral_secret.zeroize();

    let mut nonce = [0_u8; 24];
    rng.fill_bytes(&mut nonce);
    let mut padded_payload = vec![0_u8; PADDED_PRIVATE_ORDER_BYTES];
    rng.fill_bytes(&mut padded_payload);
    let payload_len = u16::try_from(payload.len()).expect("payload limit fits in u16");
    padded_payload[..2].copy_from_slice(&payload_len.to_be_bytes());
    padded_payload[2..2 + payload.len()].copy_from_slice(payload);

    let ephemeral_public_key = ephemeral_public.compress().to_bytes();
    let mut key = derive_aead_key(
        &shared_point,
        &aad,
        &public_keys.key_id,
        &public_keys.public_key,
        &ephemeral_public_key,
    )?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let tag_result =
        cipher.encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, &mut padded_payload);
    key.zeroize();
    let tag = match tag_result {
        Ok(tag) => tag,
        Err(_error) => {
            padded_payload.zeroize();
            return Err(PrivateOrderError::AuthenticationFailed);
        }
    };
    padded_payload.extend_from_slice(&tag);

    let envelope = PrivateOrderEnvelope {
        header,
        ephemeral_public_key,
        nonce,
        encrypted_payload: padded_payload,
    };
    validate_envelope(public_keys, context, &envelope)?;
    Ok(envelope)
}

pub fn create_decryption_share<R>(
    public_keys: &ThresholdPublicKeySet,
    secret_share: &ValidatorSecretShare,
    context: &PrivateOrderContext,
    envelope: &PrivateOrderEnvelope,
    rng: &mut R,
) -> Result<VerifiableDecryptionShare>
where
    R: CryptoRng + RngCore,
{
    let aad = validate_envelope(public_keys, context, envelope)?;
    let mut scalar = validate_secret_share(public_keys, secret_share)?;
    let ephemeral = decompress_non_identity(
        envelope.ephemeral_public_key,
        "envelope ephemeral public key",
    )
    .map_err(PrivateOrderError::InvalidEnvelope)?;
    let validator_public = public_keys.validator(secret_share.validator_id)?;
    let validator_public_point =
        decompress_non_identity(validator_public.public_key, "validator public share")
            .map_err(PrivateOrderError::InvalidKeySet)?;

    let shared_point = scalar * ephemeral;
    let mut witness = random_nonzero_scalar(rng);
    let commitment_base = witness * RISTRETTO_BASEPOINT_POINT;
    let commitment_ephemeral = witness * ephemeral;
    let ciphertext_id = compute_ciphertext_id(envelope, &aad);
    let challenge = dleq_challenge(
        secret_share.validator_id,
        &public_keys.key_id,
        &ciphertext_id,
        &validator_public_point,
        &ephemeral,
        &shared_point,
        &commitment_base,
        &commitment_ephemeral,
    );
    let response = witness + challenge * scalar;
    scalar.zeroize();
    witness.zeroize();

    Ok(VerifiableDecryptionShare {
        version: PRIVATE_ORDER_FORMAT_VERSION,
        epoch: context.epoch,
        validator_id: secret_share.validator_id,
        key_id: public_keys.key_id,
        ciphertext_id,
        shared_point: shared_point.compress().to_bytes(),
        proof: ChaumPedersenProof {
            commitment_base: commitment_base.compress().to_bytes(),
            commitment_ephemeral: commitment_ephemeral.compress().to_bytes(),
            response: response.to_bytes(),
        },
    })
}

pub fn verify_decryption_share(
    public_keys: &ThresholdPublicKeySet,
    context: &PrivateOrderContext,
    envelope: &PrivateOrderEnvelope,
    share: &VerifiableDecryptionShare,
) -> Result<()> {
    let aad = validate_envelope(public_keys, context, envelope)?;
    let invalid = |reason: &str| PrivateOrderError::InvalidDecryptionShare {
        validator_id: share.validator_id,
        reason: reason.into(),
    };
    if share.version != PRIVATE_ORDER_FORMAT_VERSION {
        return Err(invalid("unsupported share version"));
    }
    if share.epoch != context.epoch {
        return Err(invalid("share epoch does not match the envelope"));
    }
    if share.key_id != public_keys.key_id {
        return Err(invalid("share key_id does not match the epoch key"));
    }
    let expected_ciphertext_id = compute_ciphertext_id(envelope, &aad);
    if share.ciphertext_id != expected_ciphertext_id {
        return Err(invalid(
            "share is bound to a different ciphertext or context",
        ));
    }

    let validator_public = public_keys.validator(share.validator_id)?;
    let validator_public_point =
        decompress_non_identity(validator_public.public_key, "validator public share")
            .map_err(|reason| invalid(&reason))?;
    let ephemeral = decompress_non_identity(
        envelope.ephemeral_public_key,
        "envelope ephemeral public key",
    )
    .map_err(|reason| invalid(&reason))?;
    let shared_point = decompress_non_identity(share.shared_point, "partial shared point")
        .map_err(|reason| invalid(&reason))?;
    let commitment_base = decompress_point(share.proof.commitment_base, "base commitment")
        .map_err(|reason| invalid(&reason))?;
    let commitment_ephemeral =
        decompress_point(share.proof.commitment_ephemeral, "ephemeral commitment")
            .map_err(|reason| invalid(&reason))?;
    let response = canonical_scalar(share.proof.response, "proof response")
        .map_err(|reason| invalid(&reason))?;

    let challenge = dleq_challenge(
        share.validator_id,
        &public_keys.key_id,
        &share.ciphertext_id,
        &validator_public_point,
        &ephemeral,
        &shared_point,
        &commitment_base,
        &commitment_ephemeral,
    );
    if response * RISTRETTO_BASEPOINT_POINT != commitment_base + challenge * validator_public_point
        || response * ephemeral != commitment_ephemeral + challenge * shared_point
    {
        return Err(invalid("Chaum-Pedersen proof verification failed"));
    }
    Ok(())
}

pub fn create_beacon_share<R>(
    public_keys: &ThresholdPublicKeySet,
    secret_share: &ValidatorSecretShare,
    chain_id: &str,
    height: u64,
    committed_app_hash: [u8; 32],
    rng: &mut R,
) -> Result<VerifiableBeaconShare>
where
    R: CryptoRng + RngCore,
{
    public_keys.validate()?;
    let beacon_base =
        beacon_base_point(chain_id, height, &committed_app_hash, &public_keys.key_id)?;
    let mut scalar = validate_secret_share(public_keys, secret_share)?;
    let validator_public = public_keys.validator(secret_share.validator_id)?;
    let validator_public_point =
        decompress_non_identity(validator_public.public_key, "validator public share")
            .map_err(PrivateOrderError::InvalidBeacon)?;
    let beacon_point = scalar * beacon_base;
    let mut witness = random_nonzero_scalar(rng);
    let commitment_base = witness * RISTRETTO_BASEPOINT_POINT;
    let commitment_beacon = witness * beacon_base;
    let challenge = beacon_dleq_challenge(
        chain_id,
        height,
        &committed_app_hash,
        &public_keys.key_id,
        secret_share.validator_id,
        &validator_public_point,
        &beacon_base,
        &beacon_point,
        &commitment_base,
        &commitment_beacon,
    );
    let response = witness + challenge * scalar;
    scalar.zeroize();
    witness.zeroize();

    Ok(VerifiableBeaconShare {
        version: PRIVATE_ORDER_FORMAT_VERSION,
        epoch: public_keys.epoch,
        height,
        validator_id: secret_share.validator_id,
        key_id: public_keys.key_id,
        committed_app_hash,
        beacon_point: beacon_point.compress().to_bytes(),
        proof: ChaumPedersenProof {
            commitment_base: commitment_base.compress().to_bytes(),
            commitment_ephemeral: commitment_beacon.compress().to_bytes(),
            response: response.to_bytes(),
        },
    })
}

pub fn verify_beacon_share(
    public_keys: &ThresholdPublicKeySet,
    chain_id: &str,
    height: u64,
    committed_app_hash: [u8; 32],
    share: &VerifiableBeaconShare,
) -> Result<()> {
    public_keys.validate()?;
    let invalid = |reason: &str| {
        PrivateOrderError::InvalidBeacon(format!(
            "share from validator {}: {reason}",
            share.validator_id
        ))
    };
    if share.version != PRIVATE_ORDER_FORMAT_VERSION {
        return Err(invalid("unsupported share version"));
    }
    if share.epoch != public_keys.epoch {
        return Err(invalid("share epoch does not match the public key set"));
    }
    if share.height != height {
        return Err(invalid("share height does not match the committed batch"));
    }
    if share.key_id != public_keys.key_id {
        return Err(invalid("share key_id does not match the epoch key"));
    }
    if share.committed_app_hash != committed_app_hash {
        return Err(invalid("share app hash does not match the committed batch"));
    }

    let beacon_base =
        beacon_base_point(chain_id, height, &committed_app_hash, &public_keys.key_id)?;
    let validator_public = public_keys.validator(share.validator_id)?;
    let validator_public_point =
        decompress_non_identity(validator_public.public_key, "validator public share")
            .map_err(|reason| invalid(&reason))?;
    let beacon_point = decompress_non_identity(share.beacon_point, "partial beacon point")
        .map_err(|reason| invalid(&reason))?;
    let commitment_base = decompress_point(share.proof.commitment_base, "base commitment")
        .map_err(|reason| invalid(&reason))?;
    let commitment_beacon = decompress_point(share.proof.commitment_ephemeral, "beacon commitment")
        .map_err(|reason| invalid(&reason))?;
    let response = canonical_scalar(share.proof.response, "proof response")
        .map_err(|reason| invalid(&reason))?;
    let challenge = beacon_dleq_challenge(
        chain_id,
        height,
        &committed_app_hash,
        &public_keys.key_id,
        share.validator_id,
        &validator_public_point,
        &beacon_base,
        &beacon_point,
        &commitment_base,
        &commitment_beacon,
    );
    if response * RISTRETTO_BASEPOINT_POINT != commitment_base + challenge * validator_public_point
        || response * beacon_base != commitment_beacon + challenge * beacon_point
    {
        return Err(invalid("Chaum-Pedersen proof verification failed"));
    }
    Ok(())
}

pub fn aggregate_beacon_shares(
    public_keys: &ThresholdPublicKeySet,
    chain_id: &str,
    height: u64,
    committed_app_hash: [u8; 32],
    shares: &[VerifiableBeaconShare],
) -> Result<[u8; 32]> {
    if shares.len() != PRIVATE_ORDER_THRESHOLD {
        return Err(PrivateOrderError::InvalidBeacon(format!(
            "expected exactly {PRIVATE_ORDER_THRESHOLD} shares, received {}",
            shares.len()
        )));
    }
    let mut previous_validator = 0_u16;
    let mut points = Vec::with_capacity(PRIVATE_ORDER_THRESHOLD);
    for share in shares {
        if share.validator_id <= previous_validator {
            return Err(PrivateOrderError::InvalidBeacon(
                "shares must be strictly ordered by validator_id".into(),
            ));
        }
        verify_beacon_share(public_keys, chain_id, height, committed_app_hash, share)?;
        let point = decompress_non_identity(share.beacon_point, "partial beacon point")
            .map_err(PrivateOrderError::InvalidBeacon)?;
        points.push((share.validator_id, point));
        previous_validator = share.validator_id;
    }
    let beacon = interpolate_points_at_zero(&points)?;
    if beacon == RistrettoPoint::identity() {
        return Err(PrivateOrderError::InvalidBeacon(
            "interpolated beacon must not be the identity".into(),
        ));
    }
    Ok(beacon.compress().to_bytes())
}

pub fn decrypt_private_order(
    public_keys: &ThresholdPublicKeySet,
    context: &PrivateOrderContext,
    envelope: &PrivateOrderEnvelope,
    shares: &[VerifiableDecryptionShare],
) -> Result<Vec<u8>> {
    let aad = validate_envelope(public_keys, context, envelope)?;
    if shares.len() < PRIVATE_ORDER_THRESHOLD {
        return Err(PrivateOrderError::InsufficientShares {
            provided: shares.len(),
            required: PRIVATE_ORDER_THRESHOLD,
        });
    }

    let mut seen = BTreeSet::new();
    let mut points = Vec::with_capacity(shares.len());
    for share in shares {
        if !seen.insert(share.validator_id) {
            return Err(PrivateOrderError::DuplicateValidator(share.validator_id));
        }
        verify_decryption_share(public_keys, context, envelope, share)?;
        let point = decompress_non_identity(share.shared_point, "partial shared point").map_err(
            |reason| PrivateOrderError::InvalidDecryptionShare {
                validator_id: share.validator_id,
                reason,
            },
        )?;
        points.push((share.validator_id, point));
    }
    points.sort_by_key(|(validator_id, _)| *validator_id);
    let shared_point = interpolate_points_at_zero(&points)?;

    let mut key = derive_aead_key(
        &shared_point,
        &aad,
        &public_keys.key_id,
        &public_keys.public_key,
        &envelope.ephemeral_public_key,
    )?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut padded_payload = envelope.encrypted_payload[..PADDED_PRIVATE_ORDER_BYTES].to_vec();
    let tag = Tag::from_slice(&envelope.encrypted_payload[PADDED_PRIVATE_ORDER_BYTES..]);
    let decrypt_result = cipher.decrypt_in_place_detached(
        XNonce::from_slice(&envelope.nonce),
        &aad,
        &mut padded_payload,
        tag,
    );
    key.zeroize();
    if decrypt_result.is_err() {
        padded_payload.zeroize();
        return Err(PrivateOrderError::AuthenticationFailed);
    }

    let payload_len = usize::from(u16::from_be_bytes([padded_payload[0], padded_payload[1]]));
    if payload_len == 0 || payload_len > MAX_PRIVATE_ORDER_PAYLOAD_BYTES {
        padded_payload.zeroize();
        return Err(PrivateOrderError::InvalidPayloadLength);
    }
    let payload = padded_payload[2..2 + payload_len].to_vec();
    padded_payload.zeroize();
    Ok(payload)
}

fn validate_secret_share(
    public_keys: &ThresholdPublicKeySet,
    secret_share: &ValidatorSecretShare,
) -> Result<Scalar> {
    if secret_share.version != PRIVATE_ORDER_FORMAT_VERSION {
        return Err(PrivateOrderError::InvalidSecretShare(
            "unsupported share version".into(),
        ));
    }
    if secret_share.epoch != public_keys.epoch {
        return Err(PrivateOrderError::InvalidSecretShare(
            "share epoch does not match the public key set".into(),
        ));
    }
    let public_share = public_keys.validator(secret_share.validator_id)?;
    let mut scalar = canonical_scalar(secret_share.scalar, "validator scalar share")
        .map_err(PrivateOrderError::InvalidSecretShare)?;
    if scalar == Scalar::ZERO {
        scalar.zeroize();
        return Err(PrivateOrderError::InvalidSecretShare(
            "validator scalar share must not be zero".into(),
        ));
    }
    if (scalar * RISTRETTO_BASEPOINT_POINT).compress().to_bytes() != public_share.public_key {
        scalar.zeroize();
        return Err(PrivateOrderError::InvalidSecretShare(
            "scalar share does not match its public commitment".into(),
        ));
    }
    Ok(scalar)
}

fn validate_envelope(
    public_keys: &ThresholdPublicKeySet,
    context: &PrivateOrderContext,
    envelope: &PrivateOrderEnvelope,
) -> Result<Vec<u8>> {
    public_keys.validate()?;
    context.validate()?;
    if envelope.encrypted_payload.len() != ENCRYPTED_PRIVATE_ORDER_BYTES {
        return Err(PrivateOrderError::InvalidEnvelope(format!(
            "encrypted payload must be exactly {ENCRYPTED_PRIVATE_ORDER_BYTES} bytes"
        )));
    }
    decompress_non_identity(
        envelope.ephemeral_public_key,
        "envelope ephemeral public key",
    )
    .map_err(PrivateOrderError::InvalidEnvelope)?;
    encode_and_validate_aad(public_keys, context, &envelope.header)
}

fn encode_and_validate_aad(
    public_keys: &ThresholdPublicKeySet,
    context: &PrivateOrderContext,
    header: &PrivateOrderHeader,
) -> Result<Vec<u8>> {
    if header.version != PRIVATE_ORDER_FORMAT_VERSION {
        return Err(PrivateOrderError::InvalidEnvelope(
            "unsupported envelope version".into(),
        ));
    }
    if header.market_id != context.market_id
        || header.epoch != context.epoch
        || header.batch_height != context.batch_height
    {
        return Err(PrivateOrderError::InvalidContext(
            "expected chain/market/epoch/height context does not match the envelope".into(),
        ));
    }
    if header.epoch != public_keys.epoch || header.key_id != public_keys.key_id {
        return Err(PrivateOrderError::InvalidContext(
            "envelope does not use the expected epoch key".into(),
        ));
    }
    if header.fee_payer == [0; 32] || header.anti_spam_commitment == [0; 32] {
        return Err(PrivateOrderError::InvalidEnvelope(
            "fee payer and anti-spam commitment must not be all zeroes".into(),
        ));
    }

    let mut aad = Vec::with_capacity(
        AAD_DOMAIN.len() + context.chain_id.len() + context.market_id.len() + 128,
    );
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&PRIVATE_ORDER_FORMAT_VERSION.to_be_bytes());
    append_length_prefixed(&mut aad, context.chain_id.as_bytes());
    append_length_prefixed(&mut aad, context.market_id.as_bytes());
    aad.extend_from_slice(&context.epoch.to_be_bytes());
    aad.extend_from_slice(&context.batch_height.to_be_bytes());
    aad.extend_from_slice(&header.fee_payer);
    aad.extend_from_slice(&header.anti_spam_commitment);
    aad.extend_from_slice(&header.key_id);
    Ok(aad)
}

fn compute_key_id(public_keys: &ThresholdPublicKeySet) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(public_keys.version.to_be_bytes());
    hasher.update([public_keys.threshold, public_keys.validator_count]);
    hasher.update(public_keys.epoch.to_be_bytes());
    hasher.update(public_keys.public_key);
    for validator in &public_keys.validators {
        hasher.update(validator.validator_id.to_be_bytes());
        hasher.update(validator.public_key);
    }
    hasher.finalize().into()
}

fn compute_ciphertext_id(envelope: &PrivateOrderEnvelope, aad: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CIPHERTEXT_ID_DOMAIN);
    hasher.update(aad);
    hasher.update(envelope.ephemeral_public_key);
    hasher.update(envelope.nonce);
    hasher.update(&envelope.encrypted_payload);
    hasher.finalize().into()
}

fn derive_aead_key(
    shared_point: &RistrettoPoint,
    aad: &[u8],
    key_id: &[u8; 32],
    epoch_public_key: &[u8; 32],
    ephemeral_public_key: &[u8; 32],
) -> Result<[u8; 32]> {
    let aad_hash = Sha256::digest(aad);
    let mut shared_bytes = shared_point.compress().to_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&aad_hash), &shared_bytes);
    let mut info = Vec::with_capacity(KDF_DOMAIN.len() + 96);
    info.extend_from_slice(KDF_DOMAIN);
    info.extend_from_slice(key_id);
    info.extend_from_slice(epoch_public_key);
    info.extend_from_slice(ephemeral_public_key);
    let mut key = [0_u8; 32];
    let expand_result = hkdf.expand(&info, &mut key);
    shared_bytes.zeroize();
    expand_result.map_err(|_| PrivateOrderError::KeyDerivationFailed)?;
    Ok(key)
}

#[allow(clippy::too_many_arguments)]
fn dleq_challenge(
    validator_id: u16,
    key_id: &[u8; 32],
    ciphertext_id: &[u8; 32],
    validator_public: &RistrettoPoint,
    ephemeral: &RistrettoPoint,
    shared_point: &RistrettoPoint,
    commitment_base: &RistrettoPoint,
    commitment_ephemeral: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DLEQ_DOMAIN);
    hasher.update(validator_id.to_be_bytes());
    hasher.update(key_id);
    hasher.update(ciphertext_id);
    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    hasher.update(validator_public.compress().as_bytes());
    hasher.update(ephemeral.compress().as_bytes());
    hasher.update(shared_point.compress().as_bytes());
    hasher.update(commitment_base.compress().as_bytes());
    hasher.update(commitment_ephemeral.compress().as_bytes());
    Scalar::from_hash(hasher)
}

fn beacon_base_point(
    chain_id: &str,
    height: u64,
    committed_app_hash: &[u8; 32],
    key_id: &[u8; 32],
) -> Result<RistrettoPoint> {
    validate_identifier("chain_id", chain_id, MAX_CHAIN_ID_BYTES)?;
    if height == 0 {
        return Err(PrivateOrderError::InvalidBeacon(
            "height must be greater than zero".into(),
        ));
    }
    let mut hasher = Sha512::new();
    hasher.update(BEACON_BASE_DOMAIN);
    hasher.update(PRIVATE_ORDER_FORMAT_VERSION.to_be_bytes());
    hasher.update(
        u16::try_from(chain_id.len())
            .expect("validated chain id length fits in u16")
            .to_be_bytes(),
    );
    hasher.update(chain_id.as_bytes());
    hasher.update(height.to_be_bytes());
    hasher.update(committed_app_hash);
    hasher.update(key_id);
    let point = RistrettoPoint::from_hash(hasher);
    if point == RistrettoPoint::identity() {
        return Err(PrivateOrderError::InvalidBeacon(
            "derived beacon base must not be the identity".into(),
        ));
    }
    Ok(point)
}

#[allow(clippy::too_many_arguments)]
fn beacon_dleq_challenge(
    chain_id: &str,
    height: u64,
    committed_app_hash: &[u8; 32],
    key_id: &[u8; 32],
    validator_id: u16,
    validator_public: &RistrettoPoint,
    beacon_base: &RistrettoPoint,
    beacon_point: &RistrettoPoint,
    commitment_base: &RistrettoPoint,
    commitment_beacon: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(BEACON_DLEQ_DOMAIN);
    hasher.update(PRIVATE_ORDER_FORMAT_VERSION.to_be_bytes());
    hasher.update(
        u16::try_from(chain_id.len())
            .expect("validated chain id length fits in u16")
            .to_be_bytes(),
    );
    hasher.update(chain_id.as_bytes());
    hasher.update(height.to_be_bytes());
    hasher.update(committed_app_hash);
    hasher.update(key_id);
    hasher.update(validator_id.to_be_bytes());
    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    hasher.update(validator_public.compress().as_bytes());
    hasher.update(beacon_base.compress().as_bytes());
    hasher.update(beacon_point.compress().as_bytes());
    hasher.update(commitment_base.compress().as_bytes());
    hasher.update(commitment_beacon.compress().as_bytes());
    Scalar::from_hash(hasher)
}

fn interpolate_points_at_zero(points: &[(u16, RistrettoPoint)]) -> Result<RistrettoPoint> {
    let mut seen = BTreeSet::new();
    for (validator_id, _) in points {
        if !seen.insert(*validator_id) {
            return Err(PrivateOrderError::DuplicateValidator(*validator_id));
        }
    }
    let mut result = RistrettoPoint::identity();
    for (validator_id, point) in points {
        result += lagrange_coefficient_at_zero(*validator_id, &seen)? * point;
    }
    Ok(result)
}

fn lagrange_coefficient_at_zero(validator_id: u16, ids: &BTreeSet<u16>) -> Result<Scalar> {
    let x_i = Scalar::from(u64::from(validator_id));
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for other_id in ids {
        if *other_id == validator_id {
            continue;
        }
        let x_j = Scalar::from(u64::from(*other_id));
        numerator *= -x_j;
        denominator *= x_i - x_j;
    }
    if denominator == Scalar::ZERO {
        return Err(PrivateOrderError::InvalidKeySet(
            "duplicate validator interpolation point".into(),
        ));
    }
    Ok(numerator * denominator.invert())
}

fn random_scalar<R>(rng: &mut R) -> Scalar
where
    R: CryptoRng + RngCore,
{
    let mut wide = [0_u8; 64];
    rng.fill_bytes(&mut wide);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    scalar
}

fn random_nonzero_scalar<R>(rng: &mut R) -> Scalar
where
    R: CryptoRng + RngCore,
{
    loop {
        let scalar = random_scalar(rng);
        if scalar != Scalar::ZERO {
            return scalar;
        }
    }
}

fn canonical_scalar(bytes: [u8; 32], label: &str) -> std::result::Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or_else(|| format!("{label} is not a canonical Ristretto scalar"))
}

fn decompress_point(bytes: [u8; 32], label: &str) -> std::result::Result<RistrettoPoint, String> {
    CompressedRistretto(bytes)
        .decompress()
        .ok_or_else(|| format!("{label} is not a canonical Ristretto point"))
}

fn decompress_non_identity(
    bytes: [u8; 32],
    label: &str,
) -> std::result::Result<RistrettoPoint, String> {
    let point = decompress_point(bytes, label)?;
    if point == RistrettoPoint::identity() {
        return Err(format!("{label} must not be the identity point"));
    }
    Ok(point)
}

fn validate_identifier(name: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum {
        return Err(PrivateOrderError::InvalidContext(format!(
            "{name} must contain between 1 and {maximum} bytes"
        )));
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(PrivateOrderError::InvalidContext(format!(
            "{name} must contain only non-whitespace printable ASCII"
        )));
    }
    Ok(())
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    let len = u16::try_from(value.len()).expect("validated identifiers fit in u16");
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
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

mod base64_24 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 24], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_fixed(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 24], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_fixed(deserializer)
    }
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

mod base64_vec {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != ENCRYPTED_PRIVATE_ORDER_BASE64_BYTES {
            return Err(D::Error::custom(format!(
                "encrypted payload must contain exactly {ENCRYPTED_PRIVATE_ORDER_BASE64_BYTES} base64 characters"
            )));
        }
        let decoded = STANDARD.decode(&encoded).map_err(D::Error::custom)?;
        if decoded.len() != ENCRYPTED_PRIVATE_ORDER_BYTES {
            return Err(D::Error::custom(format!(
                "encrypted payload must decode to exactly {ENCRYPTED_PRIVATE_ORDER_BYTES} bytes"
            )));
        }
        if STANDARD.encode(&decoded) != encoded {
            return Err(D::Error::custom("non-canonical base64 encoding"));
        }
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const PAYLOAD: &[u8] = br#"{"side":"buy","quantity":"1.25","price":"42000"}"#;
    const COMMITTED_APP_HASH: [u8; 32] = [0xA5; 32];

    struct Fixture {
        context: PrivateOrderContext,
        public_keys: ThresholdPublicKeySet,
        secret_shares: Vec<ValidatorSecretShare>,
        envelope: PrivateOrderEnvelope,
    }

    impl Fixture {
        fn new(payload: &[u8]) -> Self {
            let context = PrivateOrderContext {
                chain_id: "asteria-private-devnet".into(),
                market_id: "BTC-USDT-PERP".into(),
                epoch: 17,
                batch_height: 42,
            };
            let (public_keys, secret_shares) =
                generate_dealer_key_set(context.epoch, &mut OsRng).unwrap();
            let envelope = encrypt_private_order(
                &public_keys,
                &context,
                [7; 32],
                [9; 32],
                payload,
                &mut OsRng,
            )
            .unwrap();
            Self {
                context,
                public_keys,
                secret_shares,
                envelope,
            }
        }

        fn shares(&self) -> Vec<VerifiableDecryptionShare> {
            self.secret_shares
                .iter()
                .map(|secret_share| {
                    create_decryption_share(
                        &self.public_keys,
                        secret_share,
                        &self.context,
                        &self.envelope,
                        &mut OsRng,
                    )
                    .unwrap()
                })
                .collect()
        }

        fn beacon_shares(&self) -> Vec<VerifiableBeaconShare> {
            self.secret_shares
                .iter()
                .map(|secret_share| {
                    create_beacon_share(
                        &self.public_keys,
                        secret_share,
                        &self.context.chain_id,
                        self.context.batch_height,
                        COMMITTED_APP_HASH,
                        &mut OsRng,
                    )
                    .unwrap()
                })
                .collect()
        }
    }

    #[test]
    fn any_three_shares_decrypt_but_two_do_not() {
        let fixture = Fixture::new(PAYLOAD);
        assert_eq!(fixture.public_keys.threshold, 3);
        assert_eq!(fixture.secret_shares.len(), 4);
        let shares = fixture.shares();

        for omitted in 0..4 {
            let subset: Vec<_> = shares
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, share)| share.clone())
                .collect();
            assert_eq!(
                decrypt_private_order(
                    &fixture.public_keys,
                    &fixture.context,
                    &fixture.envelope,
                    &subset,
                )
                .unwrap(),
                PAYLOAD
            );
        }

        assert_eq!(
            decrypt_private_order(
                &fixture.public_keys,
                &fixture.context,
                &fixture.envelope,
                &shares[..2],
            )
            .unwrap_err(),
            PrivateOrderError::InsufficientShares {
                provided: 2,
                required: 3,
            }
        );
    }

    #[test]
    fn any_three_beacon_shares_interpolate_to_one_unique_output() {
        let fixture = Fixture::new(PAYLOAD);
        let shares = fixture.beacon_shares();
        let mut expected = None;

        for omitted in 0..PRIVATE_ORDER_VALIDATOR_COUNT {
            let subset = shares
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, share)| share.clone())
                .collect::<Vec<_>>();
            let output = aggregate_beacon_shares(
                &fixture.public_keys,
                &fixture.context.chain_id,
                fixture.context.batch_height,
                COMMITTED_APP_HASH,
                &subset,
            )
            .unwrap();
            assert_eq!(*expected.get_or_insert(output), output);
        }
    }

    #[test]
    fn beacon_share_rejects_a_tampered_committed_app_hash() {
        let fixture = Fixture::new(PAYLOAD);
        let share = fixture.beacon_shares().remove(0);
        let mut wrong_app_hash = COMMITTED_APP_HASH;
        wrong_app_hash[0] ^= 1;

        assert!(matches!(
            verify_beacon_share(
                &fixture.public_keys,
                &fixture.context.chain_id,
                fixture.context.batch_height,
                wrong_app_hash,
                &share,
            ),
            Err(PrivateOrderError::InvalidBeacon(_))
        ));
    }

    #[test]
    fn all_four_shares_decrypt_and_each_share_verifies_independently() {
        let fixture = Fixture::new(PAYLOAD);
        let shares = fixture.shares();
        for share in &shares {
            verify_decryption_share(
                &fixture.public_keys,
                &fixture.context,
                &fixture.envelope,
                share,
            )
            .unwrap();
        }
        assert_eq!(
            decrypt_private_order(
                &fixture.public_keys,
                &fixture.context,
                &fixture.envelope,
                &shares,
            )
            .unwrap(),
            PAYLOAD
        );
    }

    #[test]
    fn ciphertext_tampering_is_bound_to_shares_and_aead() {
        let fixture = Fixture::new(PAYLOAD);
        let original_shares = fixture.shares();
        let mut tampered = fixture.envelope.clone();
        tampered.encrypted_payload[10] ^= 0x80;

        assert!(matches!(
            verify_decryption_share(
                &fixture.public_keys,
                &fixture.context,
                &tampered,
                &original_shares[0],
            ),
            Err(PrivateOrderError::InvalidDecryptionShare { .. })
        ));

        let tampered_shares: Vec<_> = fixture
            .secret_shares
            .iter()
            .take(3)
            .map(|secret_share| {
                create_decryption_share(
                    &fixture.public_keys,
                    secret_share,
                    &fixture.context,
                    &tampered,
                    &mut OsRng,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            decrypt_private_order(
                &fixture.public_keys,
                &fixture.context,
                &tampered,
                &tampered_shares,
            )
            .unwrap_err(),
            PrivateOrderError::AuthenticationFailed
        );
    }

    #[test]
    fn aad_rejects_wrong_chain_market_epoch_and_height() {
        let fixture = Fixture::new(PAYLOAD);
        let share = fixture.shares().remove(0);
        let mut contexts = Vec::new();

        let mut wrong_chain = fixture.context.clone();
        wrong_chain.chain_id = "another-chain".into();
        contexts.push(wrong_chain);
        let mut wrong_market = fixture.context.clone();
        wrong_market.market_id = "ETH-USDT-PERP".into();
        contexts.push(wrong_market);
        let mut wrong_epoch = fixture.context.clone();
        wrong_epoch.epoch += 1;
        contexts.push(wrong_epoch);
        let mut wrong_height = fixture.context.clone();
        wrong_height.batch_height += 1;
        contexts.push(wrong_height);

        for context in contexts {
            assert!(
                verify_decryption_share(&fixture.public_keys, &context, &fixture.envelope, &share,)
                    .is_err()
            );
        }
    }

    #[test]
    fn duplicate_unknown_and_invalid_validator_shares_are_rejected() {
        let fixture = Fixture::new(PAYLOAD);
        let shares = fixture.shares();
        let duplicate = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert_eq!(
            decrypt_private_order(
                &fixture.public_keys,
                &fixture.context,
                &fixture.envelope,
                &duplicate,
            )
            .unwrap_err(),
            PrivateOrderError::DuplicateValidator(1)
        );

        let mut unknown = shares[0].clone();
        unknown.validator_id = 9;
        assert_eq!(
            verify_decryption_share(
                &fixture.public_keys,
                &fixture.context,
                &fixture.envelope,
                &unknown,
            )
            .unwrap_err(),
            PrivateOrderError::UnknownValidator(9)
        );

        let mut invalid = shares[0].clone();
        invalid.proof.response[0] ^= 1;
        assert!(matches!(
            verify_decryption_share(
                &fixture.public_keys,
                &fixture.context,
                &fixture.envelope,
                &invalid,
            ),
            Err(PrivateOrderError::InvalidDecryptionShare {
                validator_id: 1,
                ..
            })
        ));
    }

    #[test]
    fn payload_is_fixed_length_bounded_and_padded() {
        let short = Fixture::new(b"x");
        let long = Fixture::new(&vec![0x55; MAX_PRIVATE_ORDER_PAYLOAD_BYTES]);
        assert_eq!(
            short.envelope.encrypted_payload.len(),
            ENCRYPTED_PRIVATE_ORDER_BYTES
        );
        assert_eq!(
            long.envelope.encrypted_payload.len(),
            ENCRYPTED_PRIVATE_ORDER_BYTES
        );
        assert_eq!(
            short.envelope.fixed_crypto_size().unwrap(),
            FIXED_CRYPTO_ENVELOPE_BYTES
        );

        let context = short.context.clone();
        assert_eq!(
            encrypt_private_order(
                &short.public_keys,
                &context,
                [7; 32],
                [9; 32],
                &[],
                &mut OsRng,
            )
            .unwrap_err(),
            PrivateOrderError::EmptyPayload
        );
        let oversized = vec![0; MAX_PRIVATE_ORDER_PAYLOAD_BYTES + 1];
        assert_eq!(
            encrypt_private_order(
                &short.public_keys,
                &context,
                [7; 32],
                [9; 32],
                &oversized,
                &mut OsRng,
            )
            .unwrap_err(),
            PrivateOrderError::PayloadTooLarge {
                actual: MAX_PRIVATE_ORDER_PAYLOAD_BYTES + 1,
                maximum: MAX_PRIVATE_ORDER_PAYLOAD_BYTES,
            }
        );
    }

    #[test]
    fn envelope_keyset_and_decryption_share_have_stable_base64_serde() {
        let fixture = Fixture::new(PAYLOAD);
        let share = fixture.shares().remove(0);

        let envelope_json = serde_json::to_string(&fixture.envelope).unwrap();
        assert!(envelope_json.contains("\"encrypted_payload\":\""));
        assert!(envelope_json.contains("\"market_id\":\"BTC-USDT-PERP\""));
        let envelope: PrivateOrderEnvelope = serde_json::from_str(&envelope_json).unwrap();
        assert_eq!(envelope, fixture.envelope);

        let keys_json = serde_json::to_string(&fixture.public_keys).unwrap();
        let keys: ThresholdPublicKeySet = serde_json::from_str(&keys_json).unwrap();
        assert_eq!(keys, fixture.public_keys);
        keys.validate().unwrap();

        let share_json = serde_json::to_string(&share).unwrap();
        assert!(share_json.contains("\"shared_point\":\""));
        let decoded_share: VerifiableDecryptionShare = serde_json::from_str(&share_json).unwrap();
        assert_eq!(decoded_share, share);
        verify_decryption_share(
            &fixture.public_keys,
            &fixture.context,
            &fixture.envelope,
            &decoded_share,
        )
        .unwrap();
    }

    #[test]
    fn serde_rejects_wrong_fixed_lengths_and_unknown_fields() {
        let fixture = Fixture::new(PAYLOAD);
        let mut value = serde_json::to_value(&fixture.envelope).unwrap();
        value["encrypted_payload"] = serde_json::Value::String(STANDARD.encode([0_u8; 1]));
        assert!(serde_json::from_value::<PrivateOrderEnvelope>(value).is_err());

        let mut value = serde_json::to_value(&fixture.envelope).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PrivateOrderEnvelope>(value).is_err());
    }

    #[test]
    fn malformed_public_key_sets_are_rejected() {
        let fixture = Fixture::new(PAYLOAD);

        let mut inconsistent = fixture.public_keys.clone();
        inconsistent.validators[3].public_key = inconsistent.validators[2].public_key;
        assert!(matches!(
            inconsistent.validate(),
            Err(PrivateOrderError::InvalidKeySet(_))
        ));

        let mut wrong_key_id = fixture.public_keys.clone();
        wrong_key_id.key_id[0] ^= 1;
        assert!(matches!(
            wrong_key_id.validate(),
            Err(PrivateOrderError::InvalidKeySet(_))
        ));
    }
}
