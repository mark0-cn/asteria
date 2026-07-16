//! Authenticated and confidential transport primitives for threshold DKG.
//!
//! The FROST DKG implementation in [`crate::threshold_dkg`] deliberately
//! contains no networking.  This module defines the wire contract that a
//! real transport (Comet peer RPC, QUIC, or another authenticated channel)
//! can carry:
//!
//! * round-one messages are signed authenticated-broadcast envelopes;
//! * round-two messages are signed, recipient-bound X25519/XChaCha20-Poly1305
//!   envelopes; and
//! * every envelope is bound to the chain domain, ceremony id, epoch, round,
//!   and sender/recipient identities.
//!
//! The module intentionally does not open sockets or perform peer discovery.
//! It verifies the cryptographic and replay invariants at the boundary where
//! bytes enter the process.  A caller may therefore use any reliable network
//! while retaining one deterministic, auditable wire format.  This is a wire
//! contract, not a complete production ceremony: socket/RPC delivery,
//! authenticated peer discovery, HSM custody, and quorum orchestration remain
//! responsibilities of the deployment layer.

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::threshold_dkg::{DKG_PARTICIPANTS, DkgSession, Round1Message, Round2Message};

/// Version of the transport envelope, independent of the FROST package
/// format.  Incrementing it invalidates old wire messages.
pub const DKG_TRANSPORT_FORMAT_VERSION: u16 = 1;
pub const MAX_TRANSPORT_PAYLOAD_BYTES: usize = 16 * 1024;
pub const MAX_TRANSPORT_CIPHERTEXT_BYTES: usize = MAX_TRANSPORT_PAYLOAD_BYTES + 16;
pub const DEFAULT_REPLAY_GUARD_CAPACITY: usize = 4_096;
pub const DKG_BROADCAST_QUORUM: usize = 3;
const MAX_ENDORSEMENT_GUARD_ENTRIES: usize = DKG_PARTICIPANTS as usize;

const MAX_BROADCAST_ENVELOPE_BYTES: usize = MAX_TRANSPORT_PAYLOAD_BYTES.div_ceil(3) * 4 + 4_096;
const MAX_POINT_TO_POINT_ENVELOPE_BYTES: usize =
    MAX_TRANSPORT_CIPHERTEXT_BYTES.div_ceil(3) * 4 + 4_096;
const MAX_CERTIFIED_BROADCAST_BYTES: usize = MAX_BROADCAST_ENVELOPE_BYTES + 8_192;
// The tagged wire wrapper adds a small amount of JSON framing around the
// largest certified broadcast envelope.
const MAX_WIRE_MESSAGE_BYTES: usize = MAX_CERTIFIED_BROADCAST_BYTES + 512;
const MAX_ENDORSEMENT_GUARD_BYTES: usize = 1024 * 1024;

const TRANSPORT_SIGNING_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_DKG_TRANSPORT_SIGN_V1\0";
const TRANSPORT_KDF_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_DKG_TRANSPORT_KDF_V1\0";
const TRANSPORT_SESSION_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_DKG_TRANSPORT_SESSION_V1\0";
const TRANSPORT_REPLAY_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_DKG_TRANSPORT_REPLAY_V1\0";

/// DKG message round carried by a transport envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgTransportRound {
    Round1,
    Round2,
}

/// Public transport identity for one DKG participant.
///
/// The Ed25519 key authenticates messages.  The X25519 key is used only as a
/// static recipient key for the confidential round-two envelope.  The
/// private halves never appear in this type or on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgTransportPeer {
    pub validator_id: u16,
    #[serde(with = "base64_32")]
    pub signing_public_key: [u8; 32],
    #[serde(with = "base64_32")]
    pub encryption_public_key: [u8; 32],
}

impl DkgTransportPeer {
    pub fn validate(&self) -> Result<()> {
        validate_validator_id(self.validator_id)?;
        let verifying_key = VerifyingKey::from_bytes(&self.signing_public_key)
            .map_err(|error| DkgTransportError::InvalidPeer(error.to_string()))?;
        if verifying_key.is_weak() {
            return Err(DkgTransportError::InvalidPeer(
                "Ed25519 signing public key is weak".into(),
            ));
        }
        validate_x25519_public(&self.encryption_public_key)?;
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_canonical(self, 512, "transport peer")
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        let peer: Self = decode_canonical(bytes, 512, "transport peer")?;
        peer.validate()?;
        Ok(peer)
    }
}

/// Secret identity held by a validator while participating in a ceremony.
///
/// This type deliberately does not implement `Clone`, `Debug`, `Serialize`,
/// or `Deserialize`; callers should provision it from an HSM or a protected
/// secret store rather than copying it through a wire format.
pub struct DkgTransportIdentity {
    validator_id: u16,
    signing_key: SigningKey,
    encryption_secret: [u8; 32],
}

impl DkgTransportIdentity {
    /// Generates independent authentication and encryption keys.
    pub fn generate<R>(validator_id: u16, rng: &mut R) -> Result<Self>
    where
        R: CryptoRng + RngCore,
    {
        let mut signing_seed = [0_u8; 32];
        rng.fill_bytes(&mut signing_seed);
        let mut encryption_secret = [0_u8; 32];
        rng.fill_bytes(&mut encryption_secret);
        let result = Self::from_secrets(validator_id, signing_seed, encryption_secret);
        signing_seed.zeroize();
        encryption_secret.zeroize();
        result
    }

    /// Constructs an identity from already protected secret material.
    pub fn from_secrets(
        validator_id: u16,
        signing_seed: [u8; 32],
        encryption_secret: [u8; 32],
    ) -> Result<Self> {
        let signing_seed = Zeroizing::new(signing_seed);
        let encryption_secret = Zeroizing::new(encryption_secret);
        validate_validator_id(validator_id)?;
        if *signing_seed == [0; 32] || *encryption_secret == [0; 32] {
            return Err(DkgTransportError::InvalidPeer(
                "transport secret must not be zero".into(),
            ));
        }
        let signing_key = SigningKey::from_bytes(&signing_seed);
        Ok(Self {
            validator_id,
            signing_key,
            encryption_secret: *encryption_secret,
        })
    }

    pub fn validator_id(&self) -> u16 {
        self.validator_id
    }

    pub fn peer(&self) -> DkgTransportPeer {
        DkgTransportPeer {
            validator_id: self.validator_id,
            signing_public_key: self.signing_key.verifying_key().to_bytes(),
            encryption_public_key: X25519_BASEPOINT
                .mul_clamped(self.encryption_secret)
                .to_bytes(),
        }
    }
}

impl Drop for DkgTransportIdentity {
    fn drop(&mut self) {
        self.encryption_secret.zeroize();
    }
}

/// Registry used by a validator to authenticate the fixed ceremony
/// participant set.  A registry rejects duplicate ids and requires all four
/// threshold participants, so a caller cannot accidentally accept an
/// envelope signed by an unconfigured key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgTransportRegistry {
    peers: BTreeMap<u16, DkgTransportPeer>,
}

impl DkgTransportRegistry {
    pub fn new<I>(peers: I) -> Result<Self>
    where
        I: IntoIterator<Item = DkgTransportPeer>,
    {
        let mut registry = BTreeMap::new();
        for peer in peers {
            peer.validate()?;
            if registry.values().any(|existing: &DkgTransportPeer| {
                existing.signing_public_key == peer.signing_public_key
                    || MontgomeryPoint(existing.encryption_public_key)
                        == MontgomeryPoint(peer.encryption_public_key)
            }) {
                return Err(DkgTransportError::DuplicatePeerKey);
            }
            if registry.insert(peer.validator_id, peer).is_some() {
                return Err(DkgTransportError::DuplicatePeer);
            }
        }
        if registry.len() != usize::from(DKG_PARTICIPANTS)
            || (1..=DKG_PARTICIPANTS).any(|id| !registry.contains_key(&id))
        {
            return Err(DkgTransportError::InvalidPeer(
                "registry must contain validator ids 1 through 4".into(),
            ));
        }
        Ok(Self { peers: registry })
    }

    pub fn peer(&self, validator_id: u16) -> Result<&DkgTransportPeer> {
        self.peers
            .get(&validator_id)
            .ok_or(DkgTransportError::UnknownPeer(validator_id))
    }

    pub fn peers(&self) -> impl Iterator<Item = &DkgTransportPeer> {
        self.peers.values()
    }
}

/// Signed public round-one envelope.  The payload is normally the canonical
/// encoding of [`Round1Message`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedBroadcastEnvelope {
    pub version: u16,
    pub session: DkgSession,
    pub round: DkgTransportRound,
    pub sender_id: u16,
    #[serde(with = "base64_32")]
    pub message_id: [u8; 32],
    #[serde(with = "base64_32")]
    pub sender_signing_public_key: [u8; 32],
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
    #[serde(with = "base64_64")]
    pub signature: [u8; 64],
}

impl AuthenticatedBroadcastEnvelope {
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_canonical(self, MAX_BROADCAST_ENVELOPE_BYTES, "broadcast envelope")
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        let envelope: Self =
            decode_canonical(bytes, MAX_BROADCAST_ENVELOPE_BYTES, "broadcast envelope")?;
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> Result<()> {
        validate_common_header(
            self.version,
            &self.session,
            self.round,
            self.sender_id,
            None,
        )?;
        if self.round != DkgTransportRound::Round1 {
            return Err(DkgTransportError::WrongRound);
        }
        if self.message_id == [0; 32] {
            return Err(DkgTransportError::InvalidMessageId);
        }
        if self.payload.is_empty() || self.payload.len() > MAX_TRANSPORT_PAYLOAD_BYTES {
            return Err(DkgTransportError::MessageTooLarge {
                actual: self.payload.len(),
                maximum: MAX_TRANSPORT_PAYLOAD_BYTES,
            });
        }
        VerifyingKey::from_bytes(&self.sender_signing_public_key)
            .map_err(|error| DkgTransportError::InvalidPeer(error.to_string()))?;
        Ok(())
    }
}

/// A validator's strict signature over one round-one broadcast digest.
/// Collecting three endorsements forms a quorum certificate for the
/// authenticated-broadcast value under the four-validator/one-fault model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BroadcastEndorsement {
    pub version: u16,
    pub session: DkgSession,
    pub round: DkgTransportRound,
    /// The validator whose round-one package is being endorsed.
    pub sender_id: u16,
    #[serde(with = "base64_32")]
    pub message_id: [u8; 32],
    #[serde(with = "base64_32")]
    pub payload_digest: [u8; 32],
    pub endorser_id: u16,
    #[serde(with = "base64_32")]
    pub endorser_signing_public_key: [u8; 32],
    #[serde(with = "base64_64")]
    pub signature: [u8; 64],
}

impl BroadcastEndorsement {
    fn validate(&self) -> Result<()> {
        validate_common_header(
            self.version,
            &self.session,
            self.round,
            self.sender_id,
            None,
        )?;
        if self.round != DkgTransportRound::Round1 {
            return Err(DkgTransportError::WrongRound);
        }
        validate_validator_id(self.endorser_id)?;
        if self.message_id == [0; 32] || self.payload_digest == [0; 32] {
            return Err(DkgTransportError::InvalidMessageId);
        }
        let verifying_key = VerifyingKey::from_bytes(&self.endorser_signing_public_key)
            .map_err(|error| DkgTransportError::InvalidPeer(error.to_string()))?;
        if verifying_key.is_weak() {
            return Err(DkgTransportError::InvalidPeer(
                "Ed25519 signing public key is weak".into(),
            ));
        }
        Ok(())
    }
}

/// A round-one envelope plus the endorsements needed for a consistent
/// authenticated-broadcast delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedBroadcastEnvelope {
    pub envelope: AuthenticatedBroadcastEnvelope,
    pub endorsements: Vec<BroadcastEndorsement>,
}

impl CertifiedBroadcastEnvelope {
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        encode_canonical(
            self,
            MAX_CERTIFIED_BROADCAST_BYTES,
            "certified broadcast envelope",
        )
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        let certificate: Self = decode_canonical(
            bytes,
            MAX_CERTIFIED_BROADCAST_BYTES,
            "certified broadcast envelope",
        )?;
        certificate.validate_structure()?;
        Ok(certificate)
    }

    fn validate_structure(&self) -> Result<()> {
        self.envelope.validate()?;
        if self.envelope.round != DkgTransportRound::Round1 {
            return Err(DkgTransportError::WrongRound);
        }
        if self.endorsements.len() < DKG_BROADCAST_QUORUM
            || self.endorsements.len() > usize::from(DKG_PARTICIPANTS)
        {
            return Err(DkgTransportError::InsufficientEndorsements {
                expected: DKG_BROADCAST_QUORUM,
                actual: self.endorsements.len(),
            });
        }
        let mut previous = None;
        for endorsement in &self.endorsements {
            endorsement.validate()?;
            if let Some(previous_id) = previous {
                if endorsement.endorser_id == previous_id {
                    return Err(DkgTransportError::DuplicateEndorser {
                        endorser_id: endorsement.endorser_id,
                    });
                }
                if endorsement.endorser_id < previous_id {
                    return Err(DkgTransportError::EndorsementOrder);
                }
            }
            previous = Some(endorsement.endorser_id);
        }
        Ok(())
    }
}

/// Per-endorser anti-equivocation state.  A validator must retain this guard
/// for the lifetime of a ceremony; it refuses to sign two different values
/// for the same original sender and session.
#[derive(Debug, PartialEq, Eq)]
pub struct DkgBroadcastEndorsementGuard {
    endorser_id: u16,
    endorser_signing_public_key: [u8; 32],
    capacity: usize,
    accepted: BTreeMap<[u8; 32], BroadcastEndorsement>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndorsementGuardJournal {
    version: u16,
    endorser_id: u16,
    #[serde(with = "base64_32")]
    endorser_signing_public_key: [u8; 32],
    capacity: usize,
    entries: Vec<EndorsementGuardEntry>,
    #[serde(with = "base64_64")]
    signature: [u8; 64],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndorsementGuardEntry {
    #[serde(with = "base64_32")]
    subject: [u8; 32],
    endorsement: BroadcastEndorsement,
}

#[derive(Serialize)]
struct EndorsementGuardSigningBody<'a> {
    domain: &'static str,
    version: u16,
    endorser_id: u16,
    endorser_signing_public_key: &'a [u8; 32],
    capacity: usize,
    entries: &'a [EndorsementGuardEntry],
}

impl DkgBroadcastEndorsementGuard {
    pub fn new(endorser: &DkgTransportPeer) -> Result<Self> {
        Self::with_capacity(endorser, MAX_ENDORSEMENT_GUARD_ENTRIES)
    }

    pub fn with_capacity(endorser: &DkgTransportPeer, capacity: usize) -> Result<Self> {
        endorser.validate()?;
        if capacity == 0 || capacity > MAX_ENDORSEMENT_GUARD_ENTRIES {
            return Err(DkgTransportError::InvalidGuardCapacity {
                maximum: MAX_ENDORSEMENT_GUARD_ENTRIES,
                actual: capacity,
            });
        }
        Ok(Self {
            endorser_id: endorser.validator_id,
            endorser_signing_public_key: endorser.signing_public_key,
            capacity: capacity.max(1),
            accepted: BTreeMap::new(),
        })
    }

    pub fn endorser_id(&self) -> u16 {
        self.endorser_id
    }

    /// Serializes an authenticated anti-equivocation journal for durable
    /// storage. The caller must atomically persist the returned bytes before
    /// publishing a newly created endorsement, and use append-only storage to
    /// prevent rollback to an older valid journal.
    pub fn to_canonical_json(&self, identity: &DkgTransportIdentity) -> Result<Vec<u8>> {
        if identity.validator_id() != self.endorser_id {
            return Err(DkgTransportError::WrongEndorser {
                expected: self.endorser_id,
                actual: identity.validator_id(),
            });
        }
        let peer = identity.peer();
        if peer.signing_public_key != self.endorser_signing_public_key {
            return Err(DkgTransportError::InvalidPeer(
                "endorsement journal identity does not match the guard signing key".into(),
            ));
        }
        let entries = self
            .accepted
            .iter()
            .map(|(subject, endorsement)| EndorsementGuardEntry {
                subject: *subject,
                endorsement: endorsement.clone(),
            })
            .collect::<Vec<_>>();
        let body = EndorsementGuardSigningBody {
            domain: "endorsement_guard_journal",
            version: DKG_TRANSPORT_FORMAT_VERSION,
            endorser_id: self.endorser_id,
            endorser_signing_public_key: &self.endorser_signing_public_key,
            capacity: self.capacity,
            entries: &entries,
        };
        let signature = identity.signing_key.sign(&signing_bytes(&body)?).to_bytes();
        let journal = EndorsementGuardJournal {
            version: DKG_TRANSPORT_FORMAT_VERSION,
            endorser_id: self.endorser_id,
            endorser_signing_public_key: self.endorser_signing_public_key,
            capacity: self.capacity,
            entries,
            signature,
        };
        encode_canonical(
            &journal,
            MAX_ENDORSEMENT_GUARD_BYTES,
            "endorsement guard journal",
        )
    }

    pub fn from_canonical_json(bytes: &[u8], expected_peer: &DkgTransportPeer) -> Result<Self> {
        let journal: EndorsementGuardJournal = decode_canonical(
            bytes,
            MAX_ENDORSEMENT_GUARD_BYTES,
            "endorsement guard journal",
        )?;
        if journal.version != DKG_TRANSPORT_FORMAT_VERSION {
            return Err(DkgTransportError::Serialization(format!(
                "unsupported endorsement guard version {}",
                journal.version
            )));
        }
        expected_peer.validate()?;
        if expected_peer.validator_id != journal.endorser_id
            || expected_peer.signing_public_key != journal.endorser_signing_public_key
        {
            return Err(DkgTransportError::InvalidPeer(
                "endorsement journal signer does not match the expected peer".into(),
            ));
        }
        let body = EndorsementGuardSigningBody {
            domain: "endorsement_guard_journal",
            version: journal.version,
            endorser_id: journal.endorser_id,
            endorser_signing_public_key: &journal.endorser_signing_public_key,
            capacity: journal.capacity,
            entries: &journal.entries,
        };
        let verifying_key = VerifyingKey::from_bytes(&expected_peer.signing_public_key)
            .map_err(|error| DkgTransportError::InvalidPeer(error.to_string()))?;
        verifying_key
            .verify_strict(
                &signing_bytes(&body)?,
                &Signature::from_bytes(&journal.signature),
            )
            .map_err(|_| DkgTransportError::InvalidSignature)?;
        let mut guard = Self::with_capacity(expected_peer, journal.capacity)?;
        if journal.entries.len() > journal.capacity {
            return Err(DkgTransportError::ReplayGuardFull {
                capacity: journal.capacity,
            });
        }
        let mut previous = None;
        for entry in journal.entries {
            if entry.subject == [0; 32] {
                return Err(DkgTransportError::InvalidEndorsement);
            }
            if previous.is_some_and(|subject| subject >= entry.subject) {
                return Err(DkgTransportError::NonCanonical("endorsement guard journal"));
            }
            previous = Some(entry.subject);
            entry.endorsement.validate()?;
            if entry.endorsement.endorser_id != journal.endorser_id
                || entry.endorsement.endorser_signing_public_key
                    != journal.endorser_signing_public_key
            {
                return Err(DkgTransportError::InvalidEndorsement);
            }
            let subject = endorsement_subject_key(
                &entry.endorsement.session,
                entry.endorsement.round,
                entry.endorsement.sender_id,
                entry.endorsement.endorser_id,
            )?;
            if subject != entry.subject {
                return Err(DkgTransportError::InvalidEndorsement);
            }
            verify_endorsement_signature(expected_peer, &entry.endorsement)?;
            if guard
                .accepted
                .insert(entry.subject, entry.endorsement)
                .is_some()
            {
                return Err(DkgTransportError::InvalidEndorsement);
            }
        }
        Ok(guard)
    }

    fn existing(
        &self,
        session: &DkgSession,
        round: DkgTransportRound,
        sender_id: u16,
        digest: [u8; 32],
    ) -> Result<Option<BroadcastEndorsement>> {
        let key = endorsement_subject_key(session, round, sender_id, self.endorser_id)?;
        match self.accepted.get(&key) {
            Some(previous) if previous.payload_digest == digest => Ok(Some(previous.clone())),
            Some(_) => Err(DkgTransportError::Equivocation { sender_id }),
            None => Ok(None),
        }
    }

    fn record(
        &mut self,
        session: &DkgSession,
        round: DkgTransportRound,
        sender_id: u16,
        endorsement: BroadcastEndorsement,
    ) -> Result<BroadcastEndorsement> {
        let key = endorsement_subject_key(session, round, sender_id, self.endorser_id)?;
        if let Some(previous) = self.accepted.get(&key) {
            if previous.payload_digest == endorsement.payload_digest {
                return Ok(previous.clone());
            }
            return Err(DkgTransportError::Equivocation { sender_id });
        }
        if self.accepted.len() >= self.capacity {
            return Err(DkgTransportError::ReplayGuardFull {
                capacity: self.capacity,
            });
        }
        endorsement.validate()?;
        if endorsement.endorser_id != self.endorser_id
            || endorsement.endorser_signing_public_key != self.endorser_signing_public_key
        {
            return Err(DkgTransportError::InvalidEndorsement);
        }
        self.accepted.insert(key, endorsement.clone());
        Ok(endorsement)
    }
}

/// Signed and encrypted recipient-specific round-two envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedPointToPointEnvelope {
    pub version: u16,
    pub session: DkgSession,
    pub round: DkgTransportRound,
    pub sender_id: u16,
    pub recipient_id: u16,
    #[serde(with = "base64_32")]
    pub message_id: [u8; 32],
    #[serde(with = "base64_32")]
    pub sender_signing_public_key: [u8; 32],
    #[serde(with = "base64_32")]
    pub sender_encryption_public_key: [u8; 32],
    #[serde(with = "base64_32")]
    pub recipient_encryption_public_key: [u8; 32],
    #[serde(with = "base64_32")]
    pub ephemeral_public_key: [u8; 32],
    #[serde(with = "base64_24")]
    pub nonce: [u8; 24],
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "base64_64")]
    pub signature: [u8; 64],
}

impl EncryptedPointToPointEnvelope {
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_canonical(
            self,
            MAX_POINT_TO_POINT_ENVELOPE_BYTES,
            "point-to-point envelope",
        )
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        let envelope: Self = decode_canonical(
            bytes,
            MAX_POINT_TO_POINT_ENVELOPE_BYTES,
            "point-to-point envelope",
        )?;
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> Result<()> {
        validate_common_header(
            self.version,
            &self.session,
            self.round,
            self.sender_id,
            Some(self.recipient_id),
        )?;
        if self.round != DkgTransportRound::Round2 {
            return Err(DkgTransportError::WrongRound);
        }
        if self.sender_id == self.recipient_id {
            return Err(DkgTransportError::SelfMessage);
        }
        if self.message_id == [0; 32] {
            return Err(DkgTransportError::InvalidMessageId);
        }
        if self.ciphertext.len() < 16 || self.ciphertext.len() > MAX_TRANSPORT_CIPHERTEXT_BYTES {
            return Err(DkgTransportError::MessageTooLarge {
                actual: self.ciphertext.len(),
                maximum: MAX_TRANSPORT_CIPHERTEXT_BYTES,
            });
        }
        validate_x25519_public(&self.sender_encryption_public_key)?;
        validate_x25519_public(&self.recipient_encryption_public_key)?;
        validate_x25519_public(&self.ephemeral_public_key)?;
        let verifying_key = VerifyingKey::from_bytes(&self.sender_signing_public_key)
            .map_err(|error| DkgTransportError::InvalidPeer(error.to_string()))?;
        if verifying_key.is_weak() {
            return Err(DkgTransportError::InvalidPeer(
                "Ed25519 signing public key is weak".into(),
            ));
        }
        Ok(())
    }
}

/// A wire-level envelope, useful when a transport uses one stream for both
/// DKG rounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "envelope",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DkgWireMessage {
    Broadcast(AuthenticatedBroadcastEnvelope),
    CertifiedBroadcast(CertifiedBroadcastEnvelope),
    PointToPoint(EncryptedPointToPointEnvelope),
}

impl DkgWireMessage {
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        match self {
            Self::Broadcast(envelope) => envelope.validate()?,
            Self::CertifiedBroadcast(certificate) => certificate.validate_structure()?,
            Self::PointToPoint(envelope) => envelope.validate()?,
        }
        encode_canonical(self, MAX_WIRE_MESSAGE_BYTES, "transport envelope")
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        let message: Self = decode_canonical(bytes, MAX_WIRE_MESSAGE_BYTES, "transport envelope")?;
        match &message {
            Self::Broadcast(envelope) => envelope.validate()?,
            Self::CertifiedBroadcast(certificate) => certificate.validate_structure()?,
            Self::PointToPoint(envelope) => envelope.validate()?,
        }
        Ok(message)
    }
}

/// Bounded replay cache. The key includes the complete ceremony context and
/// both transport endpoints, so a message id cannot be replayed across a
/// chain, epoch, round, sender, or recipient.
///
/// This cache is process-local. A coordinator that crashes must either restore
/// its complete authenticated transcript atomically or abandon the ceremony
/// and start a fresh ceremony id; restoring this cache alone is not sufficient.
#[derive(Debug, PartialEq, Eq)]
pub struct DkgReplayGuard {
    capacity: usize,
    accepted: BTreeSet<[u8; 32]>,
}

impl Default for DkgReplayGuard {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_GUARD_CAPACITY)
    }
}

impl DkgReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.clamp(1, DEFAULT_REPLAY_GUARD_CAPACITY),
            accepted: BTreeSet::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > DEFAULT_REPLAY_GUARD_CAPACITY {
            return Err(DkgTransportError::InvalidGuardCapacity {
                maximum: DEFAULT_REPLAY_GUARD_CAPACITY,
                actual: capacity,
            });
        }
        Ok(Self {
            capacity,
            accepted: BTreeSet::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }

    pub fn contains(
        &self,
        session: &DkgSession,
        round: DkgTransportRound,
        sender_id: u16,
        recipient_id: Option<u16>,
        message_id: [u8; 32],
    ) -> Result<bool> {
        let key = replay_key(session, round, sender_id, recipient_id, message_id)?;
        Ok(self.accepted.contains(&key))
    }

    pub fn check_and_record(
        &mut self,
        session: &DkgSession,
        round: DkgTransportRound,
        sender_id: u16,
        recipient_id: Option<u16>,
        message_id: [u8; 32],
    ) -> Result<()> {
        if message_id == [0; 32] {
            return Err(DkgTransportError::InvalidMessageId);
        }
        let key = replay_key(session, round, sender_id, recipient_id, message_id)?;
        if self.accepted.contains(&key) {
            return Err(DkgTransportError::ReplayDetected);
        }
        if self.accepted.len() >= self.capacity {
            return Err(DkgTransportError::ReplayGuardFull {
                capacity: self.capacity,
            });
        }
        self.accepted.insert(key);
        Ok(())
    }
}

/// Local authenticated-broadcast transcript.  It accepts at most one signed
/// value per validator and surfaces locally observed equivocation evidence.
/// The deployment transport must still gossip signed envelopes or run a
/// reliable-broadcast protocol to ensure every honest validator observes the
/// same value; this local collector does not make that network-level claim.
pub struct DkgBroadcastTranscript {
    session: DkgSession,
    round: DkgTransportRound,
    peers: DkgTransportRegistry,
    messages: BTreeMap<u16, AuthenticatedBroadcastEnvelope>,
    replay_guard: DkgReplayGuard,
}

/// Ceremony round-one collector that accepts only quorum-certified FROST
/// packages.  Once all four certificates are present, each validator can pass
/// its three returned peer packages directly to `participant_round2`.
pub struct DkgCertifiedBroadcastTranscript {
    session: DkgSession,
    peers: DkgTransportRegistry,
    certificates: BTreeMap<u16, CertifiedBroadcastEnvelope>,
    messages: BTreeMap<u16, Round1Message>,
    replay_guard: DkgReplayGuard,
}

impl DkgCertifiedBroadcastTranscript {
    pub fn new(session: DkgSession, peers: DkgTransportRegistry) -> Result<Self> {
        session.validate().map_err(transport_session_error)?;
        Ok(Self {
            session,
            peers,
            certificates: BTreeMap::new(),
            messages: BTreeMap::new(),
            replay_guard: DkgReplayGuard::default(),
        })
    }

    pub fn accept(&mut self, certificate: CertifiedBroadcastEnvelope) -> Result<Round1Message> {
        if self.replay_guard.contains(
            &self.session,
            DkgTransportRound::Round1,
            certificate.envelope.sender_id,
            None,
            certificate.envelope.message_id,
        )? && self
            .certificates
            .get(&certificate.envelope.sender_id)
            .is_none_or(|existing| existing == &certificate)
        {
            return Err(DkgTransportError::ReplayDetected);
        }
        let message = open_certified_round1_broadcast(&self.session, &self.peers, &certificate)?;
        if let Some(existing) = self.certificates.get(&certificate.envelope.sender_id) {
            if existing.envelope == certificate.envelope {
                return Err(DkgTransportError::ReplayDetected);
            }
            return Err(DkgTransportError::Equivocation {
                sender_id: certificate.envelope.sender_id,
            });
        }
        self.replay_guard.check_and_record(
            &self.session,
            DkgTransportRound::Round1,
            certificate.envelope.sender_id,
            None,
            certificate.envelope.message_id,
        )?;
        self.messages.insert(message.sender_id, message.clone());
        self.certificates
            .insert(certificate.envelope.sender_id, certificate);
        Ok(message)
    }

    pub fn is_complete(&self) -> bool {
        self.messages.len() == usize::from(DKG_PARTICIPANTS)
    }

    pub fn incoming_for(&self, validator_id: u16) -> Result<Vec<Round1Message>> {
        validate_validator_id(validator_id)?;
        if !self.is_complete() {
            return Err(DkgTransportError::Incomplete {
                expected: usize::from(DKG_PARTICIPANTS),
                actual: self.messages.len(),
            });
        }
        Ok(self
            .messages
            .iter()
            .filter(|(sender_id, _)| **sender_id != validator_id)
            .map(|(_, message)| message.clone())
            .collect())
    }
}

impl DkgBroadcastTranscript {
    pub fn new(
        session: DkgSession,
        round: DkgTransportRound,
        peers: DkgTransportRegistry,
    ) -> Result<Self> {
        session.validate().map_err(transport_session_error)?;
        if round != DkgTransportRound::Round1 {
            return Err(DkgTransportError::WrongRound);
        }
        Ok(Self {
            session,
            round,
            peers,
            messages: BTreeMap::new(),
            replay_guard: DkgReplayGuard::default(),
        })
    }

    pub fn accept(&mut self, envelope: AuthenticatedBroadcastEnvelope) -> Result<Vec<u8>> {
        let peer = self.peers.peer(envelope.sender_id)?;
        if self.replay_guard.contains(
            &self.session,
            self.round,
            envelope.sender_id,
            None,
            envelope.message_id,
        )? && self
            .messages
            .get(&envelope.sender_id)
            .is_none_or(|existing| existing == &envelope)
        {
            return Err(DkgTransportError::ReplayDetected);
        }
        verify_broadcast(&self.session, self.round, peer, &envelope)?;
        let message = Round1Message::from_canonical_json(&envelope.payload)
            .map_err(|error| DkgTransportError::Serialization(error.to_string()))?;
        if message.session != self.session {
            return Err(DkgTransportError::WrongSession);
        }
        if message.sender_id != envelope.sender_id {
            return Err(DkgTransportError::WrongSender {
                expected: envelope.sender_id,
                actual: message.sender_id,
            });
        }
        if self.messages.contains_key(&envelope.sender_id) {
            let existing = self
                .messages
                .get(&envelope.sender_id)
                .expect("checked above");
            if existing == &envelope {
                return Err(DkgTransportError::ReplayDetected);
            }
            return Err(DkgTransportError::Equivocation {
                sender_id: envelope.sender_id,
            });
        }
        self.replay_guard.check_and_record(
            &self.session,
            self.round,
            envelope.sender_id,
            None,
            envelope.message_id,
        )?;
        let payload = envelope.payload.clone();
        self.messages.insert(envelope.sender_id, envelope);
        Ok(payload)
    }

    pub fn is_complete(&self) -> bool {
        self.messages.len() == usize::from(DKG_PARTICIPANTS)
    }

    pub fn payloads(&self) -> Result<Vec<Vec<u8>>> {
        if !self.is_complete() {
            return Err(DkgTransportError::Incomplete {
                expected: usize::from(DKG_PARTICIPANTS),
                actual: self.messages.len(),
            });
        }
        Ok(self
            .messages
            .values()
            .map(|message| message.payload.clone())
            .collect())
    }

    pub fn messages(&self) -> impl Iterator<Item = &AuthenticatedBroadcastEnvelope> {
        self.messages.values()
    }
}

/// Recipient-side round-two inbox.  It verifies signatures, decrypts only
/// messages addressed to the local identity, and detects sender equivocation.
pub struct DkgPointToPointInbox {
    session: DkgSession,
    recipient_id: u16,
    peers: DkgTransportRegistry,
    messages: BTreeMap<u16, EncryptedPointToPointEnvelope>,
    plaintexts: BTreeMap<u16, Zeroizing<Vec<u8>>>,
    replay_guard: DkgReplayGuard,
}

impl DkgPointToPointInbox {
    pub fn new(
        session: DkgSession,
        recipient_id: u16,
        peers: DkgTransportRegistry,
    ) -> Result<Self> {
        session.validate().map_err(transport_session_error)?;
        validate_validator_id(recipient_id)?;
        peers.peer(recipient_id)?;
        Ok(Self {
            session,
            recipient_id,
            peers,
            messages: BTreeMap::new(),
            plaintexts: BTreeMap::new(),
            replay_guard: DkgReplayGuard::default(),
        })
    }

    pub fn accept(
        &mut self,
        identity: &DkgTransportIdentity,
        envelope: EncryptedPointToPointEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if identity.validator_id() != self.recipient_id {
            return Err(DkgTransportError::WrongRecipient {
                expected: self.recipient_id,
                actual: identity.validator_id(),
            });
        }
        let registered_recipient = self.peers.peer(self.recipient_id)?;
        if identity.peer() != *registered_recipient {
            return Err(DkgTransportError::InvalidPeer(
                "recipient identity does not match the registered transport key".into(),
            ));
        }
        if self.replay_guard.contains(
            &self.session,
            DkgTransportRound::Round2,
            envelope.sender_id,
            Some(self.recipient_id),
            envelope.message_id,
        )? && self
            .messages
            .get(&envelope.sender_id)
            .is_none_or(|existing| existing == &envelope)
        {
            return Err(DkgTransportError::ReplayDetected);
        }
        let peer = self.peers.peer(envelope.sender_id)?;
        let payload = open_point_to_point(
            &self.session,
            DkgTransportRound::Round2,
            identity,
            peer,
            &envelope,
        )?;
        let message = Round2Message::from_canonical_json(&payload)
            .map_err(|error| DkgTransportError::Serialization(error.to_string()))?;
        if message.session != self.session {
            return Err(DkgTransportError::WrongSession);
        }
        if message.sender_id != envelope.sender_id {
            return Err(DkgTransportError::WrongSender {
                expected: envelope.sender_id,
                actual: message.sender_id,
            });
        }
        if message.recipient_id != envelope.recipient_id {
            return Err(DkgTransportError::WrongRecipient {
                expected: envelope.recipient_id,
                actual: message.recipient_id,
            });
        }
        if let Some(existing) = self.messages.get(&envelope.sender_id) {
            if existing == &envelope {
                return Err(DkgTransportError::ReplayDetected);
            }
            return Err(DkgTransportError::Equivocation {
                sender_id: envelope.sender_id,
            });
        }
        self.replay_guard.check_and_record(
            &self.session,
            DkgTransportRound::Round2,
            envelope.sender_id,
            Some(self.recipient_id),
            envelope.message_id,
        )?;
        self.plaintexts.insert(envelope.sender_id, payload.clone());
        self.messages.insert(envelope.sender_id, envelope);
        Ok(payload)
    }

    pub fn is_complete(&self) -> bool {
        self.messages.len() == usize::from(DKG_PARTICIPANTS - 1)
    }

    pub fn payloads(&self) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        if !self.is_complete() {
            return Err(DkgTransportError::Incomplete {
                expected: usize::from(DKG_PARTICIPANTS - 1),
                actual: self.messages.len(),
            });
        }
        Ok(self.plaintexts.values().cloned().collect())
    }
}

/// Signs a public broadcast payload for a bound DKG session.
pub fn seal_broadcast<R>(
    session: &DkgSession,
    round: DkgTransportRound,
    identity: &DkgTransportIdentity,
    payload: &[u8],
    rng: &mut R,
) -> Result<AuthenticatedBroadcastEnvelope>
where
    R: CryptoRng + RngCore,
{
    session.validate().map_err(transport_session_error)?;
    if round != DkgTransportRound::Round1 {
        return Err(DkgTransportError::WrongRound);
    }
    validate_validator_id(identity.validator_id)?;
    if payload.is_empty() || payload.len() > MAX_TRANSPORT_PAYLOAD_BYTES {
        return Err(DkgTransportError::MessageTooLarge {
            actual: payload.len(),
            maximum: MAX_TRANSPORT_PAYLOAD_BYTES,
        });
    }
    let mut message_id = [0_u8; 32];
    fill_nonzero(rng, &mut message_id);
    let peer = identity.peer();
    let body = BroadcastSigningBody {
        domain: "authenticated_broadcast",
        version: DKG_TRANSPORT_FORMAT_VERSION,
        session,
        round,
        sender_id: identity.validator_id,
        message_id: &message_id,
        sender_signing_public_key: &peer.signing_public_key,
        payload,
    };
    let signing_bytes = signing_bytes(&body)?;
    let signature = identity.signing_key.sign(&signing_bytes).to_bytes();
    Ok(AuthenticatedBroadcastEnvelope {
        version: DKG_TRANSPORT_FORMAT_VERSION,
        session: session.clone(),
        round,
        sender_id: identity.validator_id,
        message_id,
        sender_signing_public_key: peer.signing_public_key,
        payload: payload.to_vec(),
        signature,
    })
}

/// Verifies a signed broadcast against the configured validator key.
pub fn verify_broadcast(
    expected_session: &DkgSession,
    expected_round: DkgTransportRound,
    expected_peer: &DkgTransportPeer,
    envelope: &AuthenticatedBroadcastEnvelope,
) -> Result<()> {
    envelope.validate()?;
    expected_session
        .validate()
        .map_err(transport_session_error)?;
    if &envelope.session != expected_session {
        return Err(DkgTransportError::WrongSession);
    }
    if envelope.round != expected_round {
        return Err(DkgTransportError::WrongRound);
    }
    if envelope.sender_id != expected_peer.validator_id {
        return Err(DkgTransportError::WrongSender {
            expected: expected_peer.validator_id,
            actual: envelope.sender_id,
        });
    }
    expected_peer.validate()?;
    if envelope.sender_signing_public_key != expected_peer.signing_public_key {
        return Err(DkgTransportError::InvalidPeer(
            "sender signing key is not the registered key".into(),
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(&expected_peer.signing_public_key)
        .map_err(|error| DkgTransportError::InvalidPeer(error.to_string()))?;
    let signature = Signature::from_bytes(&envelope.signature);
    let body = BroadcastSigningBody {
        domain: "authenticated_broadcast",
        version: envelope.version,
        session: &envelope.session,
        round: envelope.round,
        sender_id: envelope.sender_id,
        message_id: &envelope.message_id,
        sender_signing_public_key: &envelope.sender_signing_public_key,
        payload: &envelope.payload,
    };
    verifying_key
        .verify_strict(&signing_bytes(&body)?, &signature)
        .map_err(|_| DkgTransportError::InvalidSignature)
}

/// Signs one authenticated-broadcast value as an endorsement.  The caller
/// must keep `guard` across the whole ceremony so a validator cannot endorse
/// two conflicting values for the same original sender.
pub fn endorse_broadcast(
    session: &DkgSession,
    endorser: &DkgTransportIdentity,
    registry: &DkgTransportRegistry,
    envelope: &AuthenticatedBroadcastEnvelope,
    guard: &mut DkgBroadcastEndorsementGuard,
) -> Result<BroadcastEndorsement> {
    let original_sender = registry.peer(envelope.sender_id)?;
    envelope.validate()?;
    if guard.endorser_id != endorser.validator_id {
        return Err(DkgTransportError::WrongEndorser {
            expected: guard.endorser_id,
            actual: endorser.validator_id,
        });
    }
    let peer = endorser.peer();
    if guard.endorser_signing_public_key != peer.signing_public_key {
        return Err(DkgTransportError::InvalidPeer(
            "endorser identity does not match the guard signing key".into(),
        ));
    }
    let digest = broadcast_content_digest(envelope)?;
    if let Some(existing) = guard.existing(
        session,
        DkgTransportRound::Round1,
        envelope.sender_id,
        digest,
    )? {
        return Ok(existing);
    }
    verify_broadcast(
        session,
        DkgTransportRound::Round1,
        original_sender,
        envelope,
    )?;
    let message = Round1Message::from_canonical_json(&envelope.payload)
        .map_err(|error| DkgTransportError::Serialization(error.to_string()))?;
    if &message.session != session {
        return Err(DkgTransportError::WrongSession);
    }
    if message.sender_id != envelope.sender_id {
        return Err(DkgTransportError::WrongSender {
            expected: envelope.sender_id,
            actual: message.sender_id,
        });
    }
    let body = BroadcastEndorsementSigningBody {
        domain: "authenticated_broadcast_endorsement",
        version: DKG_TRANSPORT_FORMAT_VERSION,
        session,
        round: DkgTransportRound::Round1,
        sender_id: envelope.sender_id,
        message_id: &envelope.message_id,
        payload_digest: &digest,
        endorser_id: endorser.validator_id,
        endorser_signing_public_key: &peer.signing_public_key,
    };
    let signature = endorser.signing_key.sign(&signing_bytes(&body)?).to_bytes();
    let endorsement = BroadcastEndorsement {
        version: DKG_TRANSPORT_FORMAT_VERSION,
        session: session.clone(),
        round: DkgTransportRound::Round1,
        sender_id: envelope.sender_id,
        message_id: envelope.message_id,
        payload_digest: digest,
        endorser_id: endorser.validator_id,
        endorser_signing_public_key: peer.signing_public_key,
        signature,
    };
    guard.record(
        session,
        DkgTransportRound::Round1,
        envelope.sender_id,
        endorsement,
    )
}

/// Builds a canonical certificate from endorsements gathered over the
/// network.  Verification against the validator registry is performed by
/// [`verify_certified_broadcast`].
pub fn make_broadcast_certificate(
    envelope: AuthenticatedBroadcastEnvelope,
    mut endorsements: Vec<BroadcastEndorsement>,
) -> Result<CertifiedBroadcastEnvelope> {
    endorsements.sort_by_key(|endorsement| endorsement.endorser_id);
    let certificate = CertifiedBroadcastEnvelope {
        envelope,
        endorsements,
    };
    certificate.validate_structure()?;
    Ok(certificate)
}

/// Verifies a 3-of-4 signed broadcast certificate and returns its payload.
pub fn verify_certified_broadcast(
    expected_session: &DkgSession,
    registry: &DkgTransportRegistry,
    certificate: &CertifiedBroadcastEnvelope,
) -> Result<Vec<u8>> {
    certificate.validate_structure()?;
    let original_sender = registry.peer(certificate.envelope.sender_id)?;
    verify_broadcast(
        expected_session,
        DkgTransportRound::Round1,
        original_sender,
        &certificate.envelope,
    )?;
    let digest = broadcast_content_digest(&certificate.envelope)?;
    let mut verified = BTreeSet::new();
    for endorsement in &certificate.endorsements {
        if &endorsement.session != expected_session
            || endorsement.round != DkgTransportRound::Round1
            || endorsement.sender_id != certificate.envelope.sender_id
            || endorsement.message_id != certificate.envelope.message_id
            || endorsement.payload_digest != digest
        {
            return Err(DkgTransportError::InvalidEndorsement);
        }
        if !verified.insert(endorsement.endorser_id) {
            return Err(DkgTransportError::DuplicateEndorser {
                endorser_id: endorsement.endorser_id,
            });
        }
        let peer = registry.peer(endorsement.endorser_id)?;
        if endorsement.endorser_signing_public_key != peer.signing_public_key {
            return Err(DkgTransportError::InvalidPeer(
                "endorsement signing key is not the registered key".into(),
            ));
        }
        verify_endorsement_signature(peer, endorsement)?;
    }
    Ok(certificate.envelope.payload.clone())
}

fn verify_endorsement_signature(
    expected_peer: &DkgTransportPeer,
    endorsement: &BroadcastEndorsement,
) -> Result<()> {
    endorsement.validate()?;
    expected_peer.validate()?;
    if endorsement.endorser_id != expected_peer.validator_id
        || endorsement.endorser_signing_public_key != expected_peer.signing_public_key
    {
        return Err(DkgTransportError::InvalidPeer(
            "endorsement signer does not match the expected peer".into(),
        ));
    }
    let body = BroadcastEndorsementSigningBody {
        domain: "authenticated_broadcast_endorsement",
        version: endorsement.version,
        session: &endorsement.session,
        round: endorsement.round,
        sender_id: endorsement.sender_id,
        message_id: &endorsement.message_id,
        payload_digest: &endorsement.payload_digest,
        endorser_id: endorsement.endorser_id,
        endorser_signing_public_key: &endorsement.endorser_signing_public_key,
    };
    let key = VerifyingKey::from_bytes(&expected_peer.signing_public_key)
        .map_err(|error| DkgTransportError::InvalidPeer(error.to_string()))?;
    key.verify_strict(
        &signing_bytes(&body)?,
        &Signature::from_bytes(&endorsement.signature),
    )
    .map_err(|_| DkgTransportError::InvalidSignature)
}

/// Convenience wrapper for canonical round-one FROST packages.
pub fn seal_round1_broadcast<R>(
    session: &DkgSession,
    identity: &DkgTransportIdentity,
    message: &Round1Message,
    rng: &mut R,
) -> Result<AuthenticatedBroadcastEnvelope>
where
    R: CryptoRng + RngCore,
{
    if message.sender_id != identity.validator_id() || &message.session != session {
        return Err(DkgTransportError::WrongSession);
    }
    seal_broadcast(
        session,
        DkgTransportRound::Round1,
        identity,
        &message
            .to_canonical_json()
            .map_err(|error| DkgTransportError::Serialization(error.to_string()))?,
        rng,
    )
}

/// Verifies and decodes a canonical round-one FROST package.
pub fn open_round1_broadcast(
    expected_session: &DkgSession,
    expected_peer: &DkgTransportPeer,
    envelope: &AuthenticatedBroadcastEnvelope,
) -> Result<Round1Message> {
    verify_broadcast(
        expected_session,
        DkgTransportRound::Round1,
        expected_peer,
        envelope,
    )?;
    let message = Round1Message::from_canonical_json(&envelope.payload)
        .map_err(|error| DkgTransportError::Serialization(error.to_string()))?;
    if &message.session != expected_session {
        return Err(DkgTransportError::WrongSession);
    }
    if message.sender_id != envelope.sender_id {
        return Err(DkgTransportError::WrongSender {
            expected: envelope.sender_id,
            actual: message.sender_id,
        });
    }
    Ok(message)
}

/// Verifies a quorum-certified round-one envelope and decodes its FROST
/// package, including the inner session/sender binding checks.
pub fn open_certified_round1_broadcast(
    expected_session: &DkgSession,
    registry: &DkgTransportRegistry,
    certificate: &CertifiedBroadcastEnvelope,
) -> Result<Round1Message> {
    let payload = verify_certified_broadcast(expected_session, registry, certificate)?;
    let message = Round1Message::from_canonical_json(&payload)
        .map_err(|error| DkgTransportError::Serialization(error.to_string()))?;
    if &message.session != expected_session {
        return Err(DkgTransportError::WrongSession);
    }
    if message.sender_id != certificate.envelope.sender_id {
        return Err(DkgTransportError::WrongSender {
            expected: certificate.envelope.sender_id,
            actual: message.sender_id,
        });
    }
    Ok(message)
}

/// Encrypts a recipient-specific round-two payload.  The ephemeral X25519
/// key provides sender-ephemeral confidentiality; the static recipient key and all ceremony
/// metadata are authenticated as AEAD associated data and by the Ed25519
/// signature.
pub fn seal_point_to_point<R>(
    session: &DkgSession,
    round: DkgTransportRound,
    identity: &DkgTransportIdentity,
    recipient: &DkgTransportPeer,
    payload: &[u8],
    rng: &mut R,
) -> Result<EncryptedPointToPointEnvelope>
where
    R: CryptoRng + RngCore,
{
    session.validate().map_err(transport_session_error)?;
    if round != DkgTransportRound::Round2 {
        return Err(DkgTransportError::WrongRound);
    }
    recipient.validate()?;
    validate_validator_id(identity.validator_id)?;
    if identity.validator_id == recipient.validator_id {
        return Err(DkgTransportError::SelfMessage);
    }
    if payload.is_empty() || payload.len() > MAX_TRANSPORT_PAYLOAD_BYTES {
        return Err(DkgTransportError::MessageTooLarge {
            actual: payload.len(),
            maximum: MAX_TRANSPORT_PAYLOAD_BYTES,
        });
    }

    let mut message_id = [0_u8; 32];
    fill_nonzero(rng, &mut message_id);
    let mut ephemeral_secret = [0_u8; 32];
    fill_nonzero(rng, &mut ephemeral_secret);
    let ephemeral_public = X25519_BASEPOINT.mul_clamped(ephemeral_secret).to_bytes();
    let mut shared = MontgomeryPoint(recipient.encryption_public_key)
        .mul_clamped(ephemeral_secret)
        .to_bytes();
    ephemeral_secret.zeroize();
    if shared == [0; 32] {
        return Err(DkgTransportError::InvalidPeer(
            "recipient X25519 key produced an all-zero shared secret".into(),
        ));
    }
    let sender_peer = identity.peer();
    let mut nonce = [0_u8; 24];
    fill_nonzero(rng, &mut nonce);
    let key_context = AeadKeyContext {
        session,
        round,
        sender_id: identity.validator_id,
        recipient_id: recipient.validator_id,
        sender_encryption_public_key: &sender_peer.encryption_public_key,
        recipient_encryption_public_key: &recipient.encryption_public_key,
        ephemeral_public_key: &ephemeral_public,
    };
    let key_result = derive_aead_key(&shared, &key_context);
    shared.zeroize();
    let mut key = key_result?;
    let aad = PointToPointAad {
        domain: "confidential_point_to_point",
        version: DKG_TRANSPORT_FORMAT_VERSION,
        session,
        round,
        sender_id: identity.validator_id,
        recipient_id: recipient.validator_id,
        message_id: &message_id,
        sender_signing_public_key: &sender_peer.signing_public_key,
        sender_encryption_public_key: &sender_peer.encryption_public_key,
        recipient_encryption_public_key: &recipient.encryption_public_key,
        ephemeral_public_key: &ephemeral_public,
        nonce: &nonce,
    };
    let aad_bytes = match canonical_bytes(&aad) {
        Ok(bytes) => bytes,
        Err(error) => {
            key.zeroize();
            return Err(error);
        }
    };
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let encryption_result = cipher.encrypt(
        XNonce::from_slice(&nonce),
        Payload {
            msg: payload,
            aad: &aad_bytes,
        },
    );
    key.zeroize();
    let ciphertext = encryption_result.map_err(|_| DkgTransportError::EncryptionFailed)?;

    let body = PointToPointSigningBody {
        domain: "confidential_point_to_point_signature",
        aad,
        ciphertext: &ciphertext,
    };
    let signature = identity.signing_key.sign(&signing_bytes(&body)?).to_bytes();
    Ok(EncryptedPointToPointEnvelope {
        version: DKG_TRANSPORT_FORMAT_VERSION,
        session: session.clone(),
        round,
        sender_id: identity.validator_id,
        recipient_id: recipient.validator_id,
        message_id,
        sender_signing_public_key: sender_peer.signing_public_key,
        sender_encryption_public_key: sender_peer.encryption_public_key,
        recipient_encryption_public_key: recipient.encryption_public_key,
        ephemeral_public_key: ephemeral_public,
        nonce,
        ciphertext,
        signature,
    })
}

/// Verifies and decrypts one point-to-point envelope for the expected local
/// identity.
pub fn open_point_to_point(
    expected_session: &DkgSession,
    expected_round: DkgTransportRound,
    recipient: &DkgTransportIdentity,
    expected_sender: &DkgTransportPeer,
    envelope: &EncryptedPointToPointEnvelope,
) -> Result<Zeroizing<Vec<u8>>> {
    envelope.validate()?;
    expected_session
        .validate()
        .map_err(transport_session_error)?;
    expected_sender.validate()?;
    if &envelope.session != expected_session {
        return Err(DkgTransportError::WrongSession);
    }
    if envelope.round != expected_round {
        return Err(DkgTransportError::WrongRound);
    }
    if envelope.sender_id != expected_sender.validator_id {
        return Err(DkgTransportError::WrongSender {
            expected: expected_sender.validator_id,
            actual: envelope.sender_id,
        });
    }
    if envelope.recipient_id != recipient.validator_id {
        return Err(DkgTransportError::WrongRecipient {
            expected: recipient.validator_id,
            actual: envelope.recipient_id,
        });
    }
    let recipient_peer = recipient.peer();
    if envelope.sender_signing_public_key != expected_sender.signing_public_key {
        return Err(DkgTransportError::InvalidPeer(
            "sender signing key is not the registered key".into(),
        ));
    }
    if envelope.sender_encryption_public_key != expected_sender.encryption_public_key {
        return Err(DkgTransportError::InvalidPeer(
            "sender encryption key is not the registered key".into(),
        ));
    }
    if envelope.recipient_encryption_public_key != recipient_peer.encryption_public_key {
        return Err(DkgTransportError::WrongRecipient {
            expected: recipient.validator_id,
            actual: envelope.recipient_id,
        });
    }
    let aad = PointToPointAad {
        domain: "confidential_point_to_point",
        version: envelope.version,
        session: &envelope.session,
        round: envelope.round,
        sender_id: envelope.sender_id,
        recipient_id: envelope.recipient_id,
        message_id: &envelope.message_id,
        sender_signing_public_key: &envelope.sender_signing_public_key,
        sender_encryption_public_key: &envelope.sender_encryption_public_key,
        recipient_encryption_public_key: &envelope.recipient_encryption_public_key,
        ephemeral_public_key: &envelope.ephemeral_public_key,
        nonce: &envelope.nonce,
    };
    let aad_bytes = canonical_bytes(&aad)?;
    let body = PointToPointSigningBody {
        domain: "confidential_point_to_point_signature",
        aad,
        ciphertext: &envelope.ciphertext,
    };
    let verifying_key = VerifyingKey::from_bytes(&expected_sender.signing_public_key)
        .map_err(|error| DkgTransportError::InvalidPeer(error.to_string()))?;
    let signature = Signature::from_bytes(&envelope.signature);
    verifying_key
        .verify_strict(&signing_bytes(&body)?, &signature)
        .map_err(|_| DkgTransportError::InvalidSignature)?;

    let mut shared = MontgomeryPoint(envelope.ephemeral_public_key)
        .mul_clamped(recipient.encryption_secret)
        .to_bytes();
    if shared == [0; 32] {
        return Err(DkgTransportError::InvalidPeer(
            "ephemeral X25519 key produced an all-zero shared secret".into(),
        ));
    }
    let key_context = AeadKeyContext {
        session: &envelope.session,
        round: envelope.round,
        sender_id: envelope.sender_id,
        recipient_id: envelope.recipient_id,
        sender_encryption_public_key: &envelope.sender_encryption_public_key,
        recipient_encryption_public_key: &envelope.recipient_encryption_public_key,
        ephemeral_public_key: &envelope.ephemeral_public_key,
    };
    let key_result = derive_aead_key(&shared, &key_context);
    shared.zeroize();
    let key = key_result?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let result = cipher
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| DkgTransportError::DecryptionFailed);
    let mut key = key;
    key.zeroize();
    result.map(Zeroizing::new)
}

/// Convenience wrapper for canonical round-two FROST packages.
pub fn seal_round2_point_to_point<R>(
    session: &DkgSession,
    identity: &DkgTransportIdentity,
    recipient: &DkgTransportPeer,
    message: &Round2Message,
    rng: &mut R,
) -> Result<EncryptedPointToPointEnvelope>
where
    R: CryptoRng + RngCore,
{
    if message.sender_id != identity.validator_id()
        || message.recipient_id != recipient.validator_id
        || &message.session != session
    {
        return Err(DkgTransportError::WrongSession);
    }
    let payload = Zeroizing::new(
        message
            .to_canonical_json()
            .map_err(|error| DkgTransportError::Serialization(error.to_string()))?,
    );
    seal_point_to_point(
        session,
        DkgTransportRound::Round2,
        identity,
        recipient,
        &payload,
        rng,
    )
}

/// Verifies, decrypts, and decodes a canonical round-two FROST package.
pub fn open_round2_point_to_point(
    expected_session: &DkgSession,
    recipient: &DkgTransportIdentity,
    expected_sender: &DkgTransportPeer,
    envelope: &EncryptedPointToPointEnvelope,
) -> Result<Round2Message> {
    let payload = open_point_to_point(
        expected_session,
        DkgTransportRound::Round2,
        recipient,
        expected_sender,
        envelope,
    )?;
    let message = Round2Message::from_canonical_json(&payload)
        .map_err(|error| DkgTransportError::Serialization(error.to_string()))?;
    if &message.session != expected_session {
        return Err(DkgTransportError::WrongSession);
    }
    if message.sender_id != envelope.sender_id {
        return Err(DkgTransportError::WrongSender {
            expected: envelope.sender_id,
            actual: message.sender_id,
        });
    }
    if message.recipient_id != envelope.recipient_id {
        return Err(DkgTransportError::WrongRecipient {
            expected: envelope.recipient_id,
            actual: message.recipient_id,
        });
    }
    Ok(message)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DkgTransportError {
    #[error("invalid transport peer: {0}")]
    InvalidPeer(String),
    #[error("duplicate transport peer")]
    DuplicatePeer,
    #[error("transport registry reuses an authentication or encryption key")]
    DuplicatePeerKey,
    #[error("unknown transport peer {0}")]
    UnknownPeer(u16),
    #[error("invalid validator id {0}")]
    InvalidValidatorId(u16),
    #[error("invalid transport message id")]
    InvalidMessageId,
    #[error("transport payload is {actual} bytes; maximum is {maximum}")]
    MessageTooLarge { actual: usize, maximum: usize },
    #[error("transport message belongs to another DKG session")]
    WrongSession,
    #[error("transport message is for the wrong DKG round")]
    WrongRound,
    #[error("transport sender mismatch: expected {expected}, got {actual}")]
    WrongSender { expected: u16, actual: u16 },
    #[error("transport recipient mismatch: expected {expected}, got {actual}")]
    WrongRecipient { expected: u16, actual: u16 },
    #[error("transport message cannot be addressed to its sender")]
    SelfMessage,
    #[error("transport signature is invalid")]
    InvalidSignature,
    #[error("transport message was replayed")]
    ReplayDetected,
    #[error("validator {sender_id} equivocated with two signed transport messages")]
    Equivocation { sender_id: u16 },
    #[error("broadcast certificate has too few endorsements: expected {expected}, got {actual}")]
    InsufficientEndorsements { expected: usize, actual: usize },
    #[error("broadcast certificate endorsements are not strictly ordered")]
    EndorsementOrder,
    #[error("broadcast certificate contains duplicate endorser {endorser_id}")]
    DuplicateEndorser { endorser_id: u16 },
    #[error("broadcast endorsement does not match the certified envelope")]
    InvalidEndorsement,
    #[error("replay guard is full at {capacity} entries")]
    ReplayGuardFull { capacity: usize },
    #[error("invalid endorsement guard capacity {actual}; maximum is {maximum}")]
    InvalidGuardCapacity { maximum: usize, actual: usize },
    #[error("endorsement guard is bound to validator {expected}, got {actual}")]
    WrongEndorser { expected: u16, actual: u16 },
    #[error("incomplete transport transcript: expected {expected} messages, got {actual}")]
    Incomplete { expected: usize, actual: usize },
    #[error("transport envelope is not canonical JSON: {0}")]
    NonCanonical(&'static str),
    #[error("transport serialization failed: {0}")]
    Serialization(String),
    #[error("transport encryption failed")]
    EncryptionFailed,
    #[error("transport decryption failed")]
    DecryptionFailed,
}

pub type Result<T, E = DkgTransportError> = std::result::Result<T, E>;

#[derive(Serialize)]
struct BroadcastSigningBody<'a> {
    domain: &'static str,
    version: u16,
    session: &'a DkgSession,
    round: DkgTransportRound,
    sender_id: u16,
    message_id: &'a [u8; 32],
    sender_signing_public_key: &'a [u8; 32],
    payload: &'a [u8],
}

#[derive(Serialize)]
struct BroadcastEndorsementSigningBody<'a> {
    domain: &'static str,
    version: u16,
    session: &'a DkgSession,
    round: DkgTransportRound,
    sender_id: u16,
    message_id: &'a [u8; 32],
    payload_digest: &'a [u8; 32],
    endorser_id: u16,
    endorser_signing_public_key: &'a [u8; 32],
}

#[derive(Serialize)]
struct PointToPointAad<'a> {
    domain: &'static str,
    version: u16,
    session: &'a DkgSession,
    round: DkgTransportRound,
    sender_id: u16,
    recipient_id: u16,
    message_id: &'a [u8; 32],
    sender_signing_public_key: &'a [u8; 32],
    sender_encryption_public_key: &'a [u8; 32],
    recipient_encryption_public_key: &'a [u8; 32],
    ephemeral_public_key: &'a [u8; 32],
    nonce: &'a [u8; 24],
}

#[derive(Serialize)]
struct PointToPointSigningBody<'a> {
    domain: &'static str,
    aad: PointToPointAad<'a>,
    ciphertext: &'a [u8],
}

fn signing_bytes<T: Serialize>(body: &T) -> Result<Vec<u8>> {
    canonical_bytes(body).map(|mut bytes| {
        let mut prefixed = Vec::with_capacity(TRANSPORT_SIGNING_DOMAIN.len() + bytes.len());
        prefixed.extend_from_slice(TRANSPORT_SIGNING_DOMAIN);
        prefixed.append(&mut bytes);
        prefixed
    })
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|error| DkgTransportError::Serialization(error.to_string()))
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>> {
    let bytes = canonical_bytes(value)?;
    if bytes.len() > maximum {
        return Err(DkgTransportError::MessageTooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    if label.is_empty() {
        return Err(DkgTransportError::Serialization(
            "empty canonical label".into(),
        ));
    }
    Ok(bytes)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
    label: &'static str,
) -> Result<T> {
    if bytes.len() > maximum {
        return Err(DkgTransportError::MessageTooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| DkgTransportError::Serialization(error.to_string()))?;
    if serde_jcs::to_vec(&value)
        .map_err(|error| DkgTransportError::Serialization(error.to_string()))?
        != bytes
    {
        return Err(DkgTransportError::NonCanonical(label));
    }
    Ok(value)
}

fn validate_common_header(
    version: u16,
    session: &DkgSession,
    round: DkgTransportRound,
    sender_id: u16,
    recipient_id: Option<u16>,
) -> Result<()> {
    if version != DKG_TRANSPORT_FORMAT_VERSION {
        return Err(DkgTransportError::Serialization(format!(
            "unsupported transport version {version}"
        )));
    }
    session.validate().map_err(transport_session_error)?;
    validate_validator_id(sender_id)?;
    if let Some(recipient_id) = recipient_id {
        validate_validator_id(recipient_id)?;
    }
    if round == DkgTransportRound::Round1 && recipient_id.is_some() {
        return Err(DkgTransportError::WrongRound);
    }
    Ok(())
}

fn validate_validator_id(validator_id: u16) -> Result<()> {
    if !(1..=DKG_PARTICIPANTS).contains(&validator_id) {
        return Err(DkgTransportError::InvalidValidatorId(validator_id));
    }
    Ok(())
}

fn transport_session_error(error: crate::threshold_dkg::ThresholdDkgError) -> DkgTransportError {
    DkgTransportError::Serialization(error.to_string())
}

fn fill_nonzero<R: RngCore>(rng: &mut R, output: &mut [u8]) {
    loop {
        rng.fill_bytes(output);
        if output.iter().any(|byte| *byte != 0) {
            return;
        }
    }
}

struct AeadKeyContext<'a> {
    session: &'a DkgSession,
    round: DkgTransportRound,
    sender_id: u16,
    recipient_id: u16,
    sender_encryption_public_key: &'a [u8; 32],
    recipient_encryption_public_key: &'a [u8; 32],
    ephemeral_public_key: &'a [u8; 32],
}

fn derive_aead_key(shared: &[u8; 32], context: &AeadKeyContext<'_>) -> Result<[u8; 32]> {
    let mut session_bytes = canonical_bytes(context.session)?;
    let mut info =
        Vec::with_capacity(TRANSPORT_KDF_DOMAIN.len() + session_bytes.len() + 2 * 2 + 32 * 3 + 2);
    info.extend_from_slice(TRANSPORT_KDF_DOMAIN);
    info.append(&mut session_bytes);
    info.push(round_byte(context.round));
    info.extend_from_slice(&context.sender_id.to_be_bytes());
    info.extend_from_slice(&context.recipient_id.to_be_bytes());
    info.extend_from_slice(context.sender_encryption_public_key);
    info.extend_from_slice(context.recipient_encryption_public_key);
    info.extend_from_slice(context.ephemeral_public_key);
    let hkdf = Hkdf::<Sha256>::new(Some(TRANSPORT_SESSION_DOMAIN), shared);
    let mut key = [0_u8; 32];
    let expansion = hkdf.expand(&info, &mut key);
    info.zeroize();
    expansion.map_err(|_| DkgTransportError::EncryptionFailed)?;
    Ok(key)
}

fn replay_key(
    session: &DkgSession,
    round: DkgTransportRound,
    sender_id: u16,
    recipient_id: Option<u16>,
    message_id: [u8; 32],
) -> Result<[u8; 32]> {
    validate_validator_id(sender_id)?;
    if let Some(recipient_id) = recipient_id {
        validate_validator_id(recipient_id)?;
        if recipient_id == sender_id {
            return Err(DkgTransportError::SelfMessage);
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(TRANSPORT_REPLAY_DOMAIN);
    hasher.update(canonical_bytes(session)?);
    hasher.update([round_byte(round)]);
    hasher.update(sender_id.to_be_bytes());
    match recipient_id {
        Some(recipient_id) => {
            hasher.update([1]);
            hasher.update(recipient_id.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(message_id);
    Ok(hasher.finalize().into())
}

fn broadcast_content_digest(envelope: &AuthenticatedBroadcastEnvelope) -> Result<[u8; 32]> {
    let body = BroadcastSigningBody {
        domain: "authenticated_broadcast",
        version: envelope.version,
        session: &envelope.session,
        round: envelope.round,
        sender_id: envelope.sender_id,
        message_id: &envelope.message_id,
        sender_signing_public_key: &envelope.sender_signing_public_key,
        payload: &envelope.payload,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"ASTERIA_PRIVATE_ORDER_DKG_BROADCAST_DIGEST_V1\0");
    hasher.update(signing_bytes(&body)?);
    hasher.update(envelope.signature);
    Ok(hasher.finalize().into())
}

fn endorsement_subject_key(
    session: &DkgSession,
    round: DkgTransportRound,
    sender_id: u16,
    endorser_id: u16,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"ASTERIA_PRIVATE_ORDER_DKG_ENDORSEMENT_SUBJECT_V1\0");
    hasher.update(canonical_bytes(session)?);
    hasher.update([round_byte(round)]);
    hasher.update(sender_id.to_be_bytes());
    hasher.update(endorser_id.to_be_bytes());
    Ok(hasher.finalize().into())
}

fn round_byte(round: DkgTransportRound) -> u8 {
    match round {
        DkgTransportRound::Round1 => 1,
        DkgTransportRound::Round2 => 2,
    }
}

fn validate_x25519_public(public_key: &[u8; 32]) -> Result<()> {
    let shared = MontgomeryPoint(*public_key)
        .mul_clamped([0x42; 32])
        .to_bytes();
    if shared == [0; 32] {
        return Err(DkgTransportError::InvalidPeer(
            "X25519 public key has low order".into(),
        ));
    }
    Ok(())
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> std::result::Result<S::Ok, S::Error>
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
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

mod base64_24 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 24], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 24], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 24 decoded bytes"))
    }
}

mod base64_32 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 decoded bytes"))
    }
}

mod base64_64 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 decoded bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_dkg::{
        DKG_PARTICIPANTS, participant_finalize, participant_round1, participant_round2,
    };
    use rand_core::OsRng;

    fn session() -> DkgSession {
        DkgSession::initial(
            crate::threshold_dkg::derive_dkg_chain_domain("asteria-transport-test").unwrap(),
            [77; 32],
            9,
        )
        .unwrap()
    }

    fn identities() -> Vec<DkgTransportIdentity> {
        (1..=DKG_PARTICIPANTS)
            .map(|id| DkgTransportIdentity::generate(id, &mut OsRng).unwrap())
            .collect()
    }

    fn registry(ids: &[DkgTransportIdentity]) -> DkgTransportRegistry {
        DkgTransportRegistry::new(ids.iter().map(DkgTransportIdentity::peer)).unwrap()
    }

    #[test]
    fn signed_round_one_broadcast_is_bound_and_consistent() {
        let ids = identities();
        let peers = registry(&ids);
        let session = session();
        let (_, package) = participant_round1(&session, 1, &mut OsRng).unwrap();
        let envelope = seal_round1_broadcast(&session, &ids[0], &package, &mut OsRng).unwrap();
        let decoded = AuthenticatedBroadcastEnvelope::from_canonical_json(
            &envelope.to_canonical_json().unwrap(),
        )
        .unwrap();
        let mut transcript =
            DkgBroadcastTranscript::new(session.clone(), DkgTransportRound::Round1, peers.clone())
                .unwrap();
        assert_eq!(
            open_round1_broadcast(&session, peers.peer(1).unwrap(), &decoded).unwrap(),
            package
        );
        assert_eq!(transcript.accept(decoded.clone()).unwrap(), decoded.payload);
        assert_eq!(
            transcript.accept(decoded),
            Err(DkgTransportError::ReplayDetected)
        );
    }

    #[test]
    fn transport_rounds_cannot_cross_public_and_confidential_channels() {
        let ids = identities();
        let peers = registry(&ids);
        let session = session();
        assert_eq!(
            seal_broadcast(
                &session,
                DkgTransportRound::Round2,
                &ids[0],
                b"secret round-two bytes",
                &mut OsRng,
            ),
            Err(DkgTransportError::WrongRound)
        );
        assert_eq!(
            seal_point_to_point(
                &session,
                DkgTransportRound::Round1,
                &ids[0],
                peers.peer(2).unwrap(),
                b"public round-one bytes",
                &mut OsRng,
            ),
            Err(DkgTransportError::WrongRound)
        );
    }

    #[test]
    fn broadcast_rejects_tampering_cross_session_and_equivocation() {
        let ids = identities();
        let peers = registry(&ids);
        let session = session();
        let (_, package) = participant_round1(&session, 1, &mut OsRng).unwrap();
        let mut envelope = seal_round1_broadcast(&session, &ids[0], &package, &mut OsRng).unwrap();
        envelope.payload[0] ^= 1;
        assert_eq!(
            verify_broadcast(
                &session,
                DkgTransportRound::Round1,
                peers.peer(1).unwrap(),
                &envelope
            ),
            Err(DkgTransportError::InvalidSignature)
        );

        let foreign = DkgSession::initial(session.chain_domain, [78; 32], session.epoch).unwrap();
        let (_, foreign_package) = participant_round1(&foreign, 1, &mut OsRng).unwrap();
        let foreign_envelope =
            seal_round1_broadcast(&foreign, &ids[0], &foreign_package, &mut OsRng).unwrap();
        assert_eq!(
            verify_broadcast(
                &session,
                DkgTransportRound::Round1,
                peers.peer(1).unwrap(),
                &foreign_envelope,
            ),
            Err(DkgTransportError::WrongSession)
        );

        let mut transcript =
            DkgBroadcastTranscript::new(session.clone(), DkgTransportRound::Round1, peers).unwrap();
        let (_, second_package) = participant_round1(&session, 1, &mut OsRng).unwrap();
        let second = seal_round1_broadcast(&session, &ids[0], &second_package, &mut OsRng).unwrap();
        let first = seal_round1_broadcast(&session, &ids[0], &package, &mut OsRng).unwrap();
        let mut same_id = second.clone();
        same_id.message_id = first.message_id;
        let same_id_body = BroadcastSigningBody {
            domain: "authenticated_broadcast",
            version: same_id.version,
            session: &same_id.session,
            round: same_id.round,
            sender_id: same_id.sender_id,
            message_id: &same_id.message_id,
            sender_signing_public_key: &same_id.sender_signing_public_key,
            payload: &same_id.payload,
        };
        same_id.signature = ids[0]
            .signing_key
            .sign(&signing_bytes(&same_id_body).unwrap())
            .to_bytes();
        transcript.accept(first).unwrap();
        assert_eq!(
            transcript.accept(same_id),
            Err(DkgTransportError::Equivocation { sender_id: 1 })
        );
        assert_eq!(
            transcript.accept(second),
            Err(DkgTransportError::Equivocation { sender_id: 1 })
        );

        let (_, sender_two_package) = participant_round1(&session, 2, &mut OsRng).unwrap();
        let wrong_typed_sender = seal_broadcast(
            &session,
            DkgTransportRound::Round1,
            &ids[0],
            &sender_two_package.to_canonical_json().unwrap(),
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            open_round1_broadcast(
                &session,
                registry(&ids).peer(1).unwrap(),
                &wrong_typed_sender,
            ),
            Err(DkgTransportError::WrongSender {
                expected: 1,
                actual: 2,
            })
        );

        let wrong_typed_session = seal_broadcast(
            &session,
            DkgTransportRound::Round1,
            &ids[0],
            &foreign_package.to_canonical_json().unwrap(),
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            open_round1_broadcast(
                &session,
                registry(&ids).peer(1).unwrap(),
                &wrong_typed_session,
            ),
            Err(DkgTransportError::WrongSession)
        );
    }

    #[test]
    fn three_of_four_broadcast_endorsements_form_a_certificate() {
        let ids = identities();
        let peers = registry(&ids);
        let session = session();
        let (_, package) = participant_round1(&session, 1, &mut OsRng).unwrap();
        let envelope = seal_round1_broadcast(&session, &ids[0], &package, &mut OsRng).unwrap();
        let mut guards = ids
            .iter()
            .map(|identity| DkgBroadcastEndorsementGuard::new(&identity.peer()).unwrap())
            .collect::<Vec<_>>();
        let endorsements = ids
            .iter()
            .zip(guards.iter_mut())
            .map(|(identity, guard)| {
                endorse_broadcast(&session, identity, &peers, &envelope, guard).unwrap()
            })
            .collect::<Vec<_>>();
        let certificate = make_broadcast_certificate(envelope.clone(), endorsements).unwrap();
        let wire = certificate.to_canonical_json().unwrap();
        let decoded = CertifiedBroadcastEnvelope::from_canonical_json(&wire).unwrap();
        assert_eq!(
            verify_certified_broadcast(&session, &peers, &decoded).unwrap(),
            envelope.payload
        );
        assert_eq!(
            open_certified_round1_broadcast(&session, &peers, &decoded).unwrap(),
            package
        );

        let mut tampered = decoded.clone();
        tampered.endorsements[0].signature[0] ^= 1;
        assert_eq!(
            verify_certified_broadcast(&session, &peers, &tampered),
            Err(DkgTransportError::InvalidSignature)
        );

        let mut insufficient = decoded.clone();
        insufficient.endorsements.pop();
        insufficient.endorsements.pop();
        assert_eq!(
            make_broadcast_certificate(
                insufficient.envelope.clone(),
                insufficient.endorsements.clone()
            ),
            Err(DkgTransportError::InsufficientEndorsements {
                expected: DKG_BROADCAST_QUORUM,
                actual: 2,
            })
        );

        let mut duplicate = decoded.clone();
        duplicate.endorsements[1] = duplicate.endorsements[0].clone();
        assert_eq!(
            make_broadcast_certificate(duplicate.envelope, duplicate.endorsements),
            Err(DkgTransportError::DuplicateEndorser { endorser_id: 1 })
        );

        let mut wrong_digest = decoded.clone();
        wrong_digest.endorsements[0].payload_digest[0] ^= 1;
        assert_eq!(
            verify_certified_broadcast(&session, &peers, &wrong_digest),
            Err(DkgTransportError::InvalidEndorsement)
        );

        let (_, sender_two_package) = participant_round1(&session, 2, &mut OsRng).unwrap();
        let wrong_typed = seal_broadcast(
            &session,
            DkgTransportRound::Round1,
            &ids[0],
            &sender_two_package.to_canonical_json().unwrap(),
            &mut OsRng,
        )
        .unwrap();
        let mut wrong_typed_guards = ids
            .iter()
            .map(|identity| DkgBroadcastEndorsementGuard::new(&identity.peer()).unwrap())
            .collect::<Vec<_>>();
        for (identity, guard) in ids.iter().zip(wrong_typed_guards.iter_mut()) {
            assert_eq!(
                endorse_broadcast(&session, identity, &peers, &wrong_typed, guard,),
                Err(DkgTransportError::WrongSender {
                    expected: 1,
                    actual: 2,
                })
            );
        }
        assert!(
            endorse_broadcast(
                &session,
                &ids[0],
                &peers,
                &envelope,
                &mut wrong_typed_guards[0],
            )
            .is_ok()
        );

        let (_, second_package) = participant_round1(&session, 1, &mut OsRng).unwrap();
        let second = seal_round1_broadcast(&session, &ids[0], &second_package, &mut OsRng).unwrap();
        let guard_bytes = guards[0].to_canonical_json(&ids[0]).unwrap();
        let mut restored_guard =
            DkgBroadcastEndorsementGuard::from_canonical_json(&guard_bytes, peers.peer(1).unwrap())
                .unwrap();
        assert_eq!(
            endorse_broadcast(&session, &ids[0], &peers, &envelope, &mut restored_guard,),
            Ok(decoded.endorsements[0].clone())
        );
        assert_eq!(
            endorse_broadcast(&session, &ids[0], &peers, &second, &mut restored_guard,),
            Err(DkgTransportError::Equivocation { sender_id: 1 })
        );

        let mut tampered_journal: EndorsementGuardJournal =
            serde_json::from_slice(&guard_bytes).unwrap();
        tampered_journal.signature[0] ^= 1;
        let tampered_journal = serde_jcs::to_vec(&tampered_journal).unwrap();
        assert_eq!(
            DkgBroadcastEndorsementGuard::from_canonical_json(
                &tampered_journal,
                peers.peer(1).unwrap(),
            ),
            Err(DkgTransportError::InvalidSignature)
        );
    }

    #[test]
    fn tagged_wire_accepts_a_maximum_size_certified_broadcast() {
        let ids = identities();
        let session = session();
        let envelope = seal_broadcast(
            &session,
            DkgTransportRound::Round1,
            &ids[0],
            &vec![0xa5; MAX_TRANSPORT_PAYLOAD_BYTES],
            &mut OsRng,
        )
        .unwrap();
        let digest = broadcast_content_digest(&envelope).unwrap();
        let endorsements = ids
            .iter()
            .map(|identity| {
                let peer = identity.peer();
                let body = BroadcastEndorsementSigningBody {
                    domain: "authenticated_broadcast_endorsement",
                    version: DKG_TRANSPORT_FORMAT_VERSION,
                    session: &session,
                    round: DkgTransportRound::Round1,
                    sender_id: envelope.sender_id,
                    message_id: &envelope.message_id,
                    payload_digest: &digest,
                    endorser_id: identity.validator_id(),
                    endorser_signing_public_key: &peer.signing_public_key,
                };
                BroadcastEndorsement {
                    version: DKG_TRANSPORT_FORMAT_VERSION,
                    session: session.clone(),
                    round: DkgTransportRound::Round1,
                    sender_id: envelope.sender_id,
                    message_id: envelope.message_id,
                    payload_digest: digest,
                    endorser_id: identity.validator_id(),
                    endorser_signing_public_key: peer.signing_public_key,
                    signature: identity
                        .signing_key
                        .sign(&signing_bytes(&body).unwrap())
                        .to_bytes(),
                }
            })
            .collect::<Vec<_>>();
        let wire = DkgWireMessage::CertifiedBroadcast(
            make_broadcast_certificate(envelope, endorsements).unwrap(),
        );
        let encoded = wire.to_canonical_json().unwrap();
        assert!(encoded.len() <= MAX_WIRE_MESSAGE_BYTES);
        assert_eq!(DkgWireMessage::from_canonical_json(&encoded).unwrap(), wire);
    }

    #[test]
    fn encrypted_round_two_is_confidential_authenticated_and_replay_safe() {
        let ids = identities();
        let peers = registry(&ids);
        let session = session();
        let mut round1_states = Vec::new();
        let mut round1_messages = Vec::new();
        for id in 1..=DKG_PARTICIPANTS {
            let (state, message) = participant_round1(&session, id, &mut OsRng).unwrap();
            round1_states.push(state);
            round1_messages.push(message);
        }
        let state = round1_states.remove(0);
        let incoming = round1_messages
            .iter()
            .filter(|message| message.sender_id != 1)
            .cloned()
            .collect::<Vec<_>>();
        let (_, packages) = participant_round2(state, &incoming).unwrap();
        let package = packages.iter().find(|m| m.recipient_id == 2).unwrap();
        let envelope = seal_round2_point_to_point(
            &session,
            &ids[0],
            peers.peer(2).unwrap(),
            package,
            &mut OsRng,
        )
        .unwrap();
        let mut inbox = DkgPointToPointInbox::new(session.clone(), 2, peers.clone()).unwrap();
        let alternate_recipient =
            DkgTransportIdentity::from_secrets(2, [121; 32], [122; 32]).unwrap();
        let alternate_envelope = seal_round2_point_to_point(
            &session,
            &ids[0],
            &alternate_recipient.peer(),
            package,
            &mut OsRng,
        )
        .unwrap();
        assert!(matches!(
            inbox.accept(&alternate_recipient, alternate_envelope),
            Err(DkgTransportError::InvalidPeer(_))
        ));
        let decoded = EncryptedPointToPointEnvelope::from_canonical_json(
            &envelope.to_canonical_json().unwrap(),
        )
        .unwrap();
        assert_eq!(
            open_round2_point_to_point(&session, &ids[1], peers.peer(1).unwrap(), &decoded)
                .unwrap(),
            *package
        );
        let plaintext = inbox.accept(&ids[1], decoded.clone()).unwrap();
        assert_eq!(
            Round2Message::from_canonical_json(&plaintext).unwrap(),
            *package
        );
        assert_eq!(
            inbox.accept(&ids[1], decoded),
            Err(DkgTransportError::ReplayDetected)
        );

        let mut tampered = envelope;
        tampered.ciphertext[0] ^= 1;
        assert_eq!(
            open_point_to_point(
                &session,
                DkgTransportRound::Round2,
                &ids[1],
                peers.peer(1).unwrap(),
                &tampered,
            ),
            Err(DkgTransportError::InvalidSignature)
        );

        let wrong_typed_recipient = seal_point_to_point(
            &session,
            DkgTransportRound::Round2,
            &ids[0],
            peers.peer(3).unwrap(),
            &package.to_canonical_json().unwrap(),
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            open_round2_point_to_point(
                &session,
                &ids[2],
                peers.peer(1).unwrap(),
                &wrong_typed_recipient,
            ),
            Err(DkgTransportError::WrongRecipient {
                expected: 3,
                actual: 2,
            })
        );

        let mut wrong_session_package = package.clone();
        wrong_session_package.session =
            DkgSession::initial(session.chain_domain, [79; 32], session.epoch).unwrap();
        let wrong_typed_session = seal_point_to_point(
            &session,
            DkgTransportRound::Round2,
            &ids[0],
            peers.peer(2).unwrap(),
            &wrong_session_package.to_canonical_json().unwrap(),
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            open_round2_point_to_point(
                &session,
                &ids[1],
                peers.peer(1).unwrap(),
                &wrong_typed_session,
            ),
            Err(DkgTransportError::WrongSession)
        );
    }

    #[test]
    fn point_to_point_rejects_wrong_recipient_and_wrong_epoch() {
        let ids = identities();
        let peers = registry(&ids);
        let session = session();
        let payload = b"confidential dkg package";
        let envelope = seal_point_to_point(
            &session,
            DkgTransportRound::Round2,
            &ids[0],
            peers.peer(2).unwrap(),
            payload,
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            open_point_to_point(
                &session,
                DkgTransportRound::Round2,
                &ids[2],
                peers.peer(1).unwrap(),
                &envelope,
            ),
            Err(DkgTransportError::WrongRecipient {
                expected: 3,
                actual: 2,
            })
        );
        let other = DkgSession::initial(session.chain_domain, session.ceremony_id, 10).unwrap();
        assert_eq!(
            open_point_to_point(
                &other,
                DkgTransportRound::Round2,
                &ids[1],
                peers.peer(1).unwrap(),
                &envelope,
            ),
            Err(DkgTransportError::WrongSession)
        );
    }

    #[test]
    fn replay_guard_is_context_bound_and_bounded() {
        let session = session();
        let mut guard = DkgReplayGuard::new(1);
        guard
            .check_and_record(&session, DkgTransportRound::Round1, 1, None, [1; 32])
            .unwrap();
        assert_eq!(guard.len(), 1);
        assert_eq!(
            guard.check_and_record(&session, DkgTransportRound::Round1, 1, None, [1; 32]),
            Err(DkgTransportError::ReplayDetected)
        );
        assert_eq!(
            guard.check_and_record(&session, DkgTransportRound::Round1, 1, None, [2; 32]),
            Err(DkgTransportError::ReplayGuardFull { capacity: 1 })
        );
        let mut context_guard = DkgReplayGuard::new(3);
        context_guard
            .check_and_record(&session, DkgTransportRound::Round1, 1, None, [1; 32])
            .unwrap();
        context_guard
            .check_and_record(&session, DkgTransportRound::Round1, 2, None, [1; 32])
            .unwrap();
        assert!(
            context_guard
                .check_and_record(&session, DkgTransportRound::Round2, 1, Some(2), [1; 32],)
                .is_ok()
        );
    }

    #[test]
    fn four_party_dkg_round_trips_through_certified_and_encrypted_transport() {
        let ids = identities();
        let peers = registry(&ids);
        let session = session();
        let mut endorsement_guards = ids
            .iter()
            .map(|identity| DkgBroadcastEndorsementGuard::new(&identity.peer()).unwrap())
            .collect::<Vec<_>>();
        let mut round1_states = BTreeMap::new();
        let mut certificates = Vec::new();

        for validator_id in 1..=DKG_PARTICIPANTS {
            let (state, message) = participant_round1(&session, validator_id, &mut OsRng).unwrap();
            round1_states.insert(validator_id, state);
            let envelope = seal_round1_broadcast(
                &session,
                &ids[usize::from(validator_id - 1)],
                &message,
                &mut OsRng,
            )
            .unwrap();
            let endorsements = ids
                .iter()
                .zip(endorsement_guards.iter_mut())
                .map(|(endorser, guard)| {
                    endorse_broadcast(&session, endorser, &peers, &envelope, guard).unwrap()
                })
                .collect();
            certificates.push(make_broadcast_certificate(envelope, endorsements).unwrap());
        }

        let mut round2_states = BTreeMap::new();
        let mut round2_messages = Vec::new();
        for validator_id in 1..=DKG_PARTICIPANTS {
            let mut transcript =
                DkgCertifiedBroadcastTranscript::new(session.clone(), peers.clone()).unwrap();
            for certificate in &certificates {
                transcript.accept(certificate.clone()).unwrap();
            }
            let incoming = transcript.incoming_for(validator_id).unwrap();
            let (state, outgoing) =
                participant_round2(round1_states.remove(&validator_id).unwrap(), &incoming)
                    .unwrap();
            round2_states.insert(validator_id, state);
            round2_messages.extend(outgoing);
        }
        assert_eq!(round2_messages.len(), 12);

        let mut encrypted = Vec::new();
        for message in &round2_messages {
            encrypted.push(
                seal_round2_point_to_point(
                    &session,
                    &ids[usize::from(message.sender_id - 1)],
                    peers.peer(message.recipient_id).unwrap(),
                    message,
                    &mut OsRng,
                )
                .unwrap(),
            );
        }

        let mut finalized = Vec::new();
        for validator_id in 1..=DKG_PARTICIPANTS {
            let mut inbox =
                DkgPointToPointInbox::new(session.clone(), validator_id, peers.clone()).unwrap();
            for envelope in encrypted
                .iter()
                .filter(|envelope| envelope.recipient_id == validator_id)
            {
                inbox
                    .accept(&ids[usize::from(validator_id - 1)], envelope.clone())
                    .unwrap();
            }
            assert!(inbox.is_complete());
            let incoming = inbox
                .payloads()
                .unwrap()
                .iter()
                .map(|payload| Round2Message::from_canonical_json(payload).unwrap())
                .collect::<Vec<_>>();
            finalized.push(
                participant_finalize(round2_states.remove(&validator_id).unwrap(), &incoming)
                    .unwrap(),
            );
        }

        let expected = finalized[0].public_keys().clone();
        for participant in &finalized {
            assert_eq!(participant.public_keys(), &expected);
        }
    }

    #[test]
    fn registry_rejects_reused_identity_keys() {
        let first = DkgTransportIdentity::from_secrets(1, [91; 32], [92; 32]).unwrap();
        let second = DkgTransportIdentity::from_secrets(2, [91; 32], [93; 32]).unwrap();
        assert_eq!(
            DkgTransportRegistry::new([first.peer(), second.peer()]),
            Err(DkgTransportError::DuplicatePeerKey)
        );
    }
}
