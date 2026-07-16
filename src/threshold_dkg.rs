//! Two-round 3-of-4 FROST DKG adapter for private-order threshold keys.
//!
//! This module delegates every DKG and refresh calculation to the Zcash
//! Foundation `frost-ristretto255` implementation. Round-one broadcasts need
//! an authenticated consistent-broadcast channel; round-two packages need
//! authenticated confidential point-to-point channels. The transport wrappers
//! below provide canonical encoding and metadata binding, not those channels.

use std::collections::BTreeMap;

use frost::rand_core::{CryptoRng, RngCore};
use frost_ristretto255 as frost;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::private_order::{
    PRIVATE_ORDER_VALIDATOR_COUNT, ThresholdPublicKeySet, ValidatorPublicShare,
    ValidatorSecretShare,
};

pub const DKG_FORMAT_VERSION: u16 = 2;
pub const DKG_PARTICIPANTS: u16 = 4;
pub const DKG_THRESHOLD: u16 = 3;
pub const MAX_ROUND1_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_ROUND2_MESSAGE_BYTES: usize = 4 * 1024;

const DKG_CHAIN_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_DKG_CHAIN_V2\0";
const MAX_DKG_CHAIN_ID_BYTES: usize = 128;

type FrostIdentifier = frost::Identifier;
type FrostRound1Package = frost::keys::dkg::round1::Package;
type FrostRound1Secret = frost::keys::dkg::round1::SecretPackage;
type FrostRound2Package = frost::keys::dkg::round2::Package;
type FrostRound2Secret = frost::keys::dkg::round2::SecretPackage;
type FrostKeyPackage = frost::keys::KeyPackage;
type FrostPublicKeyPackage = frost::keys::PublicKeyPackage;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum DkgKind {
    Initial,
    Refresh { previous_key_id: [u8; 32] },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgSession {
    pub chain_domain: [u8; 32],
    pub ceremony_id: [u8; 32],
    pub epoch: u64,
    pub kind: DkgKind,
}

impl DkgSession {
    pub fn initial(chain_domain: [u8; 32], ceremony_id: [u8; 32], epoch: u64) -> Result<Self> {
        let session = Self {
            chain_domain,
            ceremony_id,
            epoch,
            kind: DkgKind::Initial,
        };
        session.validate()?;
        Ok(session)
    }

    pub fn refresh(
        chain_domain: [u8; 32],
        ceremony_id: [u8; 32],
        epoch: u64,
        previous_key_id: [u8; 32],
    ) -> Result<Self> {
        let session = Self {
            chain_domain,
            ceremony_id,
            epoch,
            kind: DkgKind::Refresh { previous_key_id },
        };
        session.validate()?;
        Ok(session)
    }

    fn validate(&self) -> Result<()> {
        if self.chain_domain == [0; 32] {
            return Err(ThresholdDkgError::ZeroChainDomain);
        }
        if self.ceremony_id == [0; 32] {
            return Err(ThresholdDkgError::ZeroCeremonyId);
        }
        validate_epoch(self.epoch)?;
        if let DkgKind::Refresh { previous_key_id } = &self.kind
            && *previous_key_id == [0; 32]
        {
            return Err(ThresholdDkgError::ZeroPreviousKeyId);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Round1Message {
    pub version: u16,
    pub session: DkgSession,
    pub sender_id: u16,
    package: FrostRound1Package,
}

impl Round1Message {
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        validate_message(self.version, &self.session, self.sender_id)?;
        encode_message(self, MAX_ROUND1_MESSAGE_BYTES, "round-one message")
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        let message: Self = decode_message(bytes, MAX_ROUND1_MESSAGE_BYTES, "round-one message")?;
        validate_message(message.version, &message.session, message.sender_id)?;
        Ok(message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Round2Message {
    pub version: u16,
    pub session: DkgSession,
    pub sender_id: u16,
    pub recipient_id: u16,
    package: FrostRound2Package,
}

impl Round2Message {
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        validate_message(self.version, &self.session, self.sender_id)?;
        identifier(self.recipient_id)?;
        encode_message(self, MAX_ROUND2_MESSAGE_BYTES, "round-two message")
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        let message: Self = decode_message(bytes, MAX_ROUND2_MESSAGE_BYTES, "round-two message")?;
        validate_message(message.version, &message.session, message.sender_id)?;
        identifier(message.recipient_id)?;
        Ok(message)
    }
}

/// Secret participant state between DKG rounds one and two.
///
/// Deliberately has no `Clone`, `Debug`, `Serialize`, or `Deserialize`.
pub struct Round1Participant {
    validator_id: u16,
    session: DkgSession,
    purpose: DkgPurpose,
    secret: FrostRound1Secret,
}

impl Round1Participant {
    pub fn validator_id(&self) -> u16 {
        self.validator_id
    }

    pub fn session(&self) -> &DkgSession {
        &self.session
    }
}

/// Secret participant state between DKG round two and finalization.
///
/// Deliberately has no `Clone`, `Debug`, `Serialize`, or `Deserialize`.
pub struct Round2Participant {
    validator_id: u16,
    session: DkgSession,
    purpose: DkgPurpose,
    secret: FrostRound2Secret,
    received_round1: BTreeMap<FrostIdentifier, FrostRound1Package>,
}

impl Round2Participant {
    pub fn validator_id(&self) -> u16 {
        self.validator_id
    }

    pub fn session(&self) -> &DkgSession {
        &self.session
    }
}

enum DkgPurpose {
    Initial,
    Refresh {
        old_key_package: Box<FrostKeyPackage>,
        old_public_key_package: Box<FrostPublicKeyPackage>,
    },
}

/// Long-lived output for one validator.
///
/// This type intentionally has no cloning, debugging, or serialization. The
/// FROST key package is retained privately so the official share-refresh API
/// can later consume it without reconstructing the group secret.
pub struct FinalizedParticipant {
    validator_id: u16,
    epoch: u64,
    public_keys: ThresholdPublicKeySet,
    secret_share: ValidatorSecretShare,
    frost_key_package: FrostKeyPackage,
    frost_public_key_package: FrostPublicKeyPackage,
}

impl FinalizedParticipant {
    pub fn validator_id(&self) -> u16 {
        self.validator_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn public_keys(&self) -> &ThresholdPublicKeySet {
        &self.public_keys
    }

    pub fn secret_share(&self) -> &ValidatorSecretShare {
        &self.secret_share
    }

    pub fn frost_public_key_package(&self) -> &FrostPublicKeyPackage {
        &self.frost_public_key_package
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ThresholdDkgError {
    #[error("validator id must be one of 1, 2, 3, or 4; received {0}")]
    InvalidValidatorId(u16),
    #[error("DKG epoch must be greater than zero")]
    ZeroEpoch,
    #[error("DKG chain domain must not be zero")]
    ZeroChainDomain,
    #[error("DKG ceremony id must not be zero")]
    ZeroCeremonyId,
    #[error("refresh DKG previous key id must not be zero")]
    ZeroPreviousKeyId,
    #[error("DKG chain id must contain 1 to {MAX_DKG_CHAIN_ID_BYTES} bytes")]
    InvalidChainId,
    #[error("refresh epoch {new_epoch} must be greater than current epoch {current_epoch}")]
    InvalidRefreshEpoch { current_epoch: u64, new_epoch: u64 },
    #[error("unsupported DKG message version {0}")]
    UnsupportedVersion(u16),
    #[error("{label} exceeds {maximum} bytes")]
    MessageTooLarge { label: &'static str, maximum: usize },
    #[error("{0} is not encoded as canonical RFC 8785 JSON")]
    NonCanonical(&'static str),
    #[error("failed to encode or decode {label}: {reason}")]
    Serialization { label: &'static str, reason: String },
    #[error("{round} requires exactly three messages; received {actual}")]
    IncorrectMessageCount { round: &'static str, actual: usize },
    #[error("duplicate {round} message from validator {sender_id}")]
    DuplicateSender { round: &'static str, sender_id: u16 },
    #[error("validator {validator_id} received its own {round} message")]
    SelfMessage {
        round: &'static str,
        validator_id: u16,
    },
    #[error("round-two message for validator {actual} was delivered to validator {expected}")]
    WrongRecipient { expected: u16, actual: u16 },
    #[error("message belongs to a different DKG session")]
    WrongSession,
    #[error("missing {round} message from validator {validator_id}")]
    MissingSender {
        round: &'static str,
        validator_id: u16,
    },
    #[error("FROST DKG failed: {0}")]
    Frost(String),
    #[error("FROST output is inconsistent: {0}")]
    InconsistentOutput(&'static str),
    #[error("private-order key adaptation failed: {0}")]
    PrivateOrder(String),
}

pub type Result<T, E = ThresholdDkgError> = std::result::Result<T, E>;

pub fn derive_dkg_chain_domain(chain_id: &str) -> Result<[u8; 32]> {
    if chain_id.is_empty() || chain_id.len() > MAX_DKG_CHAIN_ID_BYTES || chain_id.trim() != chain_id
    {
        return Err(ThresholdDkgError::InvalidChainId);
    }
    let mut hasher = Sha256::new();
    hasher.update(DKG_CHAIN_DOMAIN);
    hasher.update(
        u64::try_from(chain_id.len())
            .map_err(|_| ThresholdDkgError::InvalidChainId)?
            .to_be_bytes(),
    );
    hasher.update(chain_id.as_bytes());
    Ok(hasher.finalize().into())
}

/// Starts the initial 3-of-4 DKG for one validator.
pub fn participant_round1<R>(
    session: &DkgSession,
    validator_id: u16,
    rng: &mut R,
) -> Result<(Round1Participant, Round1Message)>
where
    R: CryptoRng + RngCore,
{
    session.validate()?;
    if !matches!(&session.kind, DkgKind::Initial) {
        return Err(ThresholdDkgError::WrongSession);
    }
    let identifier = identifier(validator_id)?;
    let (secret, package) =
        frost::keys::dkg::part1(identifier, DKG_PARTICIPANTS, DKG_THRESHOLD, &mut *rng)
            .map_err(frost_error)?;
    Ok((
        Round1Participant {
            validator_id,
            session: session.clone(),
            purpose: DkgPurpose::Initial,
            secret,
        },
        Round1Message {
            version: DKG_FORMAT_VERSION,
            session: session.clone(),
            sender_id: validator_id,
            package,
        },
    ))
}

/// Starts an official FROST DKG share refresh for one validator.
///
/// The existing participant is consumed. The refresh changes all verification
/// shares while preserving the group public key; no secret reconstruction is
/// performed.
pub fn participant_refresh_round1<R>(
    session: &DkgSession,
    current: FinalizedParticipant,
    rng: &mut R,
) -> Result<(Round1Participant, Round1Message)>
where
    R: CryptoRng + RngCore,
{
    session.validate()?;
    let DkgKind::Refresh { previous_key_id } = &session.kind else {
        return Err(ThresholdDkgError::WrongSession);
    };
    if *previous_key_id != current.public_keys.key_id {
        return Err(ThresholdDkgError::WrongSession);
    }
    if session.epoch <= current.epoch {
        return Err(ThresholdDkgError::InvalidRefreshEpoch {
            current_epoch: current.epoch,
            new_epoch: session.epoch,
        });
    }
    let identifier = identifier(current.validator_id)?;
    let (secret, package) = frost::keys::refresh::refresh_dkg_part1(
        identifier,
        DKG_PARTICIPANTS,
        DKG_THRESHOLD,
        &mut *rng,
    )
    .map_err(frost_error)?;

    let FinalizedParticipant {
        validator_id,
        public_keys: _,
        secret_share: _,
        frost_key_package,
        frost_public_key_package,
        ..
    } = current;
    Ok((
        Round1Participant {
            validator_id,
            session: session.clone(),
            purpose: DkgPurpose::Refresh {
                old_key_package: Box::new(frost_key_package),
                old_public_key_package: Box::new(frost_public_key_package),
            },
            secret,
        },
        Round1Message {
            version: DKG_FORMAT_VERSION,
            session: session.clone(),
            sender_id: validator_id,
            package,
        },
    ))
}

/// Consumes round-one secret state and produces recipient-specific round-two
/// messages.
pub fn participant_round2(
    participant: Round1Participant,
    received: &[Round1Message],
) -> Result<(Round2Participant, Vec<Round2Message>)> {
    let received_round1 = collect_round1(participant.validator_id, &participant.session, received)?;
    let (secret, packages) = match &participant.purpose {
        DkgPurpose::Initial => frost::keys::dkg::part2(participant.secret, &received_round1),
        DkgPurpose::Refresh { .. } => {
            frost::keys::refresh::refresh_dkg_part2(participant.secret, &received_round1)
        }
    }
    .map_err(frost_error)?;

    if packages.len() != usize::from(DKG_PARTICIPANTS - 1) {
        return Err(ThresholdDkgError::InconsistentOutput(
            "FROST round two did not produce three recipient packages",
        ));
    }
    let mut outgoing = Vec::with_capacity(packages.len());
    for (recipient, package) in packages {
        let recipient_id = validator_id(&recipient)?;
        if recipient_id == participant.validator_id {
            return Err(ThresholdDkgError::InconsistentOutput(
                "FROST emitted a round-two package for its sender",
            ));
        }
        outgoing.push(Round2Message {
            version: DKG_FORMAT_VERSION,
            session: participant.session.clone(),
            sender_id: participant.validator_id,
            recipient_id,
            package,
        });
    }
    outgoing.sort_by_key(|message| message.recipient_id);

    Ok((
        Round2Participant {
            validator_id: participant.validator_id,
            session: participant.session,
            purpose: participant.purpose,
            secret,
            received_round1,
        },
        outgoing,
    ))
}

/// Finalizes one validator's DKG and adapts its FROST key material to the
/// private-order threshold-decryption backend.
pub fn participant_finalize(
    participant: Round2Participant,
    received: &[Round2Message],
) -> Result<FinalizedParticipant> {
    let received_round2 = collect_round2(participant.validator_id, &participant.session, received)?;
    let (key_package, public_key_package) = match participant.purpose {
        DkgPurpose::Initial => frost::keys::dkg::part3(
            &participant.secret,
            &participant.received_round1,
            &received_round2,
        ),
        DkgPurpose::Refresh {
            old_key_package,
            old_public_key_package,
        } => {
            let old_group_key = old_public_key_package
                .verifying_key()
                .serialize()
                .map_err(frost_error)?;
            let result = frost::keys::refresh::refresh_dkg_shares(
                &participant.secret,
                &participant.received_round1,
                &received_round2,
                *old_public_key_package,
                *old_key_package,
            );
            if let Ok((_, public_keys)) = &result
                && public_keys
                    .verifying_key()
                    .serialize()
                    .map_err(frost_error)?
                    != old_group_key
            {
                return Err(ThresholdDkgError::InconsistentOutput(
                    "FROST refresh changed the group public key",
                ));
            }
            result
        }
    }
    .map_err(frost_error)?;

    adapt_frost_output(
        participant.session.epoch,
        participant.validator_id,
        key_package,
        public_key_package,
    )
}

fn adapt_frost_output(
    epoch: u64,
    expected_validator_id: u16,
    key_package: FrostKeyPackage,
    public_key_package: FrostPublicKeyPackage,
) -> Result<FinalizedParticipant> {
    let expected_identifier = identifier(expected_validator_id)?;
    if key_package.identifier() != &expected_identifier {
        return Err(ThresholdDkgError::InconsistentOutput(
            "key package identifier differs from the participant",
        ));
    }
    if *key_package.min_signers() != DKG_THRESHOLD
        || public_key_package.min_signers() != Some(DKG_THRESHOLD)
        || public_key_package.max_signers() != DKG_PARTICIPANTS
    {
        return Err(ThresholdDkgError::InconsistentOutput(
            "FROST output is not a 3-of-4 key",
        ));
    }
    if key_package.verifying_key() != public_key_package.verifying_key() {
        return Err(ThresholdDkgError::InconsistentOutput(
            "participant and public group keys differ",
        ));
    }
    let own_public_share = public_key_package
        .verifying_shares()
        .get(&expected_identifier)
        .ok_or(ThresholdDkgError::InconsistentOutput(
            "public package omits the participant verification share",
        ))?;
    if key_package.verifying_share() != own_public_share {
        return Err(ThresholdDkgError::InconsistentOutput(
            "participant verification share differs from the public package",
        ));
    }

    let group_public_key = fixed_32(
        public_key_package
            .verifying_key()
            .serialize()
            .map_err(frost_error)?,
        "FROST group public key is not 32 bytes",
    )?;
    let mut validators = Vec::with_capacity(PRIVATE_ORDER_VALIDATOR_COUNT);
    for validator_id in 1..=DKG_PARTICIPANTS {
        let frost_id = identifier(validator_id)?;
        let share = public_key_package.verifying_shares().get(&frost_id).ok_or(
            ThresholdDkgError::InconsistentOutput(
                "public package does not contain validator IDs 1 through 4",
            ),
        )?;
        validators.push(ValidatorPublicShare {
            validator_id,
            public_key: fixed_32(
                share.serialize().map_err(frost_error)?,
                "FROST verification share is not 32 bytes",
            )?,
        });
    }
    if public_key_package.verifying_shares().len() != PRIVATE_ORDER_VALIDATOR_COUNT {
        return Err(ThresholdDkgError::InconsistentOutput(
            "public package contains an unexpected validator identifier",
        ));
    }

    let public_keys =
        ThresholdPublicKeySet::from_provisioned_public_shares(epoch, group_public_key, validators)
            .map_err(|error| ThresholdDkgError::PrivateOrder(error.to_string()))?;

    let mut scalar = fixed_32(
        key_package.signing_share().serialize(),
        "FROST signing share is not 32 bytes",
    )?;
    let secret_share =
        ValidatorSecretShare::from_provisioned_scalar(&public_keys, expected_validator_id, scalar)
            .map_err(|error| ThresholdDkgError::PrivateOrder(error.to_string()));
    scalar.zeroize();
    let secret_share = secret_share?;

    Ok(FinalizedParticipant {
        validator_id: expected_validator_id,
        epoch,
        public_keys,
        secret_share,
        frost_key_package: key_package,
        frost_public_key_package: public_key_package,
    })
}

fn collect_round1(
    own_id: u16,
    session: &DkgSession,
    messages: &[Round1Message],
) -> Result<BTreeMap<FrostIdentifier, FrostRound1Package>> {
    if messages.len() != usize::from(DKG_PARTICIPANTS - 1) {
        return Err(ThresholdDkgError::IncorrectMessageCount {
            round: "round one",
            actual: messages.len(),
        });
    }
    let mut packages = BTreeMap::new();
    for message in messages {
        validate_message(message.version, &message.session, message.sender_id)?;
        if &message.session != session {
            return Err(ThresholdDkgError::WrongSession);
        }
        if message.sender_id == own_id {
            return Err(ThresholdDkgError::SelfMessage {
                round: "round one",
                validator_id: own_id,
            });
        }
        let sender = identifier(message.sender_id)?;
        if packages.insert(sender, message.package.clone()).is_some() {
            return Err(ThresholdDkgError::DuplicateSender {
                round: "round one",
                sender_id: message.sender_id,
            });
        }
    }
    ensure_other_senders(own_id, "round one", &packages)?;
    Ok(packages)
}

fn collect_round2(
    own_id: u16,
    session: &DkgSession,
    messages: &[Round2Message],
) -> Result<BTreeMap<FrostIdentifier, FrostRound2Package>> {
    if messages.len() != usize::from(DKG_PARTICIPANTS - 1) {
        return Err(ThresholdDkgError::IncorrectMessageCount {
            round: "round two",
            actual: messages.len(),
        });
    }
    let mut packages = BTreeMap::new();
    for message in messages {
        validate_message(message.version, &message.session, message.sender_id)?;
        identifier(message.recipient_id)?;
        if &message.session != session {
            return Err(ThresholdDkgError::WrongSession);
        }
        if message.recipient_id != own_id {
            return Err(ThresholdDkgError::WrongRecipient {
                expected: own_id,
                actual: message.recipient_id,
            });
        }
        if message.sender_id == own_id {
            return Err(ThresholdDkgError::SelfMessage {
                round: "round two",
                validator_id: own_id,
            });
        }
        let sender = identifier(message.sender_id)?;
        if packages.insert(sender, message.package.clone()).is_some() {
            return Err(ThresholdDkgError::DuplicateSender {
                round: "round two",
                sender_id: message.sender_id,
            });
        }
    }
    ensure_other_senders(own_id, "round two", &packages)?;
    Ok(packages)
}

fn ensure_other_senders<T>(
    own_id: u16,
    round: &'static str,
    packages: &BTreeMap<FrostIdentifier, T>,
) -> Result<()> {
    for validator_id in 1..=DKG_PARTICIPANTS {
        if validator_id != own_id && !packages.contains_key(&identifier(validator_id)?) {
            return Err(ThresholdDkgError::MissingSender {
                round,
                validator_id,
            });
        }
    }
    Ok(())
}

fn validate_message(version: u16, session: &DkgSession, sender_id: u16) -> Result<()> {
    if version != DKG_FORMAT_VERSION {
        return Err(ThresholdDkgError::UnsupportedVersion(version));
    }
    session.validate()?;
    identifier(sender_id)?;
    Ok(())
}

fn encode_message<T: Serialize>(
    message: &T,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>> {
    let bytes = serde_jcs::to_vec(message).map_err(|error| ThresholdDkgError::Serialization {
        label,
        reason: error.to_string(),
    })?;
    if bytes.len() > maximum {
        return Err(ThresholdDkgError::MessageTooLarge { label, maximum });
    }
    Ok(bytes)
}

fn decode_message<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
    label: &'static str,
) -> Result<T> {
    if bytes.len() > maximum {
        return Err(ThresholdDkgError::MessageTooLarge { label, maximum });
    }
    let message: T =
        serde_json::from_slice(bytes).map_err(|error| ThresholdDkgError::Serialization {
            label,
            reason: error.to_string(),
        })?;
    let canonical =
        serde_jcs::to_vec(&message).map_err(|error| ThresholdDkgError::Serialization {
            label,
            reason: error.to_string(),
        })?;
    if canonical != bytes {
        return Err(ThresholdDkgError::NonCanonical(label));
    }
    Ok(message)
}

fn validate_epoch(epoch: u64) -> Result<()> {
    if epoch == 0 {
        return Err(ThresholdDkgError::ZeroEpoch);
    }
    Ok(())
}

fn identifier(validator_id: u16) -> Result<FrostIdentifier> {
    if !(1..=DKG_PARTICIPANTS).contains(&validator_id) {
        return Err(ThresholdDkgError::InvalidValidatorId(validator_id));
    }
    FrostIdentifier::try_from(validator_id).map_err(frost_error)
}

fn validator_id(identifier: &FrostIdentifier) -> Result<u16> {
    for validator_id in 1..=DKG_PARTICIPANTS {
        if identifier == &self::identifier(validator_id)? {
            return Ok(validator_id);
        }
    }
    Err(ThresholdDkgError::InconsistentOutput(
        "FROST emitted an identifier outside 1 through 4",
    ))
}

fn fixed_32(bytes: Vec<u8>, reason: &'static str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| ThresholdDkgError::InconsistentOutput(reason))
}

fn frost_error(error: frost::Error) -> ThresholdDkgError {
    ThresholdDkgError::Frost(format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use frost::rand_core::OsRng;

    use super::*;
    use crate::private_order::{
        PrivateOrderContext, create_decryption_share, decrypt_private_order, encrypt_private_order,
    };

    fn test_chain_domain() -> [u8; 32] {
        derive_dkg_chain_domain("asteria-dkg-test").unwrap()
    }

    fn initial_session(epoch: u64) -> DkgSession {
        DkgSession::initial(
            test_chain_domain(),
            [u8::try_from(epoch).unwrap_or(1); 32],
            epoch,
        )
        .unwrap()
    }

    fn run_initial_dkg(epoch: u64) -> Vec<FinalizedParticipant> {
        let session = initial_session(epoch);
        let mut round1_states = Vec::new();
        let mut round1_messages = Vec::new();
        for validator_id in 1..=DKG_PARTICIPANTS {
            let (state, message) = participant_round1(&session, validator_id, &mut OsRng).unwrap();
            round1_states.push(state);
            round1_messages.push(message);
        }

        let mut round2_states = Vec::new();
        let mut round2_messages = Vec::new();
        for state in round1_states {
            let incoming = round1_messages
                .iter()
                .filter(|message| message.sender_id != state.validator_id())
                .cloned()
                .collect::<Vec<_>>();
            let (state, outgoing) = participant_round2(state, &incoming).unwrap();
            round2_states.push(state);
            round2_messages.extend(outgoing);
        }

        round2_states
            .into_iter()
            .map(|state| {
                let incoming = round2_messages
                    .iter()
                    .filter(|message| message.recipient_id == state.validator_id())
                    .cloned()
                    .collect::<Vec<_>>();
                participant_finalize(state, &incoming).unwrap()
            })
            .collect()
    }

    fn run_refresh(
        new_epoch: u64,
        participants: Vec<FinalizedParticipant>,
    ) -> Vec<FinalizedParticipant> {
        let session = DkgSession::refresh(
            test_chain_domain(),
            [u8::try_from(new_epoch).unwrap_or(1); 32],
            new_epoch,
            participants[0].public_keys().key_id,
        )
        .unwrap();
        let mut round1_states = Vec::new();
        let mut round1_messages = Vec::new();
        for participant in participants {
            let (state, message) =
                participant_refresh_round1(&session, participant, &mut OsRng).unwrap();
            round1_states.push(state);
            round1_messages.push(message);
        }
        let mut round2_states = Vec::new();
        let mut round2_messages = Vec::new();
        for state in round1_states {
            let incoming = round1_messages
                .iter()
                .filter(|message| message.sender_id != state.validator_id())
                .cloned()
                .collect::<Vec<_>>();
            let (state, outgoing) = participant_round2(state, &incoming).unwrap();
            round2_states.push(state);
            round2_messages.extend(outgoing);
        }
        round2_states
            .into_iter()
            .map(|state| {
                let incoming = round2_messages
                    .iter()
                    .filter(|message| message.recipient_id == state.validator_id())
                    .cloned()
                    .collect::<Vec<_>>();
                participant_finalize(state, &incoming).unwrap()
            })
            .collect()
    }

    #[test]
    fn full_four_party_dkg_agrees_and_any_three_decrypt() {
        let participants = run_initial_dkg(7);
        for participant in &participants {
            assert_eq!(participant.public_keys(), participants[0].public_keys());
            assert_eq!(
                participant.frost_public_key_package(),
                participants[0].frost_public_key_package()
            );
            assert_eq!(
                participant.validator_id(),
                participant.secret_share().validator_id()
            );
        }

        let context = PrivateOrderContext {
            chain_id: "asteria-dkg-test".into(),
            market_id: "BTCUSDT".into(),
            epoch: 7,
            batch_height: 10,
        };
        let payload = b"frost-dkg-private-order";
        let envelope = encrypt_private_order(
            participants[0].public_keys(),
            &context,
            [1; 32],
            [2; 32],
            payload,
            &mut OsRng,
        )
        .unwrap();

        for omitted in 0..participants.len() {
            let shares = participants
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, participant)| {
                    create_decryption_share(
                        participant.public_keys(),
                        participant.secret_share(),
                        &context,
                        &envelope,
                        &mut OsRng,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(
                decrypt_private_order(participants[0].public_keys(), &context, &envelope, &shares,)
                    .unwrap(),
                payload
            );
        }
    }

    #[test]
    fn messages_are_canonical_bounded_and_round_trip() {
        let session = initial_session(1);
        let (state, round1) = participant_round1(&session, 1, &mut OsRng).unwrap();
        let bytes = round1.to_canonical_json().unwrap();
        assert!(bytes.len() <= MAX_ROUND1_MESSAGE_BYTES);
        assert_eq!(Round1Message::from_canonical_json(&bytes).unwrap(), round1);

        let mut noncanonical = bytes.clone();
        noncanonical.push(b' ');
        assert_eq!(
            Round1Message::from_canonical_json(&noncanonical),
            Err(ThresholdDkgError::NonCanonical("round-one message"))
        );
        assert!(matches!(
            Round1Message::from_canonical_json(&vec![b' '; MAX_ROUND1_MESSAGE_BYTES + 1]),
            Err(ThresholdDkgError::MessageTooLarge { .. })
        ));

        // Finish enough round one to exercise the confidential round-two codec.
        let mut messages = vec![round1];
        for validator_id in 2..=4 {
            messages.push(
                participant_round1(&session, validator_id, &mut OsRng)
                    .unwrap()
                    .1,
            );
        }
        let incoming = messages
            .iter()
            .filter(|message| message.sender_id != 1)
            .cloned()
            .collect::<Vec<_>>();
        let (_, outgoing) = participant_round2(state, &incoming).unwrap();
        for message in outgoing {
            let bytes = message.to_canonical_json().unwrap();
            assert!(bytes.len() <= MAX_ROUND2_MESSAGE_BYTES);
            assert_eq!(Round2Message::from_canonical_json(&bytes).unwrap(), message);
        }
    }

    #[test]
    fn missing_tampered_and_wrong_identifier_messages_fail() {
        let session = initial_session(1);
        assert!(matches!(
            participant_round1(&session, 0, &mut OsRng),
            Err(ThresholdDkgError::InvalidValidatorId(0))
        ));
        assert!(matches!(
            participant_round1(&session, 5, &mut OsRng),
            Err(ThresholdDkgError::InvalidValidatorId(5))
        ));

        let session = initial_session(2);
        let mut states = Vec::new();
        let mut messages = Vec::new();
        for validator_id in 1..=4 {
            let (state, message) = participant_round1(&session, validator_id, &mut OsRng).unwrap();
            states.push(state);
            messages.push(message);
        }
        let state = states.remove(0);
        let missing = messages
            .iter()
            .filter(|message| matches!(message.sender_id, 2 | 3))
            .cloned()
            .collect::<Vec<_>>();
        assert!(matches!(
            participant_round2(state, &missing),
            Err(ThresholdDkgError::IncorrectMessageCount {
                round: "round one",
                actual: 2
            })
        ));

        let session = initial_session(3);
        let (state, _) = participant_round1(&session, 1, &mut OsRng).unwrap();
        let mut incoming = Vec::new();
        for validator_id in 2..=4 {
            incoming.push(
                participant_round1(&session, validator_id, &mut OsRng)
                    .unwrap()
                    .1,
            );
        }
        // Bind validator 2's proof to validator 4's transport identity.
        incoming[0].sender_id = 4;
        incoming[2].sender_id = 2;
        assert!(matches!(
            participant_round2(state, &incoming),
            Err(ThresholdDkgError::Frost(_))
        ));

        let session = initial_session(4);
        let (_, message) = participant_round1(&session, 1, &mut OsRng).unwrap();
        let mut bytes = message.to_canonical_json().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(Round1Message::from_canonical_json(&bytes).is_err());
    }

    #[test]
    fn cross_chain_or_reused_ceremony_messages_are_rejected() {
        let local = DkgSession::initial(test_chain_domain(), [41; 32], 5).unwrap();
        let other_chain = DkgSession::initial(
            derive_dkg_chain_domain("asteria-dkg-other").unwrap(),
            [41; 32],
            5,
        )
        .unwrap();
        let reused_ceremony = DkgSession::initial(test_chain_domain(), [42; 32], 5).unwrap();
        let (local_state, _) = participant_round1(&local, 1, &mut OsRng).unwrap();

        for foreign in [&other_chain, &reused_ceremony] {
            let incoming = (2..=4)
                .map(|validator_id| {
                    participant_round1(foreign, validator_id, &mut OsRng)
                        .unwrap()
                        .1
                })
                .collect::<Vec<_>>();
            assert!(matches!(
                collect_round1(1, local_state.session(), &incoming),
                Err(ThresholdDkgError::WrongSession)
            ));
        }
    }

    #[test]
    fn official_refresh_preserves_group_key_and_rotates_shares() {
        let participants = run_initial_dkg(11);
        let old_group_key = participants[0].public_keys().public_key;
        let old_public_shares = participants[0]
            .public_keys()
            .validators
            .iter()
            .map(|share| share.public_key)
            .collect::<Vec<_>>();
        let refreshed = run_refresh(12, participants);

        assert_eq!(refreshed[0].public_keys().public_key, old_group_key);
        assert_ne!(
            refreshed[0]
                .public_keys()
                .validators
                .iter()
                .map(|share| share.public_key)
                .collect::<Vec<_>>(),
            old_public_shares
        );
        for participant in &refreshed {
            assert_eq!(participant.epoch(), 12);
            assert_eq!(participant.public_keys(), refreshed[0].public_keys());
        }
    }
}
