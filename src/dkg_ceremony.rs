//! Recoverable orchestration for the two-round threshold DKG.
//!
//! [`crate::threshold_dkg`] owns FROST state transitions and
//! [`crate::dkg_transport`] owns authenticated wire messages.  This module is
//! deliberately the small coordinator between them: it persists only public
//! transcripts and an opaque provider checkpoint, while a software wallet or
//! HSM keeps the non-serializable FROST participant state.  A journal entry is
//! never deleted, including after completion or abort, so a ceremony id and
//! its endorsement guard can never be reused.

use std::{collections::BTreeMap, sync::Arc};

use parking_lot::Mutex;
use rand_core::OsRng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    dkg_transport::{
        AuthenticatedBroadcastEnvelope, BroadcastEndorsement, CertifiedBroadcastEnvelope,
        DkgBroadcastEndorsementGuard, DkgTransportError, DkgTransportIdentity, DkgTransportPeer,
        DkgTransportRegistry, EncryptedPointToPointEnvelope, endorse_broadcast,
        open_certified_round1_broadcast, open_round2_point_to_point, seal_round1_broadcast,
        seal_round2_point_to_point,
    },
    threshold_dkg::{
        DKG_PARTICIPANTS, DkgKind, DkgSession, FinalizedParticipant, Round1Message,
        Round1Participant, Round2Message, Round2Participant, participant_finalize,
        participant_refresh_round1, participant_round1, participant_round2,
    },
};

pub const DKG_CEREMONY_RECORD_VERSION: u16 = 1;
pub const MAX_DKG_CEREMONY_RECORD_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DKG_PROVIDER_CHECKPOINT_BYTES: usize = 512 * 1024;
pub const DKG_CEREMONY_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_ORDER_DKG_CEREMONY_V1\0";

/// Durable protocol phase.  The `Finalize` phase is an intent record: a crash
/// after entering it is resumed by asking the provider to repeat an idempotent
/// `part3` operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgCeremonyPhase {
    Initial,
    Round1,
    Round2,
    Finalize,
    Completed,
    Aborted,
}

impl DkgCeremonyPhase {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgCeremonyDeadlines {
    pub round1_unix_ms: u64,
    pub round2_unix_ms: u64,
    pub finalize_unix_ms: u64,
}

impl DkgCeremonyDeadlines {
    pub fn validate(&self) -> Result<(), DkgCeremonyError> {
        if self.round1_unix_ms == 0
            || self.round2_unix_ms <= self.round1_unix_ms
            || self.finalize_unix_ms <= self.round2_unix_ms
        {
            return Err(DkgCeremonyError::InvalidRecord(
                "ceremony deadlines must be non-zero and strictly increasing".into(),
            ));
        }
        Ok(())
    }

    fn deadline_for(self, phase: DkgCeremonyPhase) -> Option<u64> {
        match phase {
            DkgCeremonyPhase::Initial | DkgCeremonyPhase::Round1 => Some(self.round1_unix_ms),
            DkgCeremonyPhase::Round2 => Some(self.round2_unix_ms),
            DkgCeremonyPhase::Finalize => Some(self.finalize_unix_ms),
            DkgCeremonyPhase::Completed | DkgCeremonyPhase::Aborted => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgCeremonyAbortCode {
    Timeout,
    Equivocation,
    Round2SemanticFailure,
    FinalizeSemanticFailure,
    ProviderFailure,
    Operator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgCeremonyAbort {
    pub at_unix_ms: u64,
    pub code: DkgCeremonyAbortCode,
    pub detail_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgCeremonyCompletion {
    pub validator_id: u16,
    pub epoch: u64,
    pub public_key: [u8; 32],
    pub key_id: [u8; 32],
}

impl DkgCeremonyCompletion {
    fn validate(&self, session: &DkgSession) -> Result<(), DkgCeremonyError> {
        if !(1..=DKG_PARTICIPANTS).contains(&self.validator_id)
            || self.epoch != session.epoch
            || self.public_key == [0; 32]
            || self.key_id == [0; 32]
        {
            return Err(DkgCeremonyError::InvalidRecord(
                "provider completion is not bound to the ceremony".into(),
            ));
        }
        Ok(())
    }
}

/// The only state persisted by the coordinator.  FROST participant secrets
/// are represented by `provider_checkpoint` and never enter this structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgCeremonyRecord {
    pub version: u16,
    pub revision: u64,
    pub session: DkgSession,
    pub validator_id: u16,
    pub registry_digest: [u8; 32],
    pub phase: DkgCeremonyPhase,
    pub deadlines: DkgCeremonyDeadlines,
    #[serde(default)]
    pub provider_checkpoint: Vec<u8>,
    #[serde(default)]
    pub local_round1_message: Option<Vec<u8>>,
    #[serde(default)]
    pub local_round1_envelope: Option<Vec<u8>>,
    #[serde(default)]
    pub round1_certificates: BTreeMap<u16, Vec<u8>>,
    #[serde(default)]
    pub round1_messages: BTreeMap<u16, Vec<u8>>,
    #[serde(default)]
    pub outgoing_round2_envelopes: BTreeMap<u16, Vec<u8>>,
    #[serde(default)]
    pub incoming_round2_envelopes: BTreeMap<u16, Vec<u8>>,
    #[serde(default)]
    pub incoming_round2_messages: BTreeMap<u16, Vec<u8>>,
    #[serde(default)]
    pub completion: Option<DkgCeremonyCompletion>,
    #[serde(default)]
    pub abort: Option<DkgCeremonyAbort>,
}

impl DkgCeremonyRecord {
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, DkgCeremonyError> {
        self.validate_shape()?;
        let bytes = serde_jcs::to_vec(self)
            .map_err(|error| DkgCeremonyError::Serialization(error.to_string()))?;
        if bytes.len() > MAX_DKG_CEREMONY_RECORD_BYTES {
            return Err(DkgCeremonyError::RecordTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, DkgCeremonyError> {
        if bytes.is_empty() || bytes.len() > MAX_DKG_CEREMONY_RECORD_BYTES {
            return Err(DkgCeremonyError::RecordTooLarge);
        }
        let record: Self = decode_canonical(bytes)?;
        record.validate_shape()?;
        Ok(record)
    }

    fn validate_shape(&self) -> Result<(), DkgCeremonyError> {
        if self.version != DKG_CEREMONY_RECORD_VERSION || self.revision == 0 {
            return Err(DkgCeremonyError::InvalidRecord(
                "unsupported ceremony record version or revision".into(),
            ));
        }
        self.session
            .validate()
            .map_err(|error| DkgCeremonyError::InvalidRecord(error.to_string()))?;
        if !(1..=DKG_PARTICIPANTS).contains(&self.validator_id)
            || self.registry_digest == [0; 32]
            || self.provider_checkpoint.len() > MAX_DKG_PROVIDER_CHECKPOINT_BYTES
        {
            return Err(DkgCeremonyError::InvalidRecord(
                "ceremony record identity or checkpoint is invalid".into(),
            ));
        }
        self.deadlines.validate()?;
        if self.phase == DkgCeremonyPhase::Aborted {
            if self.abort.is_none() || self.completion.is_some() {
                return Err(DkgCeremonyError::InvalidRecord(
                    "aborted ceremony must carry only an abort tombstone".into(),
                ));
            }
        } else if self.abort.is_some() {
            return Err(DkgCeremonyError::InvalidRecord(
                "non-aborted ceremony cannot carry an abort tombstone".into(),
            ));
        }
        if self.phase == DkgCeremonyPhase::Completed {
            self.completion
                .as_ref()
                .ok_or_else(|| {
                    DkgCeremonyError::InvalidRecord(
                        "completed ceremony is missing its public completion".into(),
                    )
                })?
                .validate(&self.session)?;
        } else if self.completion.is_some() {
            return Err(DkgCeremonyError::InvalidRecord(
                "non-completed ceremony cannot carry a completion".into(),
            ));
        }
        for (id, bytes) in self
            .round1_certificates
            .iter()
            .chain(self.round1_messages.iter())
            .chain(self.outgoing_round2_envelopes.iter())
            .chain(self.incoming_round2_envelopes.iter())
            .chain(self.incoming_round2_messages.iter())
        {
            if !(1..=DKG_PARTICIPANTS).contains(id) || bytes.is_empty() {
                return Err(DkgCeremonyError::InvalidRecord(
                    "ceremony transcript has an invalid validator id or empty payload".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgCeremonyJournalError {
    #[error("ceremony journal entry already exists")]
    AlreadyExists,
    #[error("ceremony journal entry was not found")]
    NotFound,
    #[error("ceremony journal revision conflict: expected {expected}, found {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("ceremony journal storage failure: {0}")]
    Storage(String),
    #[error("ceremony journal contains invalid canonical data: {0}")]
    InvalidData(String),
}

/// Durable journal contract.  Implementations must make `create` and
/// `compare_and_swap` atomic and must retain terminal records forever.
pub trait DkgCeremonyJournal {
    fn create(&self, record: &DkgCeremonyRecord) -> Result<(), DkgCeremonyJournalError>;
    fn load(
        &self,
        ceremony_id: [u8; 32],
    ) -> Result<Option<DkgCeremonyRecord>, DkgCeremonyJournalError>;
    fn compare_and_swap(
        &self,
        ceremony_id: [u8; 32],
        expected_revision: u64,
        next: &DkgCeremonyRecord,
    ) -> Result<(), DkgCeremonyJournalError>;
}

/// In-memory journal used by tests and local tooling.  It deliberately stores
/// canonical bytes rather than Rust values, exercising the same boundary a
/// redb/SQL/HSM-backed implementation must provide.
#[derive(Clone, Default)]
pub struct MemoryDkgCeremonyJournal {
    entries: Arc<Mutex<BTreeMap<[u8; 32], Vec<u8>>>>,
}

impl MemoryDkgCeremonyJournal {
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

impl DkgCeremonyJournal for MemoryDkgCeremonyJournal {
    fn create(&self, record: &DkgCeremonyRecord) -> Result<(), DkgCeremonyJournalError> {
        let id = record.session.ceremony_id;
        let bytes = record
            .to_canonical_json()
            .map_err(|error| DkgCeremonyJournalError::InvalidData(error.to_string()))?;
        let mut entries = self.entries.lock();
        if entries.contains_key(&id) {
            return Err(DkgCeremonyJournalError::AlreadyExists);
        }
        entries.insert(id, bytes);
        Ok(())
    }

    fn load(
        &self,
        ceremony_id: [u8; 32],
    ) -> Result<Option<DkgCeremonyRecord>, DkgCeremonyJournalError> {
        let entries = self.entries.lock();
        entries
            .get(&ceremony_id)
            .map(|bytes| DkgCeremonyRecord::from_canonical_json(bytes))
            .transpose()
            .map_err(|error| DkgCeremonyJournalError::InvalidData(error.to_string()))
    }

    fn compare_and_swap(
        &self,
        ceremony_id: [u8; 32],
        expected_revision: u64,
        next: &DkgCeremonyRecord,
    ) -> Result<(), DkgCeremonyJournalError> {
        let next_revision = expected_revision.checked_add(1).ok_or_else(|| {
            DkgCeremonyJournalError::InvalidData("journal revision overflow".into())
        })?;
        if next.session.ceremony_id != ceremony_id || next.revision != next_revision {
            return Err(DkgCeremonyJournalError::InvalidData(
                "journal CAS record has an invalid identity or revision".into(),
            ));
        }
        let bytes = next
            .to_canonical_json()
            .map_err(|error| DkgCeremonyJournalError::InvalidData(error.to_string()))?;
        let mut entries = self.entries.lock();
        let current = entries
            .get(&ceremony_id)
            .ok_or(DkgCeremonyJournalError::NotFound)?;
        let current_record = DkgCeremonyRecord::from_canonical_json(current)
            .map_err(|error| DkgCeremonyJournalError::InvalidData(error.to_string()))?;
        if current_record.revision != expected_revision {
            return Err(DkgCeremonyJournalError::RevisionConflict {
                expected: expected_revision,
                actual: current_record.revision,
            });
        }
        if current_record.version != next.version
            || current_record.session != next.session
            || current_record.validator_id != next.validator_id
            || current_record.registry_digest != next.registry_digest
            || current_record.deadlines != next.deadlines
        {
            return Err(DkgCeremonyJournalError::InvalidData(
                "journal CAS attempted to change an immutable ceremony binding".into(),
            ));
        }
        if !valid_phase_transition(current_record.phase, next.phase) {
            return Err(DkgCeremonyJournalError::InvalidData(format!(
                "journal CAS attempted invalid phase transition {:?} -> {:?}",
                current_record.phase, next.phase
            )));
        }
        entries.insert(ceremony_id, bytes);
        Ok(())
    }
}

fn valid_phase_transition(current: DkgCeremonyPhase, next: DkgCeremonyPhase) -> bool {
    match current {
        DkgCeremonyPhase::Initial => {
            matches!(next, DkgCeremonyPhase::Round1 | DkgCeremonyPhase::Aborted)
        }
        DkgCeremonyPhase::Round1 => matches!(
            next,
            DkgCeremonyPhase::Round1 | DkgCeremonyPhase::Round2 | DkgCeremonyPhase::Aborted
        ),
        DkgCeremonyPhase::Round2 => matches!(
            next,
            DkgCeremonyPhase::Round2 | DkgCeremonyPhase::Finalize | DkgCeremonyPhase::Aborted
        ),
        DkgCeremonyPhase::Finalize => {
            matches!(
                next,
                DkgCeremonyPhase::Completed | DkgCeremonyPhase::Aborted
            )
        }
        DkgCeremonyPhase::Completed | DkgCeremonyPhase::Aborted => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgProviderState {
    Ready,
    Round1,
    Round2,
    Completed,
    Quarantined,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgCeremonyProviderError {
    #[error("provider transport failure: {0}")]
    Transport(String),
    #[error("provider FROST failure: {0}")]
    Frost(String),
    #[error("provider key custody failure: {0}")]
    Custody(String),
    #[error("provider state failure: {0}")]
    State(String),
}

pub type DkgCeremonyProviderResult<T> = Result<T, DkgCeremonyProviderError>;

/// HSM/transport boundary.  Implementations keep signing, X25519, and FROST
/// secret packages behind this trait; the coordinator only sees typed public
/// envelopes and an opaque, bounded checkpoint.  Every mutating method must be
/// idempotent for `(session, operation, message digest)` and `quarantine` must
/// be rollback-resistant, so a journal crash cannot make a guard reusable.
pub trait DkgCeremonyCryptoProvider {
    fn local_peer(&self) -> DkgTransportPeer;
    fn checkpoint(&self, session: &DkgSession) -> DkgCeremonyProviderResult<Vec<u8>>;
    fn restore_checkpoint(
        &mut self,
        session: &DkgSession,
        phase: DkgCeremonyPhase,
        checkpoint: &[u8],
    ) -> DkgCeremonyProviderResult<DkgProviderState>;
    fn begin_round1(
        &mut self,
        session: &DkgSession,
    ) -> DkgCeremonyProviderResult<(Round1Message, AuthenticatedBroadcastEnvelope)>;
    fn endorse_round1(
        &mut self,
        session: &DkgSession,
        envelope: &AuthenticatedBroadcastEnvelope,
    ) -> DkgCeremonyProviderResult<BroadcastEndorsement>;
    fn advance_round2(
        &mut self,
        session: &DkgSession,
        received: &[Round1Message],
    ) -> DkgCeremonyProviderResult<Vec<(Round2Message, EncryptedPointToPointEnvelope)>>;
    fn open_round2(
        &mut self,
        session: &DkgSession,
        envelope: &EncryptedPointToPointEnvelope,
    ) -> DkgCeremonyProviderResult<Round2Message>;
    fn finalize(
        &mut self,
        session: &DkgSession,
        received: &[Round2Message],
    ) -> DkgCeremonyProviderResult<DkgCeremonyCompletion>;
    fn quarantine(
        &mut self,
        session: &DkgSession,
        reason: DkgCeremonyAbortCode,
    ) -> DkgCeremonyProviderResult<()>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgCeremonyError {
    #[error("ceremony journal error: {0}")]
    Journal(#[from] DkgCeremonyJournalError),
    #[error("ceremony provider error: {0}")]
    Provider(String),
    #[error("ceremony transport error: {0}")]
    Transport(String),
    #[error("invalid ceremony record: {0}")]
    InvalidRecord(String),
    #[error("ceremony record exceeds the configured size limit")]
    RecordTooLarge,
    #[error("ceremony is in phase {actual:?}, expected {expected:?}")]
    WrongPhase {
        expected: DkgCeremonyPhase,
        actual: DkgCeremonyPhase,
    },
    #[error("ceremony is not ready: expected {expected} messages, received {actual}")]
    NotReady { expected: usize, actual: usize },
    #[error("ceremony timed out in phase {phase:?}")]
    TimedOut { phase: DkgCeremonyPhase },
    #[error("ceremony was aborted in phase {phase:?}")]
    Aborted { phase: DkgCeremonyPhase },
    #[error("ceremony observed equivocation by validator {validator_id}")]
    Equivocation { validator_id: u16 },
    #[error("ceremony message is invalid: {0}")]
    InvalidMessage(String),
    #[error("ceremony serialization failure: {0}")]
    Serialization(String),
}

pub type DkgCeremonyResult<T> = Result<T, DkgCeremonyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DkgMessageAcceptance {
    New,
    Duplicate,
}

pub struct DkgCeremonyCoordinator<J, P> {
    journal: J,
    provider: P,
    registry: DkgTransportRegistry,
    record: DkgCeremonyRecord,
}

impl<J, P> DkgCeremonyCoordinator<J, P>
where
    J: DkgCeremonyJournal,
    P: DkgCeremonyCryptoProvider,
{
    pub fn start(
        journal: J,
        provider: P,
        registry: DkgTransportRegistry,
        session: DkgSession,
        deadlines: DkgCeremonyDeadlines,
        expected_chain_domain: [u8; 32],
        expected_epoch: u64,
    ) -> DkgCeremonyResult<Self> {
        session
            .validate()
            .map_err(|error| DkgCeremonyError::InvalidRecord(error.to_string()))?;
        deadlines.validate()?;
        if session.chain_domain != expected_chain_domain || session.epoch != expected_epoch {
            return Err(DkgCeremonyError::InvalidRecord(
                "ceremony session is not bound to the expected chain domain and epoch".into(),
            ));
        }
        let peer = provider.local_peer();
        validate_registry_identity(&registry, &peer)?;
        let checkpoint = provider.checkpoint(&session).map_err(provider_error)?;
        validate_checkpoint(&checkpoint)?;
        let record = DkgCeremonyRecord {
            version: DKG_CEREMONY_RECORD_VERSION,
            revision: 1,
            session,
            validator_id: peer.validator_id,
            registry_digest: registry_digest(&registry)?,
            phase: DkgCeremonyPhase::Initial,
            deadlines,
            provider_checkpoint: checkpoint,
            local_round1_message: None,
            local_round1_envelope: None,
            round1_certificates: BTreeMap::new(),
            round1_messages: BTreeMap::new(),
            outgoing_round2_envelopes: BTreeMap::new(),
            incoming_round2_envelopes: BTreeMap::new(),
            incoming_round2_messages: BTreeMap::new(),
            completion: None,
            abort: None,
        };
        journal.create(&record)?;
        Ok(Self {
            journal,
            provider,
            registry,
            record,
        })
    }

    pub fn recover(
        journal: J,
        mut provider: P,
        registry: DkgTransportRegistry,
        ceremony_id: [u8; 32],
        expected_chain_domain: [u8; 32],
        expected_epoch: u64,
    ) -> DkgCeremonyResult<Self> {
        let record = journal
            .load(ceremony_id)?
            .ok_or(DkgCeremonyJournalError::NotFound)?;
        if record.session.ceremony_id != ceremony_id
            || record.session.chain_domain != expected_chain_domain
            || record.session.epoch != expected_epoch
            || record.registry_digest != registry_digest(&registry)?
        {
            return Err(DkgCeremonyError::InvalidRecord(
                "recovered ceremony binding does not match the requested context".into(),
            ));
        }
        let peer = provider.local_peer();
        validate_registry_identity(&registry, &peer)?;
        if peer.validator_id != record.validator_id {
            return Err(DkgCeremonyError::InvalidRecord(
                "recovered ceremony validator identity differs from the provider".into(),
            ));
        }
        let provider_state = provider
            .restore_checkpoint(&record.session, record.phase, &record.provider_checkpoint)
            .map_err(provider_error)?;
        let expected = expected_provider_states(record.phase);
        if !expected.contains(&provider_state) {
            return Err(DkgCeremonyError::InvalidRecord(format!(
                "provider reported state {provider_state:?} while journal is {:?}",
                record.phase
            )));
        }
        Ok(Self {
            journal,
            provider,
            registry,
            record,
        })
    }

    pub fn phase(&self) -> DkgCeremonyPhase {
        self.record.phase
    }

    pub fn record(&self) -> &DkgCeremonyRecord {
        &self.record
    }

    pub fn into_parts(self) -> (J, P) {
        (self.journal, self.provider)
    }

    pub fn begin_round1(
        &mut self,
        now_unix_ms: u64,
    ) -> DkgCeremonyResult<AuthenticatedBroadcastEnvelope> {
        self.ensure_live(now_unix_ms)?;
        if self.record.phase == DkgCeremonyPhase::Round1 {
            return self
                .record
                .local_round1_envelope
                .as_deref()
                .ok_or_else(|| {
                    DkgCeremonyError::InvalidRecord("round-one envelope is missing".into())
                })
                .and_then(decode_broadcast);
        }
        self.expect_phase(DkgCeremonyPhase::Initial)?;
        let (message, envelope) = match self.provider.begin_round1(&self.record.session) {
            Ok(output) => output,
            Err(error) => {
                let mapped = provider_error(error);
                return Err(self.abort_on_provider_error(
                    now_unix_ms,
                    DkgCeremonyAbortCode::ProviderFailure,
                    mapped,
                ));
            }
        };
        validate_local_round1(
            &self.record.session,
            self.record.validator_id,
            &self.registry,
            &message,
            &envelope,
        )?;
        let mut next = self.record.clone();
        next.phase = DkgCeremonyPhase::Round1;
        next.local_round1_message = Some(canonical(&message)?);
        next.local_round1_envelope = Some(envelope.to_canonical_json().map_err(transport_error)?);
        next.provider_checkpoint = self.checkpoint()?;
        self.commit(next)?;
        Ok(envelope)
    }

    pub fn endorse_round1(
        &mut self,
        envelope: &AuthenticatedBroadcastEnvelope,
        now_unix_ms: u64,
    ) -> DkgCeremonyResult<BroadcastEndorsement> {
        self.ensure_live(now_unix_ms)?;
        self.expect_phase(DkgCeremonyPhase::Round1)?;
        let endorsement = self
            .provider
            .endorse_round1(&self.record.session, envelope)
            .map_err(provider_error)?;
        let mut next = self.record.clone();
        next.provider_checkpoint = self.checkpoint()?;
        self.commit(next)?;
        Ok(endorsement)
    }

    pub fn accept_round1_certificate(
        &mut self,
        certificate: &CertifiedBroadcastEnvelope,
        now_unix_ms: u64,
    ) -> DkgCeremonyResult<DkgMessageAcceptance> {
        self.ensure_live(now_unix_ms)?;
        self.expect_phase(DkgCeremonyPhase::Round1)?;
        let message =
            open_certified_round1_broadcast(&self.record.session, &self.registry, certificate)
                .map_err(transport_error)?;
        let sender_id = message.sender_id;
        let message_bytes = canonical(&message)?;
        if let Some(existing) = self.record.round1_messages.get(&sender_id) {
            if existing == &message_bytes {
                return Ok(DkgMessageAcceptance::Duplicate);
            }
            return Err(self.abort_for_equivocation(now_unix_ms, sender_id));
        }
        let mut next = self.record.clone();
        next.round1_messages.insert(sender_id, message_bytes);
        next.round1_certificates.insert(
            sender_id,
            certificate.to_canonical_json().map_err(transport_error)?,
        );
        self.commit(next)?;
        Ok(DkgMessageAcceptance::New)
    }

    pub fn advance_round2(
        &mut self,
        now_unix_ms: u64,
    ) -> DkgCeremonyResult<Vec<EncryptedPointToPointEnvelope>> {
        self.ensure_live(now_unix_ms)?;
        if self.record.phase == DkgCeremonyPhase::Round2 {
            return self
                .record
                .outgoing_round2_envelopes
                .values()
                .map(|bytes| decode_point_to_point(bytes))
                .collect();
        }
        self.expect_phase(DkgCeremonyPhase::Round1)?;
        if self.record.round1_messages.len() != usize::from(DKG_PARTICIPANTS) {
            return Err(DkgCeremonyError::NotReady {
                expected: usize::from(DKG_PARTICIPANTS),
                actual: self.record.round1_messages.len(),
            });
        }
        let mut messages = Vec::with_capacity(usize::from(DKG_PARTICIPANTS - 1));
        for (sender, bytes) in &self.record.round1_messages {
            if *sender == self.record.validator_id {
                continue;
            }
            messages.push(decode_round1(bytes)?);
        }
        let outgoing = match self
            .provider
            .advance_round2(&self.record.session, &messages)
        {
            Ok(outgoing) => outgoing,
            Err(error) => {
                let mapped = provider_error(error);
                return Err(self.abort_for_failure(
                    now_unix_ms,
                    DkgCeremonyAbortCode::Round2SemanticFailure,
                    &mapped,
                ));
            }
        };
        if outgoing.len() != usize::from(DKG_PARTICIPANTS - 1) {
            return Err(self.abort_for_failure(
                now_unix_ms,
                DkgCeremonyAbortCode::Round2SemanticFailure,
                &DkgCeremonyError::InvalidMessage(
                    "provider did not produce three round-two messages".into(),
                ),
            ));
        }
        let mut next = self.record.clone();
        next.phase = DkgCeremonyPhase::Round2;
        let mut recipients = BTreeMap::new();
        for (message, envelope) in outgoing {
            validate_outgoing_round2(
                &self.record.session,
                self.record.validator_id,
                &self.registry,
                &message,
                &envelope,
            )?;
            if recipients.insert(message.recipient_id, ()).is_some() {
                return Err(self.abort_for_failure(
                    now_unix_ms,
                    DkgCeremonyAbortCode::Round2SemanticFailure,
                    &DkgCeremonyError::InvalidMessage(
                        "provider emitted duplicate round-two recipient".into(),
                    ),
                ));
            }
            next.outgoing_round2_envelopes.insert(
                message.recipient_id,
                envelope.to_canonical_json().map_err(transport_error)?,
            );
        }
        next.provider_checkpoint = self.checkpoint()?;
        self.commit(next)?;
        self.record
            .outgoing_round2_envelopes
            .values()
            .map(|bytes| decode_point_to_point(bytes))
            .collect()
    }

    pub fn accept_round2(
        &mut self,
        envelope: &EncryptedPointToPointEnvelope,
        now_unix_ms: u64,
    ) -> DkgCeremonyResult<DkgMessageAcceptance> {
        self.ensure_live(now_unix_ms)?;
        self.expect_phase(DkgCeremonyPhase::Round2)?;
        let sender_id = envelope.sender_id;
        let envelope_bytes = envelope.to_canonical_json().map_err(transport_error)?;
        if let Some(existing) = self.record.incoming_round2_envelopes.get(&sender_id)
            && existing == &envelope_bytes
        {
            return Ok(DkgMessageAcceptance::Duplicate);
        }
        let message = self
            .provider
            .open_round2(&self.record.session, envelope)
            .map_err(provider_error)?;
        if message.session != self.record.session
            || message.sender_id != sender_id
            || message.recipient_id != self.record.validator_id
        {
            return Err(DkgCeremonyError::InvalidMessage(
                "round-two message is not bound to this coordinator".into(),
            ));
        }
        let message_bytes = canonical(&message)?;
        if let Some(existing) = self.record.incoming_round2_messages.get(&sender_id) {
            if existing == &message_bytes {
                return Ok(DkgMessageAcceptance::Duplicate);
            }
            return Err(self.abort_for_equivocation(now_unix_ms, sender_id));
        }
        let mut next = self.record.clone();
        next.incoming_round2_messages
            .insert(sender_id, message_bytes);
        next.incoming_round2_envelopes
            .insert(sender_id, envelope_bytes);
        next.provider_checkpoint = self.checkpoint()?;
        self.commit(next)?;
        Ok(DkgMessageAcceptance::New)
    }

    pub fn finalize(&mut self, now_unix_ms: u64) -> DkgCeremonyResult<DkgCeremonyCompletion> {
        self.ensure_live(now_unix_ms)?;
        if self.record.phase == DkgCeremonyPhase::Completed {
            return self.record.completion.clone().ok_or_else(|| {
                DkgCeremonyError::InvalidRecord("completed result is missing".into())
            });
        }
        if self.record.phase == DkgCeremonyPhase::Round2 {
            if self.record.incoming_round2_messages.len() != usize::from(DKG_PARTICIPANTS - 1) {
                return Err(DkgCeremonyError::NotReady {
                    expected: usize::from(DKG_PARTICIPANTS - 1),
                    actual: self.record.incoming_round2_messages.len(),
                });
            }
            let mut next = self.record.clone();
            next.phase = DkgCeremonyPhase::Finalize;
            self.commit(next)?;
        } else {
            self.expect_phase(DkgCeremonyPhase::Finalize)?;
        }
        let received = self
            .record
            .incoming_round2_messages
            .values()
            .map(|bytes| decode_round2(bytes))
            .collect::<DkgCeremonyResult<Vec<_>>>()?;
        let completion = match self.provider.finalize(&self.record.session, &received) {
            Ok(completion) => completion,
            Err(error) => {
                let mapped = provider_error(error);
                return Err(self.abort_for_failure(
                    now_unix_ms,
                    DkgCeremonyAbortCode::FinalizeSemanticFailure,
                    &mapped,
                ));
            }
        };
        completion.validate(&self.record.session)?;
        let mut next = self.record.clone();
        next.phase = DkgCeremonyPhase::Completed;
        next.completion = Some(completion.clone());
        next.provider_checkpoint = self.checkpoint()?;
        self.commit(next)?;
        Ok(completion)
    }

    pub fn abort(&mut self, now_unix_ms: u64) -> DkgCeremonyResult<()> {
        if self.record.phase == DkgCeremonyPhase::Aborted {
            return Ok(());
        }
        if self.record.phase == DkgCeremonyPhase::Completed {
            return Err(DkgCeremonyError::WrongPhase {
                expected: DkgCeremonyPhase::Aborted,
                actual: self.record.phase,
            });
        }
        self.abort_internal(
            now_unix_ms,
            DkgCeremonyAbortCode::Operator,
            "operator abort",
        )
    }

    fn ensure_live(&mut self, now_unix_ms: u64) -> DkgCeremonyResult<()> {
        if self.record.phase == DkgCeremonyPhase::Aborted {
            return Err(DkgCeremonyError::Aborted {
                phase: self.record.phase,
            });
        }
        if self.record.phase == DkgCeremonyPhase::Completed {
            return Ok(());
        }
        if self
            .record
            .deadlines
            .deadline_for(self.record.phase)
            .is_some_and(|deadline| now_unix_ms >= deadline)
        {
            let phase = self.record.phase;
            self.abort_internal(
                now_unix_ms,
                DkgCeremonyAbortCode::Timeout,
                "phase deadline elapsed",
            )?;
            return Err(DkgCeremonyError::TimedOut { phase });
        }
        Ok(())
    }

    fn expect_phase(&self, expected: DkgCeremonyPhase) -> DkgCeremonyResult<()> {
        if self.record.phase != expected {
            return Err(DkgCeremonyError::WrongPhase {
                expected,
                actual: self.record.phase,
            });
        }
        Ok(())
    }

    fn checkpoint(&self) -> DkgCeremonyResult<Vec<u8>> {
        let checkpoint = self
            .provider
            .checkpoint(&self.record.session)
            .map_err(provider_error)?;
        validate_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    fn commit(&mut self, mut next: DkgCeremonyRecord) -> DkgCeremonyResult<()> {
        next.revision =
            self.record.revision.checked_add(1).ok_or_else(|| {
                DkgCeremonyError::InvalidRecord("journal revision overflow".into())
            })?;
        self.journal.compare_and_swap(
            self.record.session.ceremony_id,
            self.record.revision,
            &next,
        )?;
        self.record = next;
        Ok(())
    }

    fn abort_on_provider_error(
        &mut self,
        now_unix_ms: u64,
        code: DkgCeremonyAbortCode,
        error: DkgCeremonyError,
    ) -> DkgCeremonyError {
        self.abort_for_failure(now_unix_ms, code, &error)
    }

    fn abort_for_equivocation(&mut self, now_unix_ms: u64, validator_id: u16) -> DkgCeremonyError {
        let error = DkgCeremonyError::Equivocation { validator_id };
        self.abort_for_failure(now_unix_ms, DkgCeremonyAbortCode::Equivocation, &error)
    }

    fn abort_for_failure(
        &mut self,
        now_unix_ms: u64,
        code: DkgCeremonyAbortCode,
        error: &DkgCeremonyError,
    ) -> DkgCeremonyError {
        match self.abort_internal(now_unix_ms, code, &error.to_string()) {
            Ok(()) => DkgCeremonyError::Aborted {
                phase: self.record.phase,
            },
            Err(abort_error) => abort_error,
        }
    }

    fn abort_internal(
        &mut self,
        now_unix_ms: u64,
        code: DkgCeremonyAbortCode,
        detail: &str,
    ) -> DkgCeremonyResult<()> {
        if self.record.phase == DkgCeremonyPhase::Aborted {
            return Ok(());
        }
        let quarantine = self.provider.quarantine(&self.record.session, code);
        let checkpoint = self.provider.checkpoint(&self.record.session);
        let mut next = self.record.clone();
        next.phase = DkgCeremonyPhase::Aborted;
        next.abort = Some(DkgCeremonyAbort {
            at_unix_ms: now_unix_ms,
            code,
            detail_hash: hash_detail(detail),
        });
        if let Ok(checkpoint) = checkpoint
            && checkpoint.len() <= MAX_DKG_PROVIDER_CHECKPOINT_BYTES
        {
            next.provider_checkpoint = checkpoint;
        }
        // Persist the tombstone even if HSM quarantine reports an error.  The
        // journal then prevents the ceremony id from ever being retried.
        let journal_result = self.commit(next);
        journal_result?;
        quarantine.map_err(provider_error)
    }
}

fn expected_provider_states(phase: DkgCeremonyPhase) -> &'static [DkgProviderState] {
    match phase {
        DkgCeremonyPhase::Initial => &[DkgProviderState::Ready, DkgProviderState::Round1],
        DkgCeremonyPhase::Round1 => &[DkgProviderState::Round1],
        DkgCeremonyPhase::Round2 => &[DkgProviderState::Round2],
        DkgCeremonyPhase::Finalize => &[DkgProviderState::Round2, DkgProviderState::Completed],
        DkgCeremonyPhase::Completed => &[DkgProviderState::Completed],
        DkgCeremonyPhase::Aborted => &[DkgProviderState::Quarantined],
    }
}

fn validate_checkpoint(checkpoint: &[u8]) -> DkgCeremonyResult<()> {
    if checkpoint.len() > MAX_DKG_PROVIDER_CHECKPOINT_BYTES {
        return Err(DkgCeremonyError::InvalidRecord(
            "provider checkpoint exceeds the configured limit".into(),
        ));
    }
    Ok(())
}

fn validate_registry_identity(
    registry: &DkgTransportRegistry,
    local: &DkgTransportPeer,
) -> DkgCeremonyResult<()> {
    let registered = registry.peer(local.validator_id).map_err(transport_error)?;
    if registered != local {
        return Err(DkgCeremonyError::InvalidRecord(
            "provider transport identity does not match the registry".into(),
        ));
    }
    Ok(())
}

fn registry_digest(registry: &DkgTransportRegistry) -> DkgCeremonyResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(DKG_CEREMONY_DOMAIN);
    for peer in registry.peers() {
        let bytes = peer.to_canonical_json().map_err(transport_error)?;
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hasher.finalize().into())
}

fn hash_detail(detail: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DKG_CEREMONY_DOMAIN);
    hasher.update(detail.as_bytes());
    hasher.finalize().into()
}

fn canonical<T: Serialize>(value: &T) -> DkgCeremonyResult<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|error| DkgCeremonyError::Serialization(error.to_string()))
}

fn decode_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> DkgCeremonyResult<T> {
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| DkgCeremonyError::Serialization(error.to_string()))?;
    if serde_jcs::to_vec(&value)
        .map_err(|error| DkgCeremonyError::Serialization(error.to_string()))?
        != bytes
    {
        return Err(DkgCeremonyError::Serialization(
            "non-canonical ceremony journal record".into(),
        ));
    }
    Ok(value)
}

fn decode_broadcast(bytes: &[u8]) -> DkgCeremonyResult<AuthenticatedBroadcastEnvelope> {
    AuthenticatedBroadcastEnvelope::from_canonical_json(bytes).map_err(transport_error)
}

fn decode_point_to_point(bytes: &[u8]) -> DkgCeremonyResult<EncryptedPointToPointEnvelope> {
    EncryptedPointToPointEnvelope::from_canonical_json(bytes).map_err(transport_error)
}

fn decode_round1(bytes: &[u8]) -> DkgCeremonyResult<Round1Message> {
    Round1Message::from_canonical_json(bytes)
        .map_err(|error| DkgCeremonyError::InvalidMessage(error.to_string()))
}

fn decode_round2(bytes: &[u8]) -> DkgCeremonyResult<Round2Message> {
    Round2Message::from_canonical_json(bytes)
        .map_err(|error| DkgCeremonyError::InvalidMessage(error.to_string()))
}

fn validate_local_round1(
    session: &DkgSession,
    validator_id: u16,
    registry: &DkgTransportRegistry,
    message: &Round1Message,
    envelope: &AuthenticatedBroadcastEnvelope,
) -> DkgCeremonyResult<()> {
    if message.session != *session || message.sender_id != validator_id {
        return Err(DkgCeremonyError::InvalidMessage(
            "provider round-one message is not locally bound".into(),
        ));
    }
    let peer = registry.peer(validator_id).map_err(transport_error)?;
    crate::dkg_transport::open_round1_broadcast(session, peer, envelope)
        .map_err(transport_error)?;
    Ok(())
}

fn validate_outgoing_round2(
    session: &DkgSession,
    validator_id: u16,
    registry: &DkgTransportRegistry,
    message: &Round2Message,
    envelope: &EncryptedPointToPointEnvelope,
) -> DkgCeremonyResult<()> {
    if message.session != *session
        || message.sender_id != validator_id
        || message.recipient_id == validator_id
    {
        return Err(DkgCeremonyError::InvalidMessage(
            "provider round-two message is not locally bound".into(),
        ));
    }
    registry
        .peer(message.recipient_id)
        .map_err(transport_error)?;
    envelope.to_canonical_json().map_err(transport_error)?;
    if envelope.session != *session
        || envelope.sender_id != validator_id
        || envelope.recipient_id != message.recipient_id
    {
        return Err(DkgCeremonyError::InvalidMessage(
            "round-two envelope does not match its inner message".into(),
        ));
    }
    Ok(())
}

fn provider_error(error: DkgCeremonyProviderError) -> DkgCeremonyError {
    DkgCeremonyError::Provider(error.to_string())
}

fn transport_error(error: DkgTransportError) -> DkgCeremonyError {
    DkgCeremonyError::Transport(error.to_string())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SoftwareProviderCheckpoint {
    version: u16,
    session: DkgSession,
    state: DkgProviderState,
    guard: Vec<u8>,
}

enum SoftwareSecretState {
    Ready(Option<FinalizedParticipant>),
    Round1 {
        participant: Round1Participant,
        _message: Round1Message,
        _envelope: AuthenticatedBroadcastEnvelope,
    },
    Round2 {
        participant: Round2Participant,
        _outgoing: Vec<(Round2Message, EncryptedPointToPointEnvelope)>,
    },
    Completed {
        _participant: FinalizedParticipant,
        completion: DkgCeremonyCompletion,
    },
    Quarantined,
}

impl SoftwareSecretState {
    fn kind(&self) -> DkgProviderState {
        match self {
            Self::Ready(_) => DkgProviderState::Ready,
            Self::Round1 { .. } => DkgProviderState::Round1,
            Self::Round2 { .. } => DkgProviderState::Round2,
            Self::Completed { .. } => DkgProviderState::Completed,
            Self::Quarantined => DkgProviderState::Quarantined,
        }
    }
}

/// A process-local provider that exercises the real FROST and transport APIs.
/// It is useful for the four-validator development network and tests.  The
/// secret participant objects intentionally remain process-local; a production
/// HSM implementation must replace this type and make its opaque checkpoint
/// recoverable after restart.
pub struct SoftwareDkgCeremonyProvider {
    identity: DkgTransportIdentity,
    registry: DkgTransportRegistry,
    session: DkgSession,
    guard: DkgBroadcastEndorsementGuard,
    state: SoftwareSecretState,
}

impl SoftwareDkgCeremonyProvider {
    pub fn new_initial(
        identity: DkgTransportIdentity,
        registry: DkgTransportRegistry,
        session: DkgSession,
    ) -> DkgCeremonyProviderResult<Self> {
        if !matches!(&session.kind, DkgKind::Initial) {
            return Err(DkgCeremonyProviderError::State(
                "initial provider received a refresh session".into(),
            ));
        }
        validate_registry_identity(&registry, &identity.peer())
            .map_err(|error| DkgCeremonyProviderError::State(error.to_string()))?;
        let guard = DkgBroadcastEndorsementGuard::new(&identity.peer())
            .map_err(|error| DkgCeremonyProviderError::Transport(error.to_string()))?;
        Ok(Self {
            identity,
            registry,
            session,
            guard,
            state: SoftwareSecretState::Ready(None),
        })
    }

    pub fn new_refresh(
        identity: DkgTransportIdentity,
        registry: DkgTransportRegistry,
        session: DkgSession,
        current: FinalizedParticipant,
    ) -> DkgCeremonyProviderResult<Self> {
        if !matches!(&session.kind, DkgKind::Refresh { .. }) {
            return Err(DkgCeremonyProviderError::State(
                "refresh provider received an initial session".into(),
            ));
        }
        validate_registry_identity(&registry, &identity.peer())
            .map_err(|error| DkgCeremonyProviderError::State(error.to_string()))?;
        let guard = DkgBroadcastEndorsementGuard::new(&identity.peer())
            .map_err(|error| DkgCeremonyProviderError::Transport(error.to_string()))?;
        Ok(Self {
            identity,
            registry,
            session,
            guard,
            state: SoftwareSecretState::Ready(Some(current)),
        })
    }

    pub fn provider_state(&self) -> DkgProviderState {
        self.state.kind()
    }
}

impl DkgCeremonyCryptoProvider for SoftwareDkgCeremonyProvider {
    fn local_peer(&self) -> DkgTransportPeer {
        self.identity.peer()
    }

    fn checkpoint(&self, session: &DkgSession) -> DkgCeremonyProviderResult<Vec<u8>> {
        if *session != self.session {
            return Err(DkgCeremonyProviderError::State(
                "checkpoint requested for a different session".into(),
            ));
        }
        let guard = self
            .guard
            .to_canonical_json(&self.identity)
            .map_err(|error| DkgCeremonyProviderError::Transport(error.to_string()))?;
        let checkpoint = SoftwareProviderCheckpoint {
            version: DKG_CEREMONY_RECORD_VERSION,
            session: self.session.clone(),
            state: self.state.kind(),
            guard,
        };
        let bytes = serde_jcs::to_vec(&checkpoint)
            .map_err(|error| DkgCeremonyProviderError::Custody(error.to_string()))?;
        if bytes.len() > MAX_DKG_PROVIDER_CHECKPOINT_BYTES {
            return Err(DkgCeremonyProviderError::Custody(
                "software provider checkpoint is too large".into(),
            ));
        }
        Ok(bytes)
    }

    fn restore_checkpoint(
        &mut self,
        session: &DkgSession,
        phase: DkgCeremonyPhase,
        checkpoint: &[u8],
    ) -> DkgCeremonyProviderResult<DkgProviderState> {
        let checkpoint: SoftwareProviderCheckpoint = serde_json::from_slice(checkpoint)
            .map_err(|error| DkgCeremonyProviderError::Custody(error.to_string()))?;
        if checkpoint.version != DKG_CEREMONY_RECORD_VERSION
            || checkpoint.session != *session
            || checkpoint.session != self.session
        {
            return Err(DkgCeremonyProviderError::State(
                "provider checkpoint session mismatch".into(),
            ));
        }
        let guard = DkgBroadcastEndorsementGuard::from_canonical_json(
            &checkpoint.guard,
            &self.identity.peer(),
        )
        .map_err(|error| DkgCeremonyProviderError::Transport(error.to_string()))?;
        if self.state.kind() != checkpoint.state {
            return Err(DkgCeremonyProviderError::Custody(format!(
                "software secret state {:?} is not recoverable as {:?}",
                self.state.kind(),
                checkpoint.state
            )));
        }
        if !expected_provider_states(phase).contains(&checkpoint.state) {
            return Err(DkgCeremonyProviderError::State(
                "provider checkpoint phase mismatch".into(),
            ));
        }
        self.guard = guard;
        Ok(checkpoint.state)
    }

    fn begin_round1(
        &mut self,
        session: &DkgSession,
    ) -> DkgCeremonyProviderResult<(Round1Message, AuthenticatedBroadcastEnvelope)> {
        if *session != self.session {
            return Err(DkgCeremonyProviderError::State(
                "round-one session mismatch".into(),
            ));
        }
        let state = std::mem::replace(&mut self.state, SoftwareSecretState::Quarantined);
        let SoftwareSecretState::Ready(current) = state else {
            self.state = state;
            return Err(DkgCeremonyProviderError::State(
                "round one was already started".into(),
            ));
        };
        let result = match (&self.session.kind, current) {
            (DkgKind::Initial, None) => {
                participant_round1(&self.session, self.identity.validator_id(), &mut OsRng)
                    .map_err(|error| DkgCeremonyProviderError::Frost(error.to_string()))
            }
            (DkgKind::Refresh { .. }, Some(current)) => {
                participant_refresh_round1(&self.session, current, &mut OsRng)
                    .map_err(|error| DkgCeremonyProviderError::Frost(error.to_string()))
            }
            _ => Err(DkgCeremonyProviderError::State(
                "provider/session kind does not match its secret state".into(),
            )),
        };
        let (participant, message) = result?;
        let envelope =
            match seal_round1_broadcast(&self.session, &self.identity, &message, &mut OsRng) {
                Ok(envelope) => envelope,
                Err(error) => {
                    return Err(DkgCeremonyProviderError::Transport(error.to_string()));
                }
            };
        self.state = SoftwareSecretState::Round1 {
            participant,
            _message: message.clone(),
            _envelope: envelope.clone(),
        };
        Ok((message, envelope))
    }

    fn endorse_round1(
        &mut self,
        session: &DkgSession,
        envelope: &AuthenticatedBroadcastEnvelope,
    ) -> DkgCeremonyProviderResult<BroadcastEndorsement> {
        if *session != self.session {
            return Err(DkgCeremonyProviderError::State(
                "endorsement session mismatch".into(),
            ));
        }
        endorse_broadcast(
            session,
            &self.identity,
            &self.registry,
            envelope,
            &mut self.guard,
        )
        .map_err(|error| DkgCeremonyProviderError::Transport(error.to_string()))
    }

    fn advance_round2(
        &mut self,
        session: &DkgSession,
        received: &[Round1Message],
    ) -> DkgCeremonyProviderResult<Vec<(Round2Message, EncryptedPointToPointEnvelope)>> {
        if *session != self.session {
            return Err(DkgCeremonyProviderError::State(
                "round-two session mismatch".into(),
            ));
        }
        let state = std::mem::replace(&mut self.state, SoftwareSecretState::Quarantined);
        let SoftwareSecretState::Round1 { participant, .. } = state else {
            self.state = state;
            return Err(DkgCeremonyProviderError::State(
                "round one secret state is unavailable".into(),
            ));
        };
        let (participant, messages) = match participant_round2(participant, received) {
            Ok(value) => value,
            Err(error) => {
                return Err(DkgCeremonyProviderError::Frost(error.to_string()));
            }
        };
        let mut outgoing = Vec::with_capacity(messages.len());
        for message in messages {
            let recipient = self
                .registry
                .peer(message.recipient_id)
                .map_err(|error| DkgCeremonyProviderError::Transport(error.to_string()))?;
            let envelope = seal_round2_point_to_point(
                &self.session,
                &self.identity,
                recipient,
                &message,
                &mut OsRng,
            )
            .map_err(|error| DkgCeremonyProviderError::Transport(error.to_string()))?;
            outgoing.push((message, envelope));
        }
        self.state = SoftwareSecretState::Round2 {
            participant,
            _outgoing: outgoing.clone(),
        };
        Ok(outgoing)
    }

    fn open_round2(
        &mut self,
        session: &DkgSession,
        envelope: &EncryptedPointToPointEnvelope,
    ) -> DkgCeremonyProviderResult<Round2Message> {
        if *session != self.session {
            return Err(DkgCeremonyProviderError::State(
                "round-two open session mismatch".into(),
            ));
        }
        if !matches!(self.state, SoftwareSecretState::Round2 { .. }) {
            return Err(DkgCeremonyProviderError::State(
                "round-two secret state is unavailable".into(),
            ));
        }
        let sender = self
            .registry
            .peer(envelope.sender_id)
            .map_err(|error| DkgCeremonyProviderError::Transport(error.to_string()))?;
        open_round2_point_to_point(&self.session, &self.identity, sender, envelope)
            .map_err(|error| DkgCeremonyProviderError::Transport(error.to_string()))
    }

    fn finalize(
        &mut self,
        session: &DkgSession,
        received: &[Round2Message],
    ) -> DkgCeremonyProviderResult<DkgCeremonyCompletion> {
        if *session != self.session {
            return Err(DkgCeremonyProviderError::State(
                "finalize session mismatch".into(),
            ));
        }
        if let SoftwareSecretState::Completed { completion, .. } = &self.state {
            return Ok(completion.clone());
        }
        let state = std::mem::replace(&mut self.state, SoftwareSecretState::Quarantined);
        let SoftwareSecretState::Round2 { participant, .. } = state else {
            self.state = state;
            return Err(DkgCeremonyProviderError::State(
                "round-two secret state is unavailable for finalize".into(),
            ));
        };
        let finalized = match participant_finalize(participant, received) {
            Ok(value) => value,
            Err(error) => return Err(DkgCeremonyProviderError::Frost(error.to_string())),
        };
        let public_keys = finalized.public_keys();
        let completion = DkgCeremonyCompletion {
            validator_id: finalized.validator_id(),
            epoch: finalized.epoch(),
            public_key: public_keys.public_key,
            key_id: public_keys.key_id,
        };
        self.state = SoftwareSecretState::Completed {
            _participant: finalized,
            completion: completion.clone(),
        };
        Ok(completion)
    }

    fn quarantine(
        &mut self,
        _session: &DkgSession,
        _reason: DkgCeremonyAbortCode,
    ) -> DkgCeremonyProviderResult<()> {
        if matches!(self.state, SoftwareSecretState::Completed { .. }) {
            return Err(DkgCeremonyProviderError::State(
                "completed provider cannot be quarantined".into(),
            ));
        }
        self.state = SoftwareSecretState::Quarantined;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg_transport::{DkgTransportIdentity, make_broadcast_certificate};
    use rand_core::OsRng;

    fn session() -> DkgSession {
        DkgSession::initial([7; 32], [8; 32], 1).unwrap()
    }

    fn deadlines() -> DkgCeremonyDeadlines {
        DkgCeremonyDeadlines {
            round1_unix_ms: 10,
            round2_unix_ms: 20,
            finalize_unix_ms: 30,
        }
    }

    fn identities() -> (Vec<DkgTransportIdentity>, DkgTransportRegistry) {
        let identities = (1..=DKG_PARTICIPANTS)
            .map(|id| DkgTransportIdentity::generate(id, &mut OsRng).unwrap())
            .collect::<Vec<_>>();
        let registry =
            DkgTransportRegistry::new(identities.iter().map(DkgTransportIdentity::peer)).unwrap();
        (identities, registry)
    }

    fn fixed_identity(validator_id: u16) -> DkgTransportIdentity {
        DkgTransportIdentity::from_secrets(
            validator_id,
            [u8::try_from(validator_id).unwrap(); 32],
            [u8::try_from(validator_id + 16).unwrap(); 32],
        )
        .unwrap()
    }

    fn fixed_registry() -> DkgTransportRegistry {
        DkgTransportRegistry::new(
            (1..=DKG_PARTICIPANTS).map(|validator_id| fixed_identity(validator_id).peer()),
        )
        .unwrap()
    }

    fn certify_round1(
        session: &DkgSession,
        registry: &DkgTransportRegistry,
        message: &Round1Message,
    ) -> CertifiedBroadcastEnvelope {
        let sender = fixed_identity(message.sender_id);
        let envelope = seal_round1_broadcast(session, &sender, message, &mut OsRng).unwrap();
        let endorsements = (1..=3)
            .map(|validator_id| {
                let endorser = fixed_identity(validator_id);
                let mut guard = DkgBroadcastEndorsementGuard::new(&endorser.peer()).unwrap();
                endorse_broadcast(session, &endorser, registry, &envelope, &mut guard).unwrap()
            })
            .collect();
        make_broadcast_certificate(envelope, endorsements).unwrap()
    }

    fn coordinators() -> (
        Vec<DkgCeremonyCoordinator<MemoryDkgCeremonyJournal, SoftwareDkgCeremonyProvider>>,
        DkgTransportRegistry,
    ) {
        let (identities, registry) = identities();
        let session = session();
        let coordinators = identities
            .into_iter()
            .map(|identity| {
                let provider = SoftwareDkgCeremonyProvider::new_initial(
                    identity,
                    registry.clone(),
                    session.clone(),
                )
                .unwrap();
                DkgCeremonyCoordinator::start(
                    MemoryDkgCeremonyJournal::default(),
                    provider,
                    registry.clone(),
                    session.clone(),
                    deadlines(),
                    [7; 32],
                    1,
                )
                .unwrap()
            })
            .collect();
        (coordinators, registry)
    }

    #[test]
    fn four_party_coordinator_runs_real_frost_transport_and_is_idempotent() {
        let (mut coordinators, _registry) = coordinators();
        let mut envelopes = Vec::new();
        for coordinator in &mut coordinators {
            envelopes.push(coordinator.begin_round1(1).unwrap());
        }

        let mut certificates = Vec::new();
        for envelope in &envelopes {
            let endorsements = coordinators
                .iter_mut()
                .map(|coordinator| coordinator.endorse_round1(envelope, 2).unwrap())
                .collect::<Vec<_>>();
            certificates.push(make_broadcast_certificate(envelope.clone(), endorsements).unwrap());
        }

        for coordinator in &mut coordinators {
            for certificate in &certificates {
                assert_eq!(
                    coordinator
                        .accept_round1_certificate(certificate, 3)
                        .unwrap(),
                    DkgMessageAcceptance::New
                );
            }
            assert_eq!(
                coordinator
                    .accept_round1_certificate(&certificates[0], 3)
                    .unwrap(),
                DkgMessageAcceptance::Duplicate
            );
        }

        let outgoing = coordinators
            .iter_mut()
            .map(|coordinator| coordinator.advance_round2(4).unwrap())
            .collect::<Vec<_>>();
        for messages in &outgoing {
            for envelope in messages {
                let recipient = usize::from(envelope.recipient_id - 1);
                assert_eq!(
                    coordinators[recipient].accept_round2(envelope, 5).unwrap(),
                    DkgMessageAcceptance::New
                );
                assert_eq!(
                    coordinators[recipient].accept_round2(envelope, 5).unwrap(),
                    DkgMessageAcceptance::Duplicate
                );
            }
        }

        let completions = coordinators
            .iter_mut()
            .map(|coordinator| coordinator.finalize(6).unwrap())
            .collect::<Vec<_>>();
        assert!(
            completions
                .windows(2)
                .all(|pair| pair[0].key_id == pair[1].key_id)
        );
        assert!(
            completions
                .windows(2)
                .all(|pair| pair[0].public_key == pair[1].public_key)
        );
        assert!(
            coordinators
                .iter()
                .all(|coordinator| coordinator.phase() == DkgCeremonyPhase::Completed)
        );
    }

    #[test]
    fn recovery_reuses_persisted_transcript_but_never_reuses_ceremony_id() {
        let (identities, registry) = identities();
        let session = session();
        let journal = MemoryDkgCeremonyJournal::default();
        let provider = SoftwareDkgCeremonyProvider::new_initial(
            identities.into_iter().next().unwrap(),
            registry.clone(),
            session.clone(),
        )
        .unwrap();
        let coordinator = DkgCeremonyCoordinator::start(
            journal.clone(),
            provider,
            registry.clone(),
            session.clone(),
            deadlines(),
            [7; 32],
            1,
        )
        .unwrap();
        let mut coordinator = coordinator;
        let envelope = coordinator.begin_round1(1).unwrap();
        let (journal, provider) = coordinator.into_parts();
        let mut recovered = DkgCeremonyCoordinator::recover(
            journal.clone(),
            provider,
            registry.clone(),
            session.ceremony_id,
            [7; 32],
            1,
        )
        .unwrap();
        assert_eq!(recovered.begin_round1(2).unwrap(), envelope);

        let record = recovered.record().clone();
        let (journal, _provider) = recovered.into_parts();
        let second = journal.create(&record);
        assert!(matches!(
            second,
            Err(DkgCeremonyJournalError::AlreadyExists)
        ));
    }

    #[test]
    fn timeout_atomically_quarantines_provider_and_leaves_tombstone() {
        let (identities, registry) = identities();
        let session = session();
        let journal = MemoryDkgCeremonyJournal::default();
        let provider = SoftwareDkgCeremonyProvider::new_initial(
            identities.into_iter().next().unwrap(),
            registry.clone(),
            session.clone(),
        )
        .unwrap();
        let mut coordinator = DkgCeremonyCoordinator::start(
            journal.clone(),
            provider,
            registry,
            session.clone(),
            deadlines(),
            [7; 32],
            1,
        )
        .unwrap();
        coordinator.begin_round1(1).unwrap();
        assert!(matches!(
            coordinator.advance_round2(10),
            Err(DkgCeremonyError::TimedOut {
                phase: DkgCeremonyPhase::Round1
            })
        ));
        assert_eq!(coordinator.phase(), DkgCeremonyPhase::Aborted);
        assert_eq!(journal.len(), 1);
        assert!(matches!(
            coordinator.advance_round2(11),
            Err(DkgCeremonyError::Aborted { .. })
        ));
    }

    #[test]
    fn journal_cas_rejects_stale_writes_and_terminal_resurrection() {
        let registry = fixed_registry();
        let session = session();
        let journal = MemoryDkgCeremonyJournal::default();
        let provider = SoftwareDkgCeremonyProvider::new_initial(
            fixed_identity(4),
            registry.clone(),
            session.clone(),
        )
        .unwrap();
        let coordinator = DkgCeremonyCoordinator::start(
            journal.clone(),
            provider,
            registry,
            session.clone(),
            deadlines(),
            [7; 32],
            1,
        )
        .unwrap();
        let mut aborted = coordinator.record().clone();
        aborted.revision = 2;
        aborted.phase = DkgCeremonyPhase::Aborted;
        aborted.abort = Some(DkgCeremonyAbort {
            at_unix_ms: 1,
            code: DkgCeremonyAbortCode::Operator,
            detail_hash: [9; 32],
        });
        journal
            .compare_and_swap(session.ceremony_id, 1, &aborted)
            .unwrap();
        assert!(matches!(
            journal.compare_and_swap(session.ceremony_id, 1, &aborted),
            Err(DkgCeremonyJournalError::RevisionConflict {
                expected: 1,
                actual: 2
            })
        ));

        let mut resurrected = aborted;
        resurrected.revision = 3;
        resurrected.phase = DkgCeremonyPhase::Round1;
        resurrected.abort = None;
        assert!(matches!(
            journal.compare_and_swap(session.ceremony_id, 2, &resurrected),
            Err(DkgCeremonyJournalError::InvalidData(_))
        ));
        assert_eq!(
            journal.load(session.ceremony_id).unwrap().unwrap().phase,
            DkgCeremonyPhase::Aborted
        );
    }

    #[test]
    fn conflicting_valid_round1_certificates_abort_and_persist_tombstone() {
        let registry = fixed_registry();
        let session = session();
        let journal = MemoryDkgCeremonyJournal::default();
        let provider = SoftwareDkgCeremonyProvider::new_initial(
            fixed_identity(4),
            registry.clone(),
            session.clone(),
        )
        .unwrap();
        let mut coordinator = DkgCeremonyCoordinator::start(
            journal.clone(),
            provider,
            registry.clone(),
            session.clone(),
            deadlines(),
            [7; 32],
            1,
        )
        .unwrap();
        coordinator.begin_round1(1).unwrap();

        let (_, first_message) = participant_round1(&session, 1, &mut OsRng).unwrap();
        let (_, second_message) = participant_round1(&session, 1, &mut OsRng).unwrap();
        assert_ne!(first_message, second_message);
        let first = certify_round1(&session, &registry, &first_message);
        let second = certify_round1(&session, &registry, &second_message);
        assert_eq!(
            coordinator.accept_round1_certificate(&first, 2).unwrap(),
            DkgMessageAcceptance::New
        );
        assert!(matches!(
            coordinator.accept_round1_certificate(&second, 3),
            Err(DkgCeremonyError::Aborted { .. })
        ));
        assert_eq!(coordinator.phase(), DkgCeremonyPhase::Aborted);
        let persisted = journal.load(session.ceremony_id).unwrap().unwrap();
        assert_eq!(persisted.phase, DkgCeremonyPhase::Aborted);
        assert_eq!(
            persisted.abort.unwrap().code,
            DkgCeremonyAbortCode::Equivocation
        );
    }
}
