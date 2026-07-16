//! Accounting and authority protocol around shielded isolated-margin notes.
//!
//! This module does not implement zero knowledge. [`TransparentDepositVerifier`]
//! decodes the complete note opening and is accepted only by
//! [`DevelopmentShieldedLedger`]. Production methods require verifier types to
//! explicitly implement production marker traits and report production proof
//! security. Those verifier implementations, their circuits, and their setup
//! remain outside this foundational module.

use std::{collections::BTreeMap, marker::PhantomData};

use ed25519_dalek::{Signature, VerifyingKey};
use imbl::{OrdSet, Vector};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use crate::shielded_margin::{
    Hash, MAX_PROOF_BYTES, MarginPolicy, MarketId, MerkleProof, NoteOpening, Nullifier, PublicNote,
    ShieldedMarginError, ShieldedMarginPersistenceHeader, ShieldedMarginState, ShieldedSpend,
    SpendProofVerifier, SpendReceipt, TransparentWitnessVerifier,
};

pub const SHIELDED_PROTOCOL_VERSION: u16 = 3;
pub const MAX_SHIELDED_CHAIN_ID_BYTES: usize = 128;

const CHAIN_DOMAIN_DERIVATION_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_CHAIN_DOMAIN_V3\0";
const DEPOSIT_AUTHORIZATION_DOMAIN: &[u8] = b"ASTERIA_SHIELDED_DEPOSIT_AUTH_V3\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSecurity {
    TransparentDevelopment,
    ProductionZeroKnowledge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerMode {
    Development,
    Production,
}

mod private {
    pub trait Sealed {}
    pub trait ProductionDepositVerifierSealed {}
    pub trait ProductionSpendVerifierSealed {}
}

pub trait LedgerProfile: private::Sealed + Clone + Copy + PartialEq + Eq {
    const MODE: LedgerMode;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevelopmentProfile {
    Development,
}

impl private::Sealed for DevelopmentProfile {}

impl LedgerProfile for DevelopmentProfile {
    const MODE: LedgerMode = LedgerMode::Development;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionProfile {
    Production,
}

impl private::Sealed for ProductionProfile {}

impl LedgerProfile for ProductionProfile {
    const MODE: LedgerMode = LedgerMode::Production;
}

pub type DevelopmentShieldedLedger = ShieldedLedger<DevelopmentProfile>;
pub type ProductionShieldedLedger = ShieldedLedger<ProductionProfile>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShieldedProtocolError {
    #[error("unsupported shielded protocol version {actual}; expected {expected}")]
    UnsupportedVersion { actual: u16, expected: u16 },
    #[error(
        "chain id must be non-empty, canonical, and at most {MAX_SHIELDED_CHAIN_ID_BYTES} bytes"
    )]
    InvalidChainId,
    #[error("shielded chain domain must not be zero")]
    ZeroChainDomain,
    #[error("ledger id must not be zero")]
    ZeroLedgerId,
    #[error("invalid deposit authority public key: {0}")]
    InvalidDepositAuthority(String),
    #[error("deposit statement targets a different ledger")]
    LedgerIdMismatch,
    #[error("shielded statement targets a different chain")]
    ChainDomainMismatch,
    #[error("market is already registered")]
    MarketAlreadyRegistered,
    #[error("market is not registered")]
    MarketNotRegistered,
    #[error("public note collateral asset does not match the market policy")]
    CollateralAssetMismatch,
    #[error("deposit backing amount must be positive")]
    ZeroBackingAmount,
    #[error("deposit authority signature must contain exactly 64 bytes")]
    InvalidAuthoritySignatureLength,
    #[error("deposit authority signature is invalid")]
    InvalidAuthoritySignature,
    #[error("deposit proof exceeds {MAX_PROOF_BYTES} bytes")]
    DepositProofTooLarge,
    #[error("deposit proof is not encoded as canonical RFC 8785 JSON")]
    NonCanonicalDepositProof,
    #[error("canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error("deposit opening does not match the public commitment")]
    DepositCommitmentMismatch,
    #[error("deposit opening collateral {opening} does not equal backing {backing}")]
    DepositBackingMismatch { opening: u64, backing: u64 },
    #[error("authority deposit must create a flat position with leverage one")]
    DepositMustBeFlat,
    #[error("deposit opening has an invalid owner key: {0}")]
    InvalidDepositOwner(String),
    #[error("deposit opening nullifier key must not be zero")]
    ZeroDepositNullifierKey,
    #[error("deposit opening blinding must not be zero")]
    ZeroDepositBlinding,
    #[error("production ledger rejected a non-production {operation} verifier")]
    ProductionVerifierRequired { operation: &'static str },
    #[error("checked accounting overflow while computing {0}")]
    AccountingOverflow(&'static str),
    #[error("shielded accounting invariant failed")]
    AccountingInvariant,
    #[error("invalid persisted shielded ledger: {0}")]
    InvalidPersistenceState(String),
    #[error(transparent)]
    Margin(#[from] ShieldedMarginError),
}

pub type Result<T, E = ShieldedProtocolError> = std::result::Result<T, E>;

/// Public statement signed by the configured deposit authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositStatement {
    pub version: u16,
    pub chain_domain: Hash,
    pub ledger_id: Hash,
    pub note: PublicNote,
    pub backing_amount: u64,
}

impl DepositStatement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + 32 + 32 + 98 + 8);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.chain_domain);
        bytes.extend_from_slice(&self.ledger_id);
        bytes.extend_from_slice(&self.note.to_canonical_bytes());
        bytes.extend_from_slice(&self.backing_amount.to_be_bytes());
        bytes
    }

    pub fn authorization_digest(&self) -> Hash {
        hash_parts(DEPOSIT_AUTHORIZATION_DOMAIN, &[&self.canonical_bytes()])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDeposit {
    pub statement: DepositStatement,
    pub authority_signature: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentDepositProof {
    pub opening: NoteOpening,
}

impl TransparentDepositProof {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_encode(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        canonical_decode(bytes)
    }
}

/// Verifies that a public deposit commitment contains exactly the declared
/// backing amount and a valid initial note state.
pub trait DepositProofVerifier {
    const SECURITY: ProofSecurity;

    fn verify(&self, statement: &DepositStatement, proof: &[u8]) -> Result<()>;
}

/// Explicit opt-in required by [`ProductionShieldedLedger`]. The sealed
/// supertrait prevents a downstream crate from self-attesting an arbitrary
/// transparent verifier as production zero knowledge.
pub trait ProductionDepositProofVerifier:
    DepositProofVerifier + private::ProductionDepositVerifierSealed
{
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TransparentDepositVerifier;

impl DepositProofVerifier for TransparentDepositVerifier {
    const SECURITY: ProofSecurity = ProofSecurity::TransparentDevelopment;

    fn verify(&self, statement: &DepositStatement, proof_bytes: &[u8]) -> Result<()> {
        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(ShieldedProtocolError::DepositProofTooLarge);
        }
        let proof = TransparentDepositProof::from_canonical_bytes(proof_bytes)?;
        let opening = &proof.opening;
        if opening.commitment(statement.note.market_id, statement.note.collateral_asset)
            != statement.note.commitment
        {
            return Err(ShieldedProtocolError::DepositCommitmentMismatch);
        }
        if opening.collateral != statement.backing_amount {
            return Err(ShieldedProtocolError::DepositBackingMismatch {
                opening: opening.collateral,
                backing: statement.backing_amount,
            });
        }
        if opening.position != 0 || opening.leverage != 1 {
            return Err(ShieldedProtocolError::DepositMustBeFlat);
        }
        VerifyingKey::from_bytes(&opening.owner)
            .map_err(|error| ShieldedProtocolError::InvalidDepositOwner(error.to_string()))?;
        if opening.nullifier_key == [0; 32] {
            return Err(ShieldedProtocolError::ZeroDepositNullifierKey);
        }
        if opening.blinding == [0; 32] {
            return Err(ShieldedProtocolError::ZeroDepositBlinding);
        }
        Ok(())
    }
}

/// Adds an explicit security classification to the lower-level spend verifier.
pub trait ClassifiedSpendProofVerifier: SpendProofVerifier {
    const SECURITY: ProofSecurity;
}

impl ClassifiedSpendProofVerifier for TransparentWitnessVerifier {
    const SECURITY: ProofSecurity = ProofSecurity::TransparentDevelopment;
}

/// Explicit opt-in required by [`ProductionShieldedLedger`]. The sealed
/// supertrait keeps the production marker owned by this crate until a built-in
/// verifier and its pinned circuit/parameter registry are present.
pub trait ProductionSpendProofVerifier:
    ClassifiedSpendProofVerifier + private::ProductionSpendVerifierSealed
{
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositReceipt {
    pub leaf_index: u64,
    pub previous_root: Hash,
    pub new_root: Hash,
    #[serde(with = "decimal_u128")]
    pub previous_collateral: u128,
    #[serde(with = "decimal_u128")]
    pub next_collateral: u128,
    pub backing_amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolSpendReceipt {
    pub state_receipt: SpendReceipt,
    #[serde(with = "decimal_u128")]
    pub previous_collateral: u128,
    #[serde(with = "decimal_u128")]
    pub next_collateral: u128,
    #[serde(with = "decimal_u128")]
    pub previous_fee_total: u128,
    #[serde(with = "decimal_u128")]
    pub next_fee_total: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DevelopmentShieldedLedgerPersistenceHeader {
    pub version: u16,
    pub chain_domain: Hash,
    pub ledger_id: Hash,
    pub deposit_authority: Hash,
    pub profile: DevelopmentProfile,
    #[serde(with = "market_policy_map")]
    pub policies: BTreeMap<MarketId, MarginPolicy>,
    pub margin: ShieldedMarginPersistenceHeader,
    #[serde(with = "decimal_u128")]
    pub shielded_collateral: u128,
    #[serde(with = "decimal_u128")]
    pub fee_total: u128,
    #[serde(with = "decimal_u128")]
    pub total_backing: u128,
}

pub(crate) struct DevelopmentShieldedLedgerPersistenceParts<'a> {
    pub header: DevelopmentShieldedLedgerPersistenceHeader,
    pub notes: &'a Vector<PublicNote>,
    pub spent_nullifiers: &'a OrdSet<Nullifier>,
}

/// Serializable ledger state. The profile marker is serialized as a distinct
/// enum value, so development state cannot deserialize as production state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedLedger<P> {
    pub version: u16,
    pub chain_domain: Hash,
    pub ledger_id: Hash,
    pub deposit_authority: Hash,
    profile: P,
    #[serde(with = "market_policy_map")]
    policies: BTreeMap<MarketId, MarginPolicy>,
    margin_state: ShieldedMarginState,
    #[serde(with = "decimal_u128")]
    shielded_collateral: u128,
    #[serde(with = "decimal_u128")]
    fee_total: u128,
    #[serde(skip)]
    _profile: PhantomData<P>,
}

mod decimal_u128 {
    use serde::{Deserialize as _, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<u128, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.is_empty()
            || (encoded.len() > 1 && encoded.starts_with('0'))
            || !encoded.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom(
                "u128 amount must be a canonical unsigned decimal string",
            ));
        }
        encoded.parse().map_err(serde::de::Error::custom)
    }
}

mod market_policy_map {
    use serde::{Deserialize as _, Serialize as _};

    use super::*;

    pub fn serialize<S>(
        policies: &BTreeMap<MarketId, MarginPolicy>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        policies.values().collect::<Vec<_>>().serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<MarketId, MarginPolicy>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serialized = Vec::<MarginPolicy>::deserialize(deserializer)?;
        let mut policies = BTreeMap::new();
        for policy in serialized {
            let market_id = policy.market_id;
            if policies.insert(market_id, policy).is_some() {
                return Err(serde::de::Error::custom(
                    "duplicate market policy in shielded ledger",
                ));
            }
        }
        Ok(policies)
    }
}

impl ShieldedLedger<DevelopmentProfile> {
    pub fn new_development(
        chain_domain: Hash,
        ledger_id: Hash,
        deposit_authority: Hash,
    ) -> Result<Self> {
        Self::new_inner(
            chain_domain,
            ledger_id,
            deposit_authority,
            DevelopmentProfile::Development,
        )
    }

    pub(crate) fn persistence_parts(
        &self,
    ) -> Result<DevelopmentShieldedLedgerPersistenceParts<'_>> {
        self.validate_header()?;
        let total_backing = self.shielded_collateral.checked_add(self.fee_total).ok_or(
            ShieldedProtocolError::AccountingOverflow("persisted backing total"),
        )?;
        let margin = self.margin_state.persistence_parts();
        Ok(DevelopmentShieldedLedgerPersistenceParts {
            header: DevelopmentShieldedLedgerPersistenceHeader {
                version: self.version,
                chain_domain: self.chain_domain,
                ledger_id: self.ledger_id,
                deposit_authority: self.deposit_authority,
                profile: self.profile,
                policies: self.policies.clone(),
                margin: margin.header,
                shielded_collateral: self.shielded_collateral,
                fee_total: self.fee_total,
                total_backing,
            },
            notes: margin.notes,
            spent_nullifiers: margin.spent_nullifiers,
        })
    }

    pub(crate) fn rebuild_from_persistence(
        header: DevelopmentShieldedLedgerPersistenceHeader,
        notes: impl IntoIterator<Item = (u64, PublicNote)>,
        spent_nullifiers: OrdSet<Nullifier>,
    ) -> Result<Self> {
        if header.profile != DevelopmentProfile::Development {
            return Err(ShieldedProtocolError::InvalidPersistenceState(
                "ledger profile is not development".into(),
            ));
        }
        let total_backing = header
            .shielded_collateral
            .checked_add(header.fee_total)
            .ok_or(ShieldedProtocolError::AccountingOverflow(
                "rebuilt backing total",
            ))?;
        if total_backing != header.total_backing {
            return Err(ShieldedProtocolError::AccountingInvariant);
        }
        for (market_id, policy) in &header.policies {
            if *market_id != policy.market_id {
                return Err(ShieldedProtocolError::InvalidPersistenceState(
                    "market policy key does not match its policy".into(),
                ));
            }
            policy.validate()?;
        }
        let margin_state =
            ShieldedMarginState::rebuild_from_persistence(header.margin, notes, spent_nullifiers)?;
        for leaf_index in 0..u64::try_from(margin_state.note_count()).map_err(|_| {
            ShieldedProtocolError::InvalidPersistenceState(
                "note count cannot be represented as u64".into(),
            )
        })? {
            let note = margin_state.note(leaf_index).ok_or_else(|| {
                ShieldedProtocolError::InvalidPersistenceState(
                    "rebuilt note indices are not continuous".into(),
                )
            })?;
            let policy = header.policies.get(&note.market_id).ok_or_else(|| {
                ShieldedProtocolError::InvalidPersistenceState(
                    "persisted note has no registered market policy".into(),
                )
            })?;
            if policy.collateral_asset != note.collateral_asset {
                return Err(ShieldedProtocolError::InvalidPersistenceState(
                    "persisted note collateral asset differs from its policy".into(),
                ));
            }
        }
        let ledger = Self {
            version: header.version,
            chain_domain: header.chain_domain,
            ledger_id: header.ledger_id,
            deposit_authority: header.deposit_authority,
            profile: header.profile,
            policies: header.policies,
            margin_state,
            shielded_collateral: header.shielded_collateral,
            fee_total: header.fee_total,
            _profile: PhantomData,
        };
        ledger.validate_header()?;
        Ok(ledger)
    }

    pub(crate) fn persistence_root_at_note_count(&self, note_count: u64) -> Result<Hash> {
        self.margin_state
            .root_at_note_count(note_count)
            .map_err(Into::into)
    }

    pub fn authority_deposit<V: DepositProofVerifier>(
        &mut self,
        deposit: &AuthorityDeposit,
        verifier: &V,
    ) -> Result<DepositReceipt> {
        self.authority_deposit_inner(deposit, verifier)
    }

    pub fn apply_spend<V: ClassifiedSpendProofVerifier>(
        &mut self,
        spend: &ShieldedSpend,
        verifier: &V,
    ) -> Result<ProtocolSpendReceipt> {
        self.apply_spend_inner(spend, verifier)
    }
}

impl ShieldedLedger<ProductionProfile> {
    pub fn new_production(
        chain_domain: Hash,
        ledger_id: Hash,
        deposit_authority: Hash,
    ) -> Result<Self> {
        Self::new_inner(
            chain_domain,
            ledger_id,
            deposit_authority,
            ProductionProfile::Production,
        )
    }

    pub fn authority_deposit<V: ProductionDepositProofVerifier>(
        &mut self,
        deposit: &AuthorityDeposit,
        verifier: &V,
    ) -> Result<DepositReceipt> {
        self.authority_deposit_inner(deposit, verifier)
    }

    pub fn apply_spend<V: ProductionSpendProofVerifier>(
        &mut self,
        spend: &ShieldedSpend,
        verifier: &V,
    ) -> Result<ProtocolSpendReceipt> {
        self.apply_spend_inner(spend, verifier)
    }
}

impl<P: LedgerProfile> ShieldedLedger<P> {
    fn new_inner(
        chain_domain: Hash,
        ledger_id: Hash,
        deposit_authority: Hash,
        profile: P,
    ) -> Result<Self> {
        if chain_domain == [0; 32] {
            return Err(ShieldedProtocolError::ZeroChainDomain);
        }
        if ledger_id == [0; 32] {
            return Err(ShieldedProtocolError::ZeroLedgerId);
        }
        VerifyingKey::from_bytes(&deposit_authority)
            .map_err(|error| ShieldedProtocolError::InvalidDepositAuthority(error.to_string()))?;
        Ok(Self {
            version: SHIELDED_PROTOCOL_VERSION,
            chain_domain,
            ledger_id,
            deposit_authority,
            profile,
            policies: BTreeMap::new(),
            margin_state: ShieldedMarginState::new(),
            shielded_collateral: 0,
            fee_total: 0,
            _profile: PhantomData,
        })
    }

    pub fn mode(&self) -> LedgerMode {
        P::MODE
    }

    pub fn register_market(&mut self, policy: MarginPolicy) -> Result<()> {
        self.validate_header()?;
        policy.validate()?;
        if self.policies.contains_key(&policy.market_id) {
            return Err(ShieldedProtocolError::MarketAlreadyRegistered);
        }
        self.policies.insert(policy.market_id, policy);
        Ok(())
    }

    pub fn policy(&self, market_id: MarketId) -> Option<&MarginPolicy> {
        self.policies.get(&market_id)
    }

    pub fn market_count(&self) -> usize {
        self.policies.len()
    }

    pub fn root(&self) -> Hash {
        self.margin_state.root()
    }

    pub fn note_count(&self) -> usize {
        self.margin_state.note_count()
    }

    pub fn note(&self, leaf_index: u64) -> Option<&PublicNote> {
        self.margin_state.note(leaf_index)
    }

    pub fn leaf_index(&self, commitment: crate::shielded_margin::NoteCommitment) -> Option<u64> {
        self.margin_state.leaf_index(commitment)
    }

    pub fn merkle_proof(&self, leaf_index: u64) -> Result<MerkleProof> {
        self.margin_state
            .merkle_proof(leaf_index)
            .map_err(Into::into)
    }

    pub fn is_spent(&self, nullifier: Nullifier) -> bool {
        self.margin_state.is_spent(nullifier)
    }

    pub fn shielded_collateral(&self) -> u128 {
        self.shielded_collateral
    }

    pub fn fee_total(&self) -> u128 {
        self.fee_total
    }

    fn authority_deposit_inner<V: DepositProofVerifier>(
        &mut self,
        deposit: &AuthorityDeposit,
        verifier: &V,
    ) -> Result<DepositReceipt> {
        self.validate_header()?;
        self.ensure_proof_security(V::SECURITY, "deposit")?;
        let statement = &deposit.statement;
        if statement.version != SHIELDED_PROTOCOL_VERSION {
            return Err(ShieldedProtocolError::UnsupportedVersion {
                actual: statement.version,
                expected: SHIELDED_PROTOCOL_VERSION,
            });
        }
        if statement.chain_domain != self.chain_domain {
            return Err(ShieldedProtocolError::ChainDomainMismatch);
        }
        if statement.ledger_id != self.ledger_id {
            return Err(ShieldedProtocolError::LedgerIdMismatch);
        }
        if statement.backing_amount == 0 {
            return Err(ShieldedProtocolError::ZeroBackingAmount);
        }
        let policy = self
            .policies
            .get(&statement.note.market_id)
            .ok_or(ShieldedProtocolError::MarketNotRegistered)?;
        if policy.collateral_asset != statement.note.collateral_asset {
            return Err(ShieldedProtocolError::CollateralAssetMismatch);
        }
        verify_authority_signature(
            &self.deposit_authority,
            &statement.authorization_digest(),
            &deposit.authority_signature,
        )?;
        verifier.verify(statement, &deposit.proof)?;

        let previous_collateral = self.shielded_collateral;
        let next_collateral = previous_collateral
            .checked_add(u128::from(statement.backing_amount))
            .ok_or(ShieldedProtocolError::AccountingOverflow(
                "deposit collateral total",
            ))?;
        let previous_root = self.margin_state.root();
        let leaf_index = self
            .margin_state
            .append_deposit_commitment(statement.note)?;
        self.shielded_collateral = next_collateral;
        Ok(DepositReceipt {
            leaf_index,
            previous_root,
            new_root: self.margin_state.root(),
            previous_collateral,
            next_collateral,
            backing_amount: statement.backing_amount,
        })
    }

    fn apply_spend_inner<V: ClassifiedSpendProofVerifier>(
        &mut self,
        spend: &ShieldedSpend,
        verifier: &V,
    ) -> Result<ProtocolSpendReceipt> {
        self.validate_header()?;
        self.ensure_proof_security(V::SECURITY, "spend")?;
        if spend.statement.chain_domain != self.chain_domain {
            return Err(ShieldedProtocolError::ChainDomainMismatch);
        }
        if spend.statement.ledger_id != self.ledger_id {
            return Err(ShieldedProtocolError::LedgerIdMismatch);
        }
        let policy = *self
            .policies
            .get(&spend.statement.market_id)
            .ok_or(ShieldedProtocolError::MarketNotRegistered)?;

        // Calculate every fallible accounting operation before mutating the
        // lower-level commitment/nullifier state.
        let fee = u128::from(spend.statement.fee);
        let previous_collateral = self.shielded_collateral;
        let next_collateral = previous_collateral
            .checked_sub(fee)
            .ok_or(ShieldedProtocolError::AccountingInvariant)?;
        let previous_fee_total = self.fee_total;
        let next_fee_total = previous_fee_total
            .checked_add(fee)
            .ok_or(ShieldedProtocolError::AccountingOverflow("fee total"))?;
        if next_collateral.checked_add(fee) != Some(previous_collateral) {
            return Err(ShieldedProtocolError::AccountingInvariant);
        }

        let state_receipt = self.margin_state.apply_spend(spend, &policy, verifier)?;
        self.shielded_collateral = next_collateral;
        self.fee_total = next_fee_total;
        Ok(ProtocolSpendReceipt {
            state_receipt,
            previous_collateral,
            next_collateral,
            previous_fee_total,
            next_fee_total,
        })
    }

    fn validate_header(&self) -> Result<()> {
        if self.version != SHIELDED_PROTOCOL_VERSION {
            return Err(ShieldedProtocolError::UnsupportedVersion {
                actual: self.version,
                expected: SHIELDED_PROTOCOL_VERSION,
            });
        }
        if self.chain_domain == [0; 32] {
            return Err(ShieldedProtocolError::ZeroChainDomain);
        }
        if self.ledger_id == [0; 32] {
            return Err(ShieldedProtocolError::ZeroLedgerId);
        }
        VerifyingKey::from_bytes(&self.deposit_authority)
            .map_err(|error| ShieldedProtocolError::InvalidDepositAuthority(error.to_string()))?;
        Ok(())
    }

    fn ensure_proof_security(
        &self,
        security: ProofSecurity,
        operation: &'static str,
    ) -> Result<()> {
        if P::MODE == LedgerMode::Production && security != ProofSecurity::ProductionZeroKnowledge {
            return Err(ShieldedProtocolError::ProductionVerifierRequired { operation });
        }
        Ok(())
    }
}

pub fn derive_chain_domain(chain_id: &str) -> Result<Hash> {
    if chain_id.is_empty()
        || chain_id.trim() != chain_id
        || chain_id.len() > MAX_SHIELDED_CHAIN_ID_BYTES
        || chain_id.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ShieldedProtocolError::InvalidChainId);
    }
    Ok(hash_parts(
        CHAIN_DOMAIN_DERIVATION_DOMAIN,
        &[chain_id.as_bytes()],
    ))
}

fn verify_authority_signature(authority: &Hash, message: &Hash, signature: &[u8]) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(authority)
        .map_err(|error| ShieldedProtocolError::InvalidDepositAuthority(error.to_string()))?;
    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| ShieldedProtocolError::InvalidAuthoritySignatureLength)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| ShieldedProtocolError::InvalidAuthoritySignature)
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value)
        .map_err(|error| ShieldedProtocolError::CanonicalEncoding(error.to_string()))
}

fn canonical_decode<T>(bytes: &[u8]) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let decoded = serde_json::from_slice(bytes)
        .map_err(|error| ShieldedProtocolError::CanonicalEncoding(error.to_string()))?;
    if canonical_encode(&decoded)? != bytes {
        return Err(ShieldedProtocolError::NonCanonicalDepositProof);
    }
    Ok(decoded)
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

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use crate::shielded_margin::{
        CollateralAssetId, SHIELDED_MARGIN_VERSION, SpendStatement, TransparentInputWitness,
        TransparentSpendProof, derive_nullifier,
    };

    use super::*;

    fn ledger_id() -> Hash {
        [91; 32]
    }

    fn chain_domain() -> Hash {
        derive_chain_domain("asteria-test-1").unwrap()
    }

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
        owner: &SigningKey,
        seed: u8,
        collateral: u64,
        position: i64,
        leverage: u16,
    ) -> NoteOpening {
        NoteOpening {
            owner: owner.verifying_key().to_bytes(),
            nullifier_key: [seed; 32],
            collateral,
            position,
            leverage,
            blinding: [seed.wrapping_add(1); 32],
        }
    }

    fn deposit_request(
        authority: &SigningKey,
        opening: NoteOpening,
        backing_amount: u64,
    ) -> AuthorityDeposit {
        let statement = DepositStatement {
            version: SHIELDED_PROTOCOL_VERSION,
            chain_domain: chain_domain(),
            ledger_id: ledger_id(),
            note: PublicNote::new(market_id(), asset_id(), &opening),
            backing_amount,
        };
        AuthorityDeposit {
            authority_signature: authority
                .sign(&statement.authorization_digest())
                .to_bytes()
                .to_vec(),
            statement,
            proof: TransparentDepositProof { opening }
                .to_canonical_bytes()
                .unwrap(),
        }
    }

    fn development_ledger(authority: &SigningKey) -> DevelopmentShieldedLedger {
        let mut ledger = DevelopmentShieldedLedger::new_development(
            chain_domain(),
            ledger_id(),
            authority.verifying_key().to_bytes(),
        )
        .unwrap();
        ledger.register_market(policy()).unwrap();
        ledger
    }

    fn spend_request<P: LedgerProfile>(
        ledger: &ShieldedLedger<P>,
        owner: &SigningKey,
        input_opening: NoteOpening,
        input_index: u64,
        output_opening: NoteOpening,
        fee: u64,
    ) -> ShieldedSpend {
        let input_note = *ledger.note(input_index).unwrap();
        let proof = ledger.merkle_proof(input_index).unwrap();
        let nullifier = derive_nullifier(&input_note, &input_opening, input_index);
        let output_note = PublicNote::new(market_id(), asset_id(), &output_opening);
        let statement = SpendStatement {
            version: SHIELDED_MARGIN_VERSION,
            chain_domain: ledger.chain_domain,
            ledger_id: ledger.ledger_id,
            anchor_root: ledger.root(),
            market_id: market_id(),
            collateral_asset: asset_id(),
            policy_hash: policy().policy_hash().unwrap(),
            nullifiers: vec![nullifier],
            output_commitments: vec![output_note.commitment],
            fee,
        };
        let signature = owner
            .sign(&statement.authorization_digest().unwrap())
            .to_bytes()
            .to_vec();
        ShieldedSpend {
            statement,
            proof: TransparentSpendProof {
                inputs: vec![TransparentInputWitness {
                    note: input_note,
                    opening: input_opening,
                    merkle_proof: proof,
                    authorization_signature: signature,
                }],
                output_openings: vec![output_opening],
            }
            .to_canonical_bytes()
            .unwrap(),
        }
    }

    #[test]
    fn registers_public_market_policy_once() {
        let authority = SigningKey::from_bytes(&[1; 32]);
        let mut ledger = DevelopmentShieldedLedger::new_development(
            chain_domain(),
            ledger_id(),
            authority.verifying_key().to_bytes(),
        )
        .unwrap();
        ledger.register_market(policy()).unwrap();

        assert_eq!(ledger.market_count(), 1);
        assert_eq!(ledger.policy(market_id()), Some(&policy()));
        assert_eq!(
            ledger.register_market(policy()),
            Err(ShieldedProtocolError::MarketAlreadyRegistered)
        );
    }

    #[test]
    fn authority_backed_deposit_updates_commitment_tree_and_accounting() {
        let authority = SigningKey::from_bytes(&[2; 32]);
        let owner = SigningKey::from_bytes(&[3; 32]);
        let mut ledger = development_ledger(&authority);
        let deposit = deposit_request(&authority, opening(&owner, 4, 1_000, 0, 1), 1_000);

        let receipt = ledger
            .authority_deposit(&deposit, &TransparentDepositVerifier)
            .unwrap();

        assert_eq!(receipt.previous_collateral, 0);
        assert_eq!(receipt.next_collateral, 1_000);
        assert_eq!(ledger.shielded_collateral(), 1_000);
        assert_eq!(ledger.fee_total(), 0);
        assert_eq!(ledger.note_count(), 1);
        assert_eq!(ledger.note(0), Some(&deposit.statement.note));
    }

    #[test]
    fn cross_chain_deposit_replay_is_rejected_without_mutation() {
        let authority = SigningKey::from_bytes(&[40; 32]);
        let owner = SigningKey::from_bytes(&[41; 32]);
        let deposit = deposit_request(&authority, opening(&owner, 42, 1_000, 0, 1), 1_000);
        let mut other_chain = DevelopmentShieldedLedger::new_development(
            derive_chain_domain("asteria-test-2").unwrap(),
            ledger_id(),
            authority.verifying_key().to_bytes(),
        )
        .unwrap();
        other_chain.register_market(policy()).unwrap();
        let root = other_chain.root();

        assert_eq!(
            other_chain.authority_deposit(&deposit, &TransparentDepositVerifier),
            Err(ShieldedProtocolError::ChainDomainMismatch)
        );
        assert_eq!(other_chain.root(), root);
        assert_eq!(other_chain.note_count(), 0);
        assert_eq!(other_chain.shielded_collateral(), 0);
    }

    #[test]
    fn transparent_deposit_rejects_backing_mismatch_without_mutation() {
        let authority = SigningKey::from_bytes(&[5; 32]);
        let owner = SigningKey::from_bytes(&[6; 32]);
        let mut ledger = development_ledger(&authority);
        let deposit = deposit_request(&authority, opening(&owner, 7, 1_000, 0, 1), 999);
        let root = ledger.root();

        assert_eq!(
            ledger.authority_deposit(&deposit, &TransparentDepositVerifier),
            Err(ShieldedProtocolError::DepositBackingMismatch {
                opening: 1_000,
                backing: 999,
            })
        );
        assert_eq!(ledger.root(), root);
        assert_eq!(ledger.shielded_collateral(), 0);
    }

    #[test]
    fn tampered_deposit_commitment_and_authority_signature_are_rejected() {
        let authority = SigningKey::from_bytes(&[8; 32]);
        let owner = SigningKey::from_bytes(&[9; 32]);
        let mut ledger = development_ledger(&authority);
        let valid = deposit_request(&authority, opening(&owner, 10, 1_000, 0, 1), 1_000);

        let mut bad_commitment = valid.clone();
        bad_commitment.statement.note.commitment.0[0] ^= 1;
        bad_commitment.authority_signature = authority
            .sign(&bad_commitment.statement.authorization_digest())
            .to_bytes()
            .to_vec();
        assert_eq!(
            ledger.authority_deposit(&bad_commitment, &TransparentDepositVerifier),
            Err(ShieldedProtocolError::DepositCommitmentMismatch)
        );

        let mut bad_signature = valid;
        bad_signature.authority_signature[0] ^= 1;
        assert_eq!(
            ledger.authority_deposit(&bad_signature, &TransparentDepositVerifier),
            Err(ShieldedProtocolError::InvalidAuthoritySignature)
        );
        assert_eq!(ledger.note_count(), 0);
    }

    #[test]
    fn duplicate_deposit_commitment_does_not_double_backing() {
        let authority = SigningKey::from_bytes(&[11; 32]);
        let owner = SigningKey::from_bytes(&[12; 32]);
        let mut ledger = development_ledger(&authority);
        let deposit = deposit_request(&authority, opening(&owner, 13, 1_000, 0, 1), 1_000);
        ledger
            .authority_deposit(&deposit, &TransparentDepositVerifier)
            .unwrap();

        assert_eq!(
            ledger.authority_deposit(&deposit, &TransparentDepositVerifier),
            Err(ShieldedProtocolError::Margin(
                ShieldedMarginError::CommitmentAlreadyExists
            ))
        );
        assert_eq!(ledger.shielded_collateral(), 1_000);
        assert_eq!(ledger.note_count(), 1);
    }

    #[test]
    fn spend_moves_fee_from_shielded_collateral_to_fee_total() {
        let authority = SigningKey::from_bytes(&[14; 32]);
        let owner = SigningKey::from_bytes(&[15; 32]);
        let input = opening(&owner, 16, 1_000, 0, 1);
        let mut ledger = development_ledger(&authority);
        let deposit = deposit_request(&authority, input.clone(), 1_000);
        let input_index = ledger
            .authority_deposit(&deposit, &TransparentDepositVerifier)
            .unwrap()
            .leaf_index;
        let spend = spend_request(
            &ledger,
            &owner,
            input,
            input_index,
            opening(&owner, 17, 990, 0, 1),
            10,
        );

        let receipt = ledger
            .apply_spend(&spend, &TransparentWitnessVerifier)
            .unwrap();

        assert_eq!(receipt.previous_collateral, 1_000);
        assert_eq!(receipt.next_collateral, 990);
        assert_eq!(receipt.next_fee_total, 10);
        assert_eq!(
            receipt.next_collateral + u128::from(receipt.state_receipt.fee),
            receipt.previous_collateral
        );
        assert_eq!(ledger.shielded_collateral(), 990);
        assert_eq!(ledger.fee_total(), 10);
    }

    #[test]
    fn cross_chain_spend_replay_is_rejected_without_mutation() {
        let authority = SigningKey::from_bytes(&[43; 32]);
        let owner = SigningKey::from_bytes(&[44; 32]);
        let input = opening(&owner, 45, 1_000, 0, 1);
        let mut ledger = development_ledger(&authority);
        let input_index = ledger
            .authority_deposit(
                &deposit_request(&authority, input.clone(), 1_000),
                &TransparentDepositVerifier,
            )
            .unwrap()
            .leaf_index;
        let spend = spend_request(
            &ledger,
            &owner,
            input,
            input_index,
            opening(&owner, 46, 990, 0, 1),
            10,
        );
        let mut cloned_state_on_other_chain = ledger.clone();
        cloned_state_on_other_chain.chain_domain = derive_chain_domain("asteria-test-2").unwrap();
        let root = cloned_state_on_other_chain.root();

        assert_eq!(
            cloned_state_on_other_chain.apply_spend(&spend, &TransparentWitnessVerifier),
            Err(ShieldedProtocolError::ChainDomainMismatch)
        );
        assert_eq!(cloned_state_on_other_chain.root(), root);
        assert_eq!(cloned_state_on_other_chain.shielded_collateral(), 1_000);
        assert_eq!(cloned_state_on_other_chain.fee_total(), 0);
        assert!(!cloned_state_on_other_chain.is_spent(spend.statement.nullifiers[0]));
    }

    #[test]
    fn chain_domain_derivation_rejects_noncanonical_ids() {
        assert_ne!(
            derive_chain_domain("asteria-test-1").unwrap(),
            derive_chain_domain("asteria-test-2").unwrap()
        );
        for chain_id in ["", " asteria-test-1", "asteria-test-1 ", "bad\nchain"] {
            assert_eq!(
                derive_chain_domain(chain_id),
                Err(ShieldedProtocolError::InvalidChainId)
            );
        }
    }

    #[test]
    fn duplicate_nullifier_does_not_charge_fee_twice() {
        let authority = SigningKey::from_bytes(&[18; 32]);
        let owner = SigningKey::from_bytes(&[19; 32]);
        let input = opening(&owner, 20, 1_000, 0, 1);
        let mut ledger = development_ledger(&authority);
        let input_index = ledger
            .authority_deposit(
                &deposit_request(&authority, input.clone(), 1_000),
                &TransparentDepositVerifier,
            )
            .unwrap()
            .leaf_index;
        let spend = spend_request(
            &ledger,
            &owner,
            input,
            input_index,
            opening(&owner, 21, 990, 0, 1),
            10,
        );
        ledger
            .apply_spend(&spend, &TransparentWitnessVerifier)
            .unwrap();

        assert_eq!(
            ledger.apply_spend(&spend, &TransparentWitnessVerifier),
            Err(ShieldedProtocolError::Margin(
                ShieldedMarginError::NullifierAlreadySpent
            ))
        );
        assert_eq!(ledger.shielded_collateral(), 990);
        assert_eq!(ledger.fee_total(), 10);
    }

    #[test]
    fn failed_spend_keeps_protocol_and_note_state_atomic() {
        let authority = SigningKey::from_bytes(&[22; 32]);
        let owner = SigningKey::from_bytes(&[23; 32]);
        let input = opening(&owner, 24, 1_000, 0, 1);
        let mut ledger = development_ledger(&authority);
        let input_index = ledger
            .authority_deposit(
                &deposit_request(&authority, input.clone(), 1_000),
                &TransparentDepositVerifier,
            )
            .unwrap()
            .leaf_index;
        let spend = spend_request(
            &ledger,
            &owner,
            input,
            input_index,
            opening(&owner, 25, 990, 1_000, 20),
            10,
        );
        let root = ledger.root();

        assert!(matches!(
            ledger.apply_spend(&spend, &TransparentWitnessVerifier),
            Err(ShieldedProtocolError::Margin(
                ShieldedMarginError::InsufficientIsolatedMargin { .. }
            ))
        ));
        assert_eq!(ledger.root(), root);
        assert_eq!(ledger.note_count(), 1);
        assert_eq!(ledger.shielded_collateral(), 1_000);
        assert_eq!(ledger.fee_total(), 0);
    }

    #[derive(Debug, Clone, Copy)]
    struct MisclassifiedProductionDepositVerifier;

    impl DepositProofVerifier for MisclassifiedProductionDepositVerifier {
        const SECURITY: ProofSecurity = ProofSecurity::TransparentDevelopment;

        fn verify(&self, statement: &DepositStatement, proof: &[u8]) -> Result<()> {
            TransparentDepositVerifier.verify(statement, proof)
        }
    }

    impl private::ProductionDepositVerifierSealed for MisclassifiedProductionDepositVerifier {}
    impl ProductionDepositProofVerifier for MisclassifiedProductionDepositVerifier {}

    #[derive(Debug, Clone, Copy)]
    struct TestProductionDepositVerifier;

    impl DepositProofVerifier for TestProductionDepositVerifier {
        const SECURITY: ProofSecurity = ProofSecurity::ProductionZeroKnowledge;

        fn verify(&self, statement: &DepositStatement, proof: &[u8]) -> Result<()> {
            // Test adapter only: production code must use an actual ZK verifier.
            TransparentDepositVerifier.verify(statement, proof)
        }
    }

    impl private::ProductionDepositVerifierSealed for TestProductionDepositVerifier {}
    impl ProductionDepositProofVerifier for TestProductionDepositVerifier {}

    #[derive(Debug, Clone, Copy)]
    struct MisclassifiedProductionSpendVerifier;

    impl SpendProofVerifier for MisclassifiedProductionSpendVerifier {
        fn verify(
            &self,
            statement: &SpendStatement,
            policy: &MarginPolicy,
            proof: &[u8],
        ) -> crate::shielded_margin::Result<()> {
            TransparentWitnessVerifier.verify(statement, policy, proof)
        }
    }

    impl ClassifiedSpendProofVerifier for MisclassifiedProductionSpendVerifier {
        const SECURITY: ProofSecurity = ProofSecurity::TransparentDevelopment;
    }

    impl private::ProductionSpendVerifierSealed for MisclassifiedProductionSpendVerifier {}
    impl ProductionSpendProofVerifier for MisclassifiedProductionSpendVerifier {}

    #[test]
    fn production_mode_rejects_misclassified_deposit_verifier() {
        let authority = SigningKey::from_bytes(&[26; 32]);
        let owner = SigningKey::from_bytes(&[27; 32]);
        let mut ledger = ProductionShieldedLedger::new_production(
            chain_domain(),
            ledger_id(),
            authority.verifying_key().to_bytes(),
        )
        .unwrap();
        ledger.register_market(policy()).unwrap();
        let deposit = deposit_request(&authority, opening(&owner, 28, 1_000, 0, 1), 1_000);

        assert_eq!(
            ledger.authority_deposit(&deposit, &MisclassifiedProductionDepositVerifier),
            Err(ShieldedProtocolError::ProductionVerifierRequired {
                operation: "deposit"
            })
        );
        assert_eq!(ledger.shielded_collateral(), 0);
    }

    #[test]
    fn production_mode_rejects_misclassified_spend_verifier() {
        let authority = SigningKey::from_bytes(&[32; 32]);
        let owner = SigningKey::from_bytes(&[33; 32]);
        let input = opening(&owner, 34, 1_000, 0, 1);
        let mut ledger = ProductionShieldedLedger::new_production(
            chain_domain(),
            ledger_id(),
            authority.verifying_key().to_bytes(),
        )
        .unwrap();
        ledger.register_market(policy()).unwrap();
        let input_index = ledger
            .authority_deposit(
                &deposit_request(&authority, input.clone(), 1_000),
                &TestProductionDepositVerifier,
            )
            .unwrap()
            .leaf_index;
        let spend = spend_request(
            &ledger,
            &owner,
            input,
            input_index,
            opening(&owner, 35, 990, 0, 1),
            10,
        );
        let root = ledger.root();

        assert_eq!(
            ledger.apply_spend(&spend, &MisclassifiedProductionSpendVerifier),
            Err(ShieldedProtocolError::ProductionVerifierRequired { operation: "spend" })
        );
        assert_eq!(ledger.root(), root);
        assert_eq!(ledger.shielded_collateral(), 1_000);
        assert_eq!(ledger.fee_total(), 0);
    }

    #[test]
    fn accounting_overflow_fails_before_spend_state_changes() {
        let authority = SigningKey::from_bytes(&[36; 32]);
        let owner = SigningKey::from_bytes(&[37; 32]);
        let input = opening(&owner, 38, 1_000, 0, 1);
        let mut ledger = development_ledger(&authority);
        let input_index = ledger
            .authority_deposit(
                &deposit_request(&authority, input.clone(), 1_000),
                &TransparentDepositVerifier,
            )
            .unwrap()
            .leaf_index;
        let spend = spend_request(
            &ledger,
            &owner,
            input,
            input_index,
            opening(&owner, 39, 990, 0, 1),
            10,
        );
        ledger.fee_total = u128::MAX;
        let root = ledger.root();

        assert_eq!(
            ledger.apply_spend(&spend, &TransparentWitnessVerifier),
            Err(ShieldedProtocolError::AccountingOverflow("fee total"))
        );
        assert_eq!(ledger.root(), root);
        assert_eq!(ledger.shielded_collateral(), 1_000);
        assert!(!ledger.is_spent(spend.statement.nullifiers[0]));
    }

    #[test]
    fn ledger_serde_round_trip_preserves_profile_and_accounting() {
        let authority = SigningKey::from_bytes(&[29; 32]);
        let owner = SigningKey::from_bytes(&[30; 32]);
        let mut ledger = development_ledger(&authority);
        ledger
            .authority_deposit(
                &deposit_request(&authority, opening(&owner, 31, 1_000, 0, 1), 1_000),
                &TransparentDepositVerifier,
            )
            .unwrap();

        let bytes = serde_json::to_vec(&ledger).unwrap();
        let decoded: DevelopmentShieldedLedger = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, ledger);
        assert!(serde_json::from_slice::<ProductionShieldedLedger>(&bytes).is_err());
    }
}
