use std::{
    collections::BTreeMap,
    future::{Ready, ready},
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use rand_core::OsRng;
use rayon::prelude::*;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tendermint::{
    AppHash,
    abci::{
        Code, Event as AbciEvent, EventAttributeIndexExt,
        request::CheckTxKind,
        response::{self, PrepareProposal},
        types::{BlockSignatureInfo, ExecTxResult},
    },
    block::{BlockIdFlag, Height},
    v0_38::abci::{Request, Response},
};
use tokio::sync::broadcast;
use tower::Service;
use tower_abci::{
    BoxError,
    v038::{Server, split},
};

use crate::{
    chain_tx::{
        Command, MAX_DECIMAL_SCALE, MAX_INPUT_VALUE, MAX_ORDER_NOTIONAL, SignedTransaction,
        verifying_key_from_account_id,
    },
    domain::{Account, AccountId, AuditReport, MarketState},
    engine::{
        ApplyContext, CommandResult, EngineState, apply_consensus_command, audit_engine_state,
        canonical_state_bytes, compute_app_hash, execute_private_decryption_bundle,
        freeze_private_batch_liquidity, prune_consensus_history,
    },
    error::ExchangeError,
    event::Event,
    private_order::{ThresholdPublicKeySet, ValidatorSecretShare},
    private_protocol::{
        DecryptionBundle, PRIVATE_ORDER_DECRYPTION_DELAY_BLOCKS, VoteExtension,
        aggregate_vote_extensions, private_batch_execution_id, validate_vote_extension,
    },
    shielded_margin::MarginPolicy,
    shielded_protocol::{DevelopmentShieldedLedger, derive_chain_domain},
    store::StateStore,
};
use zeroize::Zeroizing;

pub const MAX_TRANSACTION_BYTES: usize = 256 * 1024;
pub const APP_PROTOCOL_VERSION: u64 = 5;
const PRIVATE_SYSTEM_TX_PREFIX: &[u8] = b"ASTERIA_PRIVATE_DECRYPTION_SYSTEM_V3\0";
const VERIFIED_TRANSACTION_CACHE_CAPACITY: usize = 1_024;
const VERIFIED_TRANSACTION_CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct PrivateValidatorConfig {
    validator_id: u16,
    scalar: Zeroizing<[u8; 32]>,
}

impl PrivateValidatorConfig {
    pub fn from_hex(validator_id: u16, scalar_hex: &str) -> Result<Self, ConsensusError> {
        if !(1..=4).contains(&validator_id) {
            return Err(ConsensusError::InvalidGenesis(
                "private validator id must be between 1 and 4".into(),
            ));
        }
        if scalar_hex.len() != 64
            || !scalar_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ConsensusError::InvalidGenesis(
                "private validator share must be 32-byte lowercase hex".into(),
            ));
        }
        let decoded = Zeroizing::new(hex::decode(scalar_hex).map_err(|_| {
            ConsensusError::InvalidGenesis(
                "private validator share must be 32-byte lowercase hex".into(),
            )
        })?);
        let mut scalar = [0_u8; 32];
        scalar.copy_from_slice(&decoded);
        Ok(Self {
            validator_id,
            scalar: Zeroizing::new(scalar),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisState {
    pub app_protocol_version: u64,
    pub authority: AccountId,
    pub markets: Vec<MarketState>,
    #[serde(default)]
    pub initial_balances: BTreeMap<AccountId, Decimal>,
    #[serde(default)]
    pub private_order_key_set: Option<ThresholdPublicKeySet>,
    #[serde(default)]
    pub private_validator_bindings: BTreeMap<String, u16>,
    #[serde(default = "default_genesis_private_order_fee")]
    pub private_order_fee: Decimal,
    #[serde(default)]
    pub shielded_development: Option<ShieldedDevelopmentGenesis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedDevelopmentGenesis {
    pub ledger_id: String,
    pub deposit_authority: String,
    #[serde(default)]
    pub policies: Vec<MarginPolicy>,
}

fn default_genesis_private_order_fee() -> Decimal {
    dec!(0.01)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSnapshot {
    pub state: EngineState,
    pub app_hash: [u8; 32],
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ConsensusError {
    #[error("chain has not been initialized")]
    NotInitialized,
    #[error("chain is already initialized with different genesis state")]
    GenesisMismatch,
    #[error("invalid genesis state: {0}")]
    InvalidGenesis(String),
    #[error("transaction exceeds {MAX_TRANSACTION_BYTES} bytes")]
    TransactionTooLarge,
    #[error("invalid transaction encoding or signature: {0}")]
    InvalidTransaction(String),
    #[error("transaction targets chain {actual}, expected {expected}")]
    WrongChain { actual: String, expected: String },
    #[error("transaction expired at height {expires}; current height is {height}")]
    Expired { expires: u64, height: u64 },
    #[error("invalid nonce for {account_id}: expected {expected}, received {actual}")]
    InvalidNonce {
        account_id: AccountId,
        expected: u64,
        actual: u64,
    },
    #[error("nonce space exhausted for {account_id}")]
    NonceExhausted { account_id: AccountId },
    #[error("mempool already contains a different transaction for {account_id} nonce {nonce}")]
    MempoolNonceConflict { account_id: AccountId, nonce: u64 },
    #[error("state transition rejected: {0}")]
    Transition(String),
    #[error("state persistence failed: {0}")]
    Persistence(String),
    #[error("application state hash mismatch in persisted data")]
    StateHashMismatch,
}

impl ConsensusError {
    fn code(&self) -> u32 {
        match self {
            Self::TransactionTooLarge => 1,
            Self::InvalidTransaction(_) => 2,
            Self::WrongChain { .. } => 3,
            Self::Expired { .. } => 4,
            Self::InvalidNonce { .. }
            | Self::NonceExhausted { .. }
            | Self::MempoolNonceConflict { .. } => 5,
            Self::Transition(_) => 6,
            Self::NotInitialized
            | Self::GenesisMismatch
            | Self::InvalidGenesis(_)
            | Self::Persistence(_)
            | Self::StateHashMismatch => 7,
        }
    }
}

struct AppliedTransaction {
    transaction: SignedTransaction,
    signer: AccountId,
    tx_hash: [u8; 32],
    result: CommandResult,
}

#[derive(Clone)]
struct VerifiedTransaction {
    transaction: SignedTransaction,
    signer: AccountId,
    tx_hash: [u8; 32],
}

#[derive(Clone)]
enum StatelessTransaction {
    Signed(Arc<VerifiedTransaction>),
    PrivateSystem(Arc<DecryptionBundle>),
}

type StatelessTransactionResult = Result<StatelessTransaction, ConsensusError>;

struct TransactionCacheEntry {
    bytes_hash: [u8; 32],
    bytes_len: usize,
    result: StatelessTransactionResult,
    last_access: u64,
}

struct TransactionVerificationCache {
    capacity: usize,
    max_bytes: usize,
    resident_bytes: usize,
    next_access: u64,
    entries: BTreeMap<[u8; 32], TransactionCacheEntry>,
    recency: BTreeMap<u64, [u8; 32]>,
}

impl TransactionVerificationCache {
    fn new(capacity: usize, max_bytes: usize) -> Self {
        Self {
            capacity,
            max_bytes,
            resident_bytes: 0,
            next_access: 0,
            entries: BTreeMap::new(),
            recency: BTreeMap::new(),
        }
    }

    fn get(
        &mut self,
        bytes_hash: [u8; 32],
        bytes_len: usize,
    ) -> Option<StatelessTransactionResult> {
        let (last_access, result) = {
            let entry = self.entries.get(&bytes_hash)?;
            if entry.bytes_hash != bytes_hash || entry.bytes_len != bytes_len {
                self.remove(bytes_hash);
                return None;
            }
            (entry.last_access, entry.result.clone())
        };
        let access = self.allocate_access();
        self.recency.remove(&last_access);
        self.recency.insert(access, bytes_hash);
        self.entries
            .get_mut(&bytes_hash)
            .expect("cached transaction remains present while updating recency")
            .last_access = access;
        Some(result)
    }

    fn insert(
        &mut self,
        bytes_hash: [u8; 32],
        bytes_len: usize,
        result: StatelessTransactionResult,
    ) {
        if self.capacity == 0 || self.max_bytes == 0 || bytes_len > self.max_bytes {
            return;
        }
        self.remove(bytes_hash);
        let access = self.allocate_access();
        self.resident_bytes = self
            .resident_bytes
            .checked_add(bytes_len)
            .expect("cached transaction byte accounting cannot overflow its fixed budget");
        self.entries.insert(
            bytes_hash,
            TransactionCacheEntry {
                bytes_hash,
                bytes_len,
                result,
                last_access: access,
            },
        );
        self.recency.insert(access, bytes_hash);
        while self.entries.len() > self.capacity || self.resident_bytes > self.max_bytes {
            let Some(oldest_hash) = self.recency.first_key_value().map(|(_, hash)| *hash) else {
                break;
            };
            self.remove(oldest_hash);
        }
    }

    fn remove(&mut self, bytes_hash: [u8; 32]) {
        let Some(entry) = self.entries.remove(&bytes_hash) else {
            return;
        };
        self.recency.remove(&entry.last_access);
        debug_assert!(self.resident_bytes >= entry.bytes_len);
        self.resident_bytes = self.resident_bytes.saturating_sub(entry.bytes_len);
    }

    fn allocate_access(&mut self) -> u64 {
        if self.next_access == u64::MAX {
            let hashes = self.recency.values().copied().collect::<Vec<_>>();
            self.recency.clear();
            for (access, hash) in hashes.into_iter().enumerate() {
                let access = access as u64;
                self.entries
                    .get_mut(&hash)
                    .expect("recency index only contains cached transactions")
                    .last_access = access;
                self.recency.insert(access, hash);
            }
            self.next_access = self.entries.len() as u64;
        }
        let access = self.next_access;
        self.next_access += 1;
        access
    }
}

#[derive(Clone, Copy)]
struct MempoolReservation {
    nonce: u64,
    tx_hash: [u8; 32],
}

struct ChainRuntime {
    store: StateStore,
    committed: Option<ChainSnapshot>,
    pending: Option<ChainSnapshot>,
    mempool_reservations: BTreeMap<AccountId, MempoolReservation>,
    private_validator: Option<PrivateValidatorConfig>,
    transaction_cache: Mutex<TransactionVerificationCache>,
    events: broadcast::Sender<Event>,
}

impl ChainRuntime {
    fn open(
        store: StateStore,
        private_validator: Option<PrivateValidatorConfig>,
    ) -> Result<Self, ConsensusError> {
        let committed = store
            .load_state()
            .map_err(|error| ConsensusError::Persistence(error.to_string()))?
            .map(|stored| ChainSnapshot {
                state: stored.state,
                app_hash: stored.app_hash,
            });
        if let Some(snapshot) = &committed {
            let actual = compute_app_hash(&snapshot.state)
                .map_err(|error| ConsensusError::Persistence(error.to_string()))?;
            if actual != snapshot.app_hash || !snapshot.state.event_log.verify() {
                return Err(ConsensusError::StateHashMismatch);
            }
        }
        let (events, _) = broadcast::channel(4_096);
        Ok(Self {
            store,
            committed,
            pending: None,
            mempool_reservations: BTreeMap::new(),
            private_validator,
            transaction_cache: Mutex::new(TransactionVerificationCache::new(
                VERIFIED_TRANSACTION_CACHE_CAPACITY,
                VERIFIED_TRANSACTION_CACHE_MAX_BYTES,
            )),
            events,
        })
    }

    fn initialize(
        &mut self,
        request: tendermint::v0_38::abci::request::InitChain,
    ) -> Result<AppHash, ConsensusError> {
        let genesis: GenesisState = serde_json::from_slice(&request.app_state_bytes)
            .map_err(|error| ConsensusError::InvalidGenesis(error.to_string()))?;
        let chain_id = request.chain_id;
        validate_genesis(&genesis, &chain_id)?;
        validate_private_order_consensus(
            &genesis,
            &request.validators,
            request.consensus_params.abci.vote_extensions_enable_height,
            request.initial_height,
        )?;
        let mut state = EngineState::genesis(chain_id.clone(), genesis.markets);
        state.authority = genesis.authority;
        state.private_order_key_set = genesis.private_order_key_set;
        state.private_validator_bindings = genesis.private_validator_bindings.into_iter().collect();
        state.private_order_fee = genesis.private_order_fee;
        state.shielded_ledger = genesis
            .shielded_development
            .as_ref()
            .map(|config| build_shielded_development_ledger(config, &chain_id))
            .transpose()?;
        state.block_time_ms = time_millis(request.time);
        for (account_id, balance) in genesis.initial_balances {
            state.accounts.insert(
                account_id.clone(),
                Account {
                    id: account_id,
                    collateral: balance,
                    reserved_margin: Decimal::ZERO,
                    fees_paid: Decimal::ZERO,
                    positions: BTreeMap::new(),
                },
            );
            state.total_credits = state.total_credits.checked_add(balance).ok_or_else(|| {
                ConsensusError::InvalidGenesis("genesis total balance exceeds Decimal range".into())
            })?;
        }
        if let Some(committed) = &self.committed {
            let app_hash = compute_app_hash(&state)
                .map_err(|error| ConsensusError::Persistence(error.to_string()))?;
            if committed.app_hash != app_hash || committed.state.chain_id != state.chain_id {
                return Err(ConsensusError::GenesisMismatch);
            }
            self.mempool_reservations.clear();
            Ok(to_app_hash(app_hash))
        } else {
            let app_hash = self
                .store
                .commit_state(None, &state)
                .map_err(|error| ConsensusError::Persistence(error.to_string()))?;
            self.committed = Some(ChainSnapshot { state, app_hash });
            self.mempool_reservations.clear();
            Ok(to_app_hash(app_hash))
        }
    }

    fn info(&self) -> response::Info {
        match &self.committed {
            Some(snapshot) => response::Info {
                data: "asteria-abci".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                app_version: APP_PROTOCOL_VERSION,
                last_block_height: height(snapshot.state.height),
                last_block_app_hash: to_app_hash(snapshot.app_hash),
            },
            None => response::Info {
                data: "asteria-abci:uninitialized".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                app_version: APP_PROTOCOL_VERSION,
                last_block_height: 0_u32.into(),
                last_block_app_hash: AppHash::default(),
            },
        }
    }

    fn check_tx(&mut self, tx_bytes: &[u8], _kind: CheckTxKind) -> response::CheckTx {
        let verified = match verify_transaction_envelope_cached(&self.transaction_cache, tx_bytes) {
            Ok(verified) => verified,
            Err(error) => return check_error(error, tx_bytes.len()),
        };
        let Some(committed) = &self.committed else {
            return check_error(ConsensusError::NotInitialized, tx_bytes.len());
        };
        let next_height = committed.state.height.saturating_add(1);
        let next_nonce = match validate_transaction_state(&committed.state, &verified, next_height)
        {
            Ok(next_nonce) => next_nonce,
            Err(error) => return check_error(error, tx_bytes.len()),
        };
        if let Some(existing) = self.mempool_reservations.get(&verified.signer)
            && (existing.nonce != verified.transaction.nonce
                || existing.tx_hash != verified.tx_hash)
        {
            return check_error(
                ConsensusError::MempoolNonceConflict {
                    account_id: verified.signer,
                    nonce: verified.transaction.nonce,
                },
                tx_bytes.len(),
            );
        }
        let signer = verified.signer.clone();
        let nonce = verified.transaction.nonce;
        let tx_hash = verified.tx_hash;
        let block_time_ms = committed.state.block_time_ms;
        let mut scratch = committed.state.clone();
        match execute_verified_transaction(
            &mut scratch,
            verified,
            next_nonce,
            next_height,
            block_time_ms,
            0,
        ) {
            Ok(_) => {
                self.mempool_reservations
                    .insert(signer, MempoolReservation { nonce, tx_hash });
                response::CheckTx {
                    code: Code::Ok,
                    data: Bytes::copy_from_slice(&tx_hash),
                    gas_wanted: tx_bytes.len() as i64,
                    gas_used: tx_bytes.len() as i64,
                    ..Default::default()
                }
            }
            Err(error) => check_error(error, tx_bytes.len()),
        }
    }

    fn prepare_proposal(
        &self,
        request: tendermint::v0_38::abci::request::PrepareProposal,
    ) -> PrepareProposal {
        let Some(committed) = &self.committed else {
            return PrepareProposal { txs: vec![] };
        };
        let mut scratch = committed.state.clone();
        let block_time_ms = time_millis(request.time);
        scratch.height = request.height.value();
        scratch.block_time_ms = block_time_ms;
        let mut selected = Vec::new();
        let mut total_bytes = 0_i64;

        let pending_height = request
            .height
            .value()
            .saturating_sub(PRIVATE_ORDER_DECRYPTION_DELAY_BLOCKS);
        if let Some(pending) = committed
            .state
            .pending_private_orders
            .get(&pending_height)
            .filter(|pending| !pending.is_empty())
        {
            let Some(key_set) = committed.state.private_order_key_set.as_ref() else {
                tracing::error!(
                    pending_height,
                    "pending private orders have no epoch key set"
                );
                return PrepareProposal { txs: vec![] };
            };
            let Some(batch_app_hash) = committed
                .state
                .private_batch_app_hashes
                .get(&pending_height)
                .copied()
            else {
                tracing::error!(
                    pending_height,
                    "pending private orders have no committed app-hash anchor"
                );
                return PrepareProposal { txs: vec![] };
            };
            let extensions = request
                .local_last_commit
                .as_ref()
                .into_iter()
                .flat_map(|commit| &commit.votes)
                .filter(|vote| {
                    matches!(vote.sig_info, BlockSignatureInfo::Flag(BlockIdFlag::Commit))
                        && !vote.vote_extension.is_empty()
                })
                .filter_map(|vote| {
                    let extension =
                        VoteExtension::from_canonical_bytes(&vote.vote_extension).ok()?;
                    let address = hex::encode(vote.validator.address);
                    if committed.state.private_validator_bindings.get(&address)
                        == Some(&extension.validator_id)
                    {
                        Some(extension)
                    } else {
                        tracing::warn!(
                            validator_address = address,
                            claimed_validator_id = extension.validator_id,
                            "ignoring a vote extension whose threshold identity is not bound to the CometBFT validator"
                        );
                        None
                    }
                })
                .collect::<Vec<_>>();
            let bundle = match aggregate_vote_extensions(
                &committed.state.chain_id,
                pending_height,
                batch_app_hash,
                key_set,
                pending,
                &extensions,
            ) {
                Ok(bundle) => bundle,
                Err(error) => {
                    tracing::warn!(pending_height, %error, "cannot construct private decryption bundle");
                    return PrepareProposal { txs: vec![] };
                }
            };
            let system_tx = match encode_private_system_transaction(&bundle) {
                Ok(system_tx) => system_tx,
                Err(error) => {
                    tracing::error!(pending_height, %error, "private decryption bundle is too large");
                    return PrepareProposal { txs: vec![] };
                }
            };
            if system_tx.len() as i64 > request.max_tx_bytes {
                return PrepareProposal { txs: vec![] };
            }
            if execute_private_decryption_bundle(
                &mut scratch,
                &bundle,
                request.height.value(),
                match private_batch_execution_id(&committed.state.chain_id, &bundle) {
                    Ok(execution_id) => execution_id,
                    Err(error) => {
                        tracing::error!(pending_height, %error, "cannot derive private batch execution identity");
                        return PrepareProposal { txs: vec![] };
                    }
                },
            )
            .is_err()
            {
                return PrepareProposal { txs: vec![] };
            }
            total_bytes = system_tx.len() as i64;
            selected.push(system_tx);
        }

        for tx in request.txs {
            if total_bytes.saturating_add(tx.len() as i64) > request.max_tx_bytes {
                break;
            }
            let Ok(verified) = verify_transaction_envelope_cached(&self.transaction_cache, &tx)
            else {
                continue;
            };
            let index = selected.len() as u32;
            let applied = validate_transaction_state(&scratch, &verified, request.height.value())
                .and_then(|next_nonce| {
                    execute_verified_transaction(
                        &mut scratch,
                        verified,
                        next_nonce,
                        request.height.value(),
                        block_time_ms,
                        index,
                    )
                });
            if applied.is_ok() {
                total_bytes += tx.len() as i64;
                selected.push(tx);
            }
        }
        PrepareProposal { txs: selected }
    }

    fn process_proposal(
        &mut self,
        request: tendermint::v0_38::abci::request::ProcessProposal,
    ) -> response::ProcessProposal {
        let Some(committed) = &self.committed else {
            return response::ProcessProposal::Reject;
        };
        let mut scratch = committed.state.clone();
        let block_time_ms = time_millis(request.time);
        scratch.height = request.height.value();
        scratch.block_time_ms = block_time_ms;
        let pending_height = request
            .height
            .value()
            .saturating_sub(PRIVATE_ORDER_DECRYPTION_DELAY_BLOCKS);
        let expects_system = committed
            .state
            .pending_private_orders
            .get(&pending_height)
            .is_some_and(|pending| !pending.is_empty());
        let mut public_offset = 0_usize;
        if expects_system {
            let Some(first) = request.txs.first() else {
                return response::ProcessProposal::Reject;
            };
            let bundle = match decode_transaction_cached(&self.transaction_cache, first) {
                Ok(StatelessTransaction::PrivateSystem(bundle)) => bundle,
                Ok(StatelessTransaction::Signed(_)) | Err(_) => {
                    return response::ProcessProposal::Reject;
                }
            };
            if execute_private_decryption_bundle(
                &mut scratch,
                &bundle,
                request.height.value(),
                match private_batch_execution_id(&committed.state.chain_id, &bundle) {
                    Ok(execution_id) => execution_id,
                    Err(_) => return response::ProcessProposal::Reject,
                },
            )
            .is_err()
            {
                return response::ProcessProposal::Reject;
            }
            public_offset = 1;
        } else if request.txs.first().is_some_and(|tx| {
            matches!(
                decode_transaction_cached(&self.transaction_cache, tx),
                Ok(StatelessTransaction::PrivateSystem(_))
            )
        }) {
            return response::ProcessProposal::Reject;
        }
        if request.txs[public_offset..].iter().any(|tx| {
            matches!(
                decode_transaction_cached(&self.transaction_cache, tx),
                Ok(StatelessTransaction::PrivateSystem(_))
            )
        }) {
            return response::ProcessProposal::Reject;
        }

        let verified = match request.txs[public_offset..]
            .par_iter()
            .map(|tx| verify_transaction_envelope_cached(&self.transaction_cache, tx))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(verified) => verified,
            Err(_) => return response::ProcessProposal::Reject,
        };
        for (index, verified) in verified.into_iter().enumerate() {
            let applied = validate_transaction_state(&scratch, &verified, request.height.value())
                .and_then(|next_nonce| {
                    execute_verified_transaction(
                        &mut scratch,
                        verified,
                        next_nonce,
                        request.height.value(),
                        block_time_ms,
                        (index + public_offset) as u32,
                    )
                });
            if applied.is_err() {
                return response::ProcessProposal::Reject;
            }
        }
        response::ProcessProposal::Accept
    }

    fn finalize_block(
        &mut self,
        request: tendermint::v0_38::abci::request::FinalizeBlock,
    ) -> Result<response::FinalizeBlock, ConsensusError> {
        let committed = self
            .committed
            .as_ref()
            .ok_or(ConsensusError::NotInitialized)?;
        let mut state = committed.state.clone();
        let block_time_ms = time_millis(request.time);
        state.height = request.height.value();
        state.block_time_ms = block_time_ms;
        let share_batch_height = request.height.value().saturating_sub(1);
        if committed
            .state
            .pending_private_orders
            .get(&share_batch_height)
            .is_some_and(|pending| !pending.is_empty())
        {
            match state
                .private_batch_app_hashes
                .insert(share_batch_height, committed.app_hash)
            {
                Some(existing) if existing != committed.app_hash => {
                    return Err(ConsensusError::StateHashMismatch);
                }
                _ => {}
            }
        }
        let mut tx_results = Vec::with_capacity(request.txs.len());
        let pending_height = request
            .height
            .value()
            .saturating_sub(PRIVATE_ORDER_DECRYPTION_DELAY_BLOCKS);
        let expects_system = committed
            .state
            .pending_private_orders
            .get(&pending_height)
            .is_some_and(|pending| !pending.is_empty());
        let mut public_offset = 0_usize;
        if expects_system {
            let first = request.txs.first().ok_or_else(|| {
                ConsensusError::InvalidTransaction(
                    "proposal omitted the required private decryption bundle".into(),
                )
            })?;
            let bundle = match decode_transaction_cached(&self.transaction_cache, first)? {
                StatelessTransaction::PrivateSystem(bundle) => bundle,
                StatelessTransaction::Signed(_) => {
                    return Err(ConsensusError::InvalidTransaction(
                        "first transaction is not the required private decryption bundle".into(),
                    ));
                }
            };
            let execution = execute_private_decryption_bundle(
                &mut state,
                &bundle,
                request.height.value(),
                private_batch_execution_id(&committed.state.chain_id, &bundle)
                    .map_err(|error| ConsensusError::InvalidTransaction(error.to_string()))?,
            )
            .map_err(|error| ConsensusError::Transition(error.to_string()))?;
            tx_results.push(private_system_execution_result(&execution, first.len()));
            public_offset = 1;
        }
        if request.txs[public_offset..].iter().any(|tx| {
            matches!(
                decode_transaction_cached(&self.transaction_cache, tx),
                Ok(StatelessTransaction::PrivateSystem(_))
            )
        }) {
            return Err(ConsensusError::InvalidTransaction(
                "private system transaction is unexpected or misplaced".into(),
            ));
        }
        let verified = request.txs[public_offset..]
            .par_iter()
            .map(|tx| verify_transaction_envelope_cached(&self.transaction_cache, tx))
            .collect::<Vec<_>>();
        for (relative_index, (tx, verified)) in request.txs[public_offset..]
            .iter()
            .zip(verified)
            .enumerate()
        {
            let index = relative_index + public_offset;
            let applied = verified.and_then(|verified| {
                let next_nonce =
                    validate_transaction_state(&state, &verified, request.height.value())?;
                execute_verified_transaction(
                    &mut state,
                    verified,
                    next_nonce,
                    request.height.value(),
                    block_time_ms,
                    index as u32,
                )
            });
            match applied {
                Ok(applied) => tx_results.push(execution_result(&applied, tx.len())),
                Err(error) => tx_results.push(execution_error(error, tx.len())),
            }
        }
        freeze_private_batch_liquidity(&mut state, request.height.value())
            .map_err(|error| ConsensusError::Transition(error.to_string()))?;
        prune_consensus_history(&mut state);
        let app_hash = self
            .store
            .preview_state_root(Some(&committed.state), &state)
            .map_err(|error| ConsensusError::Persistence(error.to_string()))?;
        self.pending = Some(ChainSnapshot { state, app_hash });
        Ok(response::FinalizeBlock {
            events: vec![AbciEvent::new(
                "asteria.block",
                vec![
                    ("height", request.height.value().to_string()).index(),
                    ("app_hash", hex::encode(app_hash)).index(),
                ],
            )],
            tx_results,
            validator_updates: vec![],
            consensus_param_updates: None,
            app_hash: to_app_hash(app_hash),
        })
    }

    fn commit(&mut self) -> Result<response::Commit, ConsensusError> {
        let previous_sequence = self
            .committed
            .as_ref()
            .map(|snapshot| snapshot.state.sequence)
            .unwrap_or(0);
        let store = self.store.clone();
        let previous_state = self
            .committed
            .as_ref()
            .map(|snapshot| snapshot.state.clone());
        let pending = persist_pending_with(&mut self.pending, move |pending| {
            let persisted = store
                .commit_state(previous_state.as_ref(), &pending.state)
                .map_err(|error| ConsensusError::Persistence(error.to_string()))?;
            if persisted != pending.app_hash {
                return Err(ConsensusError::StateHashMismatch);
            }
            Ok(())
        })?;
        for event in pending.state.event_log.after(previous_sequence, usize::MAX) {
            let _ = self.events.send(event);
        }
        self.committed = Some(pending);
        self.mempool_reservations.clear();
        Ok(response::Commit {
            data: Bytes::new(),
            retain_height: 0_u32.into(),
        })
    }

    fn extend_vote(
        &self,
        request: tendermint::v0_38::abci::request::ExtendVote,
    ) -> response::ExtendVote {
        let Some(committed) = &self.committed else {
            return response::ExtendVote {
                vote_extension: Bytes::new(),
            };
        };
        let Some(batch_height) = request.height.value().checked_sub(1) else {
            return response::ExtendVote {
                vote_extension: Bytes::new(),
            };
        };
        if committed.state.height != batch_height {
            tracing::warn!(
                vote_height = request.height.value(),
                committed_height = committed.state.height,
                "refusing to share private orders without the preceding committed state"
            );
            return response::ExtendVote {
                vote_extension: Bytes::new(),
            };
        }
        let Some(pending) = committed
            .state
            .pending_private_orders
            .get(&batch_height)
            .filter(|pending| !pending.is_empty())
        else {
            return response::ExtendVote {
                vote_extension: Bytes::new(),
            };
        };
        let (Some(config), Some(key_set)) = (
            self.private_validator.as_ref(),
            committed.state.private_order_key_set.as_ref(),
        ) else {
            tracing::warn!(
                batch_height,
                "committed private submissions are present but this node has no decryption share"
            );
            return response::ExtendVote {
                vote_extension: Bytes::new(),
            };
        };
        let secret = match ValidatorSecretShare::from_provisioned_scalar(
            key_set,
            config.validator_id,
            *config.scalar,
        ) {
            Ok(secret) => secret,
            Err(error) => {
                tracing::error!(validator_id = config.validator_id, %error, "private validator share does not match genesis");
                return response::ExtendVote {
                    vote_extension: Bytes::new(),
                };
            }
        };
        let extension = match VoteExtension::build(
            &committed.state.chain_id,
            batch_height,
            committed.app_hash,
            key_set,
            &secret,
            pending,
            &mut OsRng,
        ) {
            Ok(extension) => extension,
            Err(error) => {
                tracing::warn!(batch_height, %error, "cannot build private vote extension");
                return response::ExtendVote {
                    vote_extension: Bytes::new(),
                };
            }
        };
        match extension.to_canonical_bytes() {
            Ok(bytes) => response::ExtendVote {
                vote_extension: bytes.into(),
            },
            Err(error) => {
                tracing::warn!(height = request.height.value(), %error, "cannot encode private vote extension");
                response::ExtendVote {
                    vote_extension: Bytes::new(),
                }
            }
        }
    }

    fn verify_vote_extension(
        &self,
        request: tendermint::v0_38::abci::request::VerifyVoteExtension,
    ) -> response::VerifyVoteExtension {
        let Some(committed) = &self.committed else {
            return response::VerifyVoteExtension::Reject;
        };
        let Some(batch_height) = request.height.value().checked_sub(1) else {
            return response::VerifyVoteExtension::Reject;
        };
        if committed.state.height != batch_height {
            return response::VerifyVoteExtension::Reject;
        }
        let pending = committed
            .state
            .pending_private_orders
            .get(&batch_height)
            .filter(|pending| !pending.is_empty());
        if request.vote_extension.is_empty() {
            return if pending.is_none() {
                response::VerifyVoteExtension::Accept
            } else {
                response::VerifyVoteExtension::Reject
            };
        }
        let Some(pending) = pending else {
            return response::VerifyVoteExtension::Reject;
        };
        let Some(key_set) = committed.state.private_order_key_set.as_ref() else {
            return response::VerifyVoteExtension::Reject;
        };
        let Ok(extension) = VoteExtension::from_canonical_bytes(&request.vote_extension) else {
            return response::VerifyVoteExtension::Reject;
        };
        let validator_address = hex::encode(request.validator_address.as_bytes());
        if committed
            .state
            .private_validator_bindings
            .get(&validator_address)
            != Some(&extension.validator_id)
        {
            return response::VerifyVoteExtension::Reject;
        }
        match validate_vote_extension(
            &extension,
            &committed.state.chain_id,
            batch_height,
            committed.app_hash,
            extension.validator_id,
            key_set,
            pending,
        ) {
            Ok(()) => response::VerifyVoteExtension::Accept,
            Err(_) => response::VerifyVoteExtension::Reject,
        }
    }

    fn query(&self, request: tendermint::abci::request::Query) -> response::Query {
        let Some(snapshot) = &self.committed else {
            return query_error(ConsensusError::NotInitialized, 0);
        };
        let value = match query_value(&snapshot.state, &request.path, &request.data) {
            Ok(value) => value,
            Err(error) => return query_error(error, snapshot.state.height),
        };
        response::Query {
            code: Code::Ok,
            log: "ok".into(),
            key: request.data,
            value: value.into(),
            height: height(snapshot.state.height),
            ..Default::default()
        }
    }
}

fn persist_pending_with(
    pending: &mut Option<ChainSnapshot>,
    persist: impl FnOnce(&ChainSnapshot) -> Result<(), ConsensusError>,
) -> Result<ChainSnapshot, ConsensusError> {
    let snapshot = pending.as_ref().ok_or_else(|| {
        ConsensusError::Persistence("commit requested without finalized block".into())
    })?;
    persist(snapshot)?;
    Ok(pending
        .take()
        .expect("pending snapshot remains present after successful persistence"))
}

#[derive(Clone)]
pub struct ChainHandle {
    inner: Arc<RwLock<ChainRuntime>>,
}

impl ChainHandle {
    pub fn snapshot(&self) -> Option<ChainSnapshot> {
        self.inner.read().committed.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.read().events.subscribe()
    }

    pub fn audit(&self) -> Option<AuditReport> {
        self.inner
            .read()
            .committed
            .as_ref()
            .map(|snapshot| audit_engine_state(&snapshot.state))
    }
}

#[derive(Clone)]
pub struct ChainApplication {
    inner: Arc<RwLock<ChainRuntime>>,
}

impl ChainApplication {
    pub fn open(store: StateStore) -> Result<(Self, ChainHandle), ConsensusError> {
        Self::open_with_private_validator(store, None)
    }

    pub fn open_with_private_validator(
        store: StateStore,
        private_validator: Option<PrivateValidatorConfig>,
    ) -> Result<(Self, ChainHandle), ConsensusError> {
        let inner = Arc::new(RwLock::new(ChainRuntime::open(store, private_validator)?));
        Ok((
            Self {
                inner: inner.clone(),
            },
            ChainHandle { inner },
        ))
    }
}

impl Service<Request> for ChainApplication {
    type Response = Response;
    type Error = BoxError;
    type Future = Ready<Result<Response, BoxError>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let response: Result<Response, BoxError> = (|| {
            Ok(match request {
                Request::Info(_) => Response::Info(self.inner.read().info()),
                Request::Query(request) => Response::Query(self.inner.read().query(request)),
                Request::InitChain(request) => {
                    let app_hash = self.inner.write().initialize(request)?;
                    Response::InitChain(response::InitChain {
                        consensus_params: None,
                        validators: vec![],
                        app_hash,
                    })
                }
                Request::CheckTx(request) => {
                    Response::CheckTx(self.inner.write().check_tx(&request.tx, request.kind))
                }
                Request::PrepareProposal(request) => {
                    Response::PrepareProposal(self.inner.read().prepare_proposal(request))
                }
                Request::ProcessProposal(request) => {
                    Response::ProcessProposal(self.inner.write().process_proposal(request))
                }
                Request::FinalizeBlock(request) => {
                    Response::FinalizeBlock(self.inner.write().finalize_block(request)?)
                }
                Request::Commit => Response::Commit(self.inner.write().commit()?),
                Request::ExtendVote(request) => {
                    Response::ExtendVote(self.inner.read().extend_vote(request))
                }
                Request::VerifyVoteExtension(request) => {
                    Response::VerifyVoteExtension(self.inner.read().verify_vote_extension(request))
                }
                Request::Flush => Response::Flush,
                Request::Echo(_) => Response::Echo(Default::default()),
                Request::ListSnapshots => Response::ListSnapshots(Default::default()),
                Request::OfferSnapshot(_) => Response::OfferSnapshot(Default::default()),
                Request::LoadSnapshotChunk(_) => Response::LoadSnapshotChunk(Default::default()),
                Request::ApplySnapshotChunk(_) => Response::ApplySnapshotChunk(Default::default()),
            })
        })();
        ready(response)
    }
}

pub async fn serve_abci(
    application: ChainApplication,
    address: impl tokio::net::ToSocketAddrs + std::fmt::Debug,
) -> Result<(), BoxError> {
    let (consensus, mempool, snapshot, info) = split::service(application, 1);
    Server::builder()
        .consensus(consensus)
        .mempool(mempool)
        .snapshot(snapshot)
        .info(info)
        .finish()
        .expect("all ABCI services are configured")
        .listen_tcp(address)
        .await
}

fn encode_private_system_transaction(bundle: &DecryptionBundle) -> Result<Bytes, ConsensusError> {
    let encoded = bundle
        .to_canonical_bytes()
        .map_err(|error| ConsensusError::InvalidTransaction(error.to_string()))?;
    let mut bytes = Vec::with_capacity(PRIVATE_SYSTEM_TX_PREFIX.len() + encoded.len());
    bytes.extend_from_slice(PRIVATE_SYSTEM_TX_PREFIX);
    bytes.extend_from_slice(&encoded);
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ConsensusError::TransactionTooLarge);
    }
    Ok(bytes.into())
}

fn decode_private_system_transaction(
    bytes: &[u8],
) -> Result<Option<DecryptionBundle>, ConsensusError> {
    let Some(encoded) = bytes.strip_prefix(PRIVATE_SYSTEM_TX_PREFIX) else {
        return Ok(None);
    };
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ConsensusError::TransactionTooLarge);
    }
    DecryptionBundle::from_canonical_bytes(encoded)
        .map(Some)
        .map_err(|error| ConsensusError::InvalidTransaction(error.to_string()))
}

fn decode_transaction_cached(
    cache: &Mutex<TransactionVerificationCache>,
    bytes: &[u8],
) -> StatelessTransactionResult {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ConsensusError::TransactionTooLarge);
    }
    let bytes_hash = transaction_bytes_hash(bytes);
    if let Some(cached) = cache.lock().get(bytes_hash, bytes.len()) {
        return cached;
    }
    let result = match decode_private_system_transaction(bytes) {
        Ok(Some(bundle)) => Ok(StatelessTransaction::PrivateSystem(Arc::new(bundle))),
        Ok(None) => verify_transaction_envelope(bytes)
            .map(Arc::new)
            .map(StatelessTransaction::Signed),
        Err(error) => Err(error),
    };
    cache.lock().insert(bytes_hash, bytes.len(), result.clone());
    result
}

fn verify_transaction_envelope_cached(
    cache: &Mutex<TransactionVerificationCache>,
    bytes: &[u8],
) -> Result<VerifiedTransaction, ConsensusError> {
    match decode_transaction_cached(cache, bytes)? {
        StatelessTransaction::Signed(verified) => Ok((*verified).clone()),
        StatelessTransaction::PrivateSystem(_) => Err(ConsensusError::InvalidTransaction(
            "private system transaction is not a signed user transaction".into(),
        )),
    }
}

fn transaction_bytes_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
fn apply_transaction(
    state: &mut EngineState,
    tx_bytes: &[u8],
    block_height: u64,
    block_time_ms: i64,
    tx_index: u32,
) -> Result<AppliedTransaction, ConsensusError> {
    let verified = verify_transaction_envelope(tx_bytes)?;
    let next_nonce = validate_transaction_state(state, &verified, block_height)?;
    execute_verified_transaction(
        state,
        verified,
        next_nonce,
        block_height,
        block_time_ms,
        tx_index,
    )
}

fn verify_transaction_envelope(tx_bytes: &[u8]) -> Result<VerifiedTransaction, ConsensusError> {
    if tx_bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ConsensusError::TransactionTooLarge);
    }
    let transaction = SignedTransaction::from_canonical_bytes(tx_bytes)
        .map_err(|error| ConsensusError::InvalidTransaction(error.to_string()))?;
    let signer = transaction
        .verify()
        .map_err(|error| ConsensusError::InvalidTransaction(error.to_string()))?;
    transaction
        .command
        .validate_numeric_bounds()
        .map_err(|error| ConsensusError::InvalidTransaction(error.to_string()))?;
    let tx_hash = transaction
        .tx_hash()
        .map_err(|error| ConsensusError::InvalidTransaction(error.to_string()))?;
    Ok(VerifiedTransaction {
        transaction,
        signer,
        tx_hash,
    })
}

fn validate_transaction_state(
    state: &EngineState,
    verified: &VerifiedTransaction,
    block_height: u64,
) -> Result<u64, ConsensusError> {
    if verified.transaction.chain_id != state.chain_id {
        return Err(ConsensusError::WrongChain {
            actual: verified.transaction.chain_id.clone(),
            expected: state.chain_id.clone(),
        });
    }
    if verified.transaction.valid_until_height < block_height {
        return Err(ConsensusError::Expired {
            expires: verified.transaction.valid_until_height,
            height: block_height,
        });
    }
    let expected_nonce = state
        .account_nonces
        .get(&verified.signer)
        .copied()
        .unwrap_or(0);
    if verified.transaction.nonce != expected_nonce {
        return Err(ConsensusError::InvalidNonce {
            account_id: verified.signer.clone(),
            expected: expected_nonce,
            actual: verified.transaction.nonce,
        });
    }
    expected_nonce
        .checked_add(1)
        .ok_or_else(|| ConsensusError::NonceExhausted {
            account_id: verified.signer.clone(),
        })
}

fn execute_verified_transaction(
    state: &mut EngineState,
    verified: VerifiedTransaction,
    next_nonce: u64,
    block_height: u64,
    block_time_ms: i64,
    tx_index: u32,
) -> Result<AppliedTransaction, ConsensusError> {
    let authority = state.authority.clone();
    let result = apply_consensus_command(
        state,
        &verified.signer,
        &authority,
        &verified.transaction.command,
        ApplyContext::new(block_height, block_time_ms, tx_index, verified.tx_hash),
    )
    .map_err(|error| ConsensusError::Transition(error.to_string()))?;
    state
        .account_nonces
        .insert(verified.signer.clone(), next_nonce);
    Ok(AppliedTransaction {
        transaction: verified.transaction,
        signer: verified.signer,
        tx_hash: verified.tx_hash,
        result,
    })
}

fn execution_result(applied: &AppliedTransaction, tx_len: usize) -> ExecTxResult {
    ExecTxResult {
        code: Code::Ok,
        data: serde_jcs::to_vec(&applied.result)
            .unwrap_or_default()
            .into(),
        log: "applied".into(),
        gas_wanted: tx_len as i64,
        gas_used: tx_len as i64,
        events: vec![AbciEvent::new(
            "asteria.tx",
            vec![
                ("tx_hash", hex::encode(applied.tx_hash)).index(),
                ("signer", applied.signer.clone()).index(),
                ("command", command_name(&applied.transaction.command)).index(),
            ],
        )],
        codespace: "asteria".into(),
        ..Default::default()
    }
}

fn execution_error(error: ConsensusError, tx_len: usize) -> ExecTxResult {
    ExecTxResult {
        code: Code::from(error.code()),
        log: error.to_string(),
        gas_wanted: tx_len as i64,
        gas_used: tx_len as i64,
        codespace: "asteria".into(),
        ..Default::default()
    }
}

fn private_system_execution_result(
    execution: &crate::engine::PrivateBatchExecution,
    tx_len: usize,
) -> ExecTxResult {
    ExecTxResult {
        code: Code::Ok,
        data: serde_jcs::to_vec(execution).unwrap_or_default().into(),
        log: "private batch decrypted and cleared".into(),
        gas_wanted: tx_len as i64,
        gas_used: tx_len as i64,
        events: vec![AbciEvent::new(
            "asteria.private_batch",
            vec![
                ("batch_height", execution.batch_height.to_string()).index(),
                ("valid_orders", execution.valid_orders.to_string()).index(),
                ("invalid_orders", execution.invalid_orders.to_string()).index(),
            ],
        )],
        codespace: "asteria".into(),
        ..Default::default()
    }
}

fn check_error(error: ConsensusError, tx_len: usize) -> response::CheckTx {
    response::CheckTx {
        code: Code::from(error.code()),
        log: error.to_string(),
        gas_wanted: tx_len as i64,
        gas_used: tx_len as i64,
        codespace: "asteria".into(),
        ..Default::default()
    }
}

fn query_value(state: &EngineState, path: &str, data: &[u8]) -> Result<Vec<u8>, ConsensusError> {
    match path {
        "/state" => canonical_state_bytes(state)
            .map_err(|error| ConsensusError::Transition(error.to_string())),
        "/audit" => serde_jcs::to_vec(&audit_engine_state(state))
            .map_err(|error| ConsensusError::Transition(error.to_string())),
        "/account" => {
            let account_id = std::str::from_utf8(data)
                .map_err(|error| ConsensusError::InvalidTransaction(error.to_string()))?;
            let account = state
                .accounts
                .get(account_id)
                .ok_or_else(|| ConsensusError::Transition("account not found".into()))?;
            serde_jcs::to_vec(account)
                .map_err(|error| ConsensusError::Transition(error.to_string()))
        }
        "/market" => {
            let symbol = std::str::from_utf8(data)
                .map_err(|error| ConsensusError::InvalidTransaction(error.to_string()))?;
            let market = state
                .markets
                .get(symbol)
                .ok_or_else(|| ConsensusError::Transition("market not found".into()))?;
            serde_jcs::to_vec(market).map_err(|error| ConsensusError::Transition(error.to_string()))
        }
        _ => Err(ConsensusError::Transition(format!(
            "unsupported query path: {path}"
        ))),
    }
}

fn query_error(error: ConsensusError, block_height: u64) -> response::Query {
    response::Query {
        code: Code::from(error.code()),
        log: error.to_string(),
        height: height(block_height),
        codespace: "asteria".into(),
        ..Default::default()
    }
}

fn validate_genesis(genesis: &GenesisState, chain_id: &str) -> Result<(), ConsensusError> {
    if genesis.app_protocol_version != APP_PROTOCOL_VERSION {
        return Err(ConsensusError::InvalidGenesis(format!(
            "app_protocol_version must be {APP_PROTOCOL_VERSION}"
        )));
    }
    verifying_key_from_account_id(&genesis.authority).map_err(|error| {
        ConsensusError::InvalidGenesis(format!("authority is not a valid Ed25519 account: {error}"))
    })?;
    validate_genesis_decimal(
        "private_order_fee",
        genesis.private_order_fee,
        Decimal::ZERO,
        MAX_INPUT_VALUE,
        false,
    )?;
    if let Some(key_set) = &genesis.private_order_key_set {
        key_set.validate().map_err(|error| {
            ConsensusError::InvalidGenesis(format!("private_order_key_set is invalid: {error}"))
        })?;
    }
    validate_private_validator_bindings(genesis)?;
    if let Some(config) = &genesis.shielded_development {
        build_shielded_development_ledger(config, chain_id)?;
    }
    if genesis.markets.is_empty() {
        return Err(ConsensusError::InvalidGenesis(
            "at least one market must be declared in app_state".into(),
        ));
    }
    let unique_symbols: std::collections::BTreeSet<_> = genesis
        .markets
        .iter()
        .map(|market| &market.config.symbol)
        .collect();
    if unique_symbols.len() != genesis.markets.len() {
        return Err(ConsensusError::InvalidGenesis(
            "market symbols must be unique".into(),
        ));
    }
    for market in &genesis.markets {
        let config = &market.config;
        if config.symbol.trim().is_empty() {
            return Err(ConsensusError::InvalidGenesis(
                "market symbols must not be empty".into(),
            ));
        }
        for (field, value) in [
            ("tick_size", config.tick_size),
            ("quantity_step", config.quantity_step),
            ("min_quantity", config.min_quantity),
            ("mark_price", market.mark_price),
        ] {
            validate_genesis_decimal(field, value, Decimal::ZERO, MAX_INPUT_VALUE, false)?;
        }
        for (field, value) in [
            ("maintenance_margin_ratio", config.maintenance_margin_ratio),
            ("maker_fee_rate", config.maker_fee_rate),
            ("taker_fee_rate", config.taker_fee_rate),
            ("market_slippage_limit", config.market_slippage_limit),
            ("liquidation_penalty_rate", config.liquidation_penalty_rate),
        ] {
            validate_genesis_decimal(field, value, Decimal::ZERO, Decimal::ONE, true)?;
        }
        validate_genesis_decimal(
            "funding_rate",
            market.funding_rate,
            -dec!(0.01),
            dec!(0.01),
            true,
        )?;
        if config.max_leverage == 0 {
            return Err(ConsensusError::InvalidGenesis(
                "max_leverage must be positive".into(),
            ));
        }
    }
    let mut total_balances = Decimal::ZERO;
    for balance in genesis.initial_balances.values() {
        validate_genesis_decimal(
            "initial_balance",
            *balance,
            Decimal::ZERO,
            MAX_INPUT_VALUE,
            true,
        )?;
        total_balances = total_balances.checked_add(*balance).ok_or_else(|| {
            ConsensusError::InvalidGenesis("genesis total balance exceeds Decimal range".into())
        })?;
        if total_balances > MAX_ORDER_NOTIONAL {
            return Err(ConsensusError::InvalidGenesis(
                "genesis total balance exceeds protocol maximum".into(),
            ));
        }
    }
    Ok(())
}

fn validate_private_validator_bindings(genesis: &GenesisState) -> Result<(), ConsensusError> {
    let Some(key_set) = &genesis.private_order_key_set else {
        if genesis.private_validator_bindings.is_empty() {
            return Ok(());
        }
        return Err(ConsensusError::InvalidGenesis(
            "private_validator_bindings require private_order_key_set".into(),
        ));
    };
    if genesis.private_validator_bindings.len() != key_set.validators.len() {
        return Err(ConsensusError::InvalidGenesis(format!(
            "private_validator_bindings must contain exactly {} validators",
            key_set.validators.len()
        )));
    }
    let expected_ids = key_set
        .validators
        .iter()
        .map(|validator| validator.validator_id)
        .collect::<std::collections::BTreeSet<_>>();
    let actual_ids = genesis
        .private_validator_bindings
        .values()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if actual_ids != expected_ids || actual_ids.len() != genesis.private_validator_bindings.len() {
        return Err(ConsensusError::InvalidGenesis(
            "private_validator_bindings must assign every threshold validator id exactly once"
                .into(),
        ));
    }
    for address in genesis.private_validator_bindings.keys() {
        let decoded = hex::decode(address).map_err(|_| {
            ConsensusError::InvalidGenesis(
                "private validator addresses must be 20-byte lowercase hex".into(),
            )
        })?;
        if decoded.len() != 20 || hex::encode(&decoded) != *address || decoded == [0_u8; 20] {
            return Err(ConsensusError::InvalidGenesis(
                "private validator addresses must be nonzero 20-byte lowercase hex".into(),
            ));
        }
    }
    Ok(())
}

fn validate_private_order_consensus(
    genesis: &GenesisState,
    validators: &[tendermint::validator::Update],
    vote_extensions_enable_height: Option<Height>,
    initial_height: Height,
) -> Result<(), ConsensusError> {
    if genesis.private_order_key_set.is_none() {
        return Ok(());
    }
    if !matches!(initial_height.value(), 0 | 1) {
        return Err(ConsensusError::InvalidGenesis(
            "private-order chains must start at height zero or one".into(),
        ));
    }
    if vote_extensions_enable_height.map(|height| height.value()) != Some(1) {
        return Err(ConsensusError::InvalidGenesis(
            "private-order chains require vote extensions from height 1".into(),
        ));
    }
    if validators.len() != 4 {
        return Err(ConsensusError::InvalidGenesis(
            "private-order chains require exactly four CometBFT validators".into(),
        ));
    }
    let voting_power = validators[0].power;
    if voting_power.is_zero()
        || validators
            .iter()
            .any(|validator| validator.power != voting_power)
    {
        return Err(ConsensusError::InvalidGenesis(
            "private-order chains require four equal, positive validator voting powers".into(),
        ));
    }

    let mut validator_addresses = std::collections::BTreeSet::new();
    for validator in validators {
        let public_key = validator.pub_key.ed25519().ok_or_else(|| {
            ConsensusError::InvalidGenesis(
                "private-order chains require Ed25519 CometBFT validators".into(),
            )
        })?;
        let digest = Sha256::digest(public_key.as_bytes());
        validator_addresses.insert(hex::encode(&digest[..20]));
    }
    if validator_addresses.len() != validators.len() {
        return Err(ConsensusError::InvalidGenesis(
            "private-order CometBFT validator public keys must be unique".into(),
        ));
    }
    let bound_addresses = genesis
        .private_validator_bindings
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if validator_addresses != bound_addresses {
        return Err(ConsensusError::InvalidGenesis(
            "private validator bindings must exactly match the InitChain validator set".into(),
        ));
    }
    Ok(())
}

fn validate_genesis_decimal(
    field: &str,
    value: Decimal,
    minimum: Decimal,
    maximum: Decimal,
    allow_minimum: bool,
) -> Result<(), ConsensusError> {
    if value.scale() > MAX_DECIMAL_SCALE
        || value > maximum
        || value < minimum
        || (!allow_minimum && value == minimum)
    {
        return Err(ConsensusError::InvalidGenesis(format!(
            "{field} is outside protocol numeric bounds"
        )));
    }
    Ok(())
}

fn command_name(command: &Command) -> String {
    match command {
        Command::PlaceOrder { .. } => "place_order",
        Command::CancelOrder { .. } => "cancel_order",
        Command::CreditAccount { .. } => "credit_account",
        Command::PublishOraclePrice { .. } => "publish_oracle_price",
        Command::ApplyFunding { .. } => "apply_funding",
        Command::Liquidate { .. } => "liquidate",
        Command::SubmitPrivateOrder { .. } => "submit_private_order",
        Command::ConfigureShieldedMarket { .. } => "configure_shielded_market",
        Command::ShieldedDeposit { .. } => "shielded_deposit",
        Command::ShieldedSpend { .. } => "shielded_spend",
    }
    .into()
}

fn time_millis(time: tendermint::Time) -> i64 {
    (time.unix_timestamp_nanos() / 1_000_000)
        .try_into()
        .unwrap_or_else(|_| {
            if time.unix_timestamp_nanos().is_negative() {
                i64::MIN
            } else {
                i64::MAX
            }
        })
}

fn height(value: u64) -> Height {
    value.try_into().unwrap_or_else(|_| u32::MAX.into())
}

fn to_app_hash(hash: [u8; 32]) -> AppHash {
    hash.to_vec()
        .try_into()
        .expect("32 bytes is a valid application hash")
}

fn build_shielded_development_ledger(
    config: &ShieldedDevelopmentGenesis,
    chain_id: &str,
) -> Result<DevelopmentShieldedLedger, ConsensusError> {
    let decode_hash = |label: &str, value: &str| -> Result<[u8; 32], ConsensusError> {
        if value.len() != 64 || value.to_ascii_lowercase() != value {
            return Err(ConsensusError::InvalidGenesis(format!(
                "{label} must be 32-byte lowercase hex"
            )));
        }
        let decoded = hex::decode(value).map_err(|_| {
            ConsensusError::InvalidGenesis(format!("{label} must be 32-byte lowercase hex"))
        })?;
        let mut output = [0_u8; 32];
        output.copy_from_slice(&decoded);
        Ok(output)
    };
    let mut ledger = DevelopmentShieldedLedger::new_development(
        derive_chain_domain(chain_id)
            .map_err(|error| ConsensusError::InvalidGenesis(error.to_string()))?,
        decode_hash("shielded ledger_id", &config.ledger_id)?,
        decode_hash("shielded deposit_authority", &config.deposit_authority)?,
    )
    .map_err(|error| ConsensusError::InvalidGenesis(error.to_string()))?;
    for policy in &config.policies {
        ledger
            .register_market(*policy)
            .map_err(|error| ConsensusError::InvalidGenesis(error.to_string()))?;
    }
    tracing::warn!(
        "shielded development ledger uses transparent witnesses; do not enable it in production"
    );
    Ok(ledger)
}

impl From<ExchangeError> for ConsensusError {
    fn from(error: ExchangeError) -> Self {
        Self::Transition(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rust_decimal_macros::dec;

    use super::*;
    use crate::{
        chain_tx::{CURRENT_TRANSACTION_VERSION, UnsignedTransaction},
        domain::{OrderIntent, OrderKind, Side, TimeInForce},
        engine::default_markets,
        event::{EventKind, EventLog, MAX_RETAINED_EVENTS},
    };

    fn runtime_with_state(state: EngineState) -> (tempfile::TempDir, ChainRuntime) {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::open(directory.path().join("chain.redb")).unwrap();
        let app_hash = compute_app_hash(&state).unwrap();
        assert_eq!(store.commit_state(None, &state).unwrap(), app_hash);
        let runtime = ChainRuntime::open(store, None).unwrap();
        (directory, runtime)
    }

    #[test]
    fn two_nodes_produce_identical_state_and_app_hash() {
        let authority_key = SigningKey::from_bytes(&[1; 32]);
        let user_key = SigningKey::from_bytes(&[2; 32]);
        let authority =
            crate::chain_tx::account_id_from_signer(&authority_key.verifying_key().to_bytes());
        let user = crate::chain_tx::account_id_from_signer(&user_key.verifying_key().to_bytes());
        let mut first = EngineState::genesis("asteria-test-1", default_markets());
        first.authority = authority.clone();
        first
            .accounts
            .insert(user.clone(), Account::new(user.clone()));
        first.accounts.get_mut(&user).unwrap().collateral = dec!(1000);
        first.total_credits = dec!(1000);
        let mut second = first.clone();

        let transaction = UnsignedTransaction {
            version: CURRENT_TRANSACTION_VERSION,
            chain_id: "asteria-test-1".into(),
            signer: user_key.verifying_key().to_bytes(),
            nonce: 0,
            valid_until_height: 100,
            command: Command::PlaceOrder {
                intent: OrderIntent {
                    client_order_id: "deterministic-order".into(),
                    symbol: "BTCUSDT".into(),
                    side: Side::Buy,
                    kind: OrderKind::Limit,
                    quantity: dec!(0.01),
                    price: Some(dec!(60000)),
                    leverage: 10,
                    time_in_force: TimeInForce::Gtc,
                    reduce_only: false,
                },
            },
        }
        .sign(&user_key)
        .unwrap();
        let bytes = transaction.to_canonical_bytes().unwrap();
        apply_transaction(&mut first, &bytes, 1, 1_700_000_000_000, 0).unwrap();
        apply_transaction(&mut second, &bytes, 1, 1_700_000_000_000, 0).unwrap();

        assert_eq!(
            canonical_state_bytes(&first).unwrap(),
            canonical_state_bytes(&second).unwrap()
        );
        assert_eq!(
            compute_app_hash(&first).unwrap(),
            compute_app_hash(&second).unwrap()
        );
        let first_order = first.books["BTCUSDT"].snapshot("BTCUSDT".into(), 0, 1);
        let second_order = second.books["BTCUSDT"].snapshot("BTCUSDT".into(), 0, 1);
        assert_eq!(first_order.bids[0].price, second_order.bids[0].price);
    }

    #[test]
    fn finalize_block_prunes_legacy_event_history_on_an_empty_block() {
        let mut rolling_log = EventLog::default();
        let mut legacy_events = Vec::new();
        for sequence in 1..=(MAX_RETAINED_EVENTS as u64 + 5) {
            legacy_events.push(rolling_log.append(
                sequence,
                chrono::DateTime::UNIX_EPOCH,
                EventKind::AccountCredited {
                    account_id: "legacy".into(),
                    amount: Decimal::ONE,
                },
            ));
        }
        let legacy_log: EventLog = serde_json::from_value(serde_json::json!({
            "events": legacy_events
        }))
        .unwrap();
        assert_eq!(
            legacy_log.after(0, usize::MAX).len(),
            MAX_RETAINED_EVENTS + 5
        );

        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        state.sequence = MAX_RETAINED_EVENTS as u64 + 5;
        state.event_log = legacy_log;
        let (_directory, mut runtime) = runtime_with_state(state);
        runtime
            .finalize_block(tendermint::v0_38::abci::request::FinalizeBlock {
                txs: vec![],
                decided_last_commit: tendermint::abci::types::CommitInfo {
                    round: 0_u16.into(),
                    votes: vec![],
                },
                misbehavior: vec![],
                hash: tendermint::Hash::None,
                height: 1_u32.into(),
                time: tendermint::Time::from_unix_timestamp(1, 0).unwrap(),
                next_validators_hash: tendermint::Hash::None,
                proposer_address: tendermint::account::Id::new([0; 20]),
            })
            .unwrap();

        let retained = runtime
            .pending
            .as_ref()
            .unwrap()
            .state
            .event_log
            .after(0, usize::MAX);
        assert_eq!(retained.len(), MAX_RETAINED_EVENTS);
        assert_eq!(retained[0].sequence, 6);
    }

    #[test]
    fn nonce_prevents_replay() {
        let authority_key = SigningKey::from_bytes(&[3; 32]);
        let authority =
            crate::chain_tx::account_id_from_signer(&authority_key.verifying_key().to_bytes());
        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        state.authority = authority;
        let transaction = UnsignedTransaction {
            version: CURRENT_TRANSACTION_VERSION,
            chain_id: "asteria-test-1".into(),
            signer: authority_key.verifying_key().to_bytes(),
            nonce: 0,
            valid_until_height: 10,
            command: Command::CreditAccount {
                account_id: "ed25519:target".into(),
                amount: dec!(10),
            },
        }
        .sign(&authority_key)
        .unwrap();
        let bytes = transaction.to_canonical_bytes().unwrap();
        apply_transaction(&mut state, &bytes, 1, 1, 0).unwrap();
        assert!(matches!(
            apply_transaction(&mut state, &bytes, 2, 2, 0),
            Err(ConsensusError::InvalidNonce { .. })
        ));
    }

    #[test]
    fn pending_snapshot_is_retained_until_persistence_succeeds() {
        let state = EngineState::genesis("asteria-test-1", default_markets());
        let app_hash = compute_app_hash(&state).unwrap();
        let mut pending = Some(ChainSnapshot { state, app_hash });

        let error = persist_pending_with(&mut pending, |_| {
            Err(ConsensusError::Persistence("simulated disk failure".into()))
        })
        .unwrap_err();
        assert!(matches!(error, ConsensusError::Persistence(_)));
        assert_eq!(pending.as_ref().unwrap().app_hash, app_hash);

        let promoted = persist_pending_with(&mut pending, |_| Ok(())).unwrap();
        assert_eq!(promoted.app_hash, app_hash);
        assert!(pending.is_none());
    }

    #[test]
    fn exhausted_nonce_is_rejected_without_mutating_state() {
        let authority_key = SigningKey::from_bytes(&[4; 32]);
        let authority =
            crate::chain_tx::account_id_from_signer(&authority_key.verifying_key().to_bytes());
        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        state.authority = authority.clone();
        state.account_nonces.insert(authority.clone(), u64::MAX);
        let before = canonical_state_bytes(&state).unwrap();
        let transaction = UnsignedTransaction {
            version: CURRENT_TRANSACTION_VERSION,
            chain_id: "asteria-test-1".into(),
            signer: authority_key.verifying_key().to_bytes(),
            nonce: u64::MAX,
            valid_until_height: u64::MAX,
            command: Command::CreditAccount {
                account_id: authority.clone(),
                amount: dec!(1),
            },
        }
        .sign(&authority_key)
        .unwrap();

        assert!(matches!(
            apply_transaction(
                &mut state,
                &transaction.to_canonical_bytes().unwrap(),
                1,
                1,
                0
            ),
            Err(ConsensusError::NonceExhausted { account_id }) if account_id == authority
        ));
        assert_eq!(canonical_state_bytes(&state).unwrap(), before);
    }

    #[test]
    fn malicious_decimal_is_rejected_before_state_execution() {
        let authority_key = SigningKey::from_bytes(&[5; 32]);
        let authority =
            crate::chain_tx::account_id_from_signer(&authority_key.verifying_key().to_bytes());
        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        state.authority = authority.clone();
        let before = canonical_state_bytes(&state).unwrap();
        let transaction = UnsignedTransaction {
            version: CURRENT_TRANSACTION_VERSION,
            chain_id: "asteria-test-1".into(),
            signer: authority_key.verifying_key().to_bytes(),
            nonce: 0,
            valid_until_height: 10,
            command: Command::CreditAccount {
                account_id: authority,
                amount: Decimal::MAX,
            },
        }
        .sign(&authority_key)
        .unwrap();

        assert!(matches!(
            apply_transaction(
                &mut state,
                &transaction.to_canonical_bytes().unwrap(),
                1,
                1,
                0
            ),
            Err(ConsensusError::InvalidTransaction(_))
        ));
        assert_eq!(canonical_state_bytes(&state).unwrap(), before);
    }

    #[test]
    fn decimal_accumulation_overflow_is_an_error_and_rolls_back() {
        let authority_key = SigningKey::from_bytes(&[6; 32]);
        let authority =
            crate::chain_tx::account_id_from_signer(&authority_key.verifying_key().to_bytes());
        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        state.authority = authority.clone();
        let mut account = Account::new(authority.clone());
        account.collateral = Decimal::MAX;
        state.accounts.insert(authority.clone(), account);
        state.total_credits = Decimal::MAX;
        let before = canonical_state_bytes(&state).unwrap();
        let transaction = UnsignedTransaction {
            version: CURRENT_TRANSACTION_VERSION,
            chain_id: "asteria-test-1".into(),
            signer: authority_key.verifying_key().to_bytes(),
            nonce: 0,
            valid_until_height: 10,
            command: Command::CreditAccount {
                account_id: authority,
                amount: dec!(1),
            },
        }
        .sign(&authority_key)
        .unwrap();

        assert!(matches!(
            apply_transaction(
                &mut state,
                &transaction.to_canonical_bytes().unwrap(),
                1,
                1,
                0
            ),
            Err(ConsensusError::Transition(message)) if message.contains("numeric overflow")
        ));
        assert_eq!(canonical_state_bytes(&state).unwrap(), before);
    }

    #[test]
    fn funding_index_overflow_is_an_error_and_rolls_back() {
        let authority_key = SigningKey::from_bytes(&[8; 32]);
        let authority =
            crate::chain_tx::account_id_from_signer(&authority_key.verifying_key().to_bytes());
        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        state.authority = authority.clone();
        state.markets.get_mut("BTCUSDT").unwrap().funding_index = Decimal::MAX;
        let before = canonical_state_bytes(&state).unwrap();
        let transaction = UnsignedTransaction {
            version: CURRENT_TRANSACTION_VERSION,
            chain_id: "asteria-test-1".into(),
            signer: authority_key.verifying_key().to_bytes(),
            nonce: 0,
            valid_until_height: 10,
            command: Command::ApplyFunding {
                symbol: "BTCUSDT".into(),
                rate: dec!(0.01),
            },
        }
        .sign(&authority_key)
        .unwrap();

        assert!(matches!(
            apply_transaction(
                &mut state,
                &transaction.to_canonical_bytes().unwrap(),
                1,
                1,
                0
            ),
            Err(ConsensusError::Transition(message)) if message.contains("numeric overflow")
        ));
        assert_eq!(canonical_state_bytes(&state).unwrap(), before);
    }

    #[test]
    fn consensus_arithmetic_panic_is_contained_and_rolls_back() {
        let authority_key = SigningKey::from_bytes(&[7; 32]);
        let authority =
            crate::chain_tx::account_id_from_signer(&authority_key.verifying_key().to_bytes());
        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        state.authority = authority.clone();
        state.sequence = u64::MAX;
        let before = canonical_state_bytes(&state).unwrap();
        let transaction = UnsignedTransaction {
            version: CURRENT_TRANSACTION_VERSION,
            chain_id: "asteria-test-1".into(),
            signer: authority_key.verifying_key().to_bytes(),
            nonce: 0,
            valid_until_height: 10,
            command: Command::CreditAccount {
                account_id: authority,
                amount: dec!(1),
            },
        }
        .sign(&authority_key)
        .unwrap();

        assert!(matches!(
            apply_transaction(
                &mut state,
                &transaction.to_canonical_bytes().unwrap(),
                1,
                1,
                0
            ),
            Err(ConsensusError::Transition(message))
                if message.contains("arithmetic exceeded protocol bounds")
        ));
        assert_eq!(canonical_state_bytes(&state).unwrap(), before);
    }

    #[test]
    fn genesis_rejects_unsafe_market_numbers() {
        let mut markets = default_markets();
        markets[0].mark_price = Decimal::MAX;
        let genesis = GenesisState {
            app_protocol_version: APP_PROTOCOL_VERSION,
            authority: format!("ed25519:{}", "00".repeat(32)),
            markets,
            initial_balances: BTreeMap::new(),
            private_order_key_set: None,
            private_validator_bindings: BTreeMap::new(),
            private_order_fee: default_genesis_private_order_fee(),
            shielded_development: None,
        };

        assert!(matches!(
            validate_genesis(&genesis, "asteria-test-1"),
            Err(ConsensusError::InvalidGenesis(message))
                if message.contains("mark_price")
        ));
    }

    #[test]
    fn genesis_binds_each_threshold_share_to_one_comet_validator() {
        let authority_key = SigningKey::from_bytes(&[41; 32]);
        let (key_set, _shares) =
            crate::private_order::generate_dealer_key_set(1, &mut OsRng).unwrap();
        let bindings = (1_u16..=4)
            .map(|validator_id| {
                (
                    hex::encode([u8::try_from(validator_id).unwrap(); 20]),
                    validator_id,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut genesis = GenesisState {
            app_protocol_version: APP_PROTOCOL_VERSION,
            authority: crate::chain_tx::account_id_from_signer(
                &authority_key.verifying_key().to_bytes(),
            ),
            markets: default_markets(),
            initial_balances: BTreeMap::new(),
            private_order_key_set: Some(key_set),
            private_validator_bindings: bindings,
            private_order_fee: default_genesis_private_order_fee(),
            shielded_development: None,
        };

        assert!(validate_genesis(&genesis, "asteria-test-1").is_ok());
        let fourth_address = hex::encode([4_u8; 20]);
        *genesis
            .private_validator_bindings
            .get_mut(&fourth_address)
            .unwrap() = 3;
        assert!(matches!(
            validate_genesis(&genesis, "asteria-test-1"),
            Err(ConsensusError::InvalidGenesis(message))
                if message.contains("threshold validator id")
        ));
    }

    #[test]
    fn private_order_genesis_requires_the_bound_equal_power_validator_set() {
        let authority_key = SigningKey::from_bytes(&[41; 32]);
        let (key_set, _shares) =
            crate::private_order::generate_dealer_key_set(1, &mut OsRng).unwrap();
        let validators = (1_u8..=4)
            .map(|seed| {
                let signing_key = SigningKey::from_bytes(&[seed; 32]);
                tendermint::validator::Update {
                    pub_key: tendermint::PublicKey::from_raw_ed25519(
                        &signing_key.verifying_key().to_bytes(),
                    )
                    .unwrap(),
                    power: 10_u32.into(),
                }
            })
            .collect::<Vec<_>>();
        let bindings = validators
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                let digest = Sha256::digest(validator.pub_key.to_bytes());
                (
                    hex::encode(&digest[..20]),
                    u16::try_from(index + 1).unwrap(),
                )
            })
            .collect();
        let genesis = GenesisState {
            app_protocol_version: APP_PROTOCOL_VERSION,
            authority: crate::chain_tx::account_id_from_signer(
                &authority_key.verifying_key().to_bytes(),
            ),
            markets: default_markets(),
            initial_balances: BTreeMap::new(),
            private_order_key_set: Some(key_set),
            private_validator_bindings: bindings,
            private_order_fee: default_genesis_private_order_fee(),
            shielded_development: None,
        };

        assert!(
            validate_private_order_consensus(
                &genesis,
                &validators,
                Some(1_u32.into()),
                0_u32.into(),
            )
            .is_ok()
        );
        assert!(matches!(
            validate_private_order_consensus(
                &genesis,
                &validators[..3],
                Some(1_u32.into()),
                0_u32.into(),
            ),
            Err(ConsensusError::InvalidGenesis(message))
                if message.contains("exactly four")
        ));

        let mut unequal = validators.clone();
        unequal[3].power = 11_u32.into();
        assert!(matches!(
            validate_private_order_consensus(
                &genesis,
                &unequal,
                Some(1_u32.into()),
                0_u32.into(),
            ),
            Err(ConsensusError::InvalidGenesis(message))
                if message.contains("equal, positive")
        ));
        assert!(matches!(
            validate_private_order_consensus(&genesis, &validators, None, 0_u32.into()),
            Err(ConsensusError::InvalidGenesis(message))
                if message.contains("vote extensions")
        ));

        let mut different = validators.clone();
        let replacement = SigningKey::from_bytes(&[9; 32]);
        different[3].pub_key =
            tendermint::PublicKey::from_raw_ed25519(&replacement.verifying_key().to_bytes())
                .unwrap();
        assert!(matches!(
            validate_private_order_consensus(
                &genesis,
                &different,
                Some(1_u32.into()),
                0_u32.into(),
            ),
            Err(ConsensusError::InvalidGenesis(message))
                if message.contains("exactly match")
        ));
    }

    #[test]
    fn genesis_authority_must_be_a_parseable_lowercase_ed25519_key() {
        for authority in [
            format!("ed25519:{}", "zz".repeat(32)),
            format!("ed25519:{}", "AB".repeat(32)),
        ] {
            let genesis = GenesisState {
                app_protocol_version: APP_PROTOCOL_VERSION,
                authority,
                markets: default_markets(),
                initial_balances: BTreeMap::new(),
                private_order_key_set: None,
                private_validator_bindings: BTreeMap::new(),
                private_order_fee: default_genesis_private_order_fee(),
                shielded_development: None,
            };
            assert!(matches!(
                validate_genesis(&genesis, "asteria-test-1"),
                Err(ConsensusError::InvalidGenesis(message))
                    if message.contains("authority")
            ));
        }

        let authority_key = SigningKey::from_bytes(&[9; 32]);
        let genesis = GenesisState {
            app_protocol_version: APP_PROTOCOL_VERSION,
            authority: crate::chain_tx::account_id_from_signer(
                &authority_key.verifying_key().to_bytes(),
            ),
            markets: default_markets(),
            initial_balances: BTreeMap::new(),
            private_order_key_set: None,
            private_validator_bindings: BTreeMap::new(),
            private_order_fee: default_genesis_private_order_fee(),
            shielded_development: None,
        };
        assert!(validate_genesis(&genesis, "asteria-test-1").is_ok());
    }

    #[test]
    fn check_tx_rejects_different_transactions_with_the_same_account_nonce() {
        let authority_key = SigningKey::from_bytes(&[10; 32]);
        let authority =
            crate::chain_tx::account_id_from_signer(&authority_key.verifying_key().to_bytes());
        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        state.authority = authority;
        let (_directory, mut runtime) = runtime_with_state(state);

        let signed_credit = |account_id: &str| {
            UnsignedTransaction {
                version: CURRENT_TRANSACTION_VERSION,
                chain_id: "asteria-test-1".into(),
                signer: authority_key.verifying_key().to_bytes(),
                nonce: 0,
                valid_until_height: 10,
                command: Command::CreditAccount {
                    account_id: account_id.into(),
                    amount: dec!(1),
                },
            }
            .sign(&authority_key)
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
        };

        let first_bytes = signed_credit("first");
        let second_bytes = signed_credit("second");
        let first = runtime.check_tx(&first_bytes, CheckTxKind::New);
        let conflict = runtime.check_tx(&second_bytes, CheckTxKind::New);
        assert_eq!(first.code, Code::Ok);
        assert_ne!(conflict.code, Code::Ok);

        let recheck = runtime.check_tx(&first_bytes, CheckTxKind::Recheck);
        assert_eq!(recheck.code, Code::Ok);
        assert_eq!(runtime.mempool_reservations.len(), 1);

        runtime.pending = runtime.committed.clone();
        runtime.commit().unwrap();
        assert!(runtime.mempool_reservations.is_empty());
        assert_eq!(
            runtime.check_tx(&second_bytes, CheckTxKind::Recheck).code,
            Code::Ok
        );
    }

    #[test]
    fn stateless_envelope_validation_rejects_before_state_execution() {
        assert!(matches!(
            verify_transaction_envelope(b"not canonical JSON"),
            Err(ConsensusError::InvalidTransaction(_))
        ));
        assert!(matches!(
            verify_transaction_envelope(&vec![0_u8; MAX_TRANSACTION_BYTES + 1]),
            Err(ConsensusError::TransactionTooLarge)
        ));
    }

    #[test]
    fn transaction_verification_cache_is_bounded_and_evicts_least_recently_used() {
        let mut cache = TransactionVerificationCache::new(2, usize::MAX);
        let first_bytes = b"first";
        let second_bytes = b"second";
        let third_bytes = b"third";
        let first = transaction_bytes_hash(first_bytes);
        let second = transaction_bytes_hash(second_bytes);
        let third = transaction_bytes_hash(third_bytes);
        let invalid = || Err(ConsensusError::InvalidTransaction("cached".into()));

        cache.insert(first, first_bytes.len(), invalid());
        cache.insert(second, second_bytes.len(), invalid());
        assert!(cache.get(first, first_bytes.len()).is_some());
        cache.insert(third, third_bytes.len(), invalid());

        assert_eq!(cache.entries.len(), 2);
        assert!(cache.get(first, first_bytes.len()).is_some());
        assert!(cache.get(second, second_bytes.len()).is_none());
        assert!(cache.get(third, third_bytes.len()).is_some());
    }

    #[test]
    fn transaction_verification_cache_rejects_a_mismatched_bytes_hash() {
        let mut cache = TransactionVerificationCache::new(1, usize::MAX);
        let bytes = b"transaction";
        let bytes_hash = transaction_bytes_hash(bytes);
        cache.insert(
            bytes_hash,
            bytes.len(),
            Err(ConsensusError::InvalidTransaction("cached".into())),
        );
        cache.entries.get_mut(&bytes_hash).unwrap().bytes_hash = [0xFF; 32];

        assert!(cache.get(bytes_hash, bytes.len()).is_none());
        assert!(cache.entries.is_empty());
        assert!(cache.recency.is_empty());
        assert_eq!(cache.resident_bytes, 0);
    }

    #[test]
    fn transaction_verification_cache_enforces_byte_budget_without_underflow() {
        let mut cache = TransactionVerificationCache::new(8, 10);
        let first = transaction_bytes_hash(b"123456");
        let second = transaction_bytes_hash(b"abcdef");
        let invalid = || Err(ConsensusError::InvalidTransaction("cached".into()));

        cache.insert(first, 6, invalid());
        cache.insert(second, 6, invalid());
        assert!(!cache.entries.contains_key(&first));
        assert!(cache.entries.contains_key(&second));
        assert_eq!(cache.resident_bytes, 6);

        cache.insert(second, 6, invalid());
        assert_eq!(cache.resident_bytes, 6);
        assert!(cache.get(second, 5).is_none());
        assert_eq!(cache.resident_bytes, 0);

        cache.insert(transaction_bytes_hash(b"oversized"), 11, invalid());
        assert!(cache.entries.is_empty());
        assert_eq!(cache.resident_bytes, 0);
    }
}
