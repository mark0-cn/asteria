use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    panic::{AssertUnwindSafe, catch_unwind},
};

use chrono::{DateTime, Utc};
use imbl::OrdMap;
use rayon::prelude::*;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{
    chain_tx::{Command, account_id_from_signer},
    domain::{
        Account, AccountId, AuditReport, BookSnapshot, LiquidationResult, MarketConfig,
        MarketState, NewOrder, OracleObservation, OracleSnapshot, Order, OrderKind, OrderResult,
        OrderStatus, RiskSnapshot, Side, SocializedLoss, Symbol, TimeInForce, Trade,
    },
    error::{ExchangeError, Result},
    event::{Event, EventKind, EventLog},
    orderbook::{Execution, OrderBook, RawFill},
    private_market::{
        BatchContext, BatchParticipant, ParticipantVisibility, PrivateBatchOutcome,
        clear_private_batch, lots_to_quantity, ticks_to_price,
    },
    private_order::ThresholdPublicKeySet,
    private_protocol::{
        DecryptedPrivateOrder, DecryptionBundle, MAX_PENDING_PRIVATE_ORDERS,
        PrivateOrderDecryptionOutcome, PrivateOrderKind, PrivateOrderSide, PrivateOrderSubmission,
        validate_and_decrypt_bundle, verify_submission,
    },
    shielded_margin::{MarginPolicy, ShieldedSpend, TransparentWitnessVerifier},
    shielded_protocol::{
        AuthorityDeposit, DepositReceipt, DevelopmentShieldedLedger, ProtocolSpendReceipt,
        TransparentDepositVerifier,
    },
    store::StateStore,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "result", rename_all = "snake_case")]
pub enum CommandResult {
    OrderPlaced(OrderResult),
    OrderCancelled(Order),
    AccountCredited(Account),
    OraclePublished(OracleSnapshot),
    FundingApplied {
        funding_index: Decimal,
        funding_pool: Decimal,
    },
    LiquidationExecuted(LiquidationResult),
    PrivateOrderQueued {
        submission_id: String,
        batch_height: u64,
        fee: Decimal,
        bond: Decimal,
    },
    ShieldedMarketConfigured {
        market_id: String,
    },
    ShieldedDepositCommitted(DepositReceipt),
    ShieldedSpendApplied(ProtocolSpendReceipt),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineState {
    #[serde(default = "default_chain_id")]
    pub chain_id: String,
    #[serde(default)]
    pub authority: AccountId,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u16,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub block_time_ms: i64,
    #[serde(default)]
    pub account_nonces: OrdMap<AccountId, u64>,
    pub markets: OrdMap<Symbol, MarketState>,
    pub accounts: OrdMap<AccountId, Account>,
    pub books: OrdMap<Symbol, OrderBook>,
    pub order_market: OrdMap<Uuid, Symbol>,
    pub client_order_ids: OrdMap<String, Uuid>,
    pub sequence: u64,
    #[serde(default)]
    pub total_credits: Decimal,
    #[serde(default)]
    pub fee_vault: Decimal,
    pub insurance_fund: Decimal,
    pub funding_pool: Decimal,
    #[serde(default)]
    pub oracle: OrdMap<Symbol, OracleSnapshot>,
    #[serde(default)]
    pub private_order_key_set: Option<ThresholdPublicKeySet>,
    #[serde(default)]
    pub private_validator_bindings: OrdMap<String, u16>,
    #[serde(default)]
    pub pending_private_orders: OrdMap<u64, Vec<PrivateOrderSubmission>>,
    #[serde(default)]
    pub private_order_bonds: OrdMap<u64, OrdMap<AccountId, Decimal>>,
    #[serde(default)]
    pub private_batch_app_hashes: OrdMap<u64, [u8; 32]>,
    #[serde(default)]
    pub private_batch_snapshots: OrdMap<u64, PrivateBatchSnapshot>,
    #[serde(default = "default_private_order_fee")]
    pub private_order_fee: Decimal,
    #[serde(default)]
    pub shielded_ledger: Option<DevelopmentShieldedLedger>,
    pub event_log: EventLog,
}

impl EngineState {
    pub fn genesis(chain_id: impl Into<String>, markets: Vec<MarketState>) -> Self {
        let markets: OrdMap<Symbol, MarketState> = markets
            .into_iter()
            .map(|market| (market.config.symbol.clone(), market))
            .collect();
        let books: OrdMap<Symbol, OrderBook> = markets
            .keys()
            .map(|symbol| (symbol.clone(), OrderBook::default()))
            .collect();
        Self {
            chain_id: chain_id.into(),
            authority: String::new(),
            protocol_version: default_protocol_version(),
            height: 0,
            block_time_ms: 0,
            account_nonces: OrdMap::new(),
            markets,
            accounts: OrdMap::new(),
            books,
            order_market: OrdMap::new(),
            client_order_ids: OrdMap::new(),
            sequence: 0,
            total_credits: Decimal::ZERO,
            fee_vault: Decimal::ZERO,
            insurance_fund: Decimal::ZERO,
            funding_pool: Decimal::ZERO,
            oracle: OrdMap::new(),
            private_order_key_set: None,
            private_validator_bindings: OrdMap::new(),
            pending_private_orders: OrdMap::new(),
            private_order_bonds: OrdMap::new(),
            private_batch_app_hashes: OrdMap::new(),
            private_batch_snapshots: OrdMap::new(),
            private_order_fee: default_private_order_fee(),
            shielded_ledger: None,
            event_log: EventLog::default(),
        }
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("consensus event sequence exhausted");
        self.sequence
    }

    fn append_event(&mut self, kind: EventKind) -> Event {
        let sequence = self.next_sequence();
        self.append_event_at(sequence, kind)
    }

    fn append_event_at(&mut self, sequence: u64, kind: EventKind) -> Event {
        self.event_log.append(sequence, self.consensus_time(), kind)
    }

    fn consensus_time(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.block_time_ms).unwrap_or(DateTime::UNIX_EPOCH)
    }
}

fn default_chain_id() -> String {
    "asteria-standalone".into()
}

fn default_protocol_version() -> u16 {
    5
}

fn default_private_order_fee() -> Decimal {
    dec!(0.01)
}

const MIN_PRIVATE_ORDER_BOND: Decimal = dec!(100);

#[derive(Debug, Clone)]
pub struct ApplyContext {
    pub height: u64,
    pub block_time_ms: i64,
    pub tx_index: u32,
    pub tx_hash: [u8; 32],
    next_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivateBatchExecution {
    pub batch_height: u64,
    pub markets: Vec<PrivateMarketExecution>,
    pub valid_orders: usize,
    pub invalid_orders: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivateMarketExecution {
    pub market_id: Symbol,
    pub clearing_price: Option<Decimal>,
    pub matched_quantity: Decimal,
    pub valid_orders: usize,
    pub invalid_orders: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivateBatchSnapshot {
    pub batch_height: u64,
    pub markets: OrdMap<Symbol, PrivateMarketSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivateMarketSnapshot {
    pub reference_price: Decimal,
    pub public_orders: Vec<Order>,
}

impl ApplyContext {
    pub fn new(height: u64, block_time_ms: i64, tx_index: u32, tx_hash: [u8; 32]) -> Self {
        Self {
            height,
            block_time_ms,
            tx_index,
            tx_hash,
            next_ordinal: 0,
        }
    }

    fn next_uuid(&mut self, domain: &[u8]) -> Uuid {
        let ordinal = self.next_ordinal;
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .expect("transaction UUID ordinal exhausted");
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(self.tx_hash);
        hasher.update(ordinal.to_be_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }
}

pub struct Engine {
    state: EngineState,
    store: Option<StateStore>,
    events: broadcast::Sender<Event>,
}

impl Engine {
    pub fn in_memory(markets: Vec<MarketState>) -> Self {
        let (events, _) = broadcast::channel(4_096);
        Self {
            state: EngineState::genesis("asteria-standalone", markets),
            store: None,
            events,
        }
    }

    pub fn open(store: StateStore, default_markets: Vec<MarketState>) -> Result<Self> {
        let state = match store.load_state()? {
            Some(stored) => {
                let previous = stored.state;
                let mut state = previous.clone();
                for market in default_markets {
                    let symbol = market.config.symbol.clone();
                    state.markets.entry(symbol.clone()).or_insert(market);
                    state.books.entry(symbol).or_default();
                }
                if state != previous {
                    store.commit_state(Some(&previous), &state)?;
                }
                state
            }
            None => {
                let state = EngineState::genesis("asteria-standalone", default_markets);
                store.commit_state(None, &state)?;
                state
            }
        };
        if !state.event_log.verify() {
            return Err(ExchangeError::Persistence(
                "persisted event hash chain is invalid".into(),
            ));
        }
        let (events, _) = broadcast::channel(4_096);
        Ok(Self {
            state,
            store: Some(store),
            events,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn state(&self) -> &EngineState {
        &self.state
    }

    pub fn credit_account(&mut self, account_id: AccountId, amount: Decimal) -> Result<Account> {
        self.transaction(|state| credit_account_state(state, account_id, amount))
    }

    pub fn set_mark_price(&mut self, symbol: &str, mark_price: Decimal) -> Result<MarketState> {
        if mark_price <= Decimal::ZERO {
            return Err(ExchangeError::InvalidOrder(
                "mark price must be positive".into(),
            ));
        }
        self.transaction(|state| {
            validate_mark_price_for_frozen_batches(state, symbol, mark_price)?;
            let market = state
                .markets
                .get_mut(symbol)
                .ok_or_else(|| ExchangeError::MarketNotFound(symbol.into()))?;
            market.mark_price = mark_price;
            let result = market.clone();
            state.append_event(EventKind::MarkPriceUpdated {
                symbol: symbol.into(),
                mark_price,
            });
            revalidate_resting_orders_after_mark_change(state, symbol)?;
            Ok(result)
        })
    }

    pub fn publish_oracle_price(
        &mut self,
        symbol: &str,
        observations: Vec<OracleObservation>,
    ) -> Result<OracleSnapshot> {
        self.transaction(|state| {
            if !state.markets.contains_key(symbol) {
                return Err(ExchangeError::MarketNotFound(symbol.into()));
            }
            validate_observations(&observations)?;
            let price = weighted_median(&observations);
            let min_price = observations
                .iter()
                .map(|observation| observation.price)
                .min()
                .expect("validated observations");
            let max_price = observations
                .iter()
                .map(|observation| observation.price)
                .max()
                .expect("validated observations");
            if (max_price - min_price) / price > dec!(0.05) {
                return Err(ExchangeError::InvalidOrder(
                    "oracle source spread exceeds 5%".into(),
                ));
            }

            validate_mark_price_for_frozen_batches(state, symbol, price)?;

            state
                .markets
                .get_mut(symbol)
                .expect("market exists")
                .mark_price = price;
            let sequence = state.next_sequence();
            let snapshot = OracleSnapshot {
                symbol: symbol.into(),
                price,
                observations,
                sequence,
            };
            state.oracle.insert(symbol.into(), snapshot.clone());
            state.append_event_at(
                sequence,
                EventKind::OraclePricePublished {
                    snapshot: snapshot.clone(),
                },
            );
            revalidate_resting_orders_after_mark_change(state, symbol)?;
            Ok(snapshot)
        })
    }

    pub fn submit_order(&mut self, request: NewOrder) -> Result<OrderResult> {
        self.transaction(|state| {
            let mut context = local_context(state, b"order", &request);
            submit_order(state, request, &mut context)
        })
    }

    pub fn cancel_order(&mut self, account_id: &str, order_id: Uuid) -> Result<Order> {
        self.transaction(|state| {
            reject_locked_order_cancellation(state, order_id, account_id)?;
            let symbol = state
                .order_market
                .get(&order_id)
                .cloned()
                .ok_or(ExchangeError::OrderNotFound(order_id))?;
            let cancelled = state
                .books
                .get_mut(&symbol)
                .expect("market book exists")
                .cancel(order_id, account_id)?;
            release_margin(state, &cancelled.account_id, cancelled.reserved_margin)?;
            remove_order_indices(state, &cancelled);
            state.append_event(EventKind::OrderCancelled {
                order_id,
                account_id: account_id.into(),
                reason: "user_request".into(),
            });
            let mut result = cancelled;
            result.reserved_margin = Decimal::ZERO;
            Ok(result)
        })
    }

    pub fn liquidate(&mut self, account_id: &str, symbol: &str) -> Result<LiquidationResult> {
        let account_id = account_id.to_owned();
        let symbol = symbol.to_owned();
        self.transaction(|state| {
            let mut context = local_context(state, b"liquidation", &(&account_id, &symbol));
            liquidate_account(state, &account_id, &symbol, &mut context)
        })
    }

    pub fn apply_funding(&mut self, symbol: &str, rate: Decimal) -> Result<(Decimal, Decimal)> {
        self.transaction(|state| apply_funding_state(state, symbol, rate))
    }

    pub fn account(&self, account_id: &str) -> Result<Account> {
        self.state
            .accounts
            .get(account_id)
            .cloned()
            .ok_or_else(|| ExchangeError::AccountNotFound(account_id.into()))
    }

    pub fn risk(&self, account_id: &str) -> Result<RiskSnapshot> {
        let account = self
            .state
            .accounts
            .get(account_id)
            .ok_or_else(|| ExchangeError::AccountNotFound(account_id.into()))?;
        account.risk_snapshot(self.state.markets.iter())
    }

    pub fn liquidation_candidates(&self) -> Result<Vec<RiskSnapshot>> {
        let snapshots = self
            .state
            .accounts
            .values()
            .map(|account| account.risk_snapshot(self.state.markets.iter()))
            .collect::<Result<Vec<_>>>()?;
        Ok(snapshots
            .into_iter()
            .filter(|risk| risk.liquidation_risk)
            .collect())
    }

    pub fn book(&self, symbol: &str, depth: usize) -> Result<BookSnapshot> {
        let book = self
            .state
            .books
            .get(symbol)
            .ok_or_else(|| ExchangeError::MarketNotFound(symbol.into()))?;
        Ok(book.snapshot(symbol.into(), self.state.sequence, depth.min(100)))
    }

    pub fn events_after(&self, sequence: u64, limit: usize) -> Vec<Event> {
        self.state.event_log.after(sequence, limit.min(1_000))
    }

    pub fn audit(&self) -> AuditReport {
        audit_state(&self.state)
    }

    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut EngineState) -> Result<T>,
    ) -> Result<T> {
        let previous = self.state.clone();
        let previous_sequence = previous.sequence;
        let result = match operation(&mut self.state) {
            Ok(result) => result,
            Err(error) => {
                self.state = previous;
                return Err(error);
            }
        };

        if let Some(store) = &self.store
            && let Err(error) = store.commit_state(Some(&previous), &self.state)
        {
            self.state = previous;
            return Err(error);
        }
        for event in self.state.event_log.after(previous_sequence, usize::MAX) {
            let _ = self.events.send(event);
        }
        Ok(result)
    }
}

pub fn apply_consensus_command(
    state: &mut EngineState,
    signer: &str,
    authority: &str,
    command: &Command,
    mut context: ApplyContext,
) -> Result<CommandResult> {
    let previous = state.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        state.height = context.height;
        state.block_time_ms = context.block_time_ms;
        (|| match command {
            Command::PlaceOrder { intent } => submit_order(
                state,
                NewOrder {
                    account_id: signer.into(),
                    intent: intent.clone(),
                },
                &mut context,
            )
            .map(CommandResult::OrderPlaced),
            Command::CancelOrder { order_id } => {
                reject_locked_order_cancellation(state, *order_id, signer)?;
                let symbol = state
                    .order_market
                    .get(order_id)
                    .cloned()
                    .ok_or(ExchangeError::OrderNotFound(*order_id))?;
                let cancelled = state
                    .books
                    .get_mut(&symbol)
                    .expect("market book exists")
                    .cancel(*order_id, signer)?;
                release_margin(state, &cancelled.account_id, cancelled.reserved_margin)?;
                remove_order_indices(state, &cancelled);
                state.append_event(EventKind::OrderCancelled {
                    order_id: *order_id,
                    account_id: signer.into(),
                    reason: "user_request".into(),
                });
                let mut result = cancelled;
                result.reserved_margin = Decimal::ZERO;
                Ok(CommandResult::OrderCancelled(result))
            }
            Command::CreditAccount { account_id, amount } => {
                require_authority(signer, authority)?;
                credit_account_state(state, account_id.clone(), *amount)
                    .map(CommandResult::AccountCredited)
            }
            Command::PublishOraclePrice {
                symbol,
                observations,
            } => {
                require_authority(signer, authority)?;
                if !state.markets.contains_key(symbol) {
                    return Err(ExchangeError::MarketNotFound(symbol.clone()));
                }
                validate_observations(observations)?;
                let price = weighted_median(observations);
                let min_price = observations
                    .iter()
                    .map(|observation| observation.price)
                    .min()
                    .expect("validated observations");
                let max_price = observations
                    .iter()
                    .map(|observation| observation.price)
                    .max()
                    .expect("validated observations");
                if (max_price - min_price) / price > dec!(0.05) {
                    return Err(ExchangeError::InvalidOrder(
                        "oracle source spread exceeds 5%".into(),
                    ));
                }
                validate_mark_price_for_frozen_batches(state, symbol, price)?;
                state
                    .markets
                    .get_mut(symbol)
                    .expect("market exists")
                    .mark_price = price;
                let sequence = state.next_sequence();
                let snapshot = OracleSnapshot {
                    symbol: symbol.clone(),
                    price,
                    observations: observations.clone(),
                    sequence,
                };
                state.oracle.insert(symbol.clone(), snapshot.clone());
                state.append_event_at(
                    sequence,
                    EventKind::OraclePricePublished {
                        snapshot: snapshot.clone(),
                    },
                );
                revalidate_resting_orders_after_mark_change(state, symbol)?;
                Ok(CommandResult::OraclePublished(snapshot))
            }
            Command::ApplyFunding { symbol, rate } => {
                require_authority(signer, authority)?;
                apply_funding_state(state, symbol, *rate).map(|(funding_index, funding_pool)| {
                    CommandResult::FundingApplied {
                        funding_index,
                        funding_pool,
                    }
                })
            }
            Command::Liquidate { account_id, symbol } => {
                require_authority(signer, authority)?;
                liquidate_account(state, account_id, symbol, &mut context)
                    .map(CommandResult::LiquidationExecuted)
            }
            Command::SubmitPrivateOrder { submission } => {
                queue_private_order(state, signer, submission, context.height)
            }
            Command::ConfigureShieldedMarket { policy } => {
                require_authority(signer, authority)?;
                configure_shielded_market(state, *policy)
            }
            Command::ShieldedDeposit { deposit } => shielded_deposit(state, deposit),
            Command::ShieldedSpend { spend } => shielded_spend(state, spend),
        })()
    }));

    match result {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => {
            *state = previous;
            Err(error)
        }
        Err(_) => {
            *state = previous;
            Err(ExchangeError::Internal(
                "consensus command aborted because arithmetic exceeded protocol bounds".into(),
            ))
        }
    }
}

fn configure_shielded_market(
    state: &mut EngineState,
    policy: MarginPolicy,
) -> Result<CommandResult> {
    let ledger = state.shielded_ledger.as_mut().ok_or_else(|| {
        ExchangeError::InvalidOrder("shielded development ledger is not enabled".into())
    })?;
    ledger
        .register_market(policy)
        .map_err(|error| ExchangeError::InvalidOrder(error.to_string()))?;
    let market_id = hex::encode(policy.market_id.0);
    state.append_event(EventKind::ShieldedMarketConfigured {
        market_id: market_id.clone(),
    });
    Ok(CommandResult::ShieldedMarketConfigured { market_id })
}

fn shielded_deposit(state: &mut EngineState, deposit: &AuthorityDeposit) -> Result<CommandResult> {
    let receipt = state
        .shielded_ledger
        .as_mut()
        .ok_or_else(|| {
            ExchangeError::InvalidOrder("shielded development ledger is not enabled".into())
        })?
        .authority_deposit(deposit, &TransparentDepositVerifier)
        .map_err(|error| ExchangeError::InvalidOrder(error.to_string()))?;
    let backing = shielded_atomic_decimal(receipt.backing_amount)?;
    state.total_credits = state
        .total_credits
        .checked_add(backing)
        .ok_or_else(|| arithmetic_overflow("shielded deposit credits"))?;
    state.append_event(EventKind::ShieldedDepositCommitted {
        market_id: hex::encode(deposit.statement.note.market_id.0),
        leaf_index: receipt.leaf_index,
        backing_amount: receipt.backing_amount,
        new_root: hex::encode(receipt.new_root),
    });
    Ok(CommandResult::ShieldedDepositCommitted(receipt))
}

fn shielded_spend(state: &mut EngineState, spend: &ShieldedSpend) -> Result<CommandResult> {
    let receipt = state
        .shielded_ledger
        .as_mut()
        .ok_or_else(|| {
            ExchangeError::InvalidOrder("shielded development ledger is not enabled".into())
        })?
        .apply_spend(spend, &TransparentWitnessVerifier)
        .map_err(|error| ExchangeError::InvalidOrder(error.to_string()))?;
    let fee = shielded_atomic_decimal(receipt.state_receipt.fee)?;
    state.fee_vault = state
        .fee_vault
        .checked_add(fee)
        .ok_or_else(|| arithmetic_overflow("shielded spend fee vault"))?;
    state.append_event(EventKind::ShieldedSpendApplied {
        market_id: hex::encode(spend.statement.market_id.0),
        nullifier_count: spend.statement.nullifiers.len(),
        output_count: spend.statement.output_commitments.len(),
        fee: receipt.state_receipt.fee,
        new_root: hex::encode(receipt.state_receipt.new_root),
    });
    Ok(CommandResult::ShieldedSpendApplied(receipt))
}

fn shielded_atomic_decimal(amount: u64) -> Result<Decimal> {
    Ok(Decimal::from_i128_with_scale(i128::from(amount), 8))
}

fn queue_private_order(
    state: &mut EngineState,
    signer: &str,
    submission: &PrivateOrderSubmission,
    block_height: u64,
) -> Result<CommandResult> {
    let key_set = state.private_order_key_set.as_ref().ok_or_else(|| {
        ExchangeError::InvalidOrder("private-order markets are not enabled".into())
    })?;
    let account_id = account_id_from_signer(&submission.envelope.header.fee_payer);
    if account_id != signer {
        return Err(ExchangeError::Unauthorized);
    }
    let expected_nonce = state.account_nonces.get(signer).copied().unwrap_or(0);
    let context = verify_submission(
        submission,
        &state.chain_id,
        expected_nonce,
        block_height,
        block_height,
        key_set,
    )
    .map_err(|error| ExchangeError::InvalidOrder(error.to_string()))?;
    if !state.markets.contains_key(&context.market_id) {
        return Err(ExchangeError::MarketNotFound(context.market_id));
    }
    if state.private_order_fee <= Decimal::ZERO {
        return Err(ExchangeError::Internal(
            "private-order fee must be positive".into(),
        ));
    }
    let pending = state.pending_private_orders.get(&block_height);
    let pending_len = pending.map_or(0, Vec::len);
    if pending_len >= MAX_PENDING_PRIVATE_ORDERS {
        return Err(ExchangeError::InvalidOrder(format!(
            "private-order batch is limited to {MAX_PENDING_PRIVATE_ORDERS} submissions"
        )));
    }
    if pending
        .into_iter()
        .flatten()
        .any(|queued| queued.envelope.header.fee_payer == submission.envelope.header.fee_payer)
    {
        return Err(ExchangeError::InvalidOrder(
            "an account may submit only one private order per batch".into(),
        ));
    }
    let submission_id = submission
        .submission_id()
        .map_err(|error| ExchangeError::InvalidOrder(error.to_string()))?;
    if pending.into_iter().flatten().any(|queued| {
        queued
            .submission_id()
            .is_ok_and(|queued_id| queued_id == submission_id)
    }) {
        return Err(ExchangeError::InvalidOrder(
            "private-order submission is already queued".into(),
        ));
    }

    let available = state
        .accounts
        .get(signer)
        .ok_or_else(|| ExchangeError::AccountNotFound(signer.into()))?
        .risk_snapshot(state.markets.iter())?
        .available_margin;
    let required = state
        .private_order_fee
        .checked_add(MIN_PRIVATE_ORDER_BOND)
        .ok_or_else(|| arithmetic_overflow("private-order fee and bond"))?;
    if available < required {
        return Err(ExchangeError::InsufficientMargin {
            required: required.to_string(),
            available: available.to_string(),
        });
    }
    let bond = available
        .checked_sub(state.private_order_fee)
        .ok_or_else(|| arithmetic_overflow("private-order bond"))?;
    {
        let account = state
            .accounts
            .get_mut(signer)
            .expect("private-order fee payer exists");
        account.collateral = account
            .collateral
            .checked_sub(state.private_order_fee)
            .ok_or_else(|| arithmetic_overflow("private-order account fee"))?;
        account.fees_paid = account
            .fees_paid
            .checked_add(state.private_order_fee)
            .ok_or_else(|| arithmetic_overflow("private-order paid fees"))?;
        account.reserved_margin = account
            .reserved_margin
            .checked_add(bond)
            .ok_or_else(|| arithmetic_overflow("private-order account bond"))?;
    }
    state.fee_vault = state
        .fee_vault
        .checked_add(state.private_order_fee)
        .ok_or_else(|| arithmetic_overflow("private-order fee vault"))?;
    if state
        .private_order_bonds
        .entry(block_height)
        .or_default()
        .insert(account_id.clone(), bond)
        .is_some()
    {
        return Err(ExchangeError::Internal(
            "private-order bond already exists for this account and height".into(),
        ));
    }
    let pending = state
        .pending_private_orders
        .entry(block_height)
        .or_default();
    pending.push(submission.clone());
    pending.sort_by_cached_key(|queued| queued.submission_id().unwrap_or([0; 32]));
    let submission_id = hex::encode(submission_id);
    state.append_event(EventKind::PrivateOrderQueued {
        submission_id: submission_id.clone(),
        account_id,
        market_id: context.market_id,
        batch_height: block_height,
        fee: state.private_order_fee,
        bond,
    });
    Ok(CommandResult::PrivateOrderQueued {
        submission_id,
        batch_height: block_height,
        fee: state.private_order_fee,
        bond,
    })
}

pub fn freeze_private_batch_liquidity(state: &mut EngineState, batch_height: u64) -> Result<()> {
    let Some(pending) = state
        .pending_private_orders
        .get(&batch_height)
        .filter(|pending| !pending.is_empty())
    else {
        return Ok(());
    };
    if state.private_batch_snapshots.contains_key(&batch_height) {
        return Err(ExchangeError::Internal(format!(
            "private batch liquidity is already frozen for height {batch_height}"
        )));
    }

    let market_ids = pending
        .iter()
        .map(|submission| submission.envelope.header.market_id.clone())
        .collect::<BTreeSet<_>>();
    let mut markets = OrdMap::new();
    for market_id in market_ids {
        let market = state
            .markets
            .get(&market_id)
            .cloned()
            .ok_or_else(|| ExchangeError::MarketNotFound(market_id.clone()))?;
        let reference_price = market.mark_price;
        let active_orders = state
            .books
            .get_mut(&market_id)
            .ok_or_else(|| ExchangeError::MarketNotFound(market_id.clone()))?
            .take_active_orders();
        let mut public_orders = Vec::new();
        let mut live_orders = Vec::new();
        for mut order in active_orders {
            if order.reduce_only {
                live_orders.push(order);
                continue;
            }
            let required = frozen_order_reservation(&order, &market)?;
            let top_up = required
                .checked_sub(order.reserved_margin)
                .unwrap_or(Decimal::ZERO);
            if top_up > Decimal::ZERO {
                let available = state
                    .accounts
                    .get(&order.account_id)
                    .ok_or_else(|| ExchangeError::AccountNotFound(order.account_id.clone()))?
                    .risk_snapshot(state.markets.iter())?
                    .available_margin;
                if available < top_up {
                    live_orders.push(order);
                    continue;
                }
                let account = state
                    .accounts
                    .get_mut(&order.account_id)
                    .expect("frozen order account exists");
                account.reserved_margin = account
                    .reserved_margin
                    .checked_add(top_up)
                    .ok_or_else(|| arithmetic_overflow("frozen order reservation"))?;
                order.reserved_margin = required;
            }
            public_orders.push(order);
        }
        let book = state
            .books
            .get_mut(&market_id)
            .expect("private batch market book exists");
        for order in live_orders {
            book.restore_active_order(order)?;
        }
        public_orders.sort_by_key(|order| (order.sequence, order.id));
        markets.insert(
            market_id,
            PrivateMarketSnapshot {
                reference_price,
                public_orders,
            },
        );
    }
    state.private_batch_snapshots.insert(
        batch_height,
        PrivateBatchSnapshot {
            batch_height,
            markets,
        },
    );
    Ok(())
}

pub fn execute_private_decryption_bundle(
    state: &mut EngineState,
    bundle: &DecryptionBundle,
    execution_height: u64,
    tx_hash: [u8; 32],
) -> Result<PrivateBatchExecution> {
    let batch_height = bundle.height;
    if batch_height.checked_add(crate::private_protocol::PRIVATE_ORDER_DECRYPTION_DELAY_BLOCKS)
        != Some(execution_height)
    {
        return Err(ExchangeError::InvalidOrder(format!(
            "private decryption for height {batch_height} must execute at height {execution_height}"
        )));
    }
    let key_set = state.private_order_key_set.clone().ok_or_else(|| {
        ExchangeError::InvalidOrder("private-order markets are not enabled".into())
    })?;
    let pending = state
        .pending_private_orders
        .get(&batch_height)
        .cloned()
        .ok_or_else(|| {
            ExchangeError::InvalidOrder(format!(
                "no pending private-order batch at height {batch_height}"
            ))
        })?;
    let batch_app_hash = *state
        .private_batch_app_hashes
        .get(&batch_height)
        .ok_or_else(|| {
            ExchangeError::InvalidOrder(format!(
                "private-order batch at height {batch_height} has no committed app-hash anchor"
            ))
        })?;
    let batch_snapshot = state
        .private_batch_snapshots
        .get(&batch_height)
        .cloned()
        .ok_or_else(|| {
            ExchangeError::InvalidOrder(format!(
                "private-order batch at height {batch_height} has no frozen liquidity snapshot"
            ))
        })?;
    if batch_snapshot.batch_height != batch_height {
        return Err(ExchangeError::Internal(
            "private batch liquidity snapshot height mismatch".into(),
        ));
    }
    let outcomes = validate_and_decrypt_bundle(
        &state.chain_id,
        batch_height,
        batch_app_hash,
        &key_set,
        &pending,
        bundle,
    )
    .map_err(|error| ExchangeError::InvalidOrder(error.to_string()))?;
    let bonds = state
        .private_order_bonds
        .get(&batch_height)
        .cloned()
        .ok_or_else(|| {
            ExchangeError::InvalidOrder(format!(
                "private-order batch at height {batch_height} has no collateral bonds"
            ))
        })?;
    if bonds.len() != pending.len() {
        return Err(ExchangeError::Internal(
            "private-order bond set does not match the pending batch".into(),
        ));
    }
    for submission in &pending {
        let account_id = account_id_from_signer(&submission.envelope.header.fee_payer);
        let bond = bonds.get(&account_id).copied().ok_or_else(|| {
            ExchangeError::Internal("pending private order has no collateral bond".into())
        })?;
        if bond < MIN_PRIVATE_ORDER_BOND {
            return Err(ExchangeError::Internal(
                "pending private-order collateral bond is below the protocol minimum".into(),
            ));
        }
        release_margin(state, &account_id, bond)?;
    }

    let mut invalid = Vec::new();
    let mut by_market: BTreeMap<Symbol, Vec<BatchParticipant>> = BTreeMap::new();
    for outcome in outcomes {
        match outcome {
            PrivateOrderDecryptionOutcome::Invalid {
                submission_id,
                reason,
                ..
            } => invalid.push((submission_id, format!("{reason:?}"))),
            PrivateOrderDecryptionOutcome::Valid(order) => {
                let Some(market_snapshot) = batch_snapshot.markets.get(&order.market_id) else {
                    invalid.push((
                        order.submission_id,
                        "private order market is absent from the committed batch snapshot".into(),
                    ));
                    continue;
                };
                match private_participant(state, &order, market_snapshot.reference_price) {
                    Ok(participant) => by_market
                        .entry(order.market_id)
                        .or_default()
                        .push(participant),
                    Err(error) => invalid.push((order.submission_id, error.to_string())),
                }
            }
        }
    }

    let mut jobs = Vec::with_capacity(by_market.len());
    let mut public_order_ids = BTreeMap::new();
    let mut escrow_books = BTreeMap::new();
    for (market_id, market_snapshot) in &batch_snapshot.markets {
        let mut book = OrderBook::default();
        for order in &market_snapshot.public_orders {
            book.restore_active_order(order.clone())?;
        }
        escrow_books.insert(market_id.clone(), book);
    }
    for (market_id, book) in &mut escrow_books {
        remove_ineligible_frozen_orders(state, market_id, book)?;
    }
    for (market_id, mut participants) in by_market {
        let private_accounts = participants
            .iter()
            .map(|participant| participant.account_id.clone())
            .collect::<BTreeSet<_>>();
        let market = state
            .markets
            .get(&market_id)
            .ok_or_else(|| ExchangeError::MarketNotFound(market_id.clone()))?;
        let market_snapshot = batch_snapshot
            .markets
            .get(&market_id)
            .ok_or_else(|| ExchangeError::MarketNotFound(market_id.clone()))?;
        let book = escrow_books
            .get(&market_id)
            .ok_or_else(|| ExchangeError::MarketNotFound(market_id.clone()))?;
        for order in book.active_orders() {
            if private_accounts.contains(&order.account_id) {
                continue;
            }
            let order_id = public_batch_order_id(order.id);
            public_order_ids.insert(order_id, order.id);
            participants.push(BatchParticipant {
                visibility: ParticipantVisibility::Public,
                account_id: order.account_id,
                order_id,
                side: order.side,
                kind: order.kind,
                time_in_force: order.time_in_force,
                quantity: order.remaining,
                limit_price: Some(order.limit_price),
                leverage: order.leverage,
                reduce_only: order.reduce_only,
            });
        }
        participants.sort_by_key(|participant| participant.order_id);
        jobs.push((
            market_id,
            market.config.clone(),
            market_snapshot.reference_price,
            participants,
        ));
    }

    let chain_id = state.chain_id.clone();
    let cleared = jobs
        .par_iter()
        .map(|(market_id, config, mark_price, participants)| {
            clear_private_batch(
                config,
                &BatchContext {
                    chain_id: chain_id.clone(),
                    height: batch_height,
                    threshold_beacon: bundle.beacon_output,
                    reference_price: *mark_price,
                },
                participants,
            )
            .map(|outcome| (market_id.clone(), outcome))
            .map_err(|error| ExchangeError::InvalidOrder(error.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut context = ApplyContext::new(execution_height, state.block_time_ms, 0, tx_hash);
    let mut market_results = Vec::with_capacity(cleared.len());
    let mut valid_orders = 0_usize;
    for (market_id, outcome) in cleared {
        let private_count = outcome
            .allocations
            .iter()
            .filter(|allocation| {
                matches!(
                    allocation.participant.visibility,
                    ParticipantVisibility::Private { .. }
                )
            })
            .count();
        valid_orders = valid_orders
            .checked_add(private_count)
            .ok_or_else(|| arithmetic_overflow("private-order valid count"))?;
        let escrow_book = escrow_books
            .get_mut(&market_id)
            .expect("private batch escrow book exists");
        settle_private_market(
            state,
            &market_id,
            &outcome,
            &public_order_ids,
            escrow_book,
            &mut context,
        )?;
        let market_invalid = invalid
            .iter()
            .filter(|(submission_id, _)| {
                pending.iter().any(|submission| {
                    submission.envelope.header.market_id == market_id
                        && submission
                            .submission_id()
                            .is_ok_and(|id| id == *submission_id)
                })
            })
            .count();
        state.append_event(EventKind::PrivateBatchCleared {
            market_id: market_id.clone(),
            batch_height,
            clearing_price: outcome.clearing_price,
            matched_quantity: outcome.matched_quantity,
            valid_orders: private_count,
            invalid_orders: market_invalid,
        });
        market_results.push(PrivateMarketExecution {
            market_id,
            clearing_price: outcome.clearing_price,
            matched_quantity: outcome.matched_quantity,
            valid_orders: private_count,
            invalid_orders: market_invalid,
        });
    }
    for (submission_id, reason) in &invalid {
        state.append_event(EventKind::PrivateOrderInvalid {
            submission_id: hex::encode(submission_id),
            reason: reason.clone(),
        });
    }
    for (market_id, mut escrow_book) in escrow_books {
        restore_private_batch_orders(state, &market_id, &mut escrow_book, &mut context)?;
    }
    state.pending_private_orders.remove(&batch_height);
    state.private_order_bonds.remove(&batch_height);
    state.private_batch_app_hashes.remove(&batch_height);
    state.private_batch_snapshots.remove(&batch_height);
    Ok(PrivateBatchExecution {
        batch_height,
        markets: market_results,
        valid_orders,
        invalid_orders: invalid.len(),
    })
}

fn frozen_order_reservation(order: &Order, market: &MarketState) -> Result<Decimal> {
    let (lower_mark, upper_mark) = mark_price_band(market)?;
    let mut worst_case_market = market.clone();
    worst_case_market.mark_price = match order.side {
        Side::Buy => lower_mark,
        Side::Sell => upper_mark,
    };
    required_order_reservation(
        order.side,
        order.remaining,
        order.limit_price,
        order.leverage,
        order.reduce_only,
        &worst_case_market,
    )
}

fn remove_ineligible_frozen_orders(
    state: &mut EngineState,
    market_id: &str,
    escrow_book: &mut OrderBook,
) -> Result<()> {
    let mut cancel = Vec::new();
    for order in escrow_book.active_orders() {
        let risk = state
            .accounts
            .get(&order.account_id)
            .ok_or_else(|| ExchangeError::AccountNotFound(order.account_id.clone()))?
            .risk_snapshot(state.markets.iter())?;
        if risk.available_margin < Decimal::ZERO {
            cancel.push((order.id, order.account_id));
        }
    }
    for (order_id, account_id) in cancel {
        let cancelled = escrow_book.cancel(order_id, &account_id)?;
        release_margin(state, &account_id, cancelled.reserved_margin)?;
        remove_order_indices(state, &cancelled);
        state.append_event(EventKind::OrderCancelled {
            order_id,
            account_id,
            reason: format!("private_batch_{market_id}_risk_revalidation"),
        });
    }
    Ok(())
}

fn restore_private_batch_orders(
    state: &mut EngineState,
    market_id: &str,
    escrow_book: &mut OrderBook,
    context: &mut ApplyContext,
) -> Result<()> {
    let market = state
        .markets
        .get(market_id)
        .cloned()
        .ok_or_else(|| ExchangeError::MarketNotFound(market_id.into()))?;
    let mut orders = state
        .books
        .get_mut(market_id)
        .ok_or_else(|| ExchangeError::MarketNotFound(market_id.into()))?
        .take_active_orders();

    for mut order in escrow_book.take_active_orders() {
        let required = validate_price_in_mark_band(order.limit_price, &market).and_then(|()| {
            required_order_reservation(
                order.side,
                order.remaining,
                order.limit_price,
                order.leverage,
                order.reduce_only,
                &market,
            )
        });
        let Ok(required) = required else {
            cancel_restored_order(state, &order, "private_batch_mark_revalidation")?;
            continue;
        };
        if order.reserved_margin < required {
            cancel_restored_order(state, &order, "private_batch_margin_revalidation")?;
            continue;
        }
        let excess = order
            .reserved_margin
            .checked_sub(required)
            .ok_or_else(|| arithmetic_overflow("restored order reservation"))?;
        release_margin(state, &order.account_id, excess)?;
        order.reserved_margin = required;
        orders.push(order);
    }

    orders.sort_by_key(|order| (order.sequence, order.id));
    let mut affected_accounts = BTreeSet::new();
    for order in orders {
        let execution = state
            .books
            .get_mut(market_id)
            .expect("restored market book exists")
            .execute(order);
        apply_execution(state, &market, &execution)?;
        affected_accounts.insert(execution.order.account_id.clone());
        for fill in &execution.fills {
            affected_accounts.insert(fill.maker_account_id.clone());
            affected_accounts.insert(fill.taker_account_id.clone());
            let trade = trade_from_fill(
                state,
                &market,
                fill,
                context.next_uuid(b"asteria/private-batch-restored-trade/v1"),
            )?;
            state.append_event(EventKind::TradeExecuted { trade });
        }
    }
    for account_id in &affected_accounts {
        reconcile_reduce_only_orders(state, account_id, market_id)?;
    }
    for account_id in &affected_accounts {
        ensure_account_has_nonnegative_available_margin(state, account_id)?;
    }
    Ok(())
}

fn cancel_restored_order(state: &mut EngineState, order: &Order, reason: &str) -> Result<()> {
    release_margin(state, &order.account_id, order.reserved_margin)?;
    remove_order_indices(state, order);
    state.append_event(EventKind::OrderCancelled {
        order_id: order.id,
        account_id: order.account_id.clone(),
        reason: reason.into(),
    });
    Ok(())
}

fn private_participant(
    state: &EngineState,
    order: &DecryptedPrivateOrder,
    reference_price: Decimal,
) -> Result<BatchParticipant> {
    let mut market = state
        .markets
        .get(&order.market_id)
        .cloned()
        .ok_or_else(|| ExchangeError::MarketNotFound(order.market_id.clone()))?;
    market.mark_price = reference_price;
    let account_id = account_id_from_signer(&order.fee_payer);
    let quantity = lots_to_quantity(order.payload.quantity_lots, &market.config)
        .map_err(|error| ExchangeError::InvalidOrder(error.to_string()))?;
    let (kind, price) = match order.payload.kind {
        PrivateOrderKind::Market => (OrderKind::Market, None),
        PrivateOrderKind::Limit => (
            OrderKind::Limit,
            Some(
                ticks_to_price(order.payload.price_ticks, &market.config)
                    .map_err(|error| ExchangeError::InvalidOrder(error.to_string()))?,
            ),
        ),
    };
    let time_in_force = if order.payload.fok {
        TimeInForce::Fok
    } else {
        TimeInForce::Ioc
    };
    let request = NewOrder {
        account_id: account_id.clone(),
        intent: crate::domain::OrderIntent {
            client_order_id: order.payload.client_id.clone(),
            symbol: order.market_id.clone(),
            side: match order.payload.side {
                PrivateOrderSide::Buy => Side::Buy,
                PrivateOrderSide::Sell => Side::Sell,
            },
            kind,
            quantity,
            price,
            leverage: order.payload.leverage,
            time_in_force,
            reduce_only: order.payload.reduce_only,
        },
    };
    validate_order(state, &request, &market)?;
    let limit_price = effective_limit_price(&request, &market)?;
    let (lower_mark, upper_mark) = mark_price_band(&market)?;
    let mut worst_case_market = market.clone();
    worst_case_market.mark_price = match request.intent.side {
        Side::Buy => lower_mark,
        Side::Sell => upper_mark,
    };
    let reserve = required_order_reservation(
        request.intent.side,
        quantity,
        limit_price,
        request.intent.leverage,
        request.intent.reduce_only,
        &worst_case_market,
    )?;
    let available = state
        .accounts
        .get(&account_id)
        .expect("validated private account")
        .risk_snapshot(state.markets.iter())?
        .available_margin;
    if available < reserve {
        return Err(ExchangeError::InsufficientMargin {
            required: reserve.to_string(),
            available: available.to_string(),
        });
    }
    Ok(BatchParticipant {
        visibility: ParticipantVisibility::Private {
            ciphertext_id: order.submission_id,
        },
        account_id,
        order_id: crate::batch_auction::OrderId(order.submission_id),
        side: request.intent.side,
        kind,
        time_in_force,
        quantity,
        limit_price: price,
        leverage: request.intent.leverage,
        reduce_only: request.intent.reduce_only,
    })
}

fn settle_private_market(
    state: &mut EngineState,
    market_id: &str,
    outcome: &PrivateBatchOutcome,
    public_order_ids: &BTreeMap<crate::batch_auction::OrderId, Uuid>,
    escrow_book: &mut OrderBook,
    context: &mut ApplyContext,
) -> Result<()> {
    let market = state
        .markets
        .get(market_id)
        .cloned()
        .ok_or_else(|| ExchangeError::MarketNotFound(market_id.into()))?;
    let clearing_price = outcome.clearing_price;
    for allocation in outcome
        .allocations
        .iter()
        .filter(|allocation| allocation.executed_lots > 0)
    {
        let price = clearing_price.ok_or_else(|| {
            ExchangeError::Internal("non-zero batch allocation has no clearing price".into())
        })?;
        let fee_rate = match allocation.participant.visibility {
            ParticipantVisibility::Public => market.config.maker_fee_rate,
            ParticipantVisibility::Private { .. } => market.config.taker_fee_rate,
        };
        if matches!(
            allocation.participant.visibility,
            ParticipantVisibility::Public
        ) {
            let order_id = *public_order_ids
                .get(&allocation.participant.order_id)
                .ok_or_else(|| ExchangeError::Internal("public batch order is unmapped".into()))?;
            let update = escrow_book.apply_batch_fill(order_id, allocation.executed_quantity)?;
            release_margin(state, &update.order.account_id, update.margin_release)?;
            if update.terminal {
                remove_order_indices(state, &update.order);
            }
        }
        apply_fill_to_account(
            state,
            &allocation.participant.account_id,
            market_id,
            allocation.participant.side,
            allocation.executed_quantity,
            price,
            allocation.participant.leverage,
            fee_rate,
        )?;
    }

    let allocation_by_id = outcome
        .allocations
        .iter()
        .map(|allocation| (allocation.participant.order_id, allocation))
        .collect::<BTreeMap<_, _>>();
    for fill in &outcome.fills {
        let buy = allocation_by_id[&fill.buy_order_id];
        let sell = allocation_by_id[&fill.sell_order_id];
        let buy_public = matches!(buy.participant.visibility, ParticipantVisibility::Public);
        let sell_public = matches!(sell.participant.visibility, ParticipantVisibility::Public);
        let (maker, taker, taker_side) = if buy_public && !sell_public {
            (buy, sell, Side::Sell)
        } else if sell_public && !buy_public {
            (sell, buy, Side::Buy)
        } else if fill.buy_order_id <= fill.sell_order_id {
            (buy, sell, Side::Sell)
        } else {
            (sell, buy, Side::Buy)
        };
        let fee_for = |participant: &BatchParticipant| -> Result<Decimal> {
            let rate = match participant.visibility {
                ParticipantVisibility::Public => market.config.maker_fee_rate,
                ParticipantVisibility::Private { .. } => market.config.taker_fee_rate,
            };
            fill.quantity
                .checked_mul(fill.price)
                .and_then(|notional| notional.checked_mul(rate))
                .ok_or_else(|| arithmetic_overflow("private batch trade fee"))
        };
        let trade = Trade {
            id: context.next_uuid(b"asteria/private-batch-trade/v1"),
            symbol: market_id.into(),
            price: fill.price,
            quantity: fill.quantity,
            maker_order_id: batch_order_uuid(maker.participant.order_id, public_order_ids),
            taker_order_id: batch_order_uuid(taker.participant.order_id, public_order_ids),
            maker_account_id: maker.participant.account_id.clone(),
            taker_account_id: taker.participant.account_id.clone(),
            taker_side,
            maker_fee: fee_for(&maker.participant)?,
            taker_fee: fee_for(&taker.participant)?,
            sequence: state
                .sequence
                .checked_add(1)
                .ok_or_else(|| arithmetic_overflow("private trade sequence"))?,
        };
        state.append_event(EventKind::TradeExecuted { trade });
    }
    let affected = outcome
        .allocations
        .iter()
        .filter(|allocation| allocation.executed_lots > 0)
        .map(|allocation| allocation.participant.account_id.clone())
        .collect::<BTreeSet<_>>();
    for account_id in affected {
        reconcile_reduce_only_orders(state, &account_id, market_id)?;
        ensure_account_has_nonnegative_available_margin(state, &account_id)?;
    }
    Ok(())
}

fn public_batch_order_id(order_id: Uuid) -> crate::batch_auction::OrderId {
    let mut hasher = Sha256::new();
    hasher.update(b"ASTERIA_PUBLIC_BATCH_ORDER_ID_V1\0");
    hasher.update(order_id.as_bytes());
    crate::batch_auction::OrderId(hasher.finalize().into())
}

fn batch_order_uuid(
    order_id: crate::batch_auction::OrderId,
    public_order_ids: &BTreeMap<crate::batch_auction::OrderId, Uuid>,
) -> Uuid {
    if let Some(order_id) = public_order_ids.get(&order_id) {
        return *order_id;
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&order_id.0[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

pub fn canonical_state_bytes(state: &EngineState) -> Result<Vec<u8>> {
    serde_jcs::to_vec(state).map_err(|error| ExchangeError::Internal(error.to_string()))
}

pub fn compute_app_hash(state: &EngineState) -> Result<[u8; 32]> {
    crate::state_commitment::compute_state_root(state)
}

pub fn audit_engine_state(state: &EngineState) -> AuditReport {
    audit_state(state)
}

pub fn prune_consensus_history(state: &mut EngineState) {
    let mut terminal_orders = Vec::new();
    let symbols = state.books.keys().cloned().collect::<Vec<_>>();
    for symbol in symbols {
        terminal_orders.extend(
            state
                .books
                .get_mut(&symbol)
                .expect("collected market book exists")
                .take_terminal_orders(),
        );
    }
    for order in terminal_orders {
        remove_order_indices(state, &order);
    }
    state.event_log.prune();
}

fn require_authority(signer: &str, authority: &str) -> Result<()> {
    if signer != authority {
        return Err(ExchangeError::Unauthorized);
    }
    Ok(())
}

fn arithmetic_overflow(field: &str) -> ExchangeError {
    ExchangeError::InvalidOrder(format!("numeric overflow while updating {field}"))
}

fn credit_account_state(
    state: &mut EngineState,
    account_id: AccountId,
    amount: Decimal,
) -> Result<Account> {
    if amount <= Decimal::ZERO {
        return Err(ExchangeError::InvalidOrder(
            "credit amount must be positive".into(),
        ));
    }
    let collateral = state
        .accounts
        .get(&account_id)
        .map(|account| account.collateral)
        .unwrap_or(Decimal::ZERO)
        .checked_add(amount)
        .ok_or_else(|| arithmetic_overflow("account collateral"))?;
    let total_credits = state
        .total_credits
        .checked_add(amount)
        .ok_or_else(|| arithmetic_overflow("total credits"))?;
    let account = state
        .accounts
        .entry(account_id.clone())
        .or_insert_with(|| Account::new(account_id.clone()));
    account.collateral = collateral;
    let result = account.clone();
    state.total_credits = total_credits;
    state.append_event(EventKind::AccountCredited { account_id, amount });
    Ok(result)
}

fn apply_funding_state(
    state: &mut EngineState,
    symbol: &str,
    rate: Decimal,
) -> Result<(Decimal, Decimal)> {
    if rate < -dec!(0.01) || rate > dec!(0.01) {
        return Err(ExchangeError::InvalidOrder(
            "absolute funding rate cannot exceed 1% per interval".into(),
        ));
    }
    let market = state
        .markets
        .get_mut(symbol)
        .ok_or_else(|| ExchangeError::MarketNotFound(symbol.into()))?;
    let index_delta = market
        .mark_price
        .checked_mul(rate)
        .ok_or_else(|| arithmetic_overflow("funding index delta"))?;
    market.funding_index = market
        .funding_index
        .checked_add(index_delta)
        .ok_or_else(|| arithmetic_overflow("funding index"))?;
    market.funding_rate = rate;
    let funding_index = market.funding_index;
    let funding_pool = state.funding_pool;
    state.append_event(EventKind::FundingApplied {
        symbol: symbol.into(),
        rate,
        funding_index,
        funding_pool,
    });
    Ok((funding_index, funding_pool))
}

fn submit_order(
    state: &mut EngineState,
    request: NewOrder,
    context: &mut ApplyContext,
) -> Result<OrderResult> {
    let market = state
        .markets
        .get(&request.intent.symbol)
        .cloned()
        .ok_or_else(|| ExchangeError::MarketNotFound(request.intent.symbol.clone()))?;
    validate_order(state, &request, &market)?;

    let client_key = format!("{}:{}", request.account_id, request.intent.client_order_id);
    if state.client_order_ids.contains_key(&client_key) {
        return Err(ExchangeError::DuplicateClientOrderId(
            request.intent.client_order_id,
        ));
    }

    let limit_price = effective_limit_price(&request, &market)?;
    let reserve = required_order_reservation(
        request.intent.side,
        request.intent.quantity,
        limit_price,
        request.intent.leverage,
        request.intent.reduce_only,
        &market,
    )?;
    let available = state
        .accounts
        .get(&request.account_id)
        .expect("validated account")
        .risk_snapshot(state.markets.iter())?
        .available_margin;
    if available < reserve {
        return Err(ExchangeError::InsufficientMargin {
            required: reserve.to_string(),
            available: available.to_string(),
        });
    }

    if request.intent.time_in_force == TimeInForce::Fok
        && !state.books[&request.intent.symbol].can_fully_fill(
            request.intent.side,
            limit_price,
            request.intent.quantity,
            &request.account_id,
        )
    {
        return Err(ExchangeError::CannotFullyFill);
    }

    let account = state
        .accounts
        .get_mut(&request.account_id)
        .expect("validated account");
    account.reserved_margin = account
        .reserved_margin
        .checked_add(reserve)
        .ok_or_else(|| arithmetic_overflow("account margin reservation"))?;
    let order_sequence = state.next_sequence();
    let order = Order {
        id: context.next_uuid(b"asteria/order/v1"),
        account_id: request.account_id.clone(),
        client_order_id: request.intent.client_order_id.clone(),
        symbol: request.intent.symbol.clone(),
        side: request.intent.side,
        kind: request.intent.kind,
        quantity: request.intent.quantity,
        remaining: request.intent.quantity,
        limit_price,
        leverage: request.intent.leverage,
        time_in_force: request.intent.time_in_force,
        reduce_only: request.intent.reduce_only,
        reserved_margin: reserve,
        sequence: order_sequence,
        status: OrderStatus::Open,
    };
    state.order_market.insert(order.id, order.symbol.clone());
    state.client_order_ids.insert(client_key, order.id);
    state.append_event_at(
        order_sequence,
        EventKind::OrderAccepted {
            order: order.clone(),
        },
    );

    let execution = state
        .books
        .get_mut(&order.symbol)
        .expect("market book exists")
        .execute(order);
    apply_execution(state, &market, &execution)?;

    let mut affected_accounts = BTreeSet::new();
    affected_accounts.insert(execution.order.account_id.clone());
    for fill in &execution.fills {
        affected_accounts.insert(fill.maker_account_id.clone());
        affected_accounts.insert(fill.taker_account_id.clone());
    }
    for account_id in &affected_accounts {
        reconcile_reduce_only_orders(state, account_id, &execution.order.symbol)?;
    }
    for account_id in &affected_accounts {
        ensure_account_has_nonnegative_available_margin(state, account_id)?;
    }

    let mut trades = Vec::with_capacity(execution.fills.len());
    for fill in &execution.fills {
        let trade = trade_from_fill(state, &market, fill, context.next_uuid(b"asteria/trade/v1"))?;
        state.append_event(EventKind::TradeExecuted {
            trade: trade.clone(),
        });
        trades.push(trade);
    }

    Ok(OrderResult {
        order: execution.order,
        trades,
    })
}

fn validate_order(state: &EngineState, request: &NewOrder, market: &MarketState) -> Result<()> {
    let intent = &request.intent;
    if !state.accounts.contains_key(&request.account_id) {
        return Err(ExchangeError::AccountNotFound(request.account_id.clone()));
    }
    if intent.client_order_id.trim().is_empty() || intent.client_order_id.len() > 64 {
        return Err(ExchangeError::InvalidOrder(
            "client_order_id must contain 1-64 characters".into(),
        ));
    }
    if intent.quantity < market.config.min_quantity
        || intent.quantity % market.config.quantity_step != Decimal::ZERO
    {
        return Err(ExchangeError::InvalidOrder(format!(
            "quantity must be at least {} and a multiple of {}",
            market.config.min_quantity, market.config.quantity_step
        )));
    }
    if intent.leverage == 0 || intent.leverage > market.config.max_leverage {
        return Err(ExchangeError::InvalidOrder(format!(
            "leverage must be between 1 and {}",
            market.config.max_leverage
        )));
    }
    match intent.kind {
        OrderKind::Limit => {
            let price = intent.price.ok_or_else(|| {
                ExchangeError::InvalidOrder("limit order requires a price".into())
            })?;
            if price <= Decimal::ZERO || price % market.config.tick_size != Decimal::ZERO {
                return Err(ExchangeError::InvalidOrder(format!(
                    "price must be positive and a multiple of {}",
                    market.config.tick_size
                )));
            }
        }
        OrderKind::Market => {
            if intent.price.is_some() {
                return Err(ExchangeError::InvalidOrder(
                    "market order must not include a price".into(),
                ));
            }
            if intent.time_in_force == TimeInForce::Gtc {
                return Err(ExchangeError::InvalidOrder(
                    "market order requires ioc or fok time_in_force".into(),
                ));
            }
        }
    }
    if market.mark_price <= Decimal::ZERO {
        return Err(ExchangeError::InvalidOrder(
            "market mark price is unavailable".into(),
        ));
    }
    if let OrderKind::Limit = intent.kind {
        validate_price_in_mark_band(intent.price.expect("validated limit price"), market)?;
    }

    if intent.reduce_only {
        let account = &state.accounts[&request.account_id];
        let position = account.positions.get(&intent.symbol).ok_or_else(|| {
            ExchangeError::InvalidOrder("reduce-only order requires an open position".into())
        })?;
        let required_side = if position.quantity > Decimal::ZERO {
            Side::Sell
        } else {
            Side::Buy
        };
        if position.quantity.is_zero() || intent.side != required_side {
            return Err(ExchangeError::InvalidOrder(
                "reduce-only side must oppose the open position".into(),
            ));
        }
        let already_reserved = state.books[&intent.symbol].active_reduce_only_quantity(
            &request.account_id,
            &intent.symbol,
            intent.side,
        );
        let total_reduce_only = intent
            .quantity
            .checked_add(already_reserved)
            .ok_or_else(|| arithmetic_overflow("reduce-only quantity"))?;
        if total_reduce_only > position.quantity.abs() {
            return Err(ExchangeError::InvalidOrder(
                "reduce-only orders exceed the open position".into(),
            ));
        }
    }
    Ok(())
}

fn effective_limit_price(request: &NewOrder, market: &MarketState) -> Result<Decimal> {
    match request.intent.kind {
        OrderKind::Limit => Ok(request.intent.price.expect("validated limit price")),
        OrderKind::Market => {
            let (lower, upper) = mark_price_band(market)?;
            Ok(match request.intent.side {
                Side::Buy => upper,
                Side::Sell => lower,
            })
        }
    }
}

fn mark_price_band(market: &MarketState) -> Result<(Decimal, Decimal)> {
    let deviation = market.config.market_slippage_limit;
    if deviation < Decimal::ZERO || deviation >= Decimal::ONE {
        return Err(ExchangeError::Internal(format!(
            "market {} has an invalid price-band deviation {deviation}",
            market.config.symbol
        )));
    }
    let lower = Decimal::ONE
        .checked_sub(deviation)
        .and_then(|factor| market.mark_price.checked_mul(factor))
        .ok_or_else(|| arithmetic_overflow("lower mark-price band"))?;
    let upper = Decimal::ONE
        .checked_add(deviation)
        .and_then(|factor| market.mark_price.checked_mul(factor))
        .ok_or_else(|| arithmetic_overflow("upper mark-price band"))?;
    Ok((lower, upper))
}

fn validate_price_in_mark_band(price: Decimal, market: &MarketState) -> Result<()> {
    let (lower, upper) = mark_price_band(market)?;
    if price < lower || price > upper {
        return Err(ExchangeError::InvalidOrder(format!(
            "limit price {price} is outside the mark-price band [{lower}, {upper}]"
        )));
    }
    Ok(())
}

fn validate_mark_price_for_frozen_batches(
    state: &EngineState,
    symbol: &str,
    mark_price: Decimal,
) -> Result<()> {
    let market = state
        .markets
        .get(symbol)
        .ok_or_else(|| ExchangeError::MarketNotFound(symbol.into()))?;
    let deviation = market.config.market_slippage_limit;
    for (batch_height, snapshot) in &state.private_batch_snapshots {
        let Some(frozen) = snapshot.markets.get(symbol) else {
            continue;
        };
        let lower = Decimal::ONE
            .checked_sub(deviation)
            .and_then(|factor| frozen.reference_price.checked_mul(factor))
            .ok_or_else(|| arithmetic_overflow("frozen batch lower mark-price band"))?;
        let upper = Decimal::ONE
            .checked_add(deviation)
            .and_then(|factor| frozen.reference_price.checked_mul(factor))
            .ok_or_else(|| arithmetic_overflow("frozen batch upper mark-price band"))?;
        if mark_price < lower || mark_price > upper {
            return Err(ExchangeError::InvalidOrder(format!(
                "mark price {mark_price} is outside private batch {batch_height} frozen band [{lower}, {upper}]"
            )));
        }
    }
    Ok(())
}

pub(crate) fn required_order_reservation(
    side: Side,
    quantity: Decimal,
    limit_price: Decimal,
    leverage: u16,
    reduce_only: bool,
    market: &MarketState,
) -> Result<Decimal> {
    let notional = quantity
        .checked_mul(limit_price)
        .ok_or_else(|| arithmetic_overflow("order reservation notional"))?;
    let opening_margin = if reduce_only {
        Decimal::ZERO
    } else {
        notional
            .checked_div(Decimal::from(leverage))
            .ok_or_else(|| arithmetic_overflow("order initial margin"))?
    };
    let fee_buffer = notional
        .checked_mul(market.config.taker_fee_rate)
        .ok_or_else(|| arithmetic_overflow("order fee buffer"))?;
    let adverse_price_move = match side {
        Side::Buy if limit_price > market.mark_price => limit_price
            .checked_sub(market.mark_price)
            .ok_or_else(|| arithmetic_overflow("buy adverse price move"))?,
        Side::Sell if limit_price < market.mark_price => market
            .mark_price
            .checked_sub(limit_price)
            .ok_or_else(|| arithmetic_overflow("sell adverse price move"))?,
        _ => Decimal::ZERO,
    };
    let adverse_fill_loss = quantity
        .checked_mul(adverse_price_move)
        .ok_or_else(|| arithmetic_overflow("adverse fill loss"))?;
    opening_margin
        .checked_add(fee_buffer)
        .and_then(|reserve| reserve.checked_add(adverse_fill_loss))
        .ok_or_else(|| arithmetic_overflow("order margin reservation"))
}

fn revalidate_resting_orders_after_mark_change(
    state: &mut EngineState,
    symbol: &str,
) -> Result<()> {
    let market = state
        .markets
        .get(symbol)
        .cloned()
        .ok_or_else(|| ExchangeError::MarketNotFound(symbol.into()))?;
    let (lower, upper) = mark_price_band(&market)?;
    let active_orders = state
        .books
        .get(symbol)
        .ok_or_else(|| ExchangeError::MarketNotFound(symbol.into()))?
        .active_orders();
    let mut cancel = Vec::new();
    for order in active_orders {
        let required = required_order_reservation(
            order.side,
            order.remaining,
            order.limit_price,
            order.leverage,
            order.reduce_only,
            &market,
        );
        if order.time_in_force == TimeInForce::Gtc
            && (order.limit_price < lower
                || order.limit_price > upper
                || required.is_err()
                || required.is_ok_and(|required| order.reserved_margin < required))
        {
            cancel.push((order.id, order.account_id));
        }
    }

    for (order_id, account_id) in cancel {
        let cancelled = state
            .books
            .get_mut(symbol)
            .expect("validated market book exists")
            .cancel(order_id, &account_id)?;
        release_margin(state, &account_id, cancelled.reserved_margin)?;
        remove_order_indices(state, &cancelled);
        state.append_event(EventKind::OrderCancelled {
            order_id,
            account_id,
            reason: "mark_price_risk_revalidation".into(),
        });
    }
    Ok(())
}

pub(crate) fn ensure_account_has_nonnegative_available_margin(
    state: &EngineState,
    account_id: &str,
) -> Result<()> {
    let available = state
        .accounts
        .get(account_id)
        .ok_or_else(|| ExchangeError::AccountNotFound(account_id.into()))?
        .risk_snapshot(state.markets.iter())?
        .available_margin;
    if available < Decimal::ZERO {
        return Err(ExchangeError::InsufficientMargin {
            required: Decimal::ZERO.to_string(),
            available: available.to_string(),
        });
    }
    Ok(())
}

fn apply_execution(
    state: &mut EngineState,
    market: &MarketState,
    execution: &Execution,
) -> Result<()> {
    for order in &execution.terminal_orders {
        remove_order_indices(state, order);
    }
    for release in &execution.releases {
        release_margin(state, &release.account_id, release.amount)?;
        state.append_event(EventKind::OrderCancelled {
            order_id: release.order_id,
            account_id: release.account_id.clone(),
            reason: release.reason.into(),
        });
    }
    for fill in &execution.fills {
        release_margin(state, &fill.maker_account_id, fill.maker_margin_release)?;
        release_margin(state, &fill.taker_account_id, fill.taker_margin_release)?;
        apply_fill_to_account(
            state,
            &fill.maker_account_id,
            &market.config.symbol,
            fill.maker_side,
            fill.quantity,
            fill.price,
            fill.maker_leverage,
            market.config.maker_fee_rate,
        )?;
        apply_fill_to_account(
            state,
            &fill.taker_account_id,
            &market.config.symbol,
            fill.taker_side,
            fill.quantity,
            fill.price,
            fill.taker_leverage,
            market.config.taker_fee_rate,
        )?;
    }
    Ok(())
}

fn remove_order_indices(state: &mut EngineState, order: &Order) {
    state.order_market.remove(&order.id);
    let client_key = format!("{}:{}", order.account_id, order.client_order_id);
    if state.client_order_ids.get(&client_key) == Some(&order.id) {
        state.client_order_ids.remove(&client_key);
    }
}

fn reject_locked_order_cancellation(
    state: &EngineState,
    order_id: Uuid,
    account_id: &str,
) -> Result<()> {
    for (batch_height, batch) in &state.private_batch_snapshots {
        for order in batch
            .markets
            .values()
            .flat_map(|market| &market.public_orders)
        {
            if order.id != order_id {
                continue;
            }
            if order.account_id != account_id {
                return Err(ExchangeError::OrderOwnership { order_id });
            }
            return Err(ExchangeError::InvalidOrder(format!(
                "order {order_id} is locked in private batch {batch_height}"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_fill_to_account(
    state: &mut EngineState,
    account_id: &str,
    symbol: &str,
    side: Side,
    quantity: Decimal,
    price: Decimal,
    leverage: u16,
    fee_rate: Decimal,
) -> Result<()> {
    settle_account_funding(state, account_id, symbol)?;
    let fee = quantity
        .checked_mul(price)
        .and_then(|notional| notional.checked_mul(fee_rate))
        .ok_or_else(|| arithmetic_overflow("trade fee"))?;
    let current_funding_index = state
        .markets
        .get(symbol)
        .ok_or_else(|| ExchangeError::MarketNotFound(symbol.into()))?
        .funding_index;
    {
        let account = state
            .accounts
            .get_mut(account_id)
            .ok_or_else(|| ExchangeError::AccountNotFound(account_id.into()))?;
        let position = account.positions.entry(symbol.into()).or_default();
        position.funding_index = current_funding_index;
        let update = position.apply_fill(side, quantity, price, leverage)?;
        account.collateral = account
            .collateral
            .checked_add(update.realized_pnl)
            .and_then(|collateral| collateral.checked_sub(fee))
            .ok_or_else(|| arithmetic_overflow("account collateral after fill"))?;
        account.fees_paid = account
            .fees_paid
            .checked_add(fee)
            .ok_or_else(|| arithmetic_overflow("account fees"))?;
    }
    state.fee_vault = state
        .fee_vault
        .checked_add(fee)
        .ok_or_else(|| arithmetic_overflow("fee vault"))?;
    Ok(())
}

fn settle_account_funding(
    state: &mut EngineState,
    account_id: &str,
    symbol: &str,
) -> Result<Decimal> {
    let current_index = state
        .markets
        .get(symbol)
        .ok_or_else(|| ExchangeError::MarketNotFound(symbol.into()))?
        .funding_index;
    let account = state
        .accounts
        .get_mut(account_id)
        .ok_or_else(|| ExchangeError::AccountNotFound(account_id.into()))?;
    let Some(position) = account.positions.get_mut(symbol) else {
        return Ok(Decimal::ZERO);
    };
    let payment = position
        .quantity
        .checked_mul(
            current_index
                .checked_sub(position.funding_index)
                .ok_or_else(|| arithmetic_overflow("funding index difference"))?,
        )
        .ok_or_else(|| arithmetic_overflow("lazy funding payment"))?;
    account.collateral = account
        .collateral
        .checked_sub(payment)
        .ok_or_else(|| arithmetic_overflow("funding collateral"))?;
    position.funding_pnl = position
        .funding_pnl
        .checked_sub(payment)
        .ok_or_else(|| arithmetic_overflow("position funding PnL"))?;
    position.funding_index = current_index;
    state.funding_pool = state
        .funding_pool
        .checked_add(payment)
        .ok_or_else(|| arithmetic_overflow("funding settlement pool"))?;
    Ok(payment)
}

fn release_margin(state: &mut EngineState, account_id: &str, amount: Decimal) -> Result<()> {
    if amount.is_zero() {
        return Ok(());
    }
    let account = state
        .accounts
        .get_mut(account_id)
        .ok_or_else(|| ExchangeError::AccountNotFound(account_id.into()))?;
    if account.reserved_margin < amount {
        return Err(ExchangeError::Internal(format!(
            "reservation underflow for {account_id}: have {}, release {amount}",
            account.reserved_margin
        )));
    }
    account.reserved_margin -= amount;
    Ok(())
}

fn reconcile_reduce_only_orders(
    state: &mut EngineState,
    account_id: &str,
    symbol: &str,
) -> Result<()> {
    let position_quantity = state
        .accounts
        .get(account_id)
        .and_then(|account| account.positions.get(symbol))
        .map(|position| position.quantity)
        .unwrap_or(Decimal::ZERO);
    let required_side = if position_quantity > Decimal::ZERO {
        Some(Side::Sell)
    } else if position_quantity < Decimal::ZERO {
        Some(Side::Buy)
    } else {
        None
    };
    let orders = state.books[symbol].active_orders_for_account_symbol(account_id, symbol);
    let mut remaining_position = position_quantity.abs();
    let mut cancel_ids = Vec::new();
    for order in orders.into_iter().filter(|order| order.reduce_only) {
        if Some(order.side) != required_side || order.remaining > remaining_position {
            cancel_ids.push(order.id);
        } else {
            remaining_position -= order.remaining;
        }
    }
    for order_id in cancel_ids {
        let cancelled = state
            .books
            .get_mut(symbol)
            .expect("book exists")
            .cancel(order_id, account_id)?;
        release_margin(state, account_id, cancelled.reserved_margin)?;
        remove_order_indices(state, &cancelled);
        state.append_event(EventKind::OrderCancelled {
            order_id,
            account_id: account_id.into(),
            reason: "reduce_only_reconciliation".into(),
        });
    }
    Ok(())
}

fn trade_from_fill(
    state: &EngineState,
    market: &MarketState,
    fill: &RawFill,
    trade_id: Uuid,
) -> Result<Trade> {
    let notional = fill
        .quantity
        .checked_mul(fill.price)
        .ok_or_else(|| arithmetic_overflow("trade notional"))?;
    Ok(Trade {
        id: trade_id,
        symbol: market.config.symbol.clone(),
        price: fill.price,
        quantity: fill.quantity,
        maker_order_id: fill.maker_order_id,
        taker_order_id: fill.taker_order_id,
        maker_account_id: fill.maker_account_id.clone(),
        taker_account_id: fill.taker_account_id.clone(),
        taker_side: fill.taker_side,
        maker_fee: notional
            .checked_mul(market.config.maker_fee_rate)
            .ok_or_else(|| arithmetic_overflow("maker fee"))?,
        taker_fee: notional
            .checked_mul(market.config.taker_fee_rate)
            .ok_or_else(|| arithmetic_overflow("taker fee"))?,
        sequence: state
            .sequence
            .checked_add(1)
            .expect("consensus event sequence exhausted"),
    })
}

fn validate_observations(observations: &[OracleObservation]) -> Result<()> {
    if observations.len() < 3 {
        return Err(ExchangeError::InvalidOrder(
            "at least three oracle sources are required".into(),
        ));
    }
    let mut sources = HashSet::new();
    for observation in observations {
        if observation.source.trim().is_empty()
            || !sources.insert(observation.source.to_ascii_lowercase())
        {
            return Err(ExchangeError::InvalidOrder(
                "oracle source names must be non-empty and unique".into(),
            ));
        }
        if observation.price <= Decimal::ZERO || observation.weight == 0 {
            return Err(ExchangeError::InvalidOrder(
                "oracle prices and weights must be positive".into(),
            ));
        }
    }
    Ok(())
}

fn weighted_median(observations: &[OracleObservation]) -> Decimal {
    let mut ordered = observations.to_vec();
    ordered.sort_by_key(|observation| observation.price);
    let total_weight: u64 = ordered
        .iter()
        .map(|observation| u64::from(observation.weight))
        .sum();
    let threshold = total_weight.div_ceil(2);
    let mut cumulative = 0_u64;
    for observation in ordered {
        cumulative += u64::from(observation.weight);
        if cumulative >= threshold {
            return observation.price;
        }
    }
    unreachable!("validated observations have positive weight")
}

fn liquidate_account(
    state: &mut EngineState,
    account_id: &str,
    symbol: &str,
    context: &mut ApplyContext,
) -> Result<LiquidationResult> {
    let account = state
        .accounts
        .get(account_id)
        .ok_or_else(|| ExchangeError::AccountNotFound(account_id.into()))?;
    let risk = account.risk_snapshot(state.markets.iter())?;
    if !risk.liquidation_risk {
        return Err(ExchangeError::NotLiquidatable(account_id.into()));
    }
    let position_quantity = account
        .positions
        .get(symbol)
        .map(|position| position.quantity)
        .unwrap_or(Decimal::ZERO);
    if position_quantity.is_zero() {
        return Err(ExchangeError::NotLiquidatable(format!(
            "{account_id} has no {symbol} position"
        )));
    }

    let market = state
        .markets
        .get(symbol)
        .cloned()
        .ok_or_else(|| ExchangeError::MarketNotFound(symbol.into()))?;
    let side = if position_quantity > Decimal::ZERO {
        Side::Sell
    } else {
        Side::Buy
    };
    let limit_price = match side {
        Side::Buy => Decimal::ONE
            .checked_add(market.config.market_slippage_limit)
            .and_then(|factor| market.mark_price.checked_mul(factor)),
        Side::Sell => Decimal::ONE
            .checked_sub(market.config.market_slippage_limit)
            .and_then(|factor| market.mark_price.checked_mul(factor)),
    }
    .ok_or_else(|| arithmetic_overflow("liquidation price limit"))?;
    let order_sequence = state.next_sequence();
    let order = Order {
        id: context.next_uuid(b"asteria/liquidation-order/v1"),
        account_id: account_id.into(),
        client_order_id: format!("liquidation-{order_sequence}"),
        symbol: symbol.into(),
        side,
        kind: OrderKind::Market,
        quantity: position_quantity.abs(),
        remaining: position_quantity.abs(),
        limit_price,
        leverage: 1,
        time_in_force: TimeInForce::Ioc,
        reduce_only: true,
        reserved_margin: Decimal::ZERO,
        sequence: order_sequence,
        status: OrderStatus::Open,
    };
    state.order_market.insert(order.id, symbol.into());
    state.append_event_at(
        order_sequence,
        EventKind::OrderAccepted {
            order: order.clone(),
        },
    );
    let execution = state
        .books
        .get_mut(symbol)
        .expect("market book exists")
        .execute(order);
    apply_execution(state, &market, &execution)?;
    let closed_quantity = execution
        .fills
        .iter()
        .try_fold(Decimal::ZERO, |total, fill| {
            total.checked_add(fill.quantity)
        })
        .ok_or_else(|| arithmetic_overflow("liquidation filled quantity"))?;
    if closed_quantity.is_zero() {
        return Err(ExchangeError::CannotFullyFill);
    }

    let penalty = execution
        .fills
        .iter()
        .try_fold(Decimal::ZERO, |total, fill| {
            fill.quantity
                .checked_mul(fill.price)
                .and_then(|notional| notional.checked_mul(market.config.liquidation_penalty_rate))
                .and_then(|fill_penalty| total.checked_add(fill_penalty))
        })
        .ok_or_else(|| arithmetic_overflow("liquidation penalty"))?;
    let account = state
        .accounts
        .get_mut(account_id)
        .expect("liquidated account exists");
    account.collateral = account
        .collateral
        .checked_sub(penalty)
        .ok_or_else(|| arithmetic_overflow("liquidated collateral"))?;
    state.insurance_fund = state
        .insurance_fund
        .checked_add(penalty)
        .ok_or_else(|| arithmetic_overflow("insurance fund penalty"))?;

    let mut affected_accounts = BTreeSet::new();
    affected_accounts.insert(account_id.to_owned());
    for fill in &execution.fills {
        affected_accounts.insert(fill.maker_account_id.clone());
    }
    for affected in affected_accounts {
        reconcile_reduce_only_orders(state, &affected, symbol)?;
    }

    let remaining_quantity = state.accounts[account_id]
        .positions
        .get(symbol)
        .map(|position| position.quantity.abs())
        .unwrap_or(Decimal::ZERO);
    let mut bad_debt = Decimal::ZERO;
    let mut insurance_used = Decimal::ZERO;
    let mut fee_vault_used = Decimal::ZERO;
    let mut socialized_losses = Vec::new();
    if remaining_quantity.is_zero() && state.accounts[account_id].collateral < Decimal::ZERO {
        bad_debt = Decimal::ZERO
            .checked_sub(state.accounts[account_id].collateral)
            .ok_or_else(|| arithmetic_overflow("liquidation bad debt"))?;
        let coverage = cover_bad_debt(state, account_id, bad_debt)?;
        insurance_used = coverage.insurance_used;
        fee_vault_used = coverage.fee_vault_used;
        socialized_losses = coverage.socialized_losses;
    }

    let mut trades = Vec::with_capacity(execution.fills.len());
    for fill in &execution.fills {
        let trade = trade_from_fill(
            state,
            &market,
            fill,
            context.next_uuid(b"asteria/liquidation-trade/v1"),
        )?;
        state.append_event(EventKind::TradeExecuted {
            trade: trade.clone(),
        });
        trades.push(trade);
    }
    state.append_event(EventKind::LiquidationExecuted {
        account_id: account_id.into(),
        symbol: symbol.into(),
        closed_quantity,
        remaining_quantity,
        penalty,
        bad_debt,
        insurance_used,
        fee_vault_used,
        socialized_losses: socialized_losses.clone(),
    });

    Ok(LiquidationResult {
        account_id: account_id.into(),
        symbol: symbol.into(),
        closed_quantity,
        remaining_quantity,
        penalty,
        bad_debt,
        insurance_used,
        fee_vault_used,
        socialized_losses,
        trades,
    })
}

const SOCIAL_LOSS_SAFETY_EPSILON: Decimal = dec!(0.00000001);

struct BadDebtCoverage {
    insurance_used: Decimal,
    fee_vault_used: Decimal,
    socialized_losses: Vec<SocializedLoss>,
}

fn cover_bad_debt(
    state: &mut EngineState,
    debtor_account_id: &str,
    bad_debt: Decimal,
) -> Result<BadDebtCoverage> {
    if bad_debt <= Decimal::ZERO {
        return Err(ExchangeError::Internal(
            "bad-debt coverage requires a positive amount".into(),
        ));
    }
    if state.insurance_fund < Decimal::ZERO || state.fee_vault < Decimal::ZERO {
        return Err(ExchangeError::Internal(
            "protocol reserve balances must not be negative".into(),
        ));
    }
    let debtor = state
        .accounts
        .get(debtor_account_id)
        .ok_or_else(|| ExchangeError::AccountNotFound(debtor_account_id.into()))?;
    let debtor_shortfall = Decimal::ZERO
        .checked_sub(debtor.collateral)
        .ok_or_else(|| arithmetic_overflow("debtor collateral shortfall"))?;
    if debtor_shortfall != bad_debt {
        return Err(ExchangeError::Internal(
            "bad debt must exactly match the debtor's negative collateral".into(),
        ));
    }

    let insurance_used = state.insurance_fund.min(bad_debt);
    let after_insurance = bad_debt
        .checked_sub(insurance_used)
        .ok_or_else(|| arithmetic_overflow("bad debt after insurance"))?;
    let fee_vault_used = state.fee_vault.min(after_insurance);
    let mut remaining = after_insurance
        .checked_sub(fee_vault_used)
        .ok_or_else(|| arithmetic_overflow("bad debt after fee vault"))?;

    let mut candidates = Vec::new();
    for (account_id, account) in &state.accounts {
        if account_id == debtor_account_id {
            continue;
        }
        let risk = account.risk_snapshot(state.markets.iter())?;
        let protected_margin = risk.position_margin.max(risk.maintenance_requirement);
        let capacity = risk
            .equity
            .checked_sub(protected_margin)
            .and_then(|capacity| capacity.checked_sub(risk.reserved_margin))
            .and_then(|capacity| capacity.checked_sub(SOCIAL_LOSS_SAFETY_EPSILON))
            .ok_or_else(|| arithmetic_overflow("social loss capacity"))?;
        if capacity > Decimal::ZERO {
            candidates.push((account_id.clone(), capacity));
        }
    }
    candidates.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    // Sum only as far as the required amount, so large account balances cannot
    // overflow an intermediate total.
    let required_social_loss = remaining;
    let mut available_capacity = Decimal::ZERO;
    for (_, capacity) in &candidates {
        let needed = required_social_loss
            .checked_sub(available_capacity)
            .ok_or_else(|| arithmetic_overflow("required social loss capacity"))?;
        if needed.is_zero() {
            break;
        }
        available_capacity = available_capacity
            .checked_add((*capacity).min(needed))
            .ok_or_else(|| arithmetic_overflow("available social loss capacity"))?;
    }
    if available_capacity < required_social_loss {
        return Err(ExchangeError::InsufficientMargin {
            required: required_social_loss.to_string(),
            available: available_capacity.to_string(),
        });
    }

    let mut socialized_losses = Vec::new();
    for (account_id, capacity) in &candidates {
        if remaining.is_zero() {
            break;
        }
        let levy = remaining.min(*capacity);
        remaining = remaining
            .checked_sub(levy)
            .ok_or_else(|| arithmetic_overflow("remaining social loss"))?;
        if levy > Decimal::ZERO {
            socialized_losses.push(SocializedLoss {
                account_id: account_id.clone(),
                amount: levy,
            });
        }
    }
    if !remaining.is_zero() {
        return Err(ExchangeError::Internal(
            "social loss allocation did not cover the exact bad debt".into(),
        ));
    }

    let next_insurance_fund = state
        .insurance_fund
        .checked_sub(insurance_used)
        .ok_or_else(|| arithmetic_overflow("insurance bad-debt coverage"))?;
    let next_fee_vault = state
        .fee_vault
        .checked_sub(fee_vault_used)
        .ok_or_else(|| arithmetic_overflow("fee-vault bad-debt coverage"))?;
    if next_insurance_fund < Decimal::ZERO || next_fee_vault < Decimal::ZERO {
        return Err(ExchangeError::Internal(
            "bad-debt coverage would make a protocol reserve negative".into(),
        ));
    }

    let mut next_collateral = Vec::with_capacity(socialized_losses.len());
    for socialized in &socialized_losses {
        let account = state
            .accounts
            .get(&socialized.account_id)
            .expect("selected social loss account exists");
        let collateral = account
            .collateral
            .checked_sub(socialized.amount)
            .ok_or_else(|| arithmetic_overflow("socialized account collateral"))?;
        let mut post_levy = account.clone();
        post_levy.collateral = collateral;
        let post_risk = post_levy.risk_snapshot(state.markets.iter())?;
        if post_risk.liquidation_risk || post_risk.available_margin < SOCIAL_LOSS_SAFETY_EPSILON {
            return Err(ExchangeError::Internal(format!(
                "social loss levy would violate the risk floor for {}",
                socialized.account_id
            )));
        }
        next_collateral.push((socialized.account_id.clone(), collateral));
    }

    // All fallible calculations and post-levy risk checks complete before the
    // first state write, preserving atomic failure semantics.
    state.insurance_fund = next_insurance_fund;
    state.fee_vault = next_fee_vault;
    for (account_id, collateral) in next_collateral {
        state
            .accounts
            .get_mut(&account_id)
            .expect("validated social loss account exists")
            .collateral = collateral;
    }
    state
        .accounts
        .get_mut(debtor_account_id)
        .expect("validated debtor account exists")
        .collateral = Decimal::ZERO;

    Ok(BadDebtCoverage {
        insurance_used,
        fee_vault_used,
        socialized_losses,
    })
}

fn audit_state(state: &EngineState) -> AuditReport {
    let event_chain_valid = state.event_log.verify();
    let mut errors = Vec::new();
    let mut reservations_consistent = true;
    let mut numeric_consistent = true;
    for account in state.accounts.values() {
        let Some(book_reservation) = checked_book_reservation(state, &account.id) else {
            numeric_consistent = false;
            reservations_consistent = false;
            errors.push(format!(
                "numeric overflow while auditing reservations for {}",
                account.id
            ));
            continue;
        };
        if book_reservation != account.reserved_margin {
            reservations_consistent = false;
            errors.push(format!(
                "reservation mismatch for {}: account={}, books={}",
                account.id, account.reserved_margin, book_reservation
            ));
        }
    }

    let mut net_positions: BTreeMap<&str, Decimal> = BTreeMap::new();
    let mut positions_arithmetic_valid = true;
    for account in state.accounts.values() {
        for (symbol, position) in &account.positions {
            let total = net_positions.entry(symbol.as_str()).or_default();
            if let Some(next) = total.checked_add(position.quantity) {
                *total = next;
            } else {
                numeric_consistent = false;
                positions_arithmetic_valid = false;
                errors.push(format!(
                    "numeric overflow while auditing net position for {symbol}"
                ));
            }
        }
    }
    let open_interest_balanced =
        positions_arithmetic_valid && net_positions.values().all(Decimal::is_zero);
    for (symbol, quantity) in net_positions
        .iter()
        .filter(|(_, quantity)| !quantity.is_zero())
    {
        errors.push(format!("net position for {symbol} is {quantity}"));
    }

    let pending_funding =
        state
            .accounts
            .values()
            .try_fold(Decimal::ZERO, |all_accounts, account| {
                account
                    .positions
                    .iter()
                    .try_fold(all_accounts, |total, (symbol, position)| {
                        let market = state.markets.get(symbol)?;
                        let index_delta =
                            market.funding_index.checked_sub(position.funding_index)?;
                        let payment = position.quantity.checked_mul(index_delta)?;
                        total.checked_add(payment)
                    })
            });
    let funding_pool_difference =
        pending_funding.and_then(|pending| state.funding_pool.checked_add(pending));
    if funding_pool_difference.is_none() {
        numeric_consistent = false;
        errors.push("numeric overflow while auditing the funding settlement pool".into());
    }
    let tolerance = dec!(0.00000001);
    let funding_pool_balanced = funding_pool_difference
        .is_some_and(|difference| difference >= -tolerance && difference <= tolerance);
    if let Some(difference) = funding_pool_difference
        && !funding_pool_balanced
    {
        errors.push(format!(
            "funding settlement pool plus pending payments is {difference}"
        ));
    }

    let account_equity = state
        .accounts
        .values()
        .try_fold(Decimal::ZERO, |total, account| {
            total.checked_add(checked_account_equity(state, account)?)
        });
    if account_equity.is_none() {
        numeric_consistent = false;
        errors.push("numeric overflow while auditing account equity".into());
    }
    let shielded_collateral = state
        .shielded_ledger
        .as_ref()
        .map(|ledger| {
            i128::try_from(ledger.shielded_collateral())
                .ok()
                .map(|amount| Decimal::from_i128_with_scale(amount, 8))
        })
        .unwrap_or(Some(Decimal::ZERO));
    if shielded_collateral.is_none() {
        numeric_consistent = false;
        errors.push("shielded collateral exceeds Decimal range".into());
    }
    let conservation_difference = account_equity.and_then(|equity| {
        equity
            .checked_add(shielded_collateral?)?
            .checked_add(state.fee_vault)?
            .checked_add(state.insurance_fund)?
            .checked_sub(state.total_credits)
    });
    if conservation_difference.is_none() {
        numeric_consistent = false;
        errors.push("numeric overflow while auditing asset conservation".into());
    }
    let conservation_within_tolerance = conservation_difference
        .is_some_and(|difference| difference >= -tolerance && difference <= tolerance);
    if let Some(conservation_difference) = conservation_difference
        && !conservation_within_tolerance
    {
        errors.push(format!(
            "asset conservation difference is {conservation_difference}"
        ));
    }
    if !event_chain_valid {
        errors.push("event hash chain is invalid".into());
    }

    AuditReport {
        healthy: numeric_consistent
            && event_chain_valid
            && reservations_consistent
            && open_interest_balanced
            && funding_pool_balanced
            && conservation_within_tolerance,
        event_chain_valid,
        reservations_consistent,
        open_interest_balanced,
        total_credits: state.total_credits,
        account_equity: account_equity.unwrap_or(Decimal::ZERO),
        shielded_collateral: shielded_collateral.unwrap_or(Decimal::ZERO),
        fee_vault: state.fee_vault,
        insurance_fund: state.insurance_fund,
        funding_pool: state.funding_pool,
        funding_pool_balanced,
        conservation_difference: conservation_difference.unwrap_or(Decimal::ZERO),
        errors,
    }
}

fn checked_book_reservation(state: &EngineState, account_id: &str) -> Option<Decimal> {
    let live_total = state
        .books
        .iter()
        .try_fold(Decimal::ZERO, |all_books, (symbol, book)| {
            let book_total = book
                .active_orders_for_account_symbol(account_id, symbol)
                .iter()
                .try_fold(Decimal::ZERO, |total, order| {
                    total.checked_add(order.reserved_margin)
                })?;
            all_books.checked_add(book_total)
        })?;
    let escrow_total =
        state
            .private_batch_snapshots
            .values()
            .try_fold(live_total, |all_batches, batch| {
                batch
                    .markets
                    .values()
                    .flat_map(|market| &market.public_orders)
                    .filter(|order| order.account_id == account_id)
                    .try_fold(all_batches, |total, order| {
                        total.checked_add(order.reserved_margin)
                    })
            })?;
    state
        .private_order_bonds
        .values()
        .filter_map(|batch| batch.get(account_id))
        .try_fold(escrow_total, |total, bond| total.checked_add(*bond))
}

fn checked_account_equity(state: &EngineState, account: &Account) -> Option<Decimal> {
    let unrealized_pnl =
        state
            .markets
            .iter()
            .try_fold(Decimal::ZERO, |total, (symbol, market)| {
                let Some(position) = account.positions.get(symbol) else {
                    return Some(total);
                };
                let price_change = market.mark_price.checked_sub(position.entry_price)?;
                let position_pnl = position.quantity.checked_mul(price_change)?;
                let funding_index_delta =
                    market.funding_index.checked_sub(position.funding_index)?;
                let pending_funding = position.quantity.checked_mul(funding_index_delta)?;
                total
                    .checked_add(position_pnl)?
                    .checked_sub(pending_funding)
            })?;
    account.collateral.checked_add(unrealized_pnl)
}

fn local_context(state: &EngineState, domain: &[u8], material: &impl Serialize) -> ApplyContext {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(state.chain_id.as_bytes());
    hasher.update(state.height.to_be_bytes());
    hasher.update(state.sequence.to_be_bytes());
    hasher.update(serde_jcs::to_vec(material).expect("local command is serializable"));
    ApplyContext::new(
        state.height,
        state.block_time_ms,
        0,
        hasher.finalize().into(),
    )
}

pub fn default_markets() -> Vec<MarketState> {
    vec![
        MarketState {
            config: MarketConfig {
                symbol: "BTCUSDT".into(),
                tick_size: dec!(0.1),
                quantity_step: dec!(0.001),
                min_quantity: dec!(0.001),
                max_leverage: 50,
                maintenance_margin_ratio: dec!(0.005),
                maker_fee_rate: dec!(0.0001),
                taker_fee_rate: dec!(0.00035),
                market_slippage_limit: dec!(0.01),
                liquidation_penalty_rate: dec!(0.005),
            },
            mark_price: dec!(60000),
            funding_rate: Decimal::ZERO,
            funding_index: Decimal::ZERO,
        },
        MarketState {
            config: MarketConfig {
                symbol: "ETHUSDT".into(),
                tick_size: dec!(0.01),
                quantity_step: dec!(0.001),
                min_quantity: dec!(0.001),
                max_leverage: 50,
                maintenance_margin_ratio: dec!(0.005),
                maker_fee_rate: dec!(0.0001),
                taker_fee_rate: dec!(0.00035),
                market_slippage_limit: dec!(0.01),
                liquidation_penalty_rate: dec!(0.005),
            },
            mark_price: dec!(3000),
            funding_rate: Decimal::ZERO,
            funding_index: Decimal::ZERO,
        },
    ]
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use rust_decimal_macros::dec;

    use super::*;
    use crate::{
        domain::OrderIntent,
        private_order::{PrivateOrderContext, encrypt_private_order, generate_dealer_key_set},
        private_protocol::{
            PrivateOrderPayload, VoteExtension, aggregate_vote_extensions, anti_spam_commitment,
        },
    };

    fn limit(account_id: &str, client_id: &str, side: Side, qty: Decimal) -> NewOrder {
        NewOrder {
            account_id: account_id.into(),
            intent: OrderIntent {
                client_order_id: client_id.into(),
                symbol: "BTCUSDT".into(),
                side,
                kind: OrderKind::Limit,
                quantity: qty,
                price: Some(dec!(60000)),
                leverage: 10,
                time_in_force: TimeInForce::Gtc,
                reduce_only: false,
            },
        }
    }

    fn private_submission(
        signing_key: &SigningKey,
        key_set: &ThresholdPublicKeySet,
        chain_id: &str,
        market_id: &str,
        batch_height: u64,
        nonce: u64,
        payload: &PrivateOrderPayload,
    ) -> PrivateOrderSubmission {
        let fee_payer = signing_key.verifying_key().to_bytes();
        let envelope = encrypt_private_order(
            key_set,
            &PrivateOrderContext {
                chain_id: chain_id.into(),
                market_id: market_id.into(),
                epoch: key_set.epoch,
                batch_height,
            },
            fee_payer,
            anti_spam_commitment(chain_id, &fee_payer, nonce).unwrap(),
            &payload.to_canonical_bytes().unwrap(),
            &mut OsRng,
        )
        .unwrap();
        PrivateOrderSubmission::sign(
            chain_id.into(),
            nonce,
            batch_height + 10,
            envelope,
            signing_key,
        )
        .unwrap()
    }

    #[test]
    fn private_order_admission_locks_available_margin_until_decryption() {
        const BATCH_HEIGHT: u64 = 9;

        let mut engine = Engine::in_memory(default_markets());
        let chain_id = engine.state.chain_id.clone();
        let (key_set, _) = generate_dealer_key_set(1, &mut OsRng).unwrap();
        engine.state.private_order_key_set = Some(key_set.clone());
        let signing_key = SigningKey::from_bytes(&[33; 32]);
        let account_id = account_id_from_signer(&signing_key.verifying_key().to_bytes());
        engine
            .credit_account(account_id.clone(), dec!(1000))
            .unwrap();
        let payload = PrivateOrderPayload {
            client_id: "bonded-private-order".into(),
            side: PrivateOrderSide::Buy,
            kind: PrivateOrderKind::Limit,
            price_ticks: 600_000,
            quantity_lots: 1,
            leverage: 10,
            ioc: true,
            fok: false,
            reduce_only: false,
        };
        let submission = private_submission(
            &signing_key,
            &key_set,
            &chain_id,
            "BTCUSDT",
            BATCH_HEIGHT,
            0,
            &payload,
        );

        let result =
            queue_private_order(&mut engine.state, &account_id, &submission, BATCH_HEIGHT).unwrap();
        let CommandResult::PrivateOrderQueued { bond, .. } = result else {
            panic!("private submission returned an unexpected result");
        };
        assert_eq!(bond, dec!(999.99));
        assert_eq!(
            engine.state.private_order_bonds[&BATCH_HEIGHT][&account_id],
            bond
        );
        assert_eq!(engine.account(&account_id).unwrap().reserved_margin, bond);
        assert_eq!(
            engine.risk(&account_id).unwrap().available_margin,
            Decimal::ZERO
        );
        assert!(matches!(
            engine.submit_order(limit(&account_id, "post-private", Side::Buy, dec!(0.001))),
            Err(ExchangeError::InsufficientMargin { .. })
        ));
        assert!(engine.audit().healthy, "{:?}", engine.audit().errors);

        let mut underfunded = Engine::in_memory(default_markets());
        underfunded.state.private_order_key_set = Some(key_set);
        underfunded
            .credit_account(account_id.clone(), MIN_PRIVATE_ORDER_BOND)
            .unwrap();
        let before = underfunded.state.clone();
        assert!(matches!(
            queue_private_order(
                &mut underfunded.state,
                &account_id,
                &submission,
                BATCH_HEIGHT
            ),
            Err(ExchangeError::InsufficientMargin { .. })
        ));
        assert_eq!(underfunded.state, before);
    }

    #[test]
    fn private_self_trade_filter_is_scoped_to_each_market() {
        const BATCH_HEIGHT: u64 = 7;

        let mut engine = Engine::in_memory(default_markets());
        let chain_id = engine.state.chain_id.clone();
        let (key_set, secret_shares) = generate_dealer_key_set(1, &mut OsRng).unwrap();
        engine.state.private_order_key_set = Some(key_set.clone());

        let alice_key = SigningKey::from_bytes(&[31; 32]);
        let bob_key = SigningKey::from_bytes(&[32; 32]);
        let alice = account_id_from_signer(&alice_key.verifying_key().to_bytes());
        let bob = account_id_from_signer(&bob_key.verifying_key().to_bytes());
        let charlie = "charlie".to_string();
        engine.credit_account(alice.clone(), dec!(10000)).unwrap();
        engine.credit_account(bob.clone(), dec!(10000)).unwrap();
        engine.credit_account(charlie.clone(), dec!(10000)).unwrap();

        let frozen_public_order = engine
            .submit_order(NewOrder {
                account_id: alice.clone(),
                intent: OrderIntent {
                    client_order_id: "alice-public-eth".into(),
                    symbol: "ETHUSDT".into(),
                    side: Side::Buy,
                    kind: OrderKind::Limit,
                    quantity: dec!(2),
                    price: Some(dec!(2999)),
                    leverage: 10,
                    time_in_force: TimeInForce::Gtc,
                    reduce_only: false,
                },
            })
            .unwrap();

        let alice_btc = PrivateOrderPayload {
            client_id: "alice-private-btc".into(),
            side: PrivateOrderSide::Buy,
            kind: PrivateOrderKind::Limit,
            price_ticks: 600_000,
            quantity_lots: 1,
            leverage: 10,
            ioc: true,
            fok: false,
            reduce_only: false,
        };
        let bob_eth = PrivateOrderPayload {
            client_id: "bob-private-eth".into(),
            side: PrivateOrderSide::Sell,
            kind: PrivateOrderKind::Limit,
            price_ticks: 299_900,
            quantity_lots: 1_000,
            leverage: 10,
            ioc: true,
            fok: false,
            reduce_only: false,
        };
        let pending = vec![
            private_submission(
                &alice_key,
                &key_set,
                &chain_id,
                "BTCUSDT",
                BATCH_HEIGHT,
                0,
                &alice_btc,
            ),
            private_submission(
                &bob_key,
                &key_set,
                &chain_id,
                "ETHUSDT",
                BATCH_HEIGHT,
                0,
                &bob_eth,
            ),
        ];
        engine
            .state
            .pending_private_orders
            .insert(BATCH_HEIGHT, pending.clone());
        let mut bonds = OrdMap::new();
        for account_id in [&alice, &bob] {
            let bond = dec!(1000);
            engine
                .state
                .accounts
                .get_mut(account_id.as_str())
                .unwrap()
                .reserved_margin += bond;
            bonds.insert(account_id.clone(), bond);
        }
        engine.state.private_order_bonds.insert(BATCH_HEIGHT, bonds);
        freeze_private_batch_liquidity(&mut engine.state, BATCH_HEIGHT).unwrap();
        assert!(engine.state.books["ETHUSDT"].active_orders().is_empty());
        assert_eq!(
            engine.state.private_batch_snapshots[&BATCH_HEIGHT].markets["ETHUSDT"].reference_price,
            dec!(3000)
        );
        assert_eq!(
            engine.state.private_batch_snapshots[&BATCH_HEIGHT].markets["ETHUSDT"].public_orders[0]
                .reserved_margin,
            dec!(659.8993)
        );
        assert!(matches!(
            engine.cancel_order(&alice, frozen_public_order.order.id),
            Err(ExchangeError::InvalidOrder(message)) if message.contains("locked in private batch")
        ));
        assert!(engine.set_mark_price("ETHUSDT", dec!(3030.01)).is_err());
        assert_eq!(engine.state.markets["ETHUSDT"].mark_price, dec!(3000));
        engine.set_mark_price("ETHUSDT", dec!(2970)).unwrap();

        engine
            .submit_order(NewOrder {
                account_id: charlie.clone(),
                intent: OrderIntent {
                    client_order_id: "charlie-after-cutoff".into(),
                    symbol: "ETHUSDT".into(),
                    side: Side::Sell,
                    kind: OrderKind::Limit,
                    quantity: dec!(1),
                    price: Some(dec!(2970)),
                    leverage: 10,
                    time_in_force: TimeInForce::Gtc,
                    reduce_only: false,
                },
            })
            .unwrap();
        engine
            .state
            .private_batch_app_hashes
            .insert(BATCH_HEIGHT, [0xA5; 32]);
        let extensions = secret_shares
            .iter()
            .map(|secret_share| {
                VoteExtension::build(
                    &chain_id,
                    BATCH_HEIGHT,
                    [0xA5; 32],
                    &key_set,
                    secret_share,
                    &pending,
                    &mut OsRng,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let bundle = aggregate_vote_extensions(
            &chain_id,
            BATCH_HEIGHT,
            [0xA5; 32],
            &key_set,
            &pending,
            &extensions,
        )
        .unwrap();

        let execution = execute_private_decryption_bundle(
            &mut engine.state,
            &bundle,
            BATCH_HEIGHT + crate::private_protocol::PRIVATE_ORDER_DECRYPTION_DELAY_BLOCKS,
            [0x5A; 32],
        )
        .unwrap();

        let eth = execution
            .markets
            .iter()
            .find(|market| market.market_id == "ETHUSDT")
            .unwrap();
        assert_eq!(eth.matched_quantity, dec!(1));
        assert_eq!(
            engine.account(&alice).unwrap().positions["ETHUSDT"].quantity,
            dec!(2)
        );
        assert_eq!(
            engine.account(&bob).unwrap().positions["ETHUSDT"].quantity,
            dec!(-1)
        );
        assert_eq!(
            engine.account(&charlie).unwrap().positions["ETHUSDT"].quantity,
            dec!(-1)
        );
        assert!(engine.state.books["ETHUSDT"].active_orders().is_empty());
        assert!(
            !engine
                .state
                .private_batch_snapshots
                .contains_key(&BATCH_HEIGHT)
        );
    }

    #[test]
    fn trade_updates_both_accounts_and_preserves_reservations() {
        let mut engine = Engine::in_memory(default_markets());
        engine.credit_account("maker".into(), dec!(10000)).unwrap();
        engine.credit_account("taker".into(), dec!(10000)).unwrap();
        engine
            .submit_order(limit("maker", "m1", Side::Sell, dec!(1)))
            .unwrap();
        let result = engine
            .submit_order(limit("taker", "t1", Side::Buy, dec!(1)))
            .unwrap();
        assert_eq!(result.trades.len(), 1);

        let maker = engine.account("maker").unwrap();
        let taker = engine.account("taker").unwrap();
        assert_eq!(maker.positions["BTCUSDT"].quantity, dec!(-1));
        assert_eq!(taker.positions["BTCUSDT"].quantity, dec!(1));
        assert_eq!(maker.reserved_margin, Decimal::ZERO);
        assert_eq!(taker.reserved_margin, Decimal::ZERO);
        assert!(engine.state.event_log.verify());
        assert!(engine.audit().healthy, "{:?}", engine.audit().errors);
    }

    #[test]
    fn lazy_funding_settlements_balance_without_using_insurance() {
        let mut engine = Engine::in_memory(default_markets());
        engine.credit_account("short".into(), dec!(10000)).unwrap();
        engine.credit_account("long".into(), dec!(10000)).unwrap();
        engine
            .submit_order(limit("short", "funding-short", Side::Sell, dec!(1)))
            .unwrap();
        engine
            .submit_order(limit("long", "funding-long", Side::Buy, dec!(1)))
            .unwrap();

        let insurance_before = engine.state.insurance_fund;
        let (index, pool) = engine.apply_funding("BTCUSDT", dec!(0.001)).unwrap();
        assert_eq!(index, dec!(60));
        assert_eq!(pool, Decimal::ZERO);
        assert!(engine.audit().funding_pool_balanced);

        let long_payment = settle_account_funding(&mut engine.state, "long", "BTCUSDT").unwrap();
        assert_eq!(long_payment, dec!(60));
        assert_eq!(engine.state.funding_pool, dec!(60));
        assert_eq!(engine.state.insurance_fund, insurance_before);
        assert!(engine.audit().funding_pool_balanced);

        let short_payment = settle_account_funding(&mut engine.state, "short", "BTCUSDT").unwrap();
        assert_eq!(short_payment, dec!(-60));
        assert_eq!(engine.state.funding_pool, Decimal::ZERO);
        assert_eq!(engine.state.insurance_fund, insurance_before);
        assert!(engine.audit().healthy, "{:?}", engine.audit().errors);
    }

    #[test]
    fn terminal_order_indices_are_removed_and_client_ids_can_be_reused() {
        let mut engine = Engine::in_memory(default_markets());
        engine.credit_account("maker".into(), dec!(20000)).unwrap();
        engine.credit_account("taker".into(), dec!(20000)).unwrap();
        engine
            .submit_order(limit("maker", "reusable", Side::Sell, dec!(1)))
            .unwrap();
        engine
            .submit_order(limit("taker", "fill", Side::Buy, dec!(1)))
            .unwrap();

        assert!(engine.state.order_market.is_empty());
        assert!(engine.state.client_order_ids.is_empty());

        let replacement = engine
            .submit_order(limit("maker", "reusable", Side::Sell, dec!(1)))
            .unwrap();
        assert_eq!(engine.state.order_market.len(), 1);
        assert_eq!(
            engine.state.client_order_ids.get("maker:reusable"),
            Some(&replacement.order.id)
        );
    }

    #[test]
    fn cancellation_and_self_trade_prevention_clear_terminal_indices() {
        let mut engine = Engine::in_memory(default_markets());
        engine.credit_account("trader".into(), dec!(30000)).unwrap();

        let cancelled = engine
            .submit_order(limit("trader", "cancelled", Side::Buy, dec!(1)))
            .unwrap()
            .order;
        engine.cancel_order("trader", cancelled.id).unwrap();
        assert!(engine.state.order_market.is_empty());
        assert!(engine.state.client_order_ids.is_empty());

        engine
            .submit_order(limit("trader", "maker", Side::Sell, dec!(1)))
            .unwrap();
        let mut taker = limit("trader", "taker", Side::Buy, dec!(1));
        taker.intent.time_in_force = TimeInForce::Ioc;
        engine.submit_order(taker).unwrap();

        assert!(engine.state.order_market.is_empty());
        assert!(engine.state.client_order_ids.is_empty());
    }

    #[test]
    fn consensus_history_prunes_legacy_terminal_order_indices() {
        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        let terminal = Order {
            id: Uuid::from_bytes([9; 16]),
            account_id: "legacy".into(),
            client_order_id: "terminal".into(),
            symbol: "BTCUSDT".into(),
            side: Side::Buy,
            kind: OrderKind::Limit,
            quantity: dec!(1),
            remaining: Decimal::ZERO,
            limit_price: dec!(60000),
            leverage: 10,
            time_in_force: TimeInForce::Gtc,
            reduce_only: false,
            reserved_margin: Decimal::ZERO,
            sequence: 1,
            status: OrderStatus::Filled,
        };
        let mut serialized_book = serde_json::to_value(OrderBook::default()).unwrap();
        serialized_book["orders"] = serde_json::json!({
            terminal.id.to_string(): terminal.clone()
        });
        state.books.insert(
            "BTCUSDT".into(),
            serde_json::from_value(serialized_book).unwrap(),
        );
        state
            .order_market
            .insert(terminal.id, terminal.symbol.clone());
        state
            .client_order_ids
            .insert("legacy:terminal".into(), terminal.id);

        prune_consensus_history(&mut state);

        assert!(state.books["BTCUSDT"].order(terminal.id).is_none());
        assert!(state.order_market.is_empty());
        assert!(state.client_order_ids.is_empty());
    }

    #[test]
    fn rejected_order_rolls_back_state() {
        let mut engine = Engine::in_memory(default_markets());
        engine.credit_account("poor".into(), dec!(1)).unwrap();
        let before = engine.state.sequence;
        let error = engine
            .submit_order(limit("poor", "too-large", Side::Buy, dec!(1)))
            .unwrap_err();
        assert!(matches!(error, ExchangeError::InsufficientMargin { .. }));
        assert_eq!(engine.state.sequence, before);
        assert_eq!(
            engine.account("poor").unwrap().reserved_margin,
            Decimal::ZERO
        );
    }

    #[test]
    fn extreme_limit_price_is_rejected_before_it_can_create_bad_debt() {
        let mut engine = Engine::in_memory(default_markets());
        engine
            .credit_account("attacker-long".into(), dec!(0.02))
            .unwrap();
        engine
            .credit_account("attacker-short".into(), dec!(0.02))
            .unwrap();
        let sequence = engine.state.sequence;

        for (account_id, side) in [("attacker-long", Side::Buy), ("attacker-short", Side::Sell)] {
            let mut order = limit(account_id, "extreme-price", side, dec!(1));
            order.intent.price = Some(dec!(0.1));
            order.intent.leverage = 50;
            let error = engine.submit_order(order).unwrap_err();
            assert!(
                matches!(error, ExchangeError::InvalidOrder(message) if message.contains("mark-price band"))
            );
        }

        assert_eq!(engine.state.sequence, sequence);
        assert!(engine.state.order_market.is_empty());
        assert_eq!(
            engine.account("attacker-long").unwrap().reserved_margin,
            dec!(0)
        );
        assert_eq!(
            engine.account("attacker-short").unwrap().reserved_margin,
            dec!(0)
        );
        assert_eq!(engine.state.insurance_fund, dec!(0));
    }

    #[test]
    fn bad_debt_waterfall_never_commits_a_negative_protocol_reserve() {
        let mut state = EngineState::genesis("bad-debt-test", default_markets());
        for (account_id, collateral) in [
            ("debtor", dec!(-100)),
            ("backstop-a", dec!(100)),
            ("backstop-b", dec!(100)),
        ] {
            let mut account = Account::new(account_id.into());
            account.collateral = collateral;
            state.accounts.insert(account_id.into(), account);
        }
        state.insurance_fund = dec!(20);
        state.fee_vault = dec!(10);
        state.total_credits = dec!(130);

        let coverage = cover_bad_debt(&mut state, "debtor", dec!(100)).unwrap();

        assert_eq!(coverage.insurance_used, dec!(20));
        assert_eq!(coverage.fee_vault_used, dec!(10));
        assert_eq!(
            coverage
                .socialized_losses
                .iter()
                .map(|loss| loss.amount)
                .sum::<Decimal>(),
            dec!(70)
        );
        assert_eq!(state.insurance_fund, Decimal::ZERO);
        assert_eq!(state.fee_vault, Decimal::ZERO);
        assert_eq!(state.accounts["debtor"].collateral, Decimal::ZERO);
        assert_eq!(state.accounts["backstop-a"].collateral, dec!(30));
        assert_eq!(state.accounts["backstop-b"].collateral, dec!(100));
        assert!(
            audit_state(&state).healthy,
            "{:?}",
            audit_state(&state).errors
        );

        let mut insolvent = EngineState::genesis("insolvent-test", default_markets());
        let mut debtor = Account::new("debtor".into());
        debtor.collateral = dec!(-10);
        insolvent.accounts.insert("debtor".into(), debtor);
        let before = insolvent.clone();
        assert!(matches!(
            cover_bad_debt(&mut insolvent, "debtor", dec!(10)),
            Err(ExchangeError::InsufficientMargin { .. })
        ));
        assert_eq!(insolvent, before);
    }

    #[test]
    fn social_loss_protects_maintenance_margin_and_strict_liquidation_buffer() {
        let mut state = EngineState::genesis("maintenance-social-loss", default_markets());
        let mut debtor = Account::new("debtor".into());
        debtor.collateral = dec!(-100);
        state.accounts.insert(debtor.id.clone(), debtor);

        let mut backstop = Account::new("backstop".into());
        backstop.collateral = dec!(400);
        backstop.positions.insert(
            "BTCUSDT".into(),
            crate::domain::Position {
                quantity: dec!(1),
                entry_price: dec!(60000),
                initial_margin: dec!(100),
                ..Default::default()
            },
        );
        state.accounts.insert(backstop.id.clone(), backstop);
        state.total_credits = dec!(300);

        let before = state.clone();
        assert!(matches!(
            cover_bad_debt(&mut state, "debtor", dec!(100)),
            Err(ExchangeError::InsufficientMargin { .. })
        ));
        assert_eq!(state, before);

        state.insurance_fund = SOCIAL_LOSS_SAFETY_EPSILON;
        state.total_credits = dec!(300.00000001);
        let coverage = cover_bad_debt(&mut state, "debtor", dec!(100)).unwrap();
        assert_eq!(coverage.insurance_used, SOCIAL_LOSS_SAFETY_EPSILON);
        assert_eq!(
            coverage.socialized_losses,
            vec![SocializedLoss {
                account_id: "backstop".into(),
                amount: dec!(99.99999999),
            }]
        );

        let risk = state.accounts["backstop"]
            .risk_snapshot(state.markets.iter())
            .unwrap();
        assert_eq!(risk.position_margin, dec!(100));
        assert_eq!(risk.maintenance_requirement, dec!(300));
        assert_eq!(risk.equity, dec!(300.00000001));
        assert!(!risk.liquidation_risk);
        assert!(risk.available_margin >= SOCIAL_LOSS_SAFETY_EPSILON);
        assert_eq!(audit_state(&state).conservation_difference, Decimal::ZERO);
    }

    #[test]
    fn social_loss_uses_every_required_account_beyond_sixty_four() {
        let mut state = EngineState::genesis("many-social-loss-accounts", default_markets());
        let mut debtor = Account::new("debtor".into());
        debtor.collateral = dec!(-65);
        state.accounts.insert(debtor.id.clone(), debtor);
        for index in 0..65 {
            let account_id = format!("backstop-{index:02}");
            let mut account = Account::new(account_id.clone());
            account.collateral = dec!(1.00000001);
            state.accounts.insert(account_id, account);
        }
        state.total_credits = dec!(0.00000065);

        let coverage = cover_bad_debt(&mut state, "debtor", dec!(65)).unwrap();

        assert_eq!(coverage.socialized_losses.len(), 65);
        assert_eq!(
            coverage
                .socialized_losses
                .iter()
                .map(|loss| loss.amount)
                .sum::<Decimal>(),
            dec!(65)
        );
        for index in 0..65 {
            let account_id = format!("backstop-{index:02}");
            let risk = state.accounts[&account_id]
                .risk_snapshot(state.markets.iter())
                .unwrap();
            assert_eq!(risk.available_margin, SOCIAL_LOSS_SAFETY_EPSILON);
            assert!(!risk.liquidation_risk);
        }
        assert!(
            audit_state(&state).healthy,
            "{:?}",
            audit_state(&state).errors
        );
    }

    #[test]
    fn reservation_covers_initial_margin_fee_and_adverse_mark_loss() {
        let mut engine = Engine::in_memory(default_markets());
        engine.credit_account("maker".into(), dec!(2000)).unwrap();
        engine
            .credit_account("taker".into(), dec!(1833.21))
            .unwrap();

        let mut maker = limit("maker", "upper-band-maker", Side::Sell, dec!(1));
        maker.intent.price = Some(dec!(60600));
        maker.intent.leverage = 50;
        engine.submit_order(maker).unwrap();

        let mut taker = limit("taker", "upper-band-taker", Side::Buy, dec!(1));
        taker.intent.price = Some(dec!(60600));
        taker.intent.leverage = 50;
        let result = engine.submit_order(taker).unwrap();

        assert_eq!(result.trades.len(), 1);
        assert_eq!(engine.risk("taker").unwrap().available_margin, dec!(0));
        assert!(engine.audit().healthy, "{:?}", engine.audit().errors);

        let market = &engine.state.markets["BTCUSDT"];
        assert_eq!(
            required_order_reservation(Side::Sell, dec!(1), dec!(59400), 50, true, market).unwrap(),
            dec!(620.79)
        );
    }

    #[test]
    fn post_fill_risk_check_atomically_rejects_legacy_poisoned_liquidity() {
        let mut engine = Engine::in_memory(default_markets());
        engine
            .credit_account("legacy-maker".into(), dec!(0.02))
            .unwrap();
        engine.credit_account("taker".into(), dec!(2000)).unwrap();

        let poisoned = Order {
            id: Uuid::from_bytes([0x42; 16]),
            account_id: "legacy-maker".into(),
            client_order_id: "legacy-poison".into(),
            symbol: "BTCUSDT".into(),
            side: Side::Sell,
            kind: OrderKind::Limit,
            quantity: dec!(1),
            remaining: dec!(1),
            limit_price: dec!(0.1),
            leverage: 50,
            time_in_force: TimeInForce::Gtc,
            reduce_only: false,
            reserved_margin: dec!(0.02),
            sequence: engine.state.sequence,
            status: OrderStatus::Open,
        };
        engine
            .state
            .accounts
            .get_mut("legacy-maker")
            .unwrap()
            .reserved_margin = poisoned.reserved_margin;
        engine
            .state
            .order_market
            .insert(poisoned.id, poisoned.symbol.clone());
        engine
            .state
            .client_order_ids
            .insert("legacy-maker:legacy-poison".into(), poisoned.id);
        engine
            .state
            .books
            .get_mut("BTCUSDT")
            .unwrap()
            .execute(poisoned.clone());
        let sequence = engine.state.sequence;

        let mut taker = limit("taker", "cross-poison", Side::Buy, dec!(1));
        taker.intent.leverage = 50;
        let error = engine.submit_order(taker).unwrap_err();

        assert!(matches!(error, ExchangeError::InsufficientMargin { .. }));
        assert_eq!(engine.state.sequence, sequence);
        assert!(engine.state.books["BTCUSDT"].order(poisoned.id).is_some());
        assert!(
            !engine
                .account("taker")
                .unwrap()
                .positions
                .contains_key("BTCUSDT")
        );
        assert_eq!(engine.account("taker").unwrap().reserved_margin, dec!(0));
        assert_eq!(engine.state.insurance_fund, dec!(0));
    }

    #[test]
    fn oracle_change_cancels_resting_orders_with_stale_risk_reservations() {
        let mut engine = Engine::in_memory(default_markets());
        engine.credit_account("maker".into(), dec!(10000)).unwrap();
        let order = engine
            .submit_order(limit("maker", "stale-after-oracle", Side::Buy, dec!(1)))
            .unwrap()
            .order;
        assert!(engine.account("maker").unwrap().reserved_margin > dec!(0));

        engine
            .publish_oracle_price(
                "BTCUSDT",
                vec![
                    OracleObservation {
                        source: "a".into(),
                        price: dec!(59400),
                        weight: 1,
                    },
                    OracleObservation {
                        source: "b".into(),
                        price: dec!(59400),
                        weight: 1,
                    },
                    OracleObservation {
                        source: "c".into(),
                        price: dec!(59400),
                        weight: 1,
                    },
                ],
            )
            .unwrap();

        assert!(engine.state.books["BTCUSDT"].order(order.id).is_none());
        assert_eq!(engine.account("maker").unwrap().reserved_margin, dec!(0));
        assert!(!engine.state.order_market.contains_key(&order.id));
        assert!(
            !engine
                .state
                .client_order_ids
                .contains_key("maker:stale-after-oracle")
        );
    }

    #[test]
    fn oracle_uses_weighted_median_and_rejects_divergent_sources() {
        let mut engine = Engine::in_memory(default_markets());
        let snapshot = engine
            .publish_oracle_price(
                "BTCUSDT",
                vec![
                    OracleObservation {
                        source: "a".into(),
                        price: dec!(60000),
                        weight: 1,
                    },
                    OracleObservation {
                        source: "b".into(),
                        price: dec!(60010),
                        weight: 3,
                    },
                    OracleObservation {
                        source: "c".into(),
                        price: dec!(60020),
                        weight: 1,
                    },
                ],
            )
            .unwrap();
        assert_eq!(snapshot.price, dec!(60010));

        let error = engine
            .publish_oracle_price(
                "BTCUSDT",
                vec![
                    OracleObservation {
                        source: "a".into(),
                        price: dec!(50000),
                        weight: 1,
                    },
                    OracleObservation {
                        source: "b".into(),
                        price: dec!(60000),
                        weight: 1,
                    },
                    OracleObservation {
                        source: "c".into(),
                        price: dec!(70000),
                        weight: 1,
                    },
                ],
            )
            .unwrap_err();
        assert!(matches!(error, ExchangeError::InvalidOrder(_)));
    }

    #[test]
    fn liquidation_closes_position_and_preserves_assets() {
        let mut engine = Engine::in_memory(default_markets());
        engine.credit_account("short".into(), dec!(1000)).unwrap();
        engine.credit_account("target".into(), dec!(130)).unwrap();
        engine
            .submit_order(limit("short", "open-short", Side::Sell, dec!(0.1)))
            .unwrap();
        let mut target_order = limit("target", "open-long", Side::Buy, dec!(0.1));
        target_order.intent.leverage = 50;
        engine.submit_order(target_order).unwrap();
        engine.set_mark_price("BTCUSDT", dec!(59000)).unwrap();
        assert!(engine.risk("target").unwrap().liquidation_risk);

        engine
            .credit_account("liquidator".into(), dec!(1000))
            .unwrap();
        let mut bid = limit("liquidator", "liq-bid", Side::Buy, dec!(0.1));
        bid.intent.price = Some(dec!(59000));
        engine.submit_order(bid).unwrap();
        let result = engine.liquidate("target", "BTCUSDT").unwrap();

        assert_eq!(result.closed_quantity, dec!(0.1));
        assert_eq!(result.remaining_quantity, Decimal::ZERO);
        assert_eq!(engine.account("target").unwrap().collateral, Decimal::ZERO);
        assert!(engine.state.order_market.is_empty());
        assert!(engine.state.client_order_ids.is_empty());
        assert!(engine.audit().healthy, "{:?}", engine.audit().errors);
    }

    #[test]
    fn audit_reports_numeric_overflow_without_panicking() {
        let mut state = EngineState::genesis("asteria-test-1", default_markets());
        let mut account = Account::new("overflow".into());
        account.positions.insert(
            "BTCUSDT".into(),
            crate::domain::Position {
                quantity: Decimal::MAX,
                entry_price: Decimal::ZERO,
                initial_margin: Decimal::MAX,
                realized_pnl: Decimal::ZERO,
                funding_pnl: Decimal::ZERO,
                funding_index: Decimal::ZERO,
            },
        );
        state.accounts.insert(account.id.clone(), account);

        let report = std::panic::catch_unwind(|| audit_engine_state(&state))
            .expect("audit must convert Decimal overflow into an unhealthy report");
        assert!(!report.healthy);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("numeric overflow")),
            "{:?}",
            report.errors
        );
    }
}
