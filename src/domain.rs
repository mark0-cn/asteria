use std::collections::BTreeMap;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type AccountId = String;
pub type Symbol = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    pub fn sign(self) -> Decimal {
        match self {
            Self::Buy => Decimal::ONE,
            Self::Sell => Decimal::NEGATIVE_ONE,
        }
    }

    pub fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderKind {
    Limit,
    Market,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeInForce {
    #[default]
    Gtc,
    Ioc,
    Fok,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Open,
    PartiallyFilled,
    Filled,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderIntent {
    pub client_order_id: String,
    pub symbol: Symbol,
    pub side: Side,
    pub kind: OrderKind,
    pub quantity: Decimal,
    pub price: Option<Decimal>,
    pub leverage: u16,
    #[serde(default)]
    pub time_in_force: TimeInForce,
    #[serde(default)]
    pub reduce_only: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewOrder {
    pub account_id: AccountId,
    #[serde(flatten)]
    pub intent: OrderIntent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Order {
    pub id: Uuid,
    pub account_id: AccountId,
    pub client_order_id: String,
    pub symbol: Symbol,
    pub side: Side,
    pub kind: OrderKind,
    pub quantity: Decimal,
    pub remaining: Decimal,
    pub limit_price: Decimal,
    pub leverage: u16,
    pub time_in_force: TimeInForce,
    pub reduce_only: bool,
    pub reserved_margin: Decimal,
    pub sequence: u64,
    pub status: OrderStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trade {
    pub id: Uuid,
    pub symbol: Symbol,
    pub price: Decimal,
    pub quantity: Decimal,
    pub maker_order_id: Uuid,
    pub taker_order_id: Uuid,
    pub maker_account_id: AccountId,
    pub taker_account_id: AccountId,
    pub taker_side: Side,
    pub maker_fee: Decimal,
    pub taker_fee: Decimal,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Position {
    /// Positive quantity is long; negative quantity is short.
    pub quantity: Decimal,
    pub entry_price: Decimal,
    pub initial_margin: Decimal,
    pub realized_pnl: Decimal,
    pub funding_pnl: Decimal,
    #[serde(default)]
    pub funding_index: Decimal,
}

impl Default for Position {
    fn default() -> Self {
        Self {
            quantity: Decimal::ZERO,
            entry_price: Decimal::ZERO,
            initial_margin: Decimal::ZERO,
            realized_pnl: Decimal::ZERO,
            funding_pnl: Decimal::ZERO,
            funding_index: Decimal::ZERO,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub collateral: Decimal,
    pub reserved_margin: Decimal,
    pub fees_paid: Decimal,
    pub positions: BTreeMap<Symbol, Position>,
}

impl Account {
    pub fn new(id: AccountId) -> Self {
        Self {
            id,
            collateral: Decimal::ZERO,
            reserved_margin: Decimal::ZERO,
            fees_paid: Decimal::ZERO,
            positions: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MarketConfig {
    pub symbol: Symbol,
    pub tick_size: Decimal,
    pub quantity_step: Decimal,
    pub min_quantity: Decimal,
    pub max_leverage: u16,
    pub maintenance_margin_ratio: Decimal,
    pub maker_fee_rate: Decimal,
    pub taker_fee_rate: Decimal,
    pub market_slippage_limit: Decimal,
    pub liquidation_penalty_rate: Decimal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MarketState {
    pub config: MarketConfig,
    pub mark_price: Decimal,
    pub funding_rate: Decimal,
    #[serde(default)]
    pub funding_index: Decimal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriceLevel {
    pub price: Decimal,
    pub quantity: Decimal,
    pub order_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BookSnapshot {
    pub symbol: Symbol,
    pub sequence: u64,
    pub bids: Vec<PriceLevel>,
    pub asks: Vec<PriceLevel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderResult {
    pub order: Order,
    pub trades: Vec<Trade>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskSnapshot {
    pub account_id: AccountId,
    pub collateral: Decimal,
    pub unrealized_pnl: Decimal,
    pub equity: Decimal,
    pub position_margin: Decimal,
    pub reserved_margin: Decimal,
    pub maintenance_requirement: Decimal,
    pub available_margin: Decimal,
    pub liquidation_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CancelIntent {
    pub order_id: Uuid,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OracleObservation {
    pub source: String,
    pub price: Decimal,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OracleSnapshot {
    pub symbol: Symbol,
    pub price: Decimal,
    pub observations: Vec<OracleObservation>,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiquidationResult {
    pub account_id: AccountId,
    pub symbol: Symbol,
    pub closed_quantity: Decimal,
    pub remaining_quantity: Decimal,
    pub penalty: Decimal,
    pub bad_debt: Decimal,
    pub insurance_used: Decimal,
    pub fee_vault_used: Decimal,
    pub socialized_losses: Vec<SocializedLoss>,
    pub trades: Vec<Trade>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SocializedLoss {
    pub account_id: AccountId,
    pub amount: Decimal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditReport {
    pub healthy: bool,
    pub event_chain_valid: bool,
    pub reservations_consistent: bool,
    pub open_interest_balanced: bool,
    pub total_credits: Decimal,
    pub account_equity: Decimal,
    pub shielded_collateral: Decimal,
    pub fee_vault: Decimal,
    pub insurance_fund: Decimal,
    pub funding_pool: Decimal,
    pub funding_pool_balanced: bool,
    pub conservation_difference: Decimal,
    pub errors: Vec<String>,
}
