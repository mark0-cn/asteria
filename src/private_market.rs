//! Adapter between decimal market inputs and the fixed-point batch auction.
//!
//! Consensus-facing auction arithmetic remains integer-only. Decimal values
//! are accepted only when they are exact multiples of the configured tick or
//! quantity step; this module never rounds a price or quantity.

use std::collections::{BTreeMap, BTreeSet};

use rust_decimal::Decimal;
use sha2::{Digest, Sha256};

use crate::{
    batch_auction::{
        AllocationStatus, AuctionConfig, AuctionError, AuctionOrder, OrderId,
        OrderKind as AuctionOrderKind, Price, Quantity, Side as AuctionSide,
        TimeInForce as AuctionTimeInForce, clear_batch,
    },
    domain::{
        AccountId, MarketConfig, OrderKind as DomainOrderKind, Side as DomainSide,
        TimeInForce as DomainTimeInForce,
    },
};

const ALLOCATION_COMMITMENT_DOMAIN: &[u8] = b"ASTERIA_PRIVATE_MARKET_ALLOCATION_COMMITMENT_V2\0";
const MAX_CHAIN_ID_BYTES: usize = 128;
const MAX_MARKET_ID_BYTES: usize = 64;

pub type CiphertextId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipantVisibility {
    Public,
    Private { ciphertext_id: CiphertextId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchParticipant {
    pub visibility: ParticipantVisibility,
    pub account_id: AccountId,
    pub order_id: OrderId,
    pub side: DomainSide,
    pub kind: DomainOrderKind,
    pub time_in_force: DomainTimeInForce,
    pub quantity: Decimal,
    pub limit_price: Option<Decimal>,
    pub leverage: u16,
    pub reduce_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchContext {
    pub chain_id: String,
    pub height: u64,
    pub threshold_beacon: [u8; 32],
    pub reference_price: Decimal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantAllocation {
    pub participant: BatchParticipant,
    pub executed_lots: Quantity,
    pub executed_quantity: Decimal,
    pub status: AllocationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchFill {
    pub buy_order_id: OrderId,
    pub sell_order_id: OrderId,
    pub buy_account_id: AccountId,
    pub sell_account_id: AccountId,
    pub price_ticks: Price,
    pub price: Decimal,
    pub quantity_lots: Quantity,
    pub quantity: Decimal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateBatchOutcome {
    pub allocation_commitment: [u8; 32],
    pub clearing_price_ticks: Option<Price>,
    pub clearing_price: Option<Decimal>,
    pub matched_lots: Quantity,
    pub matched_quantity: Decimal,
    pub imbalance_lots: Quantity,
    /// Sorted by order ID, independent of participant input order.
    pub allocations: Vec<ParticipantAllocation>,
    /// Deterministic buy/sell pairing, sorted by order IDs on each side.
    pub fills: Vec<BatchFill>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PrivateMarketError {
    #[error("chain id must contain between 1 and {MAX_CHAIN_ID_BYTES} bytes")]
    InvalidChainId,
    #[error("batch height must be greater than zero")]
    ZeroHeight,
    #[error("market id must contain between 1 and {MAX_MARKET_ID_BYTES} bytes")]
    InvalidMarketId,
    #[error("threshold beacon must not be the identity encoding")]
    InvalidThresholdBeacon,
    #[error("{field} step must be positive")]
    NonPositiveStep { field: &'static str },
    #[error("market slippage limit must be between zero and one")]
    InvalidSlippageLimit,
    #[error("{field} must not be negative")]
    NegativeValue { field: &'static str },
    #[error("{field} value {value} is not an exact multiple of step {step}")]
    NotStepAligned {
        field: &'static str,
        value: Decimal,
        step: Decimal,
    },
    #[error("{field} value does not fit in u64 fixed-point units")]
    UnitOverflow { field: &'static str },
    #[error("{field} fixed-point units cannot be represented as Decimal")]
    DecimalOverflow { field: &'static str },
    #[error("duplicate private ciphertext id")]
    DuplicateCiphertextId,
    #[error("invalid participant {order_id:?}: {reason}")]
    InvalidParticipant {
        order_id: OrderId,
        reason: &'static str,
    },
    #[error("auction failed: {0}")]
    Auction(#[from] AuctionError),
    #[error("auction omitted allocation for order {0:?}")]
    MissingAllocation(OrderId),
    #[error("auction returned allocation for unknown order {0:?}")]
    UnknownAllocation(OrderId),
    #[error("auction allocation violates FOK atomicity for order {0:?}")]
    FokNotAtomic(OrderId),
    #[error("buy and sell execution quantities are not conserved")]
    AllocationConservation,
    #[error("deterministic fill pairing did not consume the matched quantity")]
    FillConservation,
    #[error("checked arithmetic overflow while adapting the auction result")]
    ArithmeticOverflow,
}

pub type Result<T, E = PrivateMarketError> = std::result::Result<T, E>;

/// Converts an exact decimal price to integer market ticks.
pub fn price_to_ticks(price: Decimal, market: &MarketConfig) -> Result<Price> {
    decimal_to_units(price, market.tick_size, "price")
}

/// Converts integer market ticks back to an exact decimal price.
pub fn ticks_to_price(ticks: Price, market: &MarketConfig) -> Result<Decimal> {
    units_to_decimal(ticks, market.tick_size, "price")
}

/// Converts an exact decimal quantity to integer market lots.
pub fn quantity_to_lots(quantity: Decimal, market: &MarketConfig) -> Result<Quantity> {
    decimal_to_units(quantity, market.quantity_step, "quantity")
}

/// Converts integer market lots back to an exact decimal quantity.
pub fn lots_to_quantity(lots: Quantity, market: &MarketConfig) -> Result<Decimal> {
    units_to_decimal(lots, market.quantity_step, "quantity")
}

/// Derives the pro-rata allocation seed solely from the verified, post-cutoff
/// threshold beacon and immutable auction context.
pub fn allocation_commitment(
    chain_id: &str,
    height: u64,
    market_id: &str,
    threshold_beacon: [u8; 32],
) -> Result<[u8; 32]> {
    if chain_id.is_empty() || chain_id.len() > MAX_CHAIN_ID_BYTES {
        return Err(PrivateMarketError::InvalidChainId);
    }
    if height == 0 {
        return Err(PrivateMarketError::ZeroHeight);
    }
    if market_id.is_empty() || market_id.len() > MAX_MARKET_ID_BYTES {
        return Err(PrivateMarketError::InvalidMarketId);
    }
    if threshold_beacon == [0; 32] {
        return Err(PrivateMarketError::InvalidThresholdBeacon);
    }

    let chain_length =
        u64::try_from(chain_id.len()).map_err(|_| PrivateMarketError::ArithmeticOverflow)?;
    let market_length =
        u64::try_from(market_id.len()).map_err(|_| PrivateMarketError::ArithmeticOverflow)?;

    let mut hasher = Sha256::new();
    hasher.update(ALLOCATION_COMMITMENT_DOMAIN);
    hasher.update(chain_length.to_be_bytes());
    hasher.update(chain_id.as_bytes());
    hasher.update(height.to_be_bytes());
    hasher.update(market_length.to_be_bytes());
    hasher.update(market_id.as_bytes());
    hasher.update(threshold_beacon);
    Ok(hasher.finalize().into())
}

/// Converts participants to integer orders, clears the uniform-price batch,
/// restores exact decimal allocations, and produces deterministic settlement
/// fills.
pub fn clear_private_batch(
    market: &MarketConfig,
    context: &BatchContext,
    participants: &[BatchParticipant],
) -> Result<PrivateBatchOutcome> {
    validate_market_steps(market)?;
    let reference_price_ticks = price_to_ticks(context.reference_price, market)?;

    let mut seen_ciphertexts = BTreeSet::new();
    let mut auction_orders = Vec::with_capacity(participants.len());
    for participant in participants {
        if let ParticipantVisibility::Private { ciphertext_id } = participant.visibility
            && !seen_ciphertexts.insert(ciphertext_id)
        {
            return Err(PrivateMarketError::DuplicateCiphertextId);
        }
        auction_orders.push(to_auction_order(
            market,
            reference_price_ticks,
            participant,
        )?);
    }

    let commitment = allocation_commitment(
        &context.chain_id,
        context.height,
        &market.symbol,
        context.threshold_beacon,
    )?;
    let auction = clear_batch(
        AuctionConfig {
            reference_price: reference_price_ticks,
            allocation_commitment: commitment,
        },
        &auction_orders,
    )?;

    let participant_by_id = participants
        .iter()
        .map(|participant| (participant.order_id, participant))
        .collect::<BTreeMap<_, _>>();
    if participant_by_id.len() != participants.len() {
        // `clear_batch` also checks this, but reporting it here avoids relying
        // on the adapter's input order if this invariant changes upstream.
        let duplicate = participants
            .iter()
            .find(|participant| {
                participants
                    .iter()
                    .filter(|other| other.order_id == participant.order_id)
                    .count()
                    > 1
            })
            .expect("a duplicate exists");
        return Err(PrivateMarketError::InvalidParticipant {
            order_id: duplicate.order_id,
            reason: "duplicate order id",
        });
    }

    let mut allocation_by_id = BTreeMap::new();
    for allocation in &auction.allocations {
        if !participant_by_id.contains_key(&allocation.order_id) {
            return Err(PrivateMarketError::UnknownAllocation(allocation.order_id));
        }
        allocation_by_id.insert(allocation.order_id, allocation);
    }

    let mut restored = Vec::with_capacity(participants.len());
    let mut buy_lots = 0_u64;
    let mut sell_lots = 0_u64;
    for (order_id, participant) in participant_by_id {
        let allocation = allocation_by_id
            .remove(&order_id)
            .ok_or(PrivateMarketError::MissingAllocation(order_id))?;
        if participant.time_in_force == DomainTimeInForce::Fok
            && allocation.executed_quantity != 0
            && allocation.executed_quantity != quantity_to_lots(participant.quantity, market)?
        {
            return Err(PrivateMarketError::FokNotAtomic(order_id));
        }
        let side_total = match participant.side {
            DomainSide::Buy => &mut buy_lots,
            DomainSide::Sell => &mut sell_lots,
        };
        *side_total = side_total
            .checked_add(allocation.executed_quantity)
            .ok_or(PrivateMarketError::ArithmeticOverflow)?;
        restored.push(ParticipantAllocation {
            participant: participant.clone(),
            executed_lots: allocation.executed_quantity,
            executed_quantity: lots_to_quantity(allocation.executed_quantity, market)?,
            status: allocation.status,
        });
    }
    if !allocation_by_id.is_empty() {
        return Err(PrivateMarketError::UnknownAllocation(
            *allocation_by_id
                .first_key_value()
                .expect("map is not empty")
                .0,
        ));
    }
    if buy_lots != sell_lots || buy_lots != auction.matched_quantity {
        return Err(PrivateMarketError::AllocationConservation);
    }

    let clearing_price = auction
        .clearing_price
        .map(|price| ticks_to_price(price, market))
        .transpose()?;
    let fills = pair_fills(
        market,
        &restored,
        auction.clearing_price,
        clearing_price,
        auction.matched_quantity,
    )?;

    Ok(PrivateBatchOutcome {
        allocation_commitment: commitment,
        clearing_price_ticks: auction.clearing_price,
        clearing_price,
        matched_lots: auction.matched_quantity,
        matched_quantity: lots_to_quantity(auction.matched_quantity, market)?,
        imbalance_lots: auction.imbalance,
        allocations: restored,
        fills,
    })
}

fn validate_market_steps(market: &MarketConfig) -> Result<()> {
    validate_step(market.tick_size, "price")?;
    validate_step(market.quantity_step, "quantity")?;
    if market.market_slippage_limit < Decimal::ZERO || market.market_slippage_limit > Decimal::ONE {
        return Err(PrivateMarketError::InvalidSlippageLimit);
    }
    let minimum_lots = quantity_to_lots(market.min_quantity, market)?;
    if minimum_lots == 0 {
        return Err(PrivateMarketError::NonPositiveStep {
            field: "minimum quantity",
        });
    }
    Ok(())
}

fn to_auction_order(
    market: &MarketConfig,
    reference_price: Price,
    participant: &BatchParticipant,
) -> Result<AuctionOrder> {
    if participant.account_id.is_empty() {
        return Err(invalid_participant(participant, "account id is empty"));
    }
    if participant.leverage == 0 || participant.leverage > market.max_leverage {
        return Err(invalid_participant(
            participant,
            "leverage is outside market bounds",
        ));
    }
    let quantity = quantity_to_lots(participant.quantity, market)?;
    let minimum_quantity = quantity_to_lots(market.min_quantity, market)?;
    if quantity < minimum_quantity {
        return Err(invalid_participant(
            participant,
            "quantity is below the market minimum",
        ));
    }

    let kind = match (participant.kind, participant.limit_price) {
        (DomainOrderKind::Limit, Some(price)) => AuctionOrderKind::Limit {
            price: price_to_ticks(price, market)?,
        },
        (DomainOrderKind::Limit, None) => {
            return Err(invalid_participant(
                participant,
                "limit order requires a price",
            ));
        }
        (DomainOrderKind::Market, None) => AuctionOrderKind::Market {
            protection_price: market_protection_price(
                reference_price,
                market.market_slippage_limit,
                participant.side,
            )?,
        },
        (DomainOrderKind::Market, Some(_)) => {
            return Err(invalid_participant(
                participant,
                "market order must not include a limit price",
            ));
        }
    };
    let time_in_force = match participant.time_in_force {
        DomainTimeInForce::Ioc => AuctionTimeInForce::Ioc,
        DomainTimeInForce::Fok => AuctionTimeInForce::Fok,
        DomainTimeInForce::Gtc
            if matches!(participant.visibility, ParticipantVisibility::Public) =>
        {
            // The auction allocation is only this batch's executable slice.
            // The caller keeps the public order's unfilled remainder resting.
            AuctionTimeInForce::Ioc
        }
        DomainTimeInForce::Gtc => {
            return Err(invalid_participant(
                participant,
                "private batch orders support only IOC or FOK",
            ));
        }
    };

    Ok(AuctionOrder {
        id: participant.order_id,
        side: match participant.side {
            DomainSide::Buy => AuctionSide::Buy,
            DomainSide::Sell => AuctionSide::Sell,
        },
        kind,
        time_in_force,
        quantity,
    })
}

fn market_protection_price(
    reference_price: Price,
    slippage_limit: Decimal,
    side: DomainSide,
) -> Result<Price> {
    let factor = match side {
        DomainSide::Buy => Decimal::ONE.checked_add(slippage_limit),
        DomainSide::Sell => Decimal::ONE.checked_sub(slippage_limit),
    }
    .ok_or(PrivateMarketError::ArithmeticOverflow)?;
    scale_price_ticks(reference_price, factor, side == DomainSide::Sell)
}

fn scale_price_ticks(reference_price: Price, factor: Decimal, round_up: bool) -> Result<Price> {
    let mut reference = u128::from(reference_price);
    let mut numerator =
        u128::try_from(factor.mantissa()).map_err(|_| PrivateMarketError::ArithmeticOverflow)?;
    let mut denominator = power_of_ten(factor.scale())?;

    let factor_cancellation = gcd(numerator, denominator);
    numerator /= factor_cancellation;
    denominator /= factor_cancellation;
    let reference_cancellation = gcd(reference, denominator);
    reference /= reference_cancellation;
    denominator /= reference_cancellation;

    let product = reference
        .checked_mul(numerator)
        .ok_or(PrivateMarketError::ArithmeticOverflow)?;
    let mut scaled = product / denominator;
    if round_up && product % denominator != 0 {
        scaled = scaled
            .checked_add(1)
            .ok_or(PrivateMarketError::ArithmeticOverflow)?;
    }
    u64::try_from(scaled).map_err(|_| PrivateMarketError::ArithmeticOverflow)
}

fn invalid_participant(participant: &BatchParticipant, reason: &'static str) -> PrivateMarketError {
    PrivateMarketError::InvalidParticipant {
        order_id: participant.order_id,
        reason,
    }
}

fn pair_fills(
    market: &MarketConfig,
    allocations: &[ParticipantAllocation],
    clearing_price_ticks: Option<Price>,
    clearing_price: Option<Decimal>,
    matched_lots: Quantity,
) -> Result<Vec<BatchFill>> {
    if matched_lots == 0 {
        if clearing_price_ticks.is_some() || clearing_price.is_some() {
            return Err(PrivateMarketError::FillConservation);
        }
        return Ok(Vec::new());
    }
    let price_ticks = clearing_price_ticks.ok_or(PrivateMarketError::FillConservation)?;
    let price = clearing_price.ok_or(PrivateMarketError::FillConservation)?;

    let mut buys = allocations
        .iter()
        .filter(|allocation| {
            allocation.participant.side == DomainSide::Buy && allocation.executed_lots > 0
        })
        .map(|allocation| (allocation, allocation.executed_lots))
        .collect::<Vec<_>>();
    let mut sells = allocations
        .iter()
        .filter(|allocation| {
            allocation.participant.side == DomainSide::Sell && allocation.executed_lots > 0
        })
        .map(|allocation| (allocation, allocation.executed_lots))
        .collect::<Vec<_>>();
    buys.sort_by_key(|(allocation, _)| allocation.participant.order_id);
    sells.sort_by_key(|(allocation, _)| allocation.participant.order_id);

    let mut buy_index = 0;
    let mut sell_index = 0;
    let mut paired_lots = 0_u64;
    let mut fills = Vec::new();
    while buy_index < buys.len() && sell_index < sells.len() {
        let quantity_lots = buys[buy_index].1.min(sells[sell_index].1);
        if quantity_lots == 0 {
            return Err(PrivateMarketError::FillConservation);
        }
        let buy = buys[buy_index].0;
        let sell = sells[sell_index].0;
        fills.push(BatchFill {
            buy_order_id: buy.participant.order_id,
            sell_order_id: sell.participant.order_id,
            buy_account_id: buy.participant.account_id.clone(),
            sell_account_id: sell.participant.account_id.clone(),
            price_ticks,
            price,
            quantity_lots,
            quantity: lots_to_quantity(quantity_lots, market)?,
        });
        paired_lots = paired_lots
            .checked_add(quantity_lots)
            .ok_or(PrivateMarketError::ArithmeticOverflow)?;
        buys[buy_index].1 = buys[buy_index]
            .1
            .checked_sub(quantity_lots)
            .ok_or(PrivateMarketError::ArithmeticOverflow)?;
        sells[sell_index].1 = sells[sell_index]
            .1
            .checked_sub(quantity_lots)
            .ok_or(PrivateMarketError::ArithmeticOverflow)?;
        if buys[buy_index].1 == 0 {
            buy_index += 1;
        }
        if sells[sell_index].1 == 0 {
            sell_index += 1;
        }
    }
    if paired_lots != matched_lots
        || buys.iter().any(|(_, remaining)| *remaining != 0)
        || sells.iter().any(|(_, remaining)| *remaining != 0)
    {
        return Err(PrivateMarketError::FillConservation);
    }
    Ok(fills)
}

fn decimal_to_units(value: Decimal, step: Decimal, field: &'static str) -> Result<u64> {
    validate_step(step, field)?;
    let value_mantissa = value.mantissa();
    if value_mantissa < 0 {
        return Err(PrivateMarketError::NegativeValue { field });
    }
    if value_mantissa == 0 {
        return Ok(0);
    }

    let mut numerator =
        u128::try_from(value_mantissa).map_err(|_| PrivateMarketError::UnitOverflow { field })?;
    let mut denominator = u128::try_from(step.mantissa())
        .map_err(|_| PrivateMarketError::NonPositiveStep { field })?;
    let common = gcd(numerator, denominator);
    numerator /= common;
    denominator /= common;

    match step.scale().cmp(&value.scale()) {
        std::cmp::Ordering::Greater => {
            let mut scale_factor = power_of_ten(step.scale() - value.scale())?;
            let cancellation = gcd(denominator, scale_factor);
            denominator /= cancellation;
            scale_factor /= cancellation;
            if denominator != 1 {
                return Err(not_aligned(field, value, step));
            }
            numerator = numerator
                .checked_mul(scale_factor)
                .ok_or(PrivateMarketError::UnitOverflow { field })?;
        }
        std::cmp::Ordering::Less => {
            let mut scale_factor = power_of_ten(value.scale() - step.scale())?;
            let cancellation = gcd(numerator, scale_factor);
            numerator /= cancellation;
            scale_factor /= cancellation;
            if denominator != 1 || scale_factor != 1 {
                return Err(not_aligned(field, value, step));
            }
        }
        std::cmp::Ordering::Equal => {
            if denominator != 1 {
                return Err(not_aligned(field, value, step));
            }
        }
    }

    u64::try_from(numerator).map_err(|_| PrivateMarketError::UnitOverflow { field })
}

fn units_to_decimal(units: u64, step: Decimal, field: &'static str) -> Result<Decimal> {
    validate_step(step, field)?;
    Decimal::from(units)
        .checked_mul(step)
        .ok_or(PrivateMarketError::DecimalOverflow { field })
}

fn validate_step(step: Decimal, field: &'static str) -> Result<()> {
    if step.mantissa() <= 0 {
        return Err(PrivateMarketError::NonPositiveStep { field });
    }
    Ok(())
}

fn not_aligned(field: &'static str, value: Decimal, step: Decimal) -> PrivateMarketError {
    PrivateMarketError::NotStepAligned { field, value, step }
}

fn power_of_ten(exponent: u32) -> Result<u128> {
    10_u128
        .checked_pow(exponent)
        .ok_or(PrivateMarketError::ArithmeticOverflow)
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use rust_decimal_macros::dec;

    use super::*;

    fn id(value: u64) -> OrderId {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        OrderId(bytes)
    }

    fn ciphertext(value: u8) -> CiphertextId {
        [value; 32]
    }

    fn market_config() -> MarketConfig {
        MarketConfig {
            symbol: "BTCUSDT".into(),
            tick_size: dec!(0.01),
            quantity_step: dec!(0.001),
            min_quantity: dec!(0.001),
            max_leverage: 50,
            maintenance_margin_ratio: dec!(0.005),
            maker_fee_rate: dec!(0.0002),
            taker_fee_rate: dec!(0.0005),
            market_slippage_limit: dec!(0.02),
            liquidation_penalty_rate: dec!(0.01),
        }
    }

    fn context() -> BatchContext {
        BatchContext {
            chain_id: "asteria-test-1".into(),
            height: 42,
            threshold_beacon: [0x42; 32],
            reference_price: dec!(100),
        }
    }

    fn participant(
        value: u64,
        side: DomainSide,
        price: Option<Decimal>,
        quantity: Decimal,
        time_in_force: DomainTimeInForce,
        visibility: ParticipantVisibility,
    ) -> BatchParticipant {
        BatchParticipant {
            visibility,
            account_id: format!("account-{value}"),
            order_id: id(value),
            side,
            kind: if price.is_some() {
                DomainOrderKind::Limit
            } else {
                DomainOrderKind::Market
            },
            time_in_force,
            quantity,
            limit_price: price,
            leverage: 10,
            reduce_only: false,
        }
    }

    #[test]
    fn decimal_unit_conversion_is_exact_and_checks_boundaries() {
        let market = market_config();
        assert_eq!(price_to_ticks(dec!(123.45), &market).unwrap(), 12_345);
        assert_eq!(ticks_to_price(12_345, &market).unwrap(), dec!(123.45));
        assert_eq!(quantity_to_lots(dec!(1.234), &market).unwrap(), 1_234);
        assert_eq!(lots_to_quantity(1_234, &market).unwrap(), dec!(1.234));

        assert!(matches!(
            price_to_ticks(dec!(1.005), &market),
            Err(PrivateMarketError::NotStepAligned { field: "price", .. })
        ));
        assert!(matches!(
            quantity_to_lots(dec!(-0.001), &market),
            Err(PrivateMarketError::NegativeValue { field: "quantity" })
        ));

        let mut whole_units = market.clone();
        whole_units.tick_size = Decimal::ONE;
        assert_eq!(
            price_to_ticks(Decimal::from(u64::MAX), &whole_units).unwrap(),
            u64::MAX
        );
        let beyond_u64 = Decimal::from_i128_with_scale(i128::from(u64::MAX) + 1, 0);
        assert!(matches!(
            price_to_ticks(beyond_u64, &whole_units),
            Err(PrivateMarketError::UnitOverflow { field: "price" })
        ));

        whole_units.tick_size = Decimal::MAX;
        assert!(matches!(
            ticks_to_price(2, &whole_units),
            Err(PrivateMarketError::DecimalOverflow { field: "price" })
        ));
    }

    #[test]
    fn market_protection_rounding_never_weakens_the_slippage_bound() {
        assert_eq!(
            market_protection_price(10_003, dec!(0.02), DomainSide::Buy).unwrap(),
            10_203
        );
        assert_eq!(
            market_protection_price(10_003, dec!(0.02), DomainSide::Sell).unwrap(),
            9_803
        );
    }

    #[test]
    fn commitment_binds_only_the_verified_beacon_and_auction_context() {
        let first = allocation_commitment("chain-a", 7, "BTCUSDT", [9; 32]).unwrap();
        assert_eq!(
            first,
            allocation_commitment("chain-a", 7, "BTCUSDT", [9; 32]).unwrap()
        );
        assert_ne!(
            first,
            allocation_commitment("chain-b", 7, "BTCUSDT", [9; 32]).unwrap()
        );
        assert_ne!(
            first,
            allocation_commitment("chain-a", 8, "BTCUSDT", [9; 32]).unwrap()
        );
        assert_ne!(
            first,
            allocation_commitment("chain-a", 7, "ETHUSDT", [9; 32]).unwrap()
        );
        assert_ne!(
            first,
            allocation_commitment("chain-a", 7, "BTCUSDT", [8; 32]).unwrap()
        );
    }

    #[test]
    fn restores_allocations_and_pairs_uniform_price_fills_conservatively() {
        let participants = vec![
            participant(
                1,
                DomainSide::Buy,
                Some(dec!(101)),
                dec!(0.006),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Private {
                    ciphertext_id: ciphertext(1),
                },
            ),
            participant(
                2,
                DomainSide::Buy,
                Some(dec!(100)),
                dec!(0.004),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Public,
            ),
            participant(
                3,
                DomainSide::Sell,
                Some(dec!(99)),
                dec!(0.005),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Private {
                    ciphertext_id: ciphertext(3),
                },
            ),
            participant(
                4,
                DomainSide::Sell,
                Some(dec!(100)),
                dec!(0.003),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Public,
            ),
        ];

        let outcome = clear_private_batch(&market_config(), &context(), &participants).unwrap();
        assert_eq!(outcome.matched_lots, 8);
        assert_eq!(outcome.matched_quantity, dec!(0.008));
        assert_eq!(outcome.clearing_price, Some(dec!(100)));
        assert_eq!(
            outcome
                .fills
                .iter()
                .map(|fill| fill.quantity_lots)
                .sum::<u64>(),
            outcome.matched_lots
        );
        assert!(
            outcome
                .fills
                .iter()
                .all(|fill| fill.price == dec!(100) && fill.price_ticks == 10_000)
        );

        let buy_lots = outcome
            .allocations
            .iter()
            .filter(|allocation| allocation.participant.side == DomainSide::Buy)
            .map(|allocation| allocation.executed_lots)
            .sum::<u64>();
        let sell_lots = outcome
            .allocations
            .iter()
            .filter(|allocation| allocation.participant.side == DomainSide::Sell)
            .map(|allocation| allocation.executed_lots)
            .sum::<u64>();
        assert_eq!(buy_lots, sell_lots);
        assert_eq!(buy_lots, outcome.matched_lots);
    }

    #[test]
    fn market_order_does_not_execute_beyond_the_configured_slippage_limit() {
        let participants = vec![
            participant(
                1,
                DomainSide::Buy,
                None,
                dec!(0.001),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Private {
                    ciphertext_id: ciphertext(1),
                },
            ),
            participant(
                2,
                DomainSide::Sell,
                Some(dec!(1000000)),
                dec!(0.001),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Private {
                    ciphertext_id: ciphertext(2),
                },
            ),
        ];

        let outcome = clear_private_batch(&market_config(), &context(), &participants).unwrap();

        assert_eq!(outcome.clearing_price, None);
        assert_eq!(outcome.matched_quantity, Decimal::ZERO);
        assert!(
            outcome
                .allocations
                .iter()
                .all(|allocation| allocation.executed_quantity.is_zero())
        );
    }

    #[test]
    fn participant_permutation_does_not_change_beacon_source_allocations_or_fills() {
        let participants = vec![
            participant(
                1,
                DomainSide::Buy,
                Some(dec!(100)),
                dec!(0.005),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Private {
                    ciphertext_id: ciphertext(9),
                },
            ),
            participant(
                2,
                DomainSide::Buy,
                Some(dec!(100)),
                dec!(0.005),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Private {
                    ciphertext_id: ciphertext(8),
                },
            ),
            participant(
                3,
                DomainSide::Sell,
                Some(dec!(100)),
                dec!(0.007),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Public,
            ),
        ];
        let expected = clear_private_batch(&market_config(), &context(), &participants).unwrap();
        assert_eq!(
            expected.allocation_commitment,
            allocation_commitment(
                &context().chain_id,
                context().height,
                &market_config().symbol,
                context().threshold_beacon,
            )
            .unwrap()
        );
        let mut reversed = participants.clone();
        reversed.reverse();
        let actual = clear_private_batch(&market_config(), &context(), &reversed).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn fok_remains_atomic_after_decimal_restoration() {
        let participants = vec![
            participant(
                1,
                DomainSide::Buy,
                Some(dec!(100)),
                dec!(0.006),
                DomainTimeInForce::Fok,
                ParticipantVisibility::Public,
            ),
            participant(
                2,
                DomainSide::Buy,
                Some(dec!(100)),
                dec!(0.002),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Public,
            ),
            participant(
                3,
                DomainSide::Sell,
                Some(dec!(100)),
                dec!(0.005),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Public,
            ),
        ];
        let outcome = clear_private_batch(&market_config(), &context(), &participants).unwrap();
        let fok = outcome
            .allocations
            .iter()
            .find(|allocation| allocation.participant.order_id == id(1))
            .unwrap();
        assert_eq!(fok.executed_lots, 0);
        assert_eq!(outcome.matched_lots, 2);
    }

    #[test]
    fn public_gtc_contributes_only_its_current_batch_execution() {
        let participants = vec![
            participant(
                1,
                DomainSide::Buy,
                Some(dec!(100)),
                dec!(0.010),
                DomainTimeInForce::Gtc,
                ParticipantVisibility::Public,
            ),
            participant(
                2,
                DomainSide::Sell,
                Some(dec!(100)),
                dec!(0.004),
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Public,
            ),
        ];

        let outcome = clear_private_batch(&market_config(), &context(), &participants).unwrap();
        let resting = outcome
            .allocations
            .iter()
            .find(|allocation| allocation.participant.order_id == id(1))
            .unwrap();
        assert_eq!(resting.participant.time_in_force, DomainTimeInForce::Gtc);
        assert_eq!(resting.executed_lots, 4);
        assert_eq!(resting.executed_quantity, dec!(0.004));
        assert_eq!(resting.status, AllocationStatus::PartiallyFilled);
        assert_eq!(outcome.matched_lots, 4);

        let private_gtc = vec![participant(
            3,
            DomainSide::Buy,
            Some(dec!(100)),
            dec!(0.010),
            DomainTimeInForce::Gtc,
            ParticipantVisibility::Private {
                ciphertext_id: ciphertext(3),
            },
        )];
        assert!(matches!(
            clear_private_batch(&market_config(), &context(), &private_gtc),
            Err(PrivateMarketError::InvalidParticipant {
                reason: "private batch orders support only IOC or FOK",
                ..
            })
        ));
    }

    #[test]
    fn aggregate_fixed_point_overflow_is_rejected() {
        let mut market = market_config();
        market.quantity_step = Decimal::ONE;
        market.min_quantity = Decimal::ONE;
        market.tick_size = Decimal::ONE;
        let quantity = Decimal::from(u64::MAX);
        let participants = vec![
            participant(
                1,
                DomainSide::Buy,
                Some(dec!(100)),
                quantity,
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Public,
            ),
            participant(
                2,
                DomainSide::Buy,
                Some(dec!(100)),
                quantity,
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Public,
            ),
            participant(
                3,
                DomainSide::Sell,
                Some(dec!(100)),
                Decimal::ONE,
                DomainTimeInForce::Ioc,
                ParticipantVisibility::Public,
            ),
        ];
        assert_eq!(
            clear_private_batch(&market, &context(), &participants),
            Err(PrivateMarketError::Auction(
                AuctionError::ArithmeticOverflow
            ))
        );
    }
}
