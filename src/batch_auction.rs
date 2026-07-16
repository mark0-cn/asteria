//! Deterministic, fixed-point frequent batch auction clearing.
//!
//! Prices and quantities are integer ticks. The caller is responsible for
//! converting user-facing values into those ticks before consensus execution.
//! Every order is one-shot: an unfilled IOC remainder and an unfilled FOK order
//! both leave the auction instead of resting on a continuous order book.

use std::{cmp::Ordering, collections::BTreeSet, error::Error, fmt};

use sha2::{Digest, Sha256};

pub type Price = u64;
pub type Quantity = u64;

const ALLOCATION_DOMAIN: &[u8] = b"ASTERIA_BATCH_AUCTION_ALLOCATION_V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrderId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderKind {
    Limit {
        price: Price,
    },
    /// A market order retains market allocation priority, but only crosses at
    /// prices no worse than this side-specific protection price.
    Market {
        protection_price: Price,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeInForce {
    Ioc,
    Fok,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuctionOrder {
    pub id: OrderId,
    pub side: Side,
    pub kind: OrderKind,
    pub time_in_force: TimeInForce,
    pub quantity: Quantity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuctionConfig {
    /// Used only after volume and imbalance ties. It also supplies a price for
    /// a market-only batch.
    pub reference_price: Price,
    /// Consensus randomness fixed independently of the submitted order IDs.
    /// If a proposer or trader can choose this after seeing the orders, they
    /// can grind the pro-rata remainder priority.
    pub allocation_commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationStatus {
    Unfilled,
    PartiallyFilled,
    Filled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    pub order_id: OrderId,
    pub executed_quantity: Quantity,
    pub status: AllocationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuctionOutcome {
    pub clearing_price: Option<Price>,
    pub matched_quantity: Quantity,
    /// Absolute eligible buy/sell imbalance at the selected clearing price,
    /// before FOK allocation constraints are applied.
    pub imbalance: Quantity,
    /// One entry per input order, sorted by order ID.
    pub allocations: Vec<Allocation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuctionError {
    ZeroReferencePrice,
    ZeroLimitPrice { order_id: OrderId },
    ZeroQuantity { order_id: OrderId },
    DuplicateOrderId { order_id: OrderId },
    ArithmeticOverflow,
    AllocationDidNotConverge,
}

impl fmt::Display for AuctionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroReferencePrice => write!(formatter, "reference price must be positive"),
            Self::ZeroLimitPrice { order_id } => {
                write!(formatter, "limit price must be positive for {order_id:?}")
            }
            Self::ZeroQuantity { order_id } => {
                write!(formatter, "quantity must be positive for {order_id:?}")
            }
            Self::DuplicateOrderId { order_id } => {
                write!(formatter, "duplicate order id: {order_id:?}")
            }
            Self::ArithmeticOverflow => write!(formatter, "auction arithmetic overflow"),
            Self::AllocationDidNotConverge => {
                write!(formatter, "FOK allocation did not converge")
            }
        }
    }
}

impl Error for AuctionError {}

/// Clears one one-shot auction batch.
///
/// Candidate prices are the reference price and all submitted limit prices.
/// They are ranked by actual executable quantity after FOK constraints, then
/// raw supply/demand imbalance, distance from the reference price, and finally
/// the lower price. The final comparison is deliberately independent of input
/// order.
pub fn clear_batch(
    config: AuctionConfig,
    orders: &[AuctionOrder],
) -> Result<AuctionOutcome, AuctionError> {
    validate(config, orders)?;

    if orders.is_empty() {
        return Ok(empty_outcome(orders));
    }

    let mut candidates = BTreeSet::from([config.reference_price]);
    for order in orders {
        if let OrderKind::Limit { price } = order.kind {
            candidates.insert(price);
        }
    }

    let mut best: Option<CandidateOutcome> = None;
    for price in candidates {
        let candidate = evaluate_candidate(config, orders, price)?;
        if candidate.matched_quantity == 0 {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|current| candidate.is_better_than(current, config.reference_price))
        {
            best = Some(candidate);
        }
    }

    let Some(best) = best else {
        return Ok(empty_outcome(orders));
    };

    let allocations = orders
        .iter()
        .enumerate()
        .map(|(index, order)| {
            let executed_quantity = best.allocations[index];
            Allocation {
                order_id: order.id,
                executed_quantity,
                status: status(executed_quantity, order.quantity),
            }
        })
        .collect::<Vec<_>>();
    let mut allocations = allocations;
    allocations.sort_by_key(|allocation| allocation.order_id);

    Ok(AuctionOutcome {
        clearing_price: Some(best.price),
        matched_quantity: best.matched_quantity,
        imbalance: best.imbalance,
        allocations,
    })
}

#[derive(Debug)]
struct CandidateOutcome {
    price: Price,
    matched_quantity: Quantity,
    imbalance: Quantity,
    allocations: Vec<Quantity>,
}

impl CandidateOutcome {
    fn is_better_than(&self, other: &Self, reference_price: Price) -> bool {
        self.matched_quantity
            .cmp(&other.matched_quantity)
            .then_with(|| other.imbalance.cmp(&self.imbalance))
            .then_with(|| {
                other
                    .price
                    .abs_diff(reference_price)
                    .cmp(&self.price.abs_diff(reference_price))
            })
            .then_with(|| other.price.cmp(&self.price))
            == Ordering::Greater
    }
}

fn validate(config: AuctionConfig, orders: &[AuctionOrder]) -> Result<(), AuctionError> {
    if config.reference_price == 0 {
        return Err(AuctionError::ZeroReferencePrice);
    }

    let mut ids = BTreeSet::new();
    let mut buy_total = 0_u64;
    let mut sell_total = 0_u64;
    for order in orders {
        if order.quantity == 0 {
            return Err(AuctionError::ZeroQuantity { order_id: order.id });
        }
        if matches!(order.kind, OrderKind::Limit { price: 0 }) {
            return Err(AuctionError::ZeroLimitPrice { order_id: order.id });
        }
        if !ids.insert(order.id) {
            return Err(AuctionError::DuplicateOrderId { order_id: order.id });
        }
        let total = match order.side {
            Side::Buy => &mut buy_total,
            Side::Sell => &mut sell_total,
        };
        *total = total
            .checked_add(order.quantity)
            .ok_or(AuctionError::ArithmeticOverflow)?;
    }
    Ok(())
}

fn empty_outcome(orders: &[AuctionOrder]) -> AuctionOutcome {
    let mut allocations = orders
        .iter()
        .map(|order| Allocation {
            order_id: order.id,
            executed_quantity: 0,
            status: AllocationStatus::Unfilled,
        })
        .collect::<Vec<_>>();
    allocations.sort_by_key(|allocation| allocation.order_id);
    AuctionOutcome {
        clearing_price: None,
        matched_quantity: 0,
        imbalance: 0,
        allocations,
    }
}

fn evaluate_candidate(
    config: AuctionConfig,
    orders: &[AuctionOrder],
    price: Price,
) -> Result<CandidateOutcome, AuctionError> {
    let eligible_buys = eligible_indices(orders, Side::Buy, price);
    let eligible_sells = eligible_indices(orders, Side::Sell, price);
    let buy_total = checked_quantity(orders, &eligible_buys)?;
    let sell_total = checked_quantity(orders, &eligible_sells)?;
    let imbalance = buy_total.abs_diff(sell_total);
    let mut target = buy_total.min(sell_total);

    if target == 0 {
        return Ok(CandidateOutcome {
            price,
            matched_quantity: 0,
            imbalance,
            allocations: vec![0; orders.len()],
        });
    }

    // A lower target can change which atomic FOK orders fit. Each unsuccessful
    // round strictly lowers the target; the explicit bound prevents adversarial
    // FOK sets from turning consensus execution into an unbounded search.
    let max_rounds = orders
        .len()
        .checked_mul(4)
        .and_then(|rounds| rounds.checked_add(8))
        .ok_or(AuctionError::ArithmeticOverflow)?;
    for _ in 0..max_rounds {
        let buys = allocate_side(
            config.allocation_commitment,
            orders,
            &eligible_buys,
            Side::Buy,
            price,
            target,
        )?;
        let sells = allocate_side(
            config.allocation_commitment,
            orders,
            &eligible_sells,
            Side::Sell,
            price,
            target,
        )?;
        let buy_executed = checked_values(&buys)?;
        let sell_executed = checked_values(&sells)?;
        let next_target = buy_executed.min(sell_executed);

        if next_target == target {
            let mut allocations = vec![0; orders.len()];
            for (index, quantity) in buys.into_iter().enumerate() {
                allocations[index] = quantity;
            }
            for (index, quantity) in sells.into_iter().enumerate() {
                allocations[index] = allocations[index]
                    .checked_add(quantity)
                    .ok_or(AuctionError::ArithmeticOverflow)?;
            }
            return Ok(CandidateOutcome {
                price,
                matched_quantity: target,
                imbalance,
                allocations,
            });
        }
        if next_target == 0 {
            return Ok(CandidateOutcome {
                price,
                matched_quantity: 0,
                imbalance,
                allocations: vec![0; orders.len()],
            });
        }
        target = next_target;
    }

    // Exhausting the deterministic budget must not poison the mandatory
    // system transaction. Drop every atomic FOK and clear the IOC subset once.
    evaluate_ioc_fallback(
        config,
        orders,
        price,
        &eligible_buys,
        &eligible_sells,
        imbalance,
    )
}

fn evaluate_ioc_fallback(
    config: AuctionConfig,
    orders: &[AuctionOrder],
    price: Price,
    eligible_buys: &[usize],
    eligible_sells: &[usize],
    imbalance: Quantity,
) -> Result<CandidateOutcome, AuctionError> {
    let ioc_buys = eligible_buys
        .iter()
        .copied()
        .filter(|index| orders[*index].time_in_force == TimeInForce::Ioc)
        .collect::<Vec<_>>();
    let ioc_sells = eligible_sells
        .iter()
        .copied()
        .filter(|index| orders[*index].time_in_force == TimeInForce::Ioc)
        .collect::<Vec<_>>();
    let target = checked_quantity(orders, &ioc_buys)?.min(checked_quantity(orders, &ioc_sells)?);
    if target == 0 {
        return Ok(CandidateOutcome {
            price,
            matched_quantity: 0,
            imbalance,
            allocations: vec![0; orders.len()],
        });
    }

    let buys = allocate_side(
        config.allocation_commitment,
        orders,
        &ioc_buys,
        Side::Buy,
        price,
        target,
    )?;
    let sells = allocate_side(
        config.allocation_commitment,
        orders,
        &ioc_sells,
        Side::Sell,
        price,
        target,
    )?;
    debug_assert_eq!(checked_values(&buys), Ok(target));
    debug_assert_eq!(checked_values(&sells), Ok(target));
    let mut allocations = vec![0; orders.len()];
    for (index, quantity) in buys.into_iter().enumerate() {
        allocations[index] = quantity;
    }
    for (index, quantity) in sells.into_iter().enumerate() {
        allocations[index] = allocations[index]
            .checked_add(quantity)
            .ok_or(AuctionError::ArithmeticOverflow)?;
    }
    Ok(CandidateOutcome {
        price,
        matched_quantity: target,
        imbalance,
        allocations,
    })
}

fn eligible_indices(orders: &[AuctionOrder], side: Side, clearing_price: Price) -> Vec<usize> {
    orders
        .iter()
        .enumerate()
        .filter_map(|(index, order)| {
            (order.side == side && crosses(order, clearing_price)).then_some(index)
        })
        .collect()
}

fn crosses(order: &AuctionOrder, clearing_price: Price) -> bool {
    match (order.side, order.kind) {
        (Side::Buy, OrderKind::Market { protection_price }) => protection_price >= clearing_price,
        (Side::Sell, OrderKind::Market { protection_price }) => protection_price <= clearing_price,
        (Side::Buy, OrderKind::Limit { price }) => price >= clearing_price,
        (Side::Sell, OrderKind::Limit { price }) => price <= clearing_price,
    }
}

fn checked_quantity(orders: &[AuctionOrder], indices: &[usize]) -> Result<u64, AuctionError> {
    indices.iter().try_fold(0_u64, |total, index| {
        total
            .checked_add(orders[*index].quantity)
            .ok_or(AuctionError::ArithmeticOverflow)
    })
}

fn checked_values(values: &[u64]) -> Result<u64, AuctionError> {
    values.iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(*value)
            .ok_or(AuctionError::ArithmeticOverflow)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PriceGroup {
    Market,
    Limit(Price),
}

fn allocate_side(
    commitment: [u8; 32],
    orders: &[AuctionOrder],
    eligible: &[usize],
    side: Side,
    clearing_price: Price,
    target: Quantity,
) -> Result<Vec<Quantity>, AuctionError> {
    let mut sorted = eligible.to_vec();
    sorted.sort_by(|left, right| {
        economic_priority(side, &orders[*left], &orders[*right])
            .then_with(|| {
                allocation_priority(commitment, orders[*left].id)
                    .cmp(&allocation_priority(commitment, orders[*right].id))
            })
            .then_with(|| orders[*left].id.cmp(&orders[*right].id))
    });

    let mut allocations = vec![0_u64; orders.len()];
    let mut remaining = target;
    let mut start = 0;
    while start < sorted.len() && remaining > 0 {
        let group = price_group(&orders[sorted[start]]);
        let mut end = start + 1;
        while end < sorted.len() && price_group(&orders[sorted[end]]) == group {
            end += 1;
        }
        allocate_group(
            commitment,
            orders,
            &sorted[start..end],
            &mut allocations,
            &mut remaining,
        )?;
        start = end;
    }

    debug_assert!(allocations.iter().enumerate().all(|(index, allocation)| {
        *allocation <= orders[index].quantity
            && (*allocation == 0 || crosses(&orders[index], clearing_price))
            && (orders[index].time_in_force != TimeInForce::Fok
                || *allocation == 0
                || *allocation == orders[index].quantity)
    }));
    Ok(allocations)
}

fn economic_priority(side: Side, left: &AuctionOrder, right: &AuctionOrder) -> Ordering {
    match (price_group(left), price_group(right)) {
        (PriceGroup::Market, PriceGroup::Market) => Ordering::Equal,
        (PriceGroup::Market, PriceGroup::Limit(_)) => Ordering::Less,
        (PriceGroup::Limit(_), PriceGroup::Market) => Ordering::Greater,
        (PriceGroup::Limit(left), PriceGroup::Limit(right)) => match side {
            Side::Buy => right.cmp(&left),
            Side::Sell => left.cmp(&right),
        },
    }
}

fn price_group(order: &AuctionOrder) -> PriceGroup {
    match order.kind {
        OrderKind::Market { .. } => PriceGroup::Market,
        OrderKind::Limit { price } => PriceGroup::Limit(price),
    }
}

fn allocate_group(
    commitment: [u8; 32],
    orders: &[AuctionOrder],
    group: &[usize],
    allocations: &mut [Quantity],
    remaining: &mut Quantity,
) -> Result<(), AuctionError> {
    let group_total = checked_quantity(orders, group)?;
    if group_total <= *remaining {
        for index in group {
            allocations[*index] = orders[*index].quantity;
        }
        *remaining = remaining
            .checked_sub(group_total)
            .ok_or(AuctionError::ArithmeticOverflow)?;
        return Ok(());
    }

    let mut fok = group
        .iter()
        .copied()
        .filter(|index| orders[*index].time_in_force == TimeInForce::Fok)
        .collect::<Vec<_>>();
    fok.sort_by(|left, right| {
        allocation_priority(commitment, orders[*left].id)
            .cmp(&allocation_priority(commitment, orders[*right].id))
            .then_with(|| orders[*left].id.cmp(&orders[*right].id))
    });
    for index in fok {
        if orders[index].quantity <= *remaining {
            allocations[index] = orders[index].quantity;
            *remaining = remaining
                .checked_sub(orders[index].quantity)
                .ok_or(AuctionError::ArithmeticOverflow)?;
        }
    }

    let ioc = group
        .iter()
        .copied()
        .filter(|index| orders[*index].time_in_force == TimeInForce::Ioc)
        .collect::<Vec<_>>();
    allocate_pro_rata(commitment, orders, &ioc, allocations, remaining)
}

fn allocate_pro_rata(
    commitment: [u8; 32],
    orders: &[AuctionOrder],
    indices: &[usize],
    allocations: &mut [Quantity],
    remaining: &mut Quantity,
) -> Result<(), AuctionError> {
    if indices.is_empty() || *remaining == 0 {
        return Ok(());
    }
    let total = checked_quantity(orders, indices)?;
    if total <= *remaining {
        for index in indices {
            allocations[*index] = orders[*index].quantity;
        }
        *remaining = remaining
            .checked_sub(total)
            .ok_or(AuctionError::ArithmeticOverflow)?;
        return Ok(());
    }

    let capacity = *remaining;
    let mut assigned = 0_u64;
    for index in indices {
        let product = u128::from(orders[*index].quantity)
            .checked_mul(u128::from(capacity))
            .ok_or(AuctionError::ArithmeticOverflow)?;
        let share = product / u128::from(total);
        let share = u64::try_from(share).map_err(|_| AuctionError::ArithmeticOverflow)?;
        allocations[*index] = share;
        assigned = assigned
            .checked_add(share)
            .ok_or(AuctionError::ArithmeticOverflow)?;
    }

    let mut remainder = capacity
        .checked_sub(assigned)
        .ok_or(AuctionError::ArithmeticOverflow)?;
    let mut priority = indices.to_vec();
    priority.sort_by(|left, right| {
        allocation_priority(commitment, orders[*left].id)
            .cmp(&allocation_priority(commitment, orders[*right].id))
            .then_with(|| orders[*left].id.cmp(&orders[*right].id))
    });
    for index in priority {
        if remainder == 0 {
            break;
        }
        if allocations[index] < orders[index].quantity {
            allocations[index] = allocations[index]
                .checked_add(1)
                .ok_or(AuctionError::ArithmeticOverflow)?;
            remainder -= 1;
        }
    }
    if remainder != 0 {
        return Err(AuctionError::ArithmeticOverflow);
    }
    *remaining = 0;
    Ok(())
}

fn allocation_priority(commitment: [u8; 32], order_id: OrderId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ALLOCATION_DOMAIN);
    hasher.update(commitment);
    hasher.update(order_id.0);
    hasher.finalize().into()
}

fn status(executed: Quantity, requested: Quantity) -> AllocationStatus {
    if executed == 0 {
        AllocationStatus::Unfilled
    } else if executed == requested {
        AllocationStatus::Filled
    } else {
        AllocationStatus::PartiallyFilled
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;

    const COMMITMENT: [u8; 32] = [0xA5; 32];

    fn id(value: u64) -> OrderId {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        OrderId(bytes)
    }

    fn limit(
        value: u64,
        side: Side,
        price: Price,
        quantity: Quantity,
        time_in_force: TimeInForce,
    ) -> AuctionOrder {
        AuctionOrder {
            id: id(value),
            side,
            kind: OrderKind::Limit { price },
            time_in_force,
            quantity,
        }
    }

    fn market(
        value: u64,
        side: Side,
        protection_price: Price,
        quantity: Quantity,
        time_in_force: TimeInForce,
    ) -> AuctionOrder {
        AuctionOrder {
            id: id(value),
            side,
            kind: OrderKind::Market { protection_price },
            time_in_force,
            quantity,
        }
    }

    fn config(reference_price: Price) -> AuctionConfig {
        AuctionConfig {
            reference_price,
            allocation_commitment: COMMITMENT,
        }
    }

    fn allocation_map(outcome: &AuctionOutcome) -> BTreeMap<OrderId, Quantity> {
        outcome
            .allocations
            .iter()
            .map(|allocation| (allocation.order_id, allocation.executed_quantity))
            .collect()
    }

    #[test]
    fn selects_maximum_volume_before_other_ties() {
        let orders = vec![
            limit(1, Side::Buy, 110, 5, TimeInForce::Ioc),
            limit(2, Side::Buy, 100, 5, TimeInForce::Ioc),
            limit(3, Side::Sell, 90, 8, TimeInForce::Ioc),
            limit(4, Side::Sell, 105, 4, TimeInForce::Ioc),
        ];

        let outcome = clear_batch(config(100), &orders).unwrap();

        assert_eq!(outcome.clearing_price, Some(100));
        assert_eq!(outcome.matched_quantity, 8);
    }

    #[test]
    fn minimizes_imbalance_then_uses_reference_and_lower_price_ties() {
        let orders = vec![
            limit(1, Side::Buy, 110, 10, TimeInForce::Ioc),
            limit(2, Side::Sell, 90, 4, TimeInForce::Ioc),
            limit(3, Side::Sell, 100, 6, TimeInForce::Ioc),
        ];
        let balanced = clear_batch(config(95), &orders).unwrap();
        assert_eq!(balanced.clearing_price, Some(100));

        let tied = vec![
            limit(4, Side::Buy, 110, 5, TimeInForce::Ioc),
            limit(5, Side::Sell, 90, 5, TimeInForce::Ioc),
        ];
        let lower = clear_batch(config(100), &tied).unwrap();
        assert_eq!(lower.clearing_price, Some(100));
    }

    #[test]
    fn market_orders_cross_and_use_reference_price() {
        let orders = vec![
            market(1, Side::Buy, 130, 7, TimeInForce::Ioc),
            market(2, Side::Sell, 120, 5, TimeInForce::Ioc),
        ];
        let outcome = clear_batch(config(123), &orders).unwrap();
        assert_eq!(outcome.clearing_price, Some(123));
        assert_eq!(outcome.matched_quantity, 5);
    }

    #[test]
    fn market_orders_do_not_cross_beyond_their_protection_price() {
        let expensive_sell = vec![
            market(1, Side::Buy, 102, 1, TimeInForce::Ioc),
            limit(2, Side::Sell, 1_000_000, 1, TimeInForce::Ioc),
        ];
        let cheap_buy = vec![
            limit(3, Side::Buy, 1, 1, TimeInForce::Ioc),
            market(4, Side::Sell, 98, 1, TimeInForce::Ioc),
        ];

        for orders in [expensive_sell, cheap_buy] {
            let outcome = clear_batch(config(100), &orders).unwrap();
            assert_eq!(outcome.clearing_price, None);
            assert_eq!(outcome.matched_quantity, 0);
        }
    }

    #[test]
    fn boundary_ioc_orders_are_pro_rata_and_remainder_is_deterministic() {
        let orders = vec![
            limit(1, Side::Buy, 100, 5, TimeInForce::Ioc),
            limit(2, Side::Buy, 100, 5, TimeInForce::Ioc),
            limit(3, Side::Buy, 100, 5, TimeInForce::Ioc),
            limit(4, Side::Sell, 100, 8, TimeInForce::Ioc),
        ];
        let forward = clear_batch(config(100), &orders).unwrap();
        let mut reversed = orders.clone();
        reversed.reverse();
        let backward = clear_batch(config(100), &reversed).unwrap();

        assert_eq!(forward, backward);
        let buys = forward
            .allocations
            .iter()
            .filter(|allocation| allocation.order_id != id(4))
            .map(|allocation| allocation.executed_quantity)
            .collect::<Vec<_>>();
        assert_eq!(buys.iter().sum::<u64>(), 8);
        assert!(buys.iter().all(|quantity| matches!(*quantity, 2 | 3)));
    }

    #[test]
    fn fok_is_atomic_when_fillable_or_unfillable() {
        let fillable = vec![
            limit(1, Side::Buy, 100, 5, TimeInForce::Fok),
            limit(2, Side::Sell, 100, 5, TimeInForce::Ioc),
        ];
        let outcome = clear_batch(config(100), &fillable).unwrap();
        assert_eq!(allocation_map(&outcome)[&id(1)], 5);

        let unfillable = vec![
            limit(3, Side::Buy, 100, 6, TimeInForce::Fok),
            limit(4, Side::Buy, 100, 2, TimeInForce::Ioc),
            limit(5, Side::Sell, 100, 5, TimeInForce::Ioc),
        ];
        let outcome = clear_batch(config(100), &unfillable).unwrap();
        let allocations = allocation_map(&outcome);
        assert_eq!(allocations[&id(3)], 0);
        assert_eq!(allocations[&id(4)], 2);
        assert_eq!(outcome.matched_quantity, 2);
    }

    #[test]
    fn adversarial_fok_fixed_point_falls_back_without_an_error() {
        let buys = [
            (10, 939),
            (8, 794),
            (6, 485),
            (1, 4),
            (14, 687),
            (4, 526),
            (11, 953),
            (5, 800),
            (9, 243),
            (15, 634),
            (13, 981),
            (3, 604),
            (16, 327),
            (7, 70),
            (2, 57),
            (12, 72),
        ];
        let sells = [
            (17, 955),
            (23, 658),
            (26, 725),
            (29, 604),
            (24, 927),
            (28, 510),
            (22, 273),
            (19, 520),
            (31, 971),
            (21, 786),
            (25, 445),
            (27, 228),
            (18, 119),
            (30, 70),
            (20, 489),
            (32, 696),
        ];
        let fok = |order_id: u64, side, quantity| AuctionOrder {
            id: OrderId([u8::try_from(order_id).unwrap(); 32]),
            side,
            kind: OrderKind::Limit { price: 100 },
            time_in_force: TimeInForce::Fok,
            quantity,
        };
        let orders = buys
            .into_iter()
            .map(|(order_id, quantity)| fok(order_id, Side::Buy, quantity))
            .chain(
                sells
                    .into_iter()
                    .map(|(order_id, quantity)| fok(order_id, Side::Sell, quantity)),
            )
            .collect::<Vec<_>>();

        let outcome = clear_batch(config(100), &orders).unwrap();

        assert_eq!(outcome.clearing_price, None);
        assert_eq!(outcome.matched_quantity, 0);
        assert!(
            outcome
                .allocations
                .iter()
                .all(|allocation| allocation.executed_quantity == 0)
        );
    }

    #[test]
    fn non_convergence_fallback_reclears_only_ioc_orders() {
        let orders = vec![
            limit(1, Side::Buy, 100, 9, TimeInForce::Fok),
            limit(2, Side::Sell, 100, 8, TimeInForce::Fok),
            limit(3, Side::Buy, 100, 7, TimeInForce::Ioc),
            limit(4, Side::Sell, 100, 5, TimeInForce::Ioc),
        ];
        let eligible_buys = eligible_indices(&orders, Side::Buy, 100);
        let eligible_sells = eligible_indices(&orders, Side::Sell, 100);

        let outcome = evaluate_ioc_fallback(
            config(100),
            &orders,
            100,
            &eligible_buys,
            &eligible_sells,
            3,
        )
        .unwrap();
        let allocations = outcome
            .allocations
            .iter()
            .copied()
            .enumerate()
            .collect::<BTreeMap<_, _>>();

        assert_eq!(outcome.matched_quantity, 5);
        assert_eq!(allocations[&0], 0);
        assert_eq!(allocations[&1], 0);
        assert_eq!(allocations[&2], 5);
        assert_eq!(allocations[&3], 5);
    }

    #[test]
    fn rejects_invalid_input_and_checked_sum_overflow() {
        let duplicate = vec![
            market(1, Side::Buy, 1, 1, TimeInForce::Ioc),
            market(1, Side::Sell, 1, 1, TimeInForce::Ioc),
        ];
        assert!(matches!(
            clear_batch(config(1), &duplicate),
            Err(AuctionError::DuplicateOrderId { .. })
        ));

        let overflow = vec![
            market(1, Side::Buy, 1, u64::MAX, TimeInForce::Ioc),
            market(2, Side::Buy, 1, 1, TimeInForce::Ioc),
            market(3, Side::Sell, 1, 1, TimeInForce::Ioc),
        ];
        assert_eq!(
            clear_batch(config(1), &overflow),
            Err(AuctionError::ArithmeticOverflow)
        );
    }

    #[test]
    fn non_crossing_batch_has_no_clearing_price() {
        let orders = vec![
            limit(1, Side::Buy, 90, 3, TimeInForce::Ioc),
            limit(2, Side::Sell, 110, 3, TimeInForce::Ioc),
        ];
        let outcome = clear_batch(config(100), &orders).unwrap();
        assert_eq!(outcome.clearing_price, None);
        assert_eq!(outcome.matched_quantity, 0);
        assert!(
            outcome
                .allocations
                .iter()
                .all(|allocation| allocation.executed_quantity == 0)
        );
    }

    fn arb_orders() -> impl Strategy<Value = Vec<AuctionOrder>> {
        prop::collection::vec(
            (
                any::<bool>(),
                any::<bool>(),
                1_u64..=200,
                1_u64..=40,
                any::<bool>(),
            ),
            0..32,
        )
        .prop_map(|specs| {
            specs
                .into_iter()
                .enumerate()
                .map(
                    |(index, (buy, is_market, price, quantity, fok))| AuctionOrder {
                        id: id(index as u64 + 1),
                        side: if buy { Side::Buy } else { Side::Sell },
                        kind: if is_market {
                            OrderKind::Market {
                                protection_price: price,
                            }
                        } else {
                            OrderKind::Limit { price }
                        },
                        time_in_force: if fok {
                            TimeInForce::Fok
                        } else {
                            TimeInForce::Ioc
                        },
                        quantity,
                    },
                )
                .collect()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_024))]

        #[test]
        fn clearing_is_conservative_respects_limits_and_keeps_fok_atomic(
            orders in arb_orders(),
            reference_price in 1_u64..=200,
            commitment in any::<[u8; 32]>(),
        ) {
            let outcome = clear_batch(
                AuctionConfig {
                    reference_price,
                    allocation_commitment: commitment,
                },
                &orders,
            ).unwrap();
            let allocations = allocation_map(&outcome);
            let mut buys = 0_u64;
            let mut sells = 0_u64;

            for order in &orders {
                let executed = allocations[&order.id];
                prop_assert!(executed <= order.quantity);
                if order.time_in_force == TimeInForce::Fok {
                    prop_assert!(executed == 0 || executed == order.quantity);
                }
                if executed > 0 {
                    let clearing_price = outcome.clearing_price.unwrap();
                    prop_assert!(crosses(order, clearing_price));
                }
                match order.side {
                    Side::Buy => buys = buys.checked_add(executed).unwrap(),
                    Side::Sell => sells = sells.checked_add(executed).unwrap(),
                }
            }
            prop_assert_eq!(buys, sells);
            prop_assert_eq!(buys, outcome.matched_quantity);
        }

        #[test]
        fn input_permutation_does_not_change_outcome(
            orders in arb_orders(),
            reference_price in 1_u64..=200,
            commitment in any::<[u8; 32]>(),
        ) {
            let config = AuctionConfig {
                reference_price,
                allocation_commitment: commitment,
            };
            let expected = clear_batch(config, &orders).unwrap();

            let mut reversed = orders.clone();
            reversed.reverse();
            prop_assert_eq!(&expected, &clear_batch(config, &reversed).unwrap());

            let mut rotated = orders.clone();
            if !rotated.is_empty() {
                let by = rotated.len() / 2;
                rotated.rotate_left(by);
            }
            prop_assert_eq!(expected, clear_batch(config, &rotated).unwrap());
        }
    }
}
