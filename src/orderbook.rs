use std::collections::{BTreeMap, VecDeque};

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::{
        AccountId, BookSnapshot, Order, OrderKind, OrderStatus, PriceLevel, Side, Symbol,
        TimeInForce,
    },
    error::{ExchangeError, Result},
};

#[derive(Debug, Clone)]
pub struct RawFill {
    pub maker_order_id: Uuid,
    pub taker_order_id: Uuid,
    pub maker_account_id: AccountId,
    pub taker_account_id: AccountId,
    pub maker_side: Side,
    pub taker_side: Side,
    pub maker_leverage: u16,
    pub taker_leverage: u16,
    pub price: Decimal,
    pub quantity: Decimal,
    pub maker_margin_release: Decimal,
    pub taker_margin_release: Decimal,
}

#[derive(Debug, Clone)]
pub struct ReservationRelease {
    pub account_id: AccountId,
    pub order_id: Uuid,
    pub amount: Decimal,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct Execution {
    pub order: Order,
    pub fills: Vec<RawFill>,
    pub releases: Vec<ReservationRelease>,
    pub terminal_orders: Vec<Order>,
}

#[derive(Debug, Clone)]
pub struct BatchOrderFill {
    pub order: Order,
    pub margin_release: Decimal,
    pub terminal: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OrderBook {
    bids: BTreeMap<Decimal, VecDeque<Uuid>>,
    asks: BTreeMap<Decimal, VecDeque<Uuid>>,
    orders: BTreeMap<Uuid, Order>,
}

impl OrderBook {
    pub fn order(&self, order_id: Uuid) -> Option<&Order> {
        self.orders.get(&order_id)
    }

    pub fn active_orders(&self) -> Vec<Order> {
        let mut orders = self
            .orders
            .values()
            .filter(|order| {
                matches!(
                    order.status,
                    OrderStatus::Open | OrderStatus::PartiallyFilled
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        orders.sort_by_key(|order| order.id);
        orders
    }

    pub fn take_active_orders(&mut self) -> Vec<Order> {
        let active_ids = self
            .orders
            .values()
            .filter(|order| {
                matches!(
                    order.status,
                    OrderStatus::Open | OrderStatus::PartiallyFilled
                )
            })
            .map(|order| order.id)
            .collect::<Vec<_>>();
        let mut active = Vec::with_capacity(active_ids.len());
        for order_id in active_ids {
            if let Some(order) = self.orders.remove(&order_id) {
                active.push(order);
            }
        }
        self.bids.clear();
        self.asks.clear();
        active.sort_by(|left, right| {
            left.sequence
                .cmp(&right.sequence)
                .then_with(|| left.id.cmp(&right.id))
        });
        active
    }

    pub fn restore_active_order(&mut self, order: Order) -> Result<()> {
        if self.orders.contains_key(&order.id) {
            return Err(ExchangeError::InvalidOrder(format!(
                "cannot restore duplicate order {}",
                order.id
            )));
        }
        if !matches!(
            order.status,
            OrderStatus::Open | OrderStatus::PartiallyFilled
        ) {
            return Err(ExchangeError::InvalidOrder(format!(
                "cannot restore non-active order {}",
                order.id
            )));
        }

        let order_id = order.id;
        let side = order.side;
        let price = order.limit_price;
        self.orders.insert(order_id, order);

        let orders = &self.orders;
        let levels = match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        let queue = levels.entry(price).or_default();
        queue.push_back(order_id);
        queue.make_contiguous().sort_by(|left, right| {
            let left = &orders[left];
            let right = &orders[right];
            left.sequence
                .cmp(&right.sequence)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(())
    }

    pub fn apply_batch_fill(
        &mut self,
        order_id: Uuid,
        quantity: Decimal,
    ) -> Result<BatchOrderFill> {
        if quantity <= Decimal::ZERO {
            return Err(ExchangeError::InvalidOrder(
                "batch fill quantity must be positive".into(),
            ));
        }
        let current = self
            .orders
            .get(&order_id)
            .ok_or(ExchangeError::OrderNotFound(order_id))?;
        if !matches!(
            current.status,
            OrderStatus::Open | OrderStatus::PartiallyFilled
        ) || quantity > current.remaining
        {
            return Err(ExchangeError::InvalidOrder(format!(
                "batch fill exceeds active quantity for order {order_id}"
            )));
        }
        let margin_release =
            proportional_release(current.reserved_margin, current.remaining, quantity);
        let side = current.side;
        let price = current.limit_price;
        let terminal;
        {
            let order = self
                .orders
                .get_mut(&order_id)
                .expect("validated order exists");
            order.remaining = order
                .remaining
                .checked_sub(quantity)
                .ok_or_else(|| ExchangeError::Internal("batch quantity underflow".into()))?;
            order.reserved_margin = order
                .reserved_margin
                .checked_sub(margin_release)
                .ok_or_else(|| ExchangeError::Internal("batch margin underflow".into()))?;
            terminal = order.remaining.is_zero();
            order.status = if terminal {
                OrderStatus::Filled
            } else {
                OrderStatus::PartiallyFilled
            };
        }
        if terminal {
            self.remove_from_level(side, price, order_id);
        }
        let order = if terminal {
            self.orders
                .remove(&order_id)
                .expect("filled batch order exists")
        } else {
            self.orders
                .get(&order_id)
                .expect("partially filled batch order exists")
                .clone()
        };
        Ok(BatchOrderFill {
            order,
            margin_release,
            terminal,
        })
    }

    pub fn can_fully_fill(
        &self,
        side: Side,
        limit_price: Decimal,
        quantity: Decimal,
        taker_account_id: &str,
    ) -> bool {
        let mut available = Decimal::ZERO;
        match side {
            Side::Buy => {
                for (price, queue) in &self.asks {
                    if *price > limit_price {
                        break;
                    }
                    for order_id in queue {
                        let order = &self.orders[order_id];
                        if order.account_id != taker_account_id {
                            available += order.remaining;
                            if available >= quantity {
                                return true;
                            }
                        }
                    }
                }
            }
            Side::Sell => {
                for (price, queue) in self.bids.iter().rev() {
                    if *price < limit_price {
                        break;
                    }
                    for order_id in queue {
                        let order = &self.orders[order_id];
                        if order.account_id != taker_account_id {
                            available += order.remaining;
                            if available >= quantity {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    pub fn execute(&mut self, mut incoming: Order) -> Execution {
        let mut fills = Vec::new();
        let mut releases = Vec::new();
        let mut terminal_orders = Vec::new();

        while incoming.remaining > Decimal::ZERO {
            let Some((maker_price, maker_order_id)) = self.best_opposite(incoming.side) else {
                break;
            };
            if !crosses(incoming.side, incoming.limit_price, maker_price) {
                break;
            }

            let maker_account_id = self.orders[&maker_order_id].account_id.clone();
            if maker_account_id == incoming.account_id {
                if let Some(cancelled) = self.cancel_internal(maker_order_id) {
                    releases.push(ReservationRelease {
                        account_id: cancelled.account_id.clone(),
                        order_id: cancelled.id,
                        amount: cancelled.reserved_margin,
                        reason: "self_trade_prevention",
                    });
                    terminal_orders.push(cancelled);
                }
                continue;
            }

            let taker_before = incoming.remaining;
            let maker_before = self.orders[&maker_order_id].remaining;
            let fill_quantity = taker_before.min(maker_before);
            let taker_margin_release =
                proportional_release(incoming.reserved_margin, taker_before, fill_quantity);
            incoming.remaining -= fill_quantity;
            incoming.reserved_margin -= taker_margin_release;

            let (maker_side, maker_leverage, maker_margin_release, maker_filled, maker_account_id) = {
                let maker = self.orders.get_mut(&maker_order_id).expect("maker exists");
                let release =
                    proportional_release(maker.reserved_margin, maker_before, fill_quantity);
                maker.remaining -= fill_quantity;
                maker.reserved_margin -= release;
                let filled = maker.remaining.is_zero();
                maker.status = if filled {
                    OrderStatus::Filled
                } else {
                    OrderStatus::PartiallyFilled
                };
                (
                    maker.side,
                    maker.leverage,
                    release,
                    filled,
                    maker.account_id.clone(),
                )
            };

            if maker_filled {
                self.remove_from_level(maker_side, maker_price, maker_order_id);
                terminal_orders.push(
                    self.orders
                        .remove(&maker_order_id)
                        .expect("filled maker exists"),
                );
            }

            fills.push(RawFill {
                maker_order_id,
                taker_order_id: incoming.id,
                maker_account_id,
                taker_account_id: incoming.account_id.clone(),
                maker_side,
                taker_side: incoming.side,
                maker_leverage,
                taker_leverage: incoming.leverage,
                price: maker_price,
                quantity: fill_quantity,
                maker_margin_release,
                taker_margin_release,
            });
        }

        let filled_quantity = incoming.quantity - incoming.remaining;
        if incoming.remaining.is_zero() {
            incoming.status = OrderStatus::Filled;
        } else if incoming.kind == OrderKind::Limit && incoming.time_in_force == TimeInForce::Gtc {
            incoming.status = if filled_quantity.is_zero() {
                OrderStatus::Open
            } else {
                OrderStatus::PartiallyFilled
            };
            self.push_level(incoming.side, incoming.limit_price, incoming.id);
        } else {
            incoming.status = OrderStatus::Cancelled;
            if incoming.reserved_margin > Decimal::ZERO {
                releases.push(ReservationRelease {
                    account_id: incoming.account_id.clone(),
                    order_id: incoming.id,
                    amount: incoming.reserved_margin,
                    reason: "unfilled_remainder",
                });
                incoming.reserved_margin = Decimal::ZERO;
            }
        }

        if matches!(
            incoming.status,
            OrderStatus::Open | OrderStatus::PartiallyFilled
        ) {
            self.orders.insert(incoming.id, incoming.clone());
        } else {
            terminal_orders.push(incoming.clone());
        }
        Execution {
            order: incoming,
            fills,
            releases,
            terminal_orders,
        }
    }

    pub fn cancel(&mut self, order_id: Uuid, account_id: &str) -> Result<Order> {
        let order = self
            .orders
            .get(&order_id)
            .ok_or(ExchangeError::OrderNotFound(order_id))?;
        if order.account_id != account_id {
            return Err(ExchangeError::OrderOwnership { order_id });
        }
        if !matches!(
            order.status,
            OrderStatus::Open | OrderStatus::PartiallyFilled
        ) {
            return Err(ExchangeError::InvalidOrder(format!(
                "order {order_id} is not open"
            )));
        }
        self.cancel_internal(order_id)
            .ok_or(ExchangeError::OrderNotFound(order_id))
    }

    pub fn active_orders_for_account_symbol(&self, account_id: &str, symbol: &str) -> Vec<Order> {
        let mut orders: Vec<_> = self
            .orders
            .values()
            .filter(|order| {
                order.account_id == account_id
                    && order.symbol == symbol
                    && matches!(
                        order.status,
                        OrderStatus::Open | OrderStatus::PartiallyFilled
                    )
            })
            .cloned()
            .collect();
        orders.sort_by_key(|order| order.sequence);
        orders
    }

    pub fn active_reduce_only_quantity(
        &self,
        account_id: &str,
        symbol: &str,
        side: Side,
    ) -> Decimal {
        self.orders
            .values()
            .filter(|order| {
                order.account_id == account_id
                    && order.symbol == symbol
                    && order.side == side
                    && order.reduce_only
                    && matches!(
                        order.status,
                        OrderStatus::Open | OrderStatus::PartiallyFilled
                    )
            })
            .map(|order| order.remaining)
            .sum()
    }

    pub fn active_reserved_margin(&self, account_id: &str) -> Decimal {
        self.orders
            .values()
            .filter(|order| {
                order.account_id == account_id
                    && matches!(
                        order.status,
                        OrderStatus::Open | OrderStatus::PartiallyFilled
                    )
            })
            .map(|order| order.reserved_margin)
            .sum()
    }

    pub fn take_terminal_orders(&mut self) -> Vec<Order> {
        let terminal_ids: Vec<_> = self
            .orders
            .values()
            .filter(|order| {
                !matches!(
                    order.status,
                    OrderStatus::Open | OrderStatus::PartiallyFilled
                )
            })
            .map(|order| order.id)
            .collect();
        let mut terminal = Vec::with_capacity(terminal_ids.len());
        for order_id in terminal_ids {
            if let Some(order) = self.orders.remove(&order_id) {
                self.remove_from_level(order.side, order.limit_price, order.id);
                terminal.push(order);
            }
        }
        terminal
    }

    pub fn snapshot(&self, symbol: Symbol, sequence: u64, depth: usize) -> BookSnapshot {
        let bids = self
            .bids
            .iter()
            .rev()
            .take(depth)
            .map(|(price, queue)| self.level(*price, queue))
            .collect();
        let asks = self
            .asks
            .iter()
            .take(depth)
            .map(|(price, queue)| self.level(*price, queue))
            .collect();
        BookSnapshot {
            symbol,
            sequence,
            bids,
            asks,
        }
    }

    fn level(&self, price: Decimal, queue: &VecDeque<Uuid>) -> PriceLevel {
        PriceLevel {
            price,
            quantity: queue.iter().map(|id| self.orders[id].remaining).sum(),
            order_count: queue.len(),
        }
    }

    fn best_opposite(&self, side: Side) -> Option<(Decimal, Uuid)> {
        let (price, queue) = match side {
            Side::Buy => self.asks.first_key_value()?,
            Side::Sell => self.bids.last_key_value()?,
        };
        Some((*price, *queue.front().expect("price level is never empty")))
    }

    fn push_level(&mut self, side: Side, price: Decimal, order_id: Uuid) {
        let levels = match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        levels.entry(price).or_default().push_back(order_id);
    }

    fn remove_from_level(&mut self, side: Side, price: Decimal, order_id: Uuid) {
        let levels = match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        let remove_level = if let Some(queue) = levels.get_mut(&price) {
            queue.retain(|id| *id != order_id);
            queue.is_empty()
        } else {
            false
        };
        if remove_level {
            levels.remove(&price);
        }
    }

    fn cancel_internal(&mut self, order_id: Uuid) -> Option<Order> {
        let (side, price) = {
            let order = self.orders.get(&order_id)?;
            (order.side, order.limit_price)
        };
        self.remove_from_level(side, price, order_id);
        let mut cancelled = self.orders.remove(&order_id)?;
        cancelled.status = OrderStatus::Cancelled;
        Some(cancelled)
    }
}

fn crosses(side: Side, limit_price: Decimal, maker_price: Decimal) -> bool {
    match side {
        Side::Buy => maker_price <= limit_price,
        Side::Sell => maker_price >= limit_price,
    }
}

fn proportional_release(reserved: Decimal, quantity_before: Decimal, filled: Decimal) -> Decimal {
    if reserved <= Decimal::ZERO || quantity_before <= Decimal::ZERO || filled <= Decimal::ZERO {
        return Decimal::ZERO;
    }
    if filled >= quantity_before {
        return reserved;
    }

    let Some(remaining) = quantity_before.checked_sub(filled) else {
        return Decimal::ZERO;
    };
    if filled <= remaining {
        bounded_proportion(reserved, filled, quantity_before).unwrap_or(Decimal::ZERO)
    } else if let Some(retained) = bounded_proportion(reserved, remaining, quantity_before) {
        reserved.checked_sub(retained).unwrap_or(Decimal::ZERO)
    } else {
        bounded_proportion(reserved, filled, quantity_before).unwrap_or(Decimal::ZERO)
    }
}

fn bounded_proportion(total: Decimal, numerator: Decimal, denominator: Decimal) -> Option<Decimal> {
    let direct = total
        .checked_mul(numerator)
        .and_then(|product| product.checked_div(denominator));
    if matches!(direct, Some(value) if value > Decimal::ZERO && value < total) {
        return direct;
    }

    let ratio = numerator.checked_div(denominator)?;
    match total.checked_mul(ratio) {
        Some(value) if value > Decimal::ZERO && value < total => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use rust_decimal_macros::dec;

    use super::*;

    fn order(account: &str, side: Side, price: Decimal, quantity: Decimal, seq: u64) -> Order {
        Order {
            id: Uuid::new_v4(),
            account_id: account.into(),
            client_order_id: format!("{account}-{seq}"),
            symbol: "BTCUSDT".into(),
            side,
            kind: OrderKind::Limit,
            quantity,
            remaining: quantity,
            limit_price: price,
            leverage: 10,
            time_in_force: TimeInForce::Gtc,
            reduce_only: false,
            reserved_margin: quantity * price / dec!(10),
            sequence: seq,
            status: OrderStatus::Open,
        }
    }

    #[test]
    fn matches_price_then_time() {
        let mut book = OrderBook::default();
        let first = order("maker-a", Side::Sell, dec!(100), dec!(1), 1);
        let first_id = first.id;
        book.execute(first);
        let second = order("maker-b", Side::Sell, dec!(100), dec!(1), 2);
        let second_id = second.id;
        book.execute(second);

        let taker = order("taker", Side::Buy, dec!(101), dec!(1.5), 3);
        let execution = book.execute(taker);
        assert_eq!(execution.fills.len(), 2);
        assert_eq!(execution.fills[0].maker_order_id, first_id);
        assert_eq!(execution.fills[1].maker_order_id, second_id);
        assert_eq!(execution.fills[1].quantity, dec!(0.5));
    }

    #[test]
    fn self_trade_cancels_resting_order() {
        let mut book = OrderBook::default();
        let maker = order("same", Side::Sell, dec!(100), dec!(1), 1);
        let maker_id = maker.id;
        book.execute(maker);
        let taker = order("same", Side::Buy, dec!(100), dec!(1), 2);
        let execution = book.execute(taker);
        assert!(execution.fills.is_empty());
        assert_eq!(execution.releases.len(), 1);
        assert_eq!(execution.releases[0].reason, "self_trade_prevention");
        assert!(book.order(maker_id).is_none());
    }

    #[test]
    fn terminal_orders_are_not_retained_in_consensus_state() {
        let mut book = OrderBook::default();
        let maker = order("maker", Side::Sell, dec!(100), dec!(1), 1);
        let maker_id = maker.id;
        book.execute(maker);
        let taker = order("taker", Side::Buy, dec!(100), dec!(1), 2);
        let taker_id = taker.id;

        let execution = book.execute(taker);

        assert_eq!(execution.fills.len(), 1);
        assert_eq!(execution.terminal_orders.len(), 2);
        assert!(book.order(maker_id).is_none());
        assert!(book.order(taker_id).is_none());
    }

    #[test]
    fn legacy_terminal_orders_can_be_pruned_after_loading() {
        let mut book = OrderBook::default();
        let mut legacy = order("legacy", Side::Buy, dec!(100), dec!(1), 1);
        let legacy_id = legacy.id;
        legacy.status = OrderStatus::Filled;
        book.orders.insert(legacy_id, legacy);

        let terminal = book.take_terminal_orders();

        assert_eq!(terminal.len(), 1);
        assert!(book.order(legacy_id).is_none());
    }

    #[test]
    fn proportional_batch_release_avoids_intermediate_overflow_and_drains_terminal() {
        let mut book = OrderBook::default();
        let mut resting = order("maker", Side::Sell, dec!(100), dec!(3), 1);
        resting.reserved_margin = Decimal::MAX;
        let order_id = resting.id;
        book.execute(resting);

        assert!(Decimal::MAX.checked_mul(dec!(2)).is_none());
        let partial = book.apply_batch_fill(order_id, dec!(2)).unwrap();
        assert!(!partial.terminal);
        assert!(partial.margin_release > Decimal::ZERO);
        assert!(partial.margin_release < Decimal::MAX);
        assert_eq!(
            partial
                .margin_release
                .checked_add(partial.order.reserved_margin),
            Some(Decimal::MAX)
        );

        let remaining_reservation = partial.order.reserved_margin;
        let terminal = book.apply_batch_fill(order_id, dec!(1)).unwrap();
        assert!(terminal.terminal);
        assert_eq!(terminal.margin_release, remaining_reservation);
        assert_eq!(terminal.order.reserved_margin, Decimal::ZERO);
        assert!(book.order(order_id).is_none());
    }

    #[test]
    fn active_orders_can_be_taken_and_restored_with_deterministic_fifo() {
        let mut book = OrderBook::default();
        let orders = vec![
            order("late", Side::Sell, dec!(100), dec!(1), 2),
            order("tie-a", Side::Sell, dec!(100), dec!(1), 1),
            order("tie-b", Side::Sell, dec!(100), dec!(1), 1),
        ];
        for order in &orders {
            book.execute(order.clone());
        }

        let mut expected = orders.clone();
        expected.sort_by(|left, right| {
            left.sequence
                .cmp(&right.sequence)
                .then_with(|| left.id.cmp(&right.id))
        });
        let taken = book.take_active_orders();
        assert_eq!(
            taken.iter().map(|order| order.id).collect::<Vec<_>>(),
            expected.iter().map(|order| order.id).collect::<Vec<_>>()
        );
        assert!(book.orders.is_empty());
        assert!(book.bids.is_empty());
        assert!(book.asks.is_empty());

        for order in taken.iter().rev() {
            book.restore_active_order(order.clone()).unwrap();
        }
        assert_eq!(
            book.asks[&dec!(100)].iter().copied().collect::<Vec<_>>(),
            expected.iter().map(|order| order.id).collect::<Vec<_>>()
        );
        assert!(matches!(
            book.restore_active_order(expected[0].clone()),
            Err(ExchangeError::InvalidOrder(_))
        ));

        let mut cancelled = order("cancelled", Side::Buy, dec!(90), dec!(1), 3);
        cancelled.status = OrderStatus::Cancelled;
        assert!(matches!(
            book.restore_active_order(cancelled),
            Err(ExchangeError::InvalidOrder(_))
        ));
    }
}
