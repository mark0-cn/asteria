use rust_decimal::{Decimal, prelude::Signed};

use crate::{
    domain::{Account, MarketState, Position, RiskSnapshot, Side},
    error::{ExchangeError, Result},
};

#[derive(Debug, Clone, Copy)]
pub struct PositionUpdate {
    pub realized_pnl: Decimal,
}

impl Position {
    pub fn apply_fill(
        &mut self,
        side: Side,
        quantity: Decimal,
        price: Decimal,
        leverage: u16,
    ) -> Result<PositionUpdate> {
        let overflow =
            || ExchangeError::InvalidOrder("numeric overflow while updating position".into());
        let delta = side.sign().checked_mul(quantity).ok_or_else(overflow)?;
        let old_quantity = self.quantity;
        let old_abs = old_quantity.abs();

        if old_quantity.is_zero() || old_quantity.signum() == delta.signum() {
            let added_margin = quantity
                .checked_mul(price)
                .and_then(|notional| notional.checked_div(Decimal::from(leverage)))
                .ok_or_else(overflow)?;
            let new_abs = old_abs.checked_add(quantity).ok_or_else(overflow)?;
            self.entry_price = if old_abs.is_zero() {
                price
            } else {
                old_abs
                    .checked_mul(self.entry_price)
                    .and_then(|old_notional| {
                        quantity
                            .checked_mul(price)
                            .and_then(|new_notional| old_notional.checked_add(new_notional))
                    })
                    .and_then(|notional| notional.checked_div(new_abs))
                    .ok_or_else(overflow)?
            };
            self.quantity = self.quantity.checked_add(delta).ok_or_else(overflow)?;
            self.initial_margin = self
                .initial_margin
                .checked_add(added_margin)
                .ok_or_else(overflow)?;
            return Ok(PositionUpdate {
                realized_pnl: Decimal::ZERO,
            });
        }

        let closing_quantity = old_abs.min(quantity);
        let realized_pnl = price
            .checked_sub(self.entry_price)
            .and_then(|price_delta| closing_quantity.checked_mul(price_delta))
            .and_then(|pnl| pnl.checked_mul(old_quantity.signum()))
            .ok_or_else(overflow)?;
        let released_margin = if closing_quantity == old_abs {
            self.initial_margin
        } else {
            self.initial_margin
                .checked_mul(closing_quantity)
                .and_then(|margin| margin.checked_div(old_abs))
                .ok_or_else(overflow)?
        };
        self.initial_margin = self
            .initial_margin
            .checked_sub(released_margin)
            .ok_or_else(overflow)?;
        self.quantity = self.quantity.checked_add(delta).ok_or_else(overflow)?;

        if self.quantity.is_zero() {
            self.entry_price = Decimal::ZERO;
            self.initial_margin = Decimal::ZERO;
        } else if self.quantity.signum() != old_quantity.signum() {
            self.entry_price = price;
            self.initial_margin = self
                .quantity
                .abs()
                .checked_mul(price)
                .and_then(|notional| notional.checked_div(Decimal::from(leverage)))
                .ok_or_else(overflow)?;
        }

        self.realized_pnl = self
            .realized_pnl
            .checked_add(realized_pnl)
            .ok_or_else(overflow)?;
        Ok(PositionUpdate { realized_pnl })
    }

    pub fn unrealized_pnl(&self, mark_price: Decimal) -> Result<Decimal> {
        if self.quantity.is_zero() {
            Ok(Decimal::ZERO)
        } else {
            let price_change = mark_price.checked_sub(self.entry_price).ok_or_else(|| {
                ExchangeError::Internal(
                    "numeric overflow while calculating position price change".into(),
                )
            })?;
            self.quantity.checked_mul(price_change).ok_or_else(|| {
                ExchangeError::Internal("numeric overflow while calculating unrealized PnL".into())
            })
        }
    }
}

impl Account {
    pub fn risk_snapshot<'a>(
        &self,
        markets: impl Iterator<Item = (&'a String, &'a MarketState)>,
    ) -> Result<RiskSnapshot> {
        let overflow =
            || ExchangeError::Internal("numeric overflow while calculating account risk".into());
        let mut unrealized_pnl = Decimal::ZERO;
        let mut maintenance_requirement = Decimal::ZERO;
        let mut position_margin = Decimal::ZERO;

        for (symbol, market) in markets {
            if let Some(position) = self.positions.get(symbol) {
                let funding_delta = market
                    .funding_index
                    .checked_sub(position.funding_index)
                    .ok_or_else(overflow)?;
                let funding_payment = position
                    .quantity
                    .checked_mul(funding_delta)
                    .ok_or_else(overflow)?;
                let accrued_funding = Decimal::ZERO
                    .checked_sub(funding_payment)
                    .ok_or_else(overflow)?;
                unrealized_pnl = unrealized_pnl
                    .checked_add(position.unrealized_pnl(market.mark_price)?)
                    .and_then(|pnl| pnl.checked_add(accrued_funding))
                    .ok_or_else(overflow)?;
                let maintenance = position
                    .quantity
                    .abs()
                    .checked_mul(market.mark_price)
                    .and_then(|notional| {
                        notional.checked_mul(market.config.maintenance_margin_ratio)
                    })
                    .ok_or_else(overflow)?;
                maintenance_requirement = maintenance_requirement
                    .checked_add(maintenance)
                    .ok_or_else(overflow)?;
                position_margin = position_margin
                    .checked_add(position.initial_margin)
                    .ok_or_else(overflow)?;
            }
        }

        let equity = self
            .collateral
            .checked_add(unrealized_pnl)
            .ok_or_else(overflow)?;
        let available_margin = equity
            .checked_sub(position_margin)
            .and_then(|available| available.checked_sub(self.reserved_margin))
            .ok_or_else(overflow)?;
        Ok(RiskSnapshot {
            account_id: self.id.clone(),
            collateral: self.collateral,
            unrealized_pnl,
            equity,
            position_margin,
            reserved_margin: self.reserved_margin,
            maintenance_requirement,
            available_margin,
            liquidation_risk: equity <= maintenance_requirement && position_margin > Decimal::ZERO,
        })
    }
}

#[cfg(test)]
mod tests {
    use rust_decimal_macros::dec;

    use super::*;

    #[test]
    fn position_realizes_pnl_and_reverses() {
        let mut position = Position::default();
        position
            .apply_fill(Side::Buy, dec!(2), dec!(100), 10)
            .unwrap();
        assert_eq!(position.quantity, dec!(2));
        assert_eq!(position.initial_margin, dec!(20));

        let update = position
            .apply_fill(Side::Sell, dec!(3), dec!(110), 10)
            .unwrap();
        assert_eq!(update.realized_pnl, dec!(20));
        assert_eq!(position.quantity, dec!(-1));
        assert_eq!(position.entry_price, dec!(110));
        assert_eq!(position.initial_margin, dec!(11));
    }

    #[test]
    fn risk_overflow_returns_an_error_instead_of_panicking() {
        let mut account = Account::new("overflow".into());
        account.positions.insert(
            "BTCUSDT".into(),
            Position {
                quantity: Decimal::MAX,
                entry_price: Decimal::ZERO,
                initial_margin: Decimal::MAX,
                realized_pnl: Decimal::ZERO,
                funding_pnl: Decimal::ZERO,
                funding_index: Decimal::ZERO,
            },
        );
        let markets = crate::engine::default_markets();

        assert!(
            account
                .risk_snapshot(markets.iter().map(|market| (&market.config.symbol, market)))
                .is_err()
        );
    }
}
