use chrono::{DateTime, Utc};
use imbl::Vector;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::{AccountId, OracleSnapshot, Order, SocializedLoss, Symbol, Trade};

pub const MAX_RETAINED_EVENTS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    AccountCredited {
        account_id: AccountId,
        amount: Decimal,
    },
    MarkPriceUpdated {
        symbol: Symbol,
        mark_price: Decimal,
    },
    OrderAccepted {
        order: Order,
    },
    OrderCancelled {
        order_id: Uuid,
        account_id: AccountId,
        reason: String,
    },
    TradeExecuted {
        trade: Trade,
    },
    FundingApplied {
        symbol: Symbol,
        rate: Decimal,
        funding_index: Decimal,
        funding_pool: Decimal,
    },
    OraclePricePublished {
        snapshot: OracleSnapshot,
    },
    LiquidationExecuted {
        account_id: AccountId,
        symbol: Symbol,
        closed_quantity: Decimal,
        remaining_quantity: Decimal,
        penalty: Decimal,
        bad_debt: Decimal,
        insurance_used: Decimal,
        fee_vault_used: Decimal,
        socialized_losses: Vec<SocializedLoss>,
    },
    PrivateOrderQueued {
        submission_id: String,
        account_id: AccountId,
        market_id: Symbol,
        batch_height: u64,
        fee: Decimal,
        bond: Decimal,
    },
    PrivateOrderInvalid {
        submission_id: String,
        reason: String,
    },
    PrivateBatchCleared {
        market_id: Symbol,
        batch_height: u64,
        clearing_price: Option<Decimal>,
        matched_quantity: Decimal,
        valid_orders: usize,
        invalid_orders: usize,
    },
    ShieldedMarketConfigured {
        market_id: String,
    },
    ShieldedDepositCommitted {
        market_id: String,
        leaf_index: u64,
        backing_amount: u64,
        new_root: String,
    },
    ShieldedSpendApplied {
        market_id: String,
        nullifier_count: usize,
        output_count: usize,
        fee: u64,
        new_root: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub previous_hash: String,
    pub hash: String,
    pub kind: EventKind,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventLog {
    events: Vector<Event>,
}

impl EventLog {
    pub fn append(&mut self, sequence: u64, timestamp: DateTime<Utc>, kind: EventKind) -> Event {
        let previous_hash = self
            .events
            .back()
            .map(|event| event.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let material = serde_json::to_vec(&(sequence, timestamp, previous_hash.as_str(), &kind))
            .expect("events are serializable");
        let hash = hex::encode(Sha256::digest(material));
        let event = Event {
            sequence,
            timestamp,
            previous_hash,
            hash,
            kind,
        };
        self.events.push_back(event.clone());
        self.prune();
        event
    }

    pub fn prune(&mut self) {
        while self.events.len() > MAX_RETAINED_EVENTS {
            self.events.pop_front();
        }
    }

    pub fn after(&self, sequence: u64, limit: usize) -> Vec<Event> {
        self.events
            .iter()
            .filter(|event| event.sequence > sequence)
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn verify(&self) -> bool {
        let Some(first) = self.events.front() else {
            return true;
        };
        // A retained window is anchored by the previous hash committed in its
        // first event; the application state hash protects that anchor.
        let mut previous_hash = first.previous_hash.clone();
        let mut previous_sequence = first.sequence.saturating_sub(1);
        for event in &self.events {
            if event.previous_hash != previous_hash || event.sequence <= previous_sequence {
                return false;
            }
            let material = serde_json::to_vec(&(
                event.sequence,
                event.timestamp,
                event.previous_hash.as_str(),
                &event.kind,
            ))
            .expect("events are serializable");
            if event.hash != hex::encode(Sha256::digest(material)) {
                return false;
            }
            previous_hash.clone_from(&event.hash);
            previous_sequence = event.sequence;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_window_is_bounded_and_keeps_a_verifiable_anchor() {
        let mut log = EventLog::default();
        for sequence in 1..=(MAX_RETAINED_EVENTS as u64 + 17) {
            log.append(
                sequence,
                DateTime::UNIX_EPOCH,
                EventKind::AccountCredited {
                    account_id: "account".into(),
                    amount: Decimal::ONE,
                },
            );
        }

        assert_eq!(log.events.len(), MAX_RETAINED_EVENTS);
        assert_eq!(log.events.front().unwrap().sequence, 18);
        assert!(log.verify());
    }

    #[test]
    fn tampering_inside_a_retained_window_is_detected() {
        let mut log = EventLog::default();
        for sequence in 1..=3 {
            log.append(
                sequence,
                DateTime::UNIX_EPOCH,
                EventKind::AccountCredited {
                    account_id: "account".into(),
                    amount: Decimal::ONE,
                },
            );
        }
        log.events.get_mut(1).unwrap().previous_hash = "f".repeat(64);

        assert!(!log.verify());
    }
}
