use std::{cell::RefCell, collections::BTreeMap};

use anyhow::Result as AnyResult;
use imbl::{OrdMap, OrdSet, ordmap::DiffItem, ordset::DiffItem as SetDiffItem};
use jmt::{
    KeyHash, OwnedValue, Sha256Jmt, Version,
    storage::{LeafNode, Node, NodeKey, TreeReader, TreeUpdateBatch},
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    domain::{AccountId, Symbol},
    engine::EngineState,
    error::{ExchangeError, Result},
    shielded_margin::{Nullifier, PublicNote},
    shielded_protocol::{
        DevelopmentShieldedLedger, DevelopmentShieldedLedgerPersistenceHeader,
        DevelopmentShieldedLedgerPersistenceParts,
    },
};

const ENTITY_KEY_DOMAIN: &[u8] = b"ASTERIA_STATE_ENTITY_KEY_V5\0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub(crate) enum EntityKey {
    Meta,
    EventLog,
    AccountNonce(AccountId),
    Market(Symbol),
    Account(AccountId),
    Book(Symbol),
    OrderMarket(Uuid),
    ClientOrderId(String),
    Oracle(Symbol),
    PrivateOrderKeySet,
    PrivateOrderBatch(u64),
    PrivateOrderBondBatch(u64),
    PrivateBatchAppHash(u64),
    PrivateBatchSnapshot(u64),
    ShieldedHeader,
    ShieldedNote(u64),
    ShieldedNullifier(Nullifier),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StateMeta {
    chain_id: String,
    authority: AccountId,
    protocol_version: u16,
    height: u64,
    block_time_ms: i64,
    sequence: u64,
    total_credits: Decimal,
    fee_vault: Decimal,
    insurance_fund: Decimal,
    funding_pool: Decimal,
    private_validator_bindings: OrdMap<String, u16>,
    private_order_fee: Decimal,
}

impl From<&EngineState> for StateMeta {
    fn from(state: &EngineState) -> Self {
        Self {
            chain_id: state.chain_id.clone(),
            authority: state.authority.clone(),
            protocol_version: state.protocol_version,
            height: state.height,
            block_time_ms: state.block_time_ms,
            sequence: state.sequence,
            total_credits: state.total_credits,
            fee_vault: state.fee_vault,
            insurance_fund: state.insurance_fund,
            funding_pool: state.funding_pool,
            private_validator_bindings: state.private_validator_bindings.clone(),
            private_order_fee: state.private_order_fee,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EntityMutation {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

impl EntityMutation {
    pub fn key_hash(&self) -> KeyHash {
        KeyHash::with::<Sha256>(&self.key)
    }
}

pub(crate) fn entity_key_bytes(key: &EntityKey) -> Result<Vec<u8>> {
    let encoded =
        serde_jcs::to_vec(key).map_err(|error| ExchangeError::Persistence(error.to_string()))?;
    let mut bytes = Vec::with_capacity(ENTITY_KEY_DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(ENTITY_KEY_DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn decode_entity_key(bytes: &[u8]) -> Result<EntityKey> {
    let encoded = bytes.strip_prefix(ENTITY_KEY_DOMAIN).ok_or_else(|| {
        ExchangeError::Persistence("state entity key has an invalid domain".into())
    })?;
    canonical_decode(encoded, "state entity key")
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|error| ExchangeError::Persistence(error.to_string()))
}

fn canonical_decode<T: DeserializeOwned + Serialize>(bytes: &[u8], label: &str) -> Result<T> {
    let decoded: T = serde_json::from_slice(bytes)
        .map_err(|error| ExchangeError::Persistence(format!("invalid {label}: {error}")))?;
    if canonical_encode(&decoded)? != bytes {
        return Err(ExchangeError::Persistence(format!(
            "{label} is not canonically encoded"
        )));
    }
    Ok(decoded)
}

fn mutation<T: Serialize>(key: EntityKey, value: Option<&T>) -> Result<EntityMutation> {
    Ok(EntityMutation {
        key: entity_key_bytes(&key)?,
        value: value.map(canonical_encode).transpose()?,
    })
}

fn push_map_diff<K, V>(
    previous: &OrdMap<K, V>,
    next: &OrdMap<K, V>,
    entity_key: impl Fn(&K) -> EntityKey,
    output: &mut Vec<EntityMutation>,
) -> Result<()>
where
    K: Ord,
    V: PartialEq + Serialize,
{
    for difference in previous.diff(next) {
        match difference {
            DiffItem::Add(key, value) => {
                output.push(mutation(entity_key(key), Some(value))?);
            }
            DiffItem::Update {
                new: (key, value), ..
            } => {
                output.push(mutation(entity_key(key), Some(value))?);
            }
            DiffItem::Remove(key, _) => {
                output.push(mutation::<V>(entity_key(key), None)?);
            }
        }
    }
    Ok(())
}

fn shielded_persistence_error(error: impl std::fmt::Display) -> ExchangeError {
    ExchangeError::Persistence(format!("invalid shielded persistence state: {error}"))
}

fn shielded_parts(
    ledger: &DevelopmentShieldedLedger,
) -> Result<DevelopmentShieldedLedgerPersistenceParts<'_>> {
    ledger
        .persistence_parts()
        .map_err(shielded_persistence_error)
}

fn push_complete_shielded_ledger(
    ledger: &DevelopmentShieldedLedger,
    output: &mut Vec<EntityMutation>,
) -> Result<()> {
    let parts = shielded_parts(ledger)?;
    output.push(mutation(EntityKey::ShieldedHeader, Some(&parts.header))?);
    for (leaf_index, note) in parts.notes.iter().enumerate() {
        output.push(mutation(
            EntityKey::ShieldedNote(u64::try_from(leaf_index).map_err(|_| {
                ExchangeError::Persistence("shielded note index exceeds u64".into())
            })?),
            Some(note),
        )?);
    }
    for nullifier in parts.spent_nullifiers {
        output.push(mutation(
            EntityKey::ShieldedNullifier(*nullifier),
            Some(&()),
        )?);
    }
    Ok(())
}

fn push_shielded_diff(
    previous: Option<&DevelopmentShieldedLedger>,
    next: Option<&DevelopmentShieldedLedger>,
    output: &mut Vec<EntityMutation>,
) -> Result<()> {
    match (previous, next) {
        (None, None) => Ok(()),
        (None, Some(next)) => push_complete_shielded_ledger(next, output),
        (Some(previous), None) => {
            let previous = shielded_parts(previous)?;
            output.push(mutation::<DevelopmentShieldedLedgerPersistenceHeader>(
                EntityKey::ShieldedHeader,
                None,
            )?);
            for leaf_index in 0..previous.header.margin.note_count {
                output.push(mutation::<PublicNote>(
                    EntityKey::ShieldedNote(leaf_index),
                    None,
                )?);
            }
            for nullifier in previous.spent_nullifiers {
                output.push(mutation::<()>(
                    EntityKey::ShieldedNullifier(*nullifier),
                    None,
                )?);
            }
            Ok(())
        }
        (Some(previous_ledger), Some(next_ledger)) => {
            let previous = shielded_parts(previous_ledger)?;
            let next = shielded_parts(next_ledger)?;
            if previous.header.version != next.header.version
                || previous.header.chain_domain != next.header.chain_domain
                || previous.header.ledger_id != next.header.ledger_id
                || previous.header.deposit_authority != next.header.deposit_authority
                || previous.header.profile != next.header.profile
                || previous.header.margin.root_history_limit
                    != next.header.margin.root_history_limit
                || previous
                    .header
                    .policies
                    .iter()
                    .any(|(market_id, policy)| next.header.policies.get(market_id) != Some(policy))
            {
                return Err(ExchangeError::Persistence(
                    "persisted shielded ledger metadata is not append-only".into(),
                ));
            }
            let previous_count = previous.header.margin.note_count;
            let next_count = next.header.margin.note_count;
            if next_count < previous_count {
                return Err(ExchangeError::Persistence(
                    "persisted shielded notes cannot be removed".into(),
                ));
            }
            let next_prefix_root = next_ledger
                .persistence_root_at_note_count(previous_count)
                .map_err(shielded_persistence_error)?;
            if next_prefix_root != previous.header.margin.current_root {
                return Err(ExchangeError::Persistence(
                    "persisted shielded note prefix was modified".into(),
                ));
            }
            for leaf_index in previous_count..next_count {
                let note = next
                    .notes
                    .get(usize::try_from(leaf_index).map_err(|_| {
                        ExchangeError::Persistence("shielded note index exceeds usize".into())
                    })?)
                    .ok_or_else(|| {
                        ExchangeError::Persistence(format!(
                            "shielded note {leaf_index} is missing from the append delta"
                        ))
                    })?;
                output.push(mutation(EntityKey::ShieldedNote(leaf_index), Some(note))?);
            }
            for difference in previous.spent_nullifiers.diff(next.spent_nullifiers) {
                match difference {
                    SetDiffItem::Add(nullifier) => output.push(mutation(
                        EntityKey::ShieldedNullifier(*nullifier),
                        Some(&()),
                    )?),
                    SetDiffItem::Remove(_) => {
                        return Err(ExchangeError::Persistence(
                            "persisted shielded nullifiers cannot be removed".into(),
                        ));
                    }
                }
            }
            if previous.header != next.header {
                output.push(mutation(EntityKey::ShieldedHeader, Some(&next.header))?);
            }
            Ok(())
        }
    }
}

pub(crate) fn state_mutations(
    previous: Option<&EngineState>,
    next: &EngineState,
) -> Result<Vec<EntityMutation>> {
    let Some(previous) = previous else {
        return all_entities(next);
    };

    let mut changes = Vec::new();
    let previous_meta = StateMeta::from(previous);
    let next_meta = StateMeta::from(next);
    if previous_meta != next_meta {
        changes.push(mutation(EntityKey::Meta, Some(&next_meta))?);
    }
    if previous.event_log != next.event_log {
        changes.push(mutation(EntityKey::EventLog, Some(&next.event_log))?);
    }
    push_map_diff(
        &previous.account_nonces,
        &next.account_nonces,
        |account_id| EntityKey::AccountNonce(account_id.clone()),
        &mut changes,
    )?;
    push_shielded_diff(
        previous.shielded_ledger.as_ref(),
        next.shielded_ledger.as_ref(),
        &mut changes,
    )?;
    if previous.private_order_key_set != next.private_order_key_set {
        changes.push(mutation(
            EntityKey::PrivateOrderKeySet,
            next.private_order_key_set.as_ref(),
        )?);
    }
    push_map_diff(
        &previous.pending_private_orders,
        &next.pending_private_orders,
        |height| EntityKey::PrivateOrderBatch(*height),
        &mut changes,
    )?;
    push_map_diff(
        &previous.private_order_bonds,
        &next.private_order_bonds,
        |height| EntityKey::PrivateOrderBondBatch(*height),
        &mut changes,
    )?;
    push_map_diff(
        &previous.private_batch_app_hashes,
        &next.private_batch_app_hashes,
        |height| EntityKey::PrivateBatchAppHash(*height),
        &mut changes,
    )?;
    push_map_diff(
        &previous.private_batch_snapshots,
        &next.private_batch_snapshots,
        |height| EntityKey::PrivateBatchSnapshot(*height),
        &mut changes,
    )?;
    push_map_diff(
        &previous.markets,
        &next.markets,
        |symbol| EntityKey::Market(symbol.clone()),
        &mut changes,
    )?;
    push_map_diff(
        &previous.accounts,
        &next.accounts,
        |account_id| EntityKey::Account(account_id.clone()),
        &mut changes,
    )?;
    push_map_diff(
        &previous.books,
        &next.books,
        |symbol| EntityKey::Book(symbol.clone()),
        &mut changes,
    )?;
    push_map_diff(
        &previous.order_market,
        &next.order_market,
        |order_id| EntityKey::OrderMarket(*order_id),
        &mut changes,
    )?;
    push_map_diff(
        &previous.client_order_ids,
        &next.client_order_ids,
        |client_order_id| EntityKey::ClientOrderId(client_order_id.clone()),
        &mut changes,
    )?;
    push_map_diff(
        &previous.oracle,
        &next.oracle,
        |symbol| EntityKey::Oracle(symbol.clone()),
        &mut changes,
    )?;
    changes.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(changes)
}

pub(crate) fn all_entities(state: &EngineState) -> Result<Vec<EntityMutation>> {
    let shielded_entity_count = state
        .shielded_ledger
        .as_ref()
        .map(|ledger| {
            shielded_parts(ledger).map(|parts| {
                1_usize
                    .saturating_add(parts.notes.len())
                    .saturating_add(parts.spent_nullifiers.len())
            })
        })
        .transpose()?
        .unwrap_or(0);
    let mut entities = Vec::with_capacity(
        2 + state.account_nonces.len()
            + state.markets.len()
            + state.accounts.len()
            + state.books.len()
            + state.order_market.len()
            + state.client_order_ids.len()
            + state.oracle.len()
            + state.pending_private_orders.len()
            + state.private_order_bonds.len()
            + state.private_batch_app_hashes.len()
            + state.private_batch_snapshots.len()
            + shielded_entity_count,
    );
    entities.push(mutation(EntityKey::Meta, Some(&StateMeta::from(state)))?);
    entities.push(mutation(EntityKey::EventLog, Some(&state.event_log))?);
    for (account_id, nonce) in &state.account_nonces {
        entities.push(mutation(
            EntityKey::AccountNonce(account_id.clone()),
            Some(nonce),
        )?);
    }
    for (symbol, market) in &state.markets {
        entities.push(mutation(EntityKey::Market(symbol.clone()), Some(market))?);
    }
    for (account_id, account) in &state.accounts {
        entities.push(mutation(
            EntityKey::Account(account_id.clone()),
            Some(account),
        )?);
    }
    for (symbol, book) in &state.books {
        entities.push(mutation(EntityKey::Book(symbol.clone()), Some(book))?);
    }
    for (order_id, symbol) in &state.order_market {
        entities.push(mutation(EntityKey::OrderMarket(*order_id), Some(symbol))?);
    }
    for (client_order_id, order_id) in &state.client_order_ids {
        entities.push(mutation(
            EntityKey::ClientOrderId(client_order_id.clone()),
            Some(order_id),
        )?);
    }
    for (symbol, oracle) in &state.oracle {
        entities.push(mutation(EntityKey::Oracle(symbol.clone()), Some(oracle))?);
    }
    if let Some(key_set) = &state.private_order_key_set {
        entities.push(mutation(EntityKey::PrivateOrderKeySet, Some(key_set))?);
    }
    for (height, pending) in &state.pending_private_orders {
        entities.push(mutation(
            EntityKey::PrivateOrderBatch(*height),
            Some(pending),
        )?);
    }
    for (height, bonds) in &state.private_order_bonds {
        entities.push(mutation(
            EntityKey::PrivateOrderBondBatch(*height),
            Some(bonds),
        )?);
    }
    for (height, app_hash) in &state.private_batch_app_hashes {
        entities.push(mutation(
            EntityKey::PrivateBatchAppHash(*height),
            Some(app_hash),
        )?);
    }
    for (height, snapshot) in &state.private_batch_snapshots {
        entities.push(mutation(
            EntityKey::PrivateBatchSnapshot(*height),
            Some(snapshot),
        )?);
    }
    if let Some(ledger) = &state.shielded_ledger {
        push_complete_shielded_ledger(ledger, &mut entities)?;
    }
    entities.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(entities)
}

pub(crate) fn decode_state(
    entities: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> Result<Option<EngineState>> {
    let mut found_any = false;
    let mut meta = None;
    let mut event_log = None;
    let mut account_nonces = OrdMap::new();
    let mut markets = OrdMap::new();
    let mut accounts = OrdMap::new();
    let mut books = OrdMap::new();
    let mut order_market = OrdMap::new();
    let mut client_order_ids = OrdMap::new();
    let mut oracle = OrdMap::new();
    let mut private_order_key_set = None;
    let mut pending_private_orders = OrdMap::new();
    let mut private_order_bonds = OrdMap::new();
    let mut private_batch_app_hashes = OrdMap::new();
    let mut private_batch_snapshots = OrdMap::new();
    let mut shielded_header = None;
    let mut shielded_notes = BTreeMap::new();
    let mut shielded_nullifiers = OrdSet::new();

    for (key_bytes, value_bytes) in entities {
        found_any = true;
        match decode_entity_key(&key_bytes)? {
            EntityKey::Meta => meta = Some(canonical_decode(&value_bytes, "state metadata")?),
            EntityKey::EventLog => event_log = Some(canonical_decode(&value_bytes, "event log")?),
            EntityKey::AccountNonce(account_id) => {
                account_nonces.insert(account_id, canonical_decode(&value_bytes, "account nonce")?);
            }
            EntityKey::Market(symbol) => {
                markets.insert(symbol, canonical_decode(&value_bytes, "market")?);
            }
            EntityKey::Account(account_id) => {
                accounts.insert(account_id, canonical_decode(&value_bytes, "account")?);
            }
            EntityKey::Book(symbol) => {
                books.insert(symbol, canonical_decode(&value_bytes, "order book")?);
            }
            EntityKey::OrderMarket(order_id) => {
                order_market.insert(
                    order_id,
                    canonical_decode(&value_bytes, "order market index")?,
                );
            }
            EntityKey::ClientOrderId(client_order_id) => {
                client_order_ids.insert(
                    client_order_id,
                    canonical_decode(&value_bytes, "client order index")?,
                );
            }
            EntityKey::Oracle(symbol) => {
                oracle.insert(symbol, canonical_decode(&value_bytes, "oracle snapshot")?);
            }
            EntityKey::PrivateOrderKeySet => {
                private_order_key_set =
                    Some(canonical_decode(&value_bytes, "private-order key set")?);
            }
            EntityKey::PrivateOrderBatch(height) => {
                pending_private_orders.insert(
                    height,
                    canonical_decode(&value_bytes, "pending private-order batch")?,
                );
            }
            EntityKey::PrivateOrderBondBatch(height) => {
                private_order_bonds.insert(
                    height,
                    canonical_decode(&value_bytes, "private-order bond batch")?,
                );
            }
            EntityKey::PrivateBatchAppHash(height) => {
                private_batch_app_hashes.insert(
                    height,
                    canonical_decode(&value_bytes, "private batch app-hash anchor")?,
                );
            }
            EntityKey::PrivateBatchSnapshot(height) => {
                private_batch_snapshots.insert(
                    height,
                    canonical_decode(&value_bytes, "private batch liquidity snapshot")?,
                );
            }
            EntityKey::ShieldedHeader => {
                let header = canonical_decode(&value_bytes, "shielded ledger header")?;
                if shielded_header.replace(header).is_some() {
                    return Err(ExchangeError::Persistence(
                        "duplicate shielded ledger header entity".into(),
                    ));
                }
            }
            EntityKey::ShieldedNote(leaf_index) => {
                let note = canonical_decode(&value_bytes, "shielded note")?;
                if shielded_notes.insert(leaf_index, note).is_some() {
                    return Err(ExchangeError::Persistence(format!(
                        "duplicate shielded note entity at index {leaf_index}"
                    )));
                }
            }
            EntityKey::ShieldedNullifier(nullifier) => {
                canonical_decode::<()>(&value_bytes, "shielded nullifier marker")?;
                if shielded_nullifiers.insert(nullifier).is_some() {
                    return Err(ExchangeError::Persistence(
                        "duplicate shielded nullifier entity".into(),
                    ));
                }
            }
        }
    }
    if !found_any {
        return Ok(None);
    }
    let meta: StateMeta = meta.ok_or_else(|| {
        ExchangeError::Persistence("state entity table is missing metadata".into())
    })?;
    let event_log = event_log.ok_or_else(|| {
        ExchangeError::Persistence("state entity table is missing the event log".into())
    })?;
    if markets.keys().any(|symbol| !books.contains_key(symbol))
        || books.keys().any(|symbol| !markets.contains_key(symbol))
    {
        return Err(ExchangeError::Persistence(
            "market and order-book entity sets differ".into(),
        ));
    }
    let shielded_ledger = match shielded_header {
        Some(header) => Some(
            DevelopmentShieldedLedger::rebuild_from_persistence(
                header,
                shielded_notes,
                shielded_nullifiers,
            )
            .map_err(shielded_persistence_error)?,
        ),
        None if shielded_notes.is_empty() && shielded_nullifiers.is_empty() => None,
        None => {
            return Err(ExchangeError::Persistence(
                "shielded note or nullifier entities exist without a ledger header".into(),
            ));
        }
    };
    Ok(Some(EngineState {
        chain_id: meta.chain_id,
        authority: meta.authority,
        protocol_version: meta.protocol_version,
        height: meta.height,
        block_time_ms: meta.block_time_ms,
        account_nonces,
        markets,
        accounts,
        books,
        order_market,
        client_order_ids,
        sequence: meta.sequence,
        total_credits: meta.total_credits,
        fee_vault: meta.fee_vault,
        insurance_fund: meta.insurance_fund,
        funding_pool: meta.funding_pool,
        oracle,
        private_order_key_set,
        private_validator_bindings: meta.private_validator_bindings,
        pending_private_orders,
        private_order_bonds,
        private_batch_app_hashes,
        private_batch_snapshots,
        private_order_fee: meta.private_order_fee,
        shielded_ledger,
        event_log,
    }))
}

pub fn compute_state_root(state: &EngineState) -> Result<[u8; 32]> {
    let memory = MemoryTreeStore::default();
    let tree = Sha256Jmt::new(&memory);
    let values = all_entities(state)?
        .into_iter()
        .map(|entity| (entity.key_hash(), entity.value));
    let (root, _) = tree
        .put_value_set(values, 0)
        .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
    Ok(root.into())
}

#[derive(Default)]
struct MemoryTreeStore {
    nodes: RefCell<BTreeMap<NodeKey, Node>>,
    values: RefCell<BTreeMap<KeyHash, (Version, Option<OwnedValue>)>>,
}

impl MemoryTreeStore {
    #[allow(dead_code)]
    fn apply(&self, update: &TreeUpdateBatch) {
        self.nodes
            .borrow_mut()
            .extend(update.node_batch.nodes().clone());
        for ((version, key_hash), value) in update.node_batch.values() {
            self.values
                .borrow_mut()
                .insert(*key_hash, (*version, value.clone()));
        }
    }
}

impl TreeReader for MemoryTreeStore {
    fn get_node_option(&self, node_key: &NodeKey) -> AnyResult<Option<Node>> {
        Ok(self.nodes.borrow().get(node_key).cloned())
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> AnyResult<Option<OwnedValue>> {
        Ok(self
            .values
            .borrow()
            .get(&key_hash)
            .filter(|(version, _)| *version <= max_version)
            .and_then(|(_, value)| value.clone()))
    }

    fn get_rightmost_leaf(&self) -> AnyResult<Option<(NodeKey, LeafNode)>> {
        Ok(self
            .nodes
            .borrow()
            .iter()
            .filter_map(|(key, node)| match node {
                Node::Leaf(leaf) => Some((key.clone(), leaf.clone())),
                _ => None,
            })
            .max_by_key(|(_, leaf)| leaf.key_hash()))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use rust_decimal_macros::dec;

    use super::*;
    use crate::{
        domain::Account,
        engine::default_markets,
        shielded_margin::{
            CollateralAssetId, MarginPolicy, MarketId, NoteOpening, SHIELDED_MARGIN_VERSION,
            ShieldedSpend, SpendStatement, TransparentInputWitness, TransparentSpendProof,
            TransparentWitnessVerifier, derive_nullifier,
        },
        shielded_protocol::{
            AuthorityDeposit, DepositStatement, SHIELDED_PROTOCOL_VERSION, TransparentDepositProof,
            TransparentDepositVerifier, derive_chain_domain,
        },
        store::StateStore,
    };

    fn shielded_test_states() -> (EngineState, EngineState, Nullifier) {
        let authority = SigningKey::from_bytes(&[51; 32]);
        let owner = SigningKey::from_bytes(&[52; 32]);
        let market_id = MarketId::from_label(b"BTC-PERP");
        let collateral_asset = CollateralAssetId::from_label(b"USDC");
        let policy = MarginPolicy {
            version: SHIELDED_MARGIN_VERSION,
            market_id,
            collateral_asset,
            mark_price: 100,
            price_scale: 1,
            minimum_initial_margin_bps: 1_000,
            maximum_leverage: 20,
            minimum_fee: 10,
        };
        let chain_domain = derive_chain_domain("shielded-persistence-test").unwrap();
        let ledger_id = [0x5A; 32];
        let mut ledger = DevelopmentShieldedLedger::new_development(
            chain_domain,
            ledger_id,
            authority.verifying_key().to_bytes(),
        )
        .unwrap();
        ledger.register_market(policy).unwrap();
        let input_opening = NoteOpening {
            owner: owner.verifying_key().to_bytes(),
            nullifier_key: [0x11; 32],
            collateral: 10_000,
            position: 0,
            leverage: 1,
            blinding: [0x12; 32],
        };
        let input_note = PublicNote::new(market_id, collateral_asset, &input_opening);
        let deposit_statement = DepositStatement {
            version: SHIELDED_PROTOCOL_VERSION,
            chain_domain,
            ledger_id,
            note: input_note,
            backing_amount: 10_000,
        };
        ledger
            .authority_deposit(
                &AuthorityDeposit {
                    authority_signature: authority
                        .sign(&deposit_statement.authorization_digest())
                        .to_bytes()
                        .to_vec(),
                    statement: deposit_statement,
                    proof: TransparentDepositProof {
                        opening: input_opening.clone(),
                    }
                    .to_canonical_bytes()
                    .unwrap(),
                },
                &TransparentDepositVerifier,
            )
            .unwrap();

        let mut before = EngineState::genesis("shielded-persistence-test", default_markets());
        before.shielded_ledger = Some(ledger.clone());
        let output_opening = NoteOpening {
            owner: owner.verifying_key().to_bytes(),
            nullifier_key: [0x21; 32],
            collateral: 9_990,
            position: 0,
            leverage: 1,
            blinding: [0x22; 32],
        };
        let nullifier = derive_nullifier(&input_note, &input_opening, 0);
        let statement = SpendStatement {
            version: SHIELDED_MARGIN_VERSION,
            chain_domain,
            ledger_id,
            anchor_root: ledger.root(),
            market_id,
            collateral_asset,
            policy_hash: policy.policy_hash().unwrap(),
            nullifiers: vec![nullifier],
            output_commitments: vec![
                PublicNote::new(market_id, collateral_asset, &output_opening).commitment,
            ],
            fee: 10,
        };
        let authorization_signature = owner
            .sign(&statement.authorization_digest().unwrap())
            .to_bytes()
            .to_vec();
        let spend = ShieldedSpend {
            statement,
            proof: TransparentSpendProof {
                inputs: vec![TransparentInputWitness {
                    note: input_note,
                    opening: input_opening,
                    merkle_proof: ledger.merkle_proof(0).unwrap(),
                    authorization_signature,
                }],
                output_openings: vec![output_opening],
            }
            .to_canonical_bytes()
            .unwrap(),
        };
        ledger
            .apply_spend(&spend, &TransparentWitnessVerifier)
            .unwrap();
        let mut after = before.clone();
        after.shielded_ledger = Some(ledger);
        (before, after, nullifier)
    }

    #[test]
    fn root_is_deterministic_and_entity_sensitive() {
        let mut first = EngineState::genesis("state-root-test", default_markets());
        let mut second = first.clone();
        assert_eq!(
            compute_state_root(&first).unwrap(),
            compute_state_root(&second).unwrap()
        );

        let mut account = Account::new("alice".into());
        account.collateral = dec!(10);
        first.accounts.insert(account.id.clone(), account);
        assert_ne!(
            compute_state_root(&first).unwrap(),
            compute_state_root(&second).unwrap()
        );

        second.accounts = first.accounts.clone();
        assert_eq!(
            compute_state_root(&first).unwrap(),
            compute_state_root(&second).unwrap()
        );
    }

    #[test]
    fn structural_diff_only_contains_changed_entities() {
        let first = EngineState::genesis("diff-test", default_markets());
        let mut second = first.clone();
        second.account_nonces.insert("alice".into(), 1);
        second.height = 1;

        let changes = state_mutations(Some(&first), &second).unwrap();
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|change| change.value.is_some()));
    }

    #[test]
    fn entity_round_trip_reconstructs_state() {
        let mut state = EngineState::genesis("round-trip", default_markets());
        state.account_nonces.insert("alice".into(), 7);
        let entities = all_entities(&state)
            .unwrap()
            .into_iter()
            .map(|entity| (entity.key, entity.value.unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(decode_state(entities).unwrap(), Some(state));
    }

    #[test]
    fn shielded_spend_writes_only_header_new_notes_and_new_nullifiers() {
        let (before, after, nullifier) = shielded_test_states();

        let changes = state_mutations(Some(&before), &after).unwrap();
        let keys = changes
            .iter()
            .map(|change| decode_entity_key(&change.key).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(changes.len(), 3, "{keys:?}");
        assert!(changes.iter().all(|change| change.value.is_some()));
        assert!(keys.contains(&EntityKey::ShieldedHeader));
        assert!(keys.contains(&EntityKey::ShieldedNote(1)));
        assert!(keys.contains(&EntityKey::ShieldedNullifier(nullifier)));
        assert!(!keys.contains(&EntityKey::ShieldedNote(0)));
    }

    #[test]
    fn split_shielded_entities_round_trip_and_reject_missing_or_duplicate_notes() {
        let (_, state, _) = shielded_test_states();
        let entities = all_entities(&state)
            .unwrap()
            .into_iter()
            .map(|entity| (entity.key, entity.value.unwrap()))
            .collect::<Vec<_>>();
        let decoded = decode_state(entities.clone()).unwrap().unwrap();
        assert_eq!(decoded, state);
        assert_eq!(
            decoded.shielded_ledger.as_ref().unwrap().root(),
            state.shielded_ledger.as_ref().unwrap().root()
        );

        let mut missing = entities.clone();
        missing.retain(|(key, _)| decode_entity_key(key).unwrap() != EntityKey::ShieldedNote(0));
        assert!(decode_state(missing).is_err());

        let first_note = entities
            .iter()
            .find(|(key, _)| decode_entity_key(key).unwrap() == EntityKey::ShieldedNote(0))
            .unwrap()
            .1
            .clone();
        let mut duplicate_commitment = entities;
        duplicate_commitment
            .iter_mut()
            .find(|(key, _)| decode_entity_key(key).unwrap() == EntityKey::ShieldedNote(1))
            .unwrap()
            .1 = first_note;
        assert!(decode_state(duplicate_commitment).is_err());
    }

    #[test]
    fn split_shielded_entities_survive_store_restart_with_the_same_root() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shielded-state.redb");
        let (_, state, _) = shielded_test_states();
        let app_hash;
        {
            let store = StateStore::open(&path).unwrap();
            app_hash = store.commit_state(None, &state).unwrap();
            let loaded = store.load_state().unwrap().unwrap();
            assert_eq!(loaded.state, state);
            assert_eq!(loaded.app_hash, app_hash);
        }

        let store = StateStore::open(&path).unwrap();
        let loaded = store.load_state().unwrap().unwrap();
        assert_eq!(loaded.state, state);
        assert_eq!(loaded.app_hash, app_hash);
        assert_eq!(
            loaded.state.shielded_ledger.as_ref().unwrap().root(),
            state.shielded_ledger.as_ref().unwrap().root()
        );
    }
}
