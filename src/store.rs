use std::{fs, path::Path, sync::Arc};

use anyhow::Result as AnyResult;
use jmt::{
    KeyHash, OwnedValue, Sha256Jmt, Version,
    storage::{LeafNode, NibblePath, Node, NodeKey, TreeReader, TreeUpdateBatch},
};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    engine::EngineState,
    error::{ExchangeError, Result},
    state_commitment::{
        EntityMutation, build_state_tree, compute_state_root, decode_state, state_mutations,
    },
};

const ENTITY_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state_entities_v5");
const JMT_NODE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("jmt_nodes_v5");
const JMT_VALUE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("jmt_values_v5");
const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state_metadata_v5");
const CURRENT_METADATA_KEY: &str = "current";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CommitMetadata {
    version: Version,
    state_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LatestValue {
    version: Version,
    value: Option<OwnedValue>,
}

#[derive(Debug, Clone)]
pub struct StoredState {
    pub state: EngineState,
    pub app_hash: [u8; 32],
    pub version: Version,
}

#[derive(Clone)]
pub struct StateStore {
    database: Arc<Database>,
}

impl StateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
        }
        let database = match Database::create(path) {
            Ok(database) => database,
            Err(redb::DatabaseError::DatabaseAlreadyOpen) => {
                return Err(ExchangeError::DatabaseInUse {
                    path: path.display().to_string(),
                });
            }
            Err(error) => return Err(ExchangeError::Persistence(error.to_string())),
        };
        Ok(Self {
            database: Arc::new(database),
        })
    }

    pub fn load_state(&self) -> Result<Option<StoredState>> {
        let metadata = self.read_metadata()?;
        let entities = self.read_entities()?;
        match (metadata, decode_state(entities)?) {
            (None, None) => Ok(None),
            (Some(_), None) => Err(ExchangeError::Persistence(
                "state metadata exists without state entities".into(),
            )),
            (None, Some(_)) => Err(ExchangeError::Persistence(
                "state entities exist without commit metadata".into(),
            )),
            (Some(metadata), Some(state)) => {
                let reconstructed = compute_state_root(&state)?;
                if reconstructed != metadata.state_root {
                    return Err(ExchangeError::Persistence(
                        "persisted entities do not match the state root".into(),
                    ));
                }
                let persisted_tree_root: [u8; 32] = Sha256Jmt::new(self)
                    .get_root_hash(metadata.version)
                    .map_err(persistence_error)?
                    .into();
                if persisted_tree_root != metadata.state_root {
                    return Err(ExchangeError::Persistence(
                        "persisted JMT nodes do not match the state root".into(),
                    ));
                }
                Ok(Some(StoredState {
                    state,
                    app_hash: metadata.state_root,
                    version: metadata.version,
                }))
            }
        }
    }

    pub fn preview_state_root(
        &self,
        previous: Option<&EngineState>,
        next: &EngineState,
    ) -> Result<[u8; 32]> {
        let (_, root, _, _) = self.build_update(previous, next)?;
        Ok(root)
    }

    pub fn commit_state(
        &self,
        previous: Option<&EngineState>,
        next: &EngineState,
    ) -> Result<[u8; 32]> {
        let (version, root, tree_update, mutations) = self.build_update(previous, next)?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
        {
            let mut entities = write
                .open_table(ENTITY_TABLE)
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            for mutation in mutations {
                match mutation.value {
                    Some(value) => {
                        entities
                            .insert(mutation.key.as_slice(), value.as_slice())
                            .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
                    }
                    None => {
                        entities
                            .remove(mutation.key.as_slice())
                            .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
                    }
                }
            }
        }
        self.write_tree_update(&write, version, &tree_update)?;
        {
            let metadata = CommitMetadata {
                version,
                state_root: root,
            };
            let bytes = canonical_encode(&metadata)?;
            let mut table = write
                .open_table(METADATA_TABLE)
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            table
                .insert(CURRENT_METADATA_KEY, bytes.as_slice())
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
        Ok(root)
    }

    /// Atomically replaces every persisted entity and JMT node with a verified
    /// snapshot state. The replacement starts again at JMT version zero so no
    /// local pre-sync history can influence the imported application hash.
    pub fn replace_state(&self, next: &EngineState) -> Result<[u8; 32]> {
        let (root, tree_update, entities) = build_state_tree(next)?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| ExchangeError::Persistence(error.to_string()))?;

        {
            let mut table = write
                .open_table(ENTITY_TABLE)
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            let mut old_keys = Vec::new();
            for entry in table
                .iter()
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?
            {
                let (key, _) =
                    entry.map_err(|error| ExchangeError::Persistence(error.to_string()))?;
                old_keys.push(key.value().to_vec());
            }
            for key in old_keys {
                table
                    .remove(key.as_slice())
                    .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            }
            for entity in entities {
                let value = entity.value.ok_or_else(|| {
                    ExchangeError::Persistence(
                        "full state replacement unexpectedly contained a deletion".into(),
                    )
                })?;
                table
                    .insert(entity.key.as_slice(), value.as_slice())
                    .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            }
        }
        {
            let mut table = write
                .open_table(JMT_NODE_TABLE)
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            let mut old_keys = Vec::new();
            for entry in table
                .iter()
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?
            {
                let (key, _) =
                    entry.map_err(|error| ExchangeError::Persistence(error.to_string()))?;
                old_keys.push(key.value().to_vec());
            }
            for key in old_keys {
                table
                    .remove(key.as_slice())
                    .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            }
        }
        {
            let mut table = write
                .open_table(JMT_VALUE_TABLE)
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            let mut old_keys = Vec::new();
            for entry in table
                .iter()
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?
            {
                let (key, _) =
                    entry.map_err(|error| ExchangeError::Persistence(error.to_string()))?;
                old_keys.push(key.value().to_vec());
            }
            for key in old_keys {
                table
                    .remove(key.as_slice())
                    .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            }
        }

        self.write_tree_update(&write, 0, &tree_update)?;
        {
            let metadata = CommitMetadata {
                version: 0,
                state_root: root,
            };
            let bytes = canonical_encode(&metadata)?;
            let mut table = write
                .open_table(METADATA_TABLE)
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            table
                .insert(CURRENT_METADATA_KEY, bytes.as_slice())
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
        Ok(root)
    }

    fn build_update(
        &self,
        previous: Option<&EngineState>,
        next: &EngineState,
    ) -> Result<(Version, [u8; 32], TreeUpdateBatch, Vec<EntityMutation>)> {
        let metadata = self.read_metadata()?;
        let version = match (&metadata, previous) {
            (None, None) => 0,
            (Some(metadata), Some(_)) => metadata.version.checked_add(1).ok_or_else(|| {
                ExchangeError::Persistence("state-store version is exhausted".into())
            })?,
            (None, Some(_)) => {
                return Err(ExchangeError::Persistence(
                    "cannot update an uninitialized state store".into(),
                ));
            }
            (Some(_), None) => {
                return Err(ExchangeError::Persistence(
                    "cannot initialize an already committed state store".into(),
                ));
            }
        };
        let mutations = state_mutations(previous, next)?;
        let values = mutations
            .iter()
            .map(|mutation| (mutation.key_hash(), mutation.value.clone()));
        let (root, tree_update) = Sha256Jmt::new(self)
            .put_value_set(values, version)
            .map_err(persistence_error)?;
        Ok((version, root.into(), tree_update, mutations))
    }

    fn read_metadata(&self) -> Result<Option<CommitMetadata>> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
        let table = match read.open_table(METADATA_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(ExchangeError::Persistence(error.to_string())),
        };
        let Some(value) = table
            .get(CURRENT_METADATA_KEY)
            .map_err(|error| ExchangeError::Persistence(error.to_string()))?
        else {
            return Ok(None);
        };
        canonical_decode(value.value(), "state commit metadata").map(Some)
    }

    fn read_entities(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
        let table = match read.open_table(ENTITY_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(ExchangeError::Persistence(error.to_string())),
        };
        table
            .iter()
            .map_err(|error| ExchangeError::Persistence(error.to_string()))?
            .map(|entry| {
                let (key, value) =
                    entry.map_err(|error| ExchangeError::Persistence(error.to_string()))?;
                Ok((key.value().to_vec(), value.value().to_vec()))
            })
            .collect()
    }

    fn write_tree_update(
        &self,
        write: &redb::WriteTransaction,
        version: Version,
        update: &TreeUpdateBatch,
    ) -> Result<()> {
        {
            let mut nodes = write
                .open_table(JMT_NODE_TABLE)
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            for (node_key, node) in update.node_batch.nodes() {
                let key = canonical_encode(node_key)?;
                let value = canonical_encode(node)?;
                nodes
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            }
            for stale in &update.stale_node_index_batch {
                if stale.stale_since_version != version {
                    return Err(ExchangeError::Persistence(format!(
                        "JMT stale node version {} does not match commit version {version}",
                        stale.stale_since_version
                    )));
                }
                let key = canonical_encode(&stale.node_key)?;
                if nodes
                    .remove(key.as_slice())
                    .map_err(|error| ExchangeError::Persistence(error.to_string()))?
                    .is_none()
                {
                    return Err(ExchangeError::Persistence(
                        "JMT stale index refers to a missing node".into(),
                    ));
                }
            }

            // An empty update copies the root to the new version without
            // reporting the previous root as stale. Current-only storage can
            // always discard that old root after the replacement is written.
            if let Some(previous_version) = version.checked_sub(1) {
                let previous_root = root_node_key(previous_version);
                let key = canonical_encode(&previous_root)?;
                nodes
                    .remove(key.as_slice())
                    .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            }
        }
        {
            let mut values = write
                .open_table(JMT_VALUE_TABLE)
                .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
            for ((version, key_hash), value) in update.node_batch.values() {
                if let Some(value) = value {
                    let latest = LatestValue {
                        version: *version,
                        value: Some(value.clone()),
                    };
                    let bytes = canonical_encode(&latest)?;
                    values
                        .insert(key_hash.0.as_slice(), bytes.as_slice())
                        .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
                } else {
                    values
                        .remove(key_hash.0.as_slice())
                        .map_err(|error| ExchangeError::Persistence(error.to_string()))?;
                }
            }
        }
        Ok(())
    }
}

fn root_node_key(version: Version) -> NodeKey {
    NodeKey::new(version, std::iter::empty().collect::<NibblePath>())
}

impl TreeReader for StateStore {
    fn get_node_option(&self, node_key: &NodeKey) -> AnyResult<Option<Node>> {
        let read = self.database.begin_read()?;
        let table = match read.open_table(JMT_NODE_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let key = serde_jcs::to_vec(node_key)?;
        let Some(value) = table.get(key.as_slice())? else {
            return Ok(None);
        };
        Ok(Some(canonical_decode_any(value.value(), "JMT node")?))
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> AnyResult<Option<OwnedValue>> {
        let read = self.database.begin_read()?;
        let table = match read.open_table(JMT_VALUE_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let Some(value) = table.get(key_hash.0.as_slice())? else {
            return Ok(None);
        };
        let latest: LatestValue = canonical_decode_any(value.value(), "JMT value")?;
        if latest.version > max_version {
            return Ok(None);
        }
        Ok(latest.value)
    }

    fn get_rightmost_leaf(&self) -> AnyResult<Option<(NodeKey, LeafNode)>> {
        let read = self.database.begin_read()?;
        let table = match read.open_table(JMT_NODE_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut rightmost = None;
        for entry in table.iter()? {
            let (key, value) = entry?;
            let node_key: NodeKey = canonical_decode_any(key.value(), "JMT node key")?;
            let node: Node = canonical_decode_any(value.value(), "JMT node")?;
            if let Node::Leaf(leaf) = node
                && rightmost
                    .as_ref()
                    .is_none_or(|(_, current): &(NodeKey, LeafNode)| {
                        leaf.key_hash() > current.key_hash()
                    })
            {
                rightmost = Some((node_key, leaf));
            }
        }
        Ok(rightmost)
    }
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|error| ExchangeError::Persistence(error.to_string()))
}

fn canonical_decode<T: DeserializeOwned + Serialize>(bytes: &[u8], label: &str) -> Result<T> {
    canonical_decode_any(bytes, label)
        .map_err(|error| ExchangeError::Persistence(error.to_string()))
}

fn canonical_decode_any<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    label: &str,
) -> AnyResult<T> {
    let decoded: T = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        serde_jcs::to_vec(&decoded)? == bytes,
        "{label} is not canonically encoded"
    );
    Ok(decoded)
}

fn persistence_error(error: impl std::fmt::Display) -> ExchangeError {
    ExchangeError::Persistence(error.to_string())
}

#[cfg(test)]
mod tests {
    use redb::ReadableTableMetadata;
    use rust_decimal_macros::dec;

    use super::*;
    use crate::{domain::Account, engine::default_markets};

    fn storage_counts(store: &StateStore) -> (u64, u64, u64, u64) {
        let read = store.database.begin_read().unwrap();
        let entities = read.open_table(ENTITY_TABLE).unwrap().len().unwrap();
        let nodes = read.open_table(JMT_NODE_TABLE).unwrap().len().unwrap();
        let values = read.open_table(JMT_VALUE_TABLE).unwrap().len().unwrap();
        let metadata = read.open_table(METADATA_TABLE).unwrap().len().unwrap();
        (entities, nodes, values, metadata)
    }

    fn persisted_node_keys(store: &StateStore) -> Vec<NodeKey> {
        let read = store.database.begin_read().unwrap();
        let table = read.open_table(JMT_NODE_TABLE).unwrap();
        table
            .iter()
            .unwrap()
            .map(|entry| {
                let (key, _) = entry.unwrap();
                canonical_decode(key.value(), "JMT node key").unwrap()
            })
            .collect()
    }

    #[test]
    fn reports_database_lock_with_its_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("locked.redb");
        let _first = StateStore::open(&path).unwrap();
        let error = match StateStore::open(&path) {
            Ok(_) => panic!("second database open unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ExchangeError::DatabaseInUse { path: locked_path }
                if locked_path == path.display().to_string()
        ));
    }

    #[test]
    fn commits_incremental_entities_and_recovers_the_same_root() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.redb");
        let store = StateStore::open(&path).unwrap();
        let first = EngineState::genesis("store-test", default_markets());
        let first_root = store.commit_state(None, &first).unwrap();
        assert_eq!(first_root, compute_state_root(&first).unwrap());

        let mut second = first.clone();
        let mut account = Account::new("alice".into());
        account.collateral = dec!(100);
        second.accounts.insert(account.id.clone(), account);
        second.height = 1;
        let counts_before_preview = storage_counts(&store);
        let stored_before_preview = store.load_state().unwrap().unwrap();
        let preview = store.preview_state_root(Some(&first), &second).unwrap();
        assert_eq!(storage_counts(&store), counts_before_preview);
        assert_eq!(
            store.load_state().unwrap().unwrap().state,
            stored_before_preview.state
        );
        assert_eq!(
            store.load_state().unwrap().unwrap().version,
            stored_before_preview.version
        );
        let committed = store.commit_state(Some(&first), &second).unwrap();
        assert_eq!(preview, committed);
        assert_eq!(committed, compute_state_root(&second).unwrap());
        drop(store);

        let reopened = StateStore::open(&path).unwrap();
        let recovered = reopened.load_state().unwrap().unwrap();
        assert_eq!(recovered.state, second);
        assert_eq!(recovered.app_hash, committed);
        assert_eq!(recovered.version, 1);
    }

    #[test]
    fn deletion_updates_the_authenticated_state() {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::open(directory.path().join("delete.redb")).unwrap();
        let mut first = EngineState::genesis("delete-test", default_markets());
        first.account_nonces.insert("alice".into(), 1);
        store.commit_state(None, &first).unwrap();
        let mut second = first.clone();
        second.account_nonces.remove("alice");
        let root = store.commit_state(Some(&first), &second).unwrap();
        assert_eq!(root, compute_state_root(&second).unwrap());
        assert!(
            !store
                .load_state()
                .unwrap()
                .unwrap()
                .state
                .account_nonces
                .contains_key("alice")
        );
    }

    #[test]
    fn state_sync_replacement_discards_old_entities_and_restarts_jmt_versioning() {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::open(directory.path().join("replace.redb")).unwrap();
        let mut local = EngineState::genesis("replace-test", default_markets());
        local.height = 1;
        local.account_nonces.insert("stale-account".into(), 9);
        let mut stale = Account::new("stale-account".into());
        stale.collateral = dec!(250);
        local.accounts.insert(stale.id.clone(), stale);
        store.commit_state(None, &local).unwrap();

        let mut imported = EngineState::genesis("replace-test", default_markets());
        imported.height = 77;
        imported.block_time_ms = 1_700_000_000_000;
        imported.account_nonces.insert("restored-account".into(), 3);
        let root = store.replace_state(&imported).unwrap();
        assert_eq!(root, compute_state_root(&imported).unwrap());

        let loaded = store.load_state().unwrap().unwrap();
        assert_eq!(loaded.state, imported);
        assert_eq!(loaded.app_hash, root);
        assert_eq!(loaded.version, 0);
        assert!(!loaded.state.accounts.contains_key("stale-account"));

        let mut next = loaded.state.clone();
        next.height = 78;
        let next_root = store.commit_state(Some(&loaded.state), &next).unwrap();
        assert_eq!(next_root, compute_state_root(&next).unwrap());
        assert_eq!(store.load_state().unwrap().unwrap().version, 1);
    }

    #[test]
    fn prunes_stale_nodes_and_keeps_only_the_current_authenticated_tree() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pruned.redb");
        let store = StateStore::open(&path).unwrap();
        let mut current = EngineState::genesis("prune-test", default_markets());
        let mut current_root = store.commit_state(None, &current).unwrap();
        let initial_node_count = persisted_node_keys(&store).len();
        assert!(initial_node_count > 1);

        for height in 1..=64 {
            let mut next = current.clone();
            next.height = height;
            let (_, expected_root, update, _) = store.build_update(Some(&current), &next).unwrap();
            assert!(!update.stale_node_index_batch.is_empty());
            let stale_keys = update
                .stale_node_index_batch
                .iter()
                .map(|stale| stale.node_key.clone())
                .collect::<Vec<_>>();
            let before_preview = storage_counts(&store);
            assert_eq!(
                store.preview_state_root(Some(&current), &next).unwrap(),
                expected_root
            );
            assert_eq!(storage_counts(&store), before_preview);

            current_root = store.commit_state(Some(&current), &next).unwrap();
            assert_eq!(current_root, expected_root);
            assert_eq!(current_root, compute_state_root(&next).unwrap());
            let current_keys = persisted_node_keys(&store);
            assert!(stale_keys.iter().all(|stale| !current_keys.contains(stale)));
            assert!(
                current_keys.len() <= initial_node_count + 1,
                "JMT node count grew from {initial_node_count} to {} at height {height}",
                current_keys.len()
            );
            current = next;
        }

        let version_before_noop = store.read_metadata().unwrap().unwrap().version;
        let old_root_key = root_node_key(version_before_noop);
        let count_before_noop = persisted_node_keys(&store).len();
        assert!(store.get_node_option(&old_root_key).unwrap().is_some());
        assert_eq!(
            store.commit_state(Some(&current), &current).unwrap(),
            current_root
        );
        assert!(store.get_node_option(&old_root_key).unwrap().is_none());
        assert_eq!(persisted_node_keys(&store).len(), count_before_noop);
        drop(store);

        let reopened = StateStore::open(&path).unwrap();
        let recovered = reopened.load_state().unwrap().unwrap();
        assert_eq!(recovered.state, current);
        assert_eq!(recovered.app_hash, current_root);
        assert_eq!(recovered.version, 65);
        assert!(persisted_node_keys(&reopened).len() <= initial_node_count + 1);
    }
}
