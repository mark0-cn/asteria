#!/usr/bin/env bash
set -Eeuo pipefail

readonly NODE_COUNT=4
readonly APP_PROTOCOL_VERSION=5
readonly NODE_ROOT=/nodes
readonly COMET_UID=100
readonly COMET_GID=1000
readonly CHAIN_ID="${ASTERIA_CHAIN_ID:-asteria-localnet-1}"
readonly AUTHORITY_ACCOUNT="${ASTERIA_AUTHORITY_ACCOUNT:-ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c}"
readonly PRIVATE_ORDER_PUBLIC_KEYS=/private/public-key-set.json
readonly APP_ROOT=/apps

if [[ ! "$CHAIN_ID" =~ ^[A-Za-z0-9._-]{1,50}$ ]]; then
  echo "ASTERIA_CHAIN_ID must be 1-50 ASCII letters, digits, dots, underscores, or hyphens" >&2
  exit 1
fi

if [[ ! "$AUTHORITY_ACCOUNT" =~ ^ed25519:[0-9a-f]{64}$ ]]; then
  echo "ASTERIA_AUTHORITY_ACCOUNT must be ed25519 followed by a 32-byte lowercase hex public key" >&2
  exit 1
fi

if [[ ! -f "$PRIVATE_ORDER_PUBLIC_KEYS" ]]; then
  echo "Private-order public key set is missing." >&2
  exit 1
fi
if ! jq -e '.threshold == 3 and .validator_count == 4 and (.validators | length) == 4' \
  "$PRIVATE_ORDER_PUBLIC_KEYS" >/dev/null; then
  echo "Private-order public key set is not a 3-of-4 configuration." >&2
  exit 1
fi

clear_managed_directory() {
  local path="$1"
  mkdir -p "$path"
  find "$path" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
}

complete_homes=0
nonempty_homes=0
complete_apps=0
nonempty_apps=0
shopt -s dotglob nullglob

for ((node = 0; node < NODE_COUNT; node++)); do
  home="$NODE_ROOT/node$node"
  mkdir -p "$home"
  entries=("$home"/*)

  if ((${#entries[@]} > 0)); then
    nonempty_homes=$((nonempty_homes + 1))
  fi

  if [[ -f "$home/config/config.toml" &&
        -f "$home/config/genesis.json" &&
        -f "$home/config/node_key.json" &&
        -f "$home/config/priv_validator_key.json" &&
        -f "$home/data/priv_validator_state.json" ]]; then
    complete_homes=$((complete_homes + 1))
  fi

  app_home="$APP_ROOT/node$node"
  mkdir -p "$app_home"
  app_entries=("$app_home"/*)
  if ((${#app_entries[@]} > 0)); then
    nonempty_apps=$((nonempty_apps + 1))
  fi
  if [[ -f "$app_home/chain.redb" ]]; then
    complete_apps=$((complete_apps + 1))
  fi
done

compatible_network=0
if [[ "$complete_homes" -eq "$NODE_COUNT" &&
      "$nonempty_homes" -eq "$NODE_COUNT" &&
      "$complete_apps" -eq "$NODE_COUNT" &&
      "$nonempty_apps" -eq "$NODE_COUNT" ]]; then
  reference_genesis="$NODE_ROOT/node0/config/genesis.json"
  actual_chain_id="$(jq -r '.chain_id' "$reference_genesis")"
  actual_authority="$(jq -r '.app_state.authority' "$reference_genesis")"
  actual_app_protocol_version="$(jq -r '.app_state.app_protocol_version // 0' "$reference_genesis")"
  if [[ "$actual_chain_id" != "$CHAIN_ID" ]]; then
    echo "Existing chain ID '$actual_chain_id' does not match requested '$CHAIN_ID'." >&2
    exit 1
  fi
  if [[ "$actual_authority" != "$AUTHORITY_ACCOUNT" ]]; then
    echo "Existing authority '$actual_authority' does not match requested '$AUTHORITY_ACCOUNT'." >&2
    exit 1
  fi
  expected_key_id="$(jq -r '.key_id' "$PRIVATE_ORDER_PUBLIC_KEYS")"
  actual_key_id="$(jq -r '.app_state.private_order_key_set.key_id // empty' "$reference_genesis")"
  vote_extension_height="$(jq -r '.consensus_params.abci.vote_extensions_enable_height // empty' "$reference_genesis")"
  bindings_valid=1
  for ((node = 0; node < NODE_COUNT; node++)); do
    validator_address="$(jq -r '.address | ascii_downcase' "$NODE_ROOT/node$node/config/priv_validator_key.json")"
    bound_id="$(jq -r --arg address "$validator_address" '.app_state.private_validator_bindings[$address] // 0' "$reference_genesis")"
    if [[ "$bound_id" -ne $((node + 1)) ]]; then
      bindings_valid=0
    fi
  done
  if [[ "$actual_app_protocol_version" == "$APP_PROTOCOL_VERSION" &&
        "$expected_key_id" == "$actual_key_id" &&
        "$vote_extension_height" == "1" &&
        "$bindings_valid" -eq 1 ]]; then
    compatible_network=1
  fi
fi

if [[ "$compatible_network" -ne 1 &&
      ( "$nonempty_homes" -gt 0 || "$nonempty_apps" -gt 0 ) ]]; then
  echo "Existing localnet state does not match private-order threshold provisioning; rebuilding managed state." >&2
  for ((node = 0; node < NODE_COUNT; node++)); do
    clear_managed_directory "$NODE_ROOT/node$node"
    clear_managed_directory "$APP_ROOT/node$node"
  done
  complete_homes=0
  nonempty_homes=0
  complete_apps=0
  nonempty_apps=0
fi

if [[ "$nonempty_homes" -eq 0 ]]; then
  testnet_root=/tmp/asteria-testnet
  rm -rf "$testnet_root"

  cometbft testnet \
    --v "$NODE_COUNT" \
    --o "$testnet_root" \
    --populate-persistent-peers=true \
    --hostname comet0 \
    --hostname comet1 \
    --hostname comet2 \
    --hostname comet3

  validator_bindings='{}'
  for ((node = 0; node < NODE_COUNT; node++)); do
    validator_address="$(jq -r '.address | ascii_downcase' "$testnet_root/node$node/config/priv_validator_key.json")"
    validator_bindings="$(jq -c \
      --arg address "$validator_address" \
      --argjson validator_id "$((node + 1))" \
      '. + {($address): $validator_id}' \
      <<<"$validator_bindings")"
  done

  jq --arg chain_id "$CHAIN_ID" \
    --arg authority "$AUTHORITY_ACCOUNT" \
    --argjson validator_bindings "$validator_bindings" \
    --slurpfile app_state /opt/asteria/genesis-app-state.json \
    --slurpfile private_keys "$PRIVATE_ORDER_PUBLIC_KEYS" \
    '.chain_id = $chain_id |
     .app_state = $app_state[0] |
     .app_state.authority = $authority |
     .app_state.private_order_key_set = $private_keys[0] |
     .app_state.private_validator_bindings = $validator_bindings |
     .consensus_params.abci.vote_extensions_enable_height = "1"' \
    "$testnet_root/node0/config/genesis.json" \
    >"$testnet_root/genesis.json"

  for ((node = 0; node < NODE_COUNT; node++)); do
    cp "$testnet_root/genesis.json" "$testnet_root/node$node/config/genesis.json"
    cp -a "$testnet_root/node$node/." "$NODE_ROOT/node$node/"
  done
elif [[ "$complete_homes" -ne "$NODE_COUNT" || "$nonempty_homes" -ne "$NODE_COUNT" ]]; then
  echo "Refusing to initialize a partial CometBFT network." >&2
  echo "Expected either four empty volumes or four complete validator homes." >&2
  exit 1
fi

reference_genesis="$NODE_ROOT/node0/config/genesis.json"
reference_hash="$(sha256sum "$reference_genesis" | cut -d' ' -f1)"
actual_chain_id="$(jq -r '.chain_id' "$reference_genesis")"
actual_authority="$(jq -r '.app_state.authority' "$reference_genesis")"
validator_count="$(jq -r '.validators | length' "$reference_genesis")"
unique_validators="$(jq -r '.validators[].address' "$reference_genesis" | sort -u | wc -l | tr -d '[:space:]')"
actual_key_id="$(jq -r '.app_state.private_order_key_set.key_id // empty' "$reference_genesis")"
expected_key_id="$(jq -r '.key_id' "$PRIVATE_ORDER_PUBLIC_KEYS")"
vote_extension_height="$(jq -r '.consensus_params.abci.vote_extensions_enable_height // empty' "$reference_genesis")"

if [[ "$actual_chain_id" != "$CHAIN_ID" ]]; then
  echo "Existing chain ID '$actual_chain_id' does not match requested '$CHAIN_ID'." >&2
  exit 1
fi


if [[ "$actual_authority" != "$AUTHORITY_ACCOUNT" ]]; then
  echo "Existing authority '$actual_authority' does not match requested '$AUTHORITY_ACCOUNT'." >&2
  exit 1
fi

if [[ "$validator_count" -ne "$NODE_COUNT" || "$unique_validators" -ne "$NODE_COUNT" ]]; then
  echo "Genesis must contain exactly four unique validators." >&2
  exit 1
fi
if [[ "$actual_key_id" != "$expected_key_id" ]]; then
  echo "Genesis private-order key set does not match provisioned public keys." >&2
  exit 1
fi
if [[ "$vote_extension_height" != "1" ]]; then
  echo "Genesis must enable vote extensions at height 1." >&2
  exit 1
fi

for ((node = 0; node < NODE_COUNT; node++)); do
  home="$NODE_ROOT/node$node"
  genesis="$home/config/genesis.json"
  config="$home/config/config.toml"
  genesis_hash="$(sha256sum "$genesis" | cut -d' ' -f1)"
  validator_address="$(jq -r '.address' "$home/config/priv_validator_key.json")"
  normalized_validator_address="$(tr '[:upper:]' '[:lower:]' <<<"$validator_address")"

  if [[ "$genesis_hash" != "$reference_hash" ]]; then
    echo "Genesis mismatch for node$node." >&2
    exit 1
  fi

  if ! jq -e --arg address "$validator_address" \
    '.validators | any(.address == $address)' "$genesis" >/dev/null; then
    echo "node$node validator key is absent from genesis." >&2
    exit 1
  fi
  bound_validator_id="$(jq -r --arg address "$normalized_validator_address" '.app_state.private_validator_bindings[$address] // 0' "$genesis")"
  if [[ "$bound_validator_id" -ne $((node + 1)) ]]; then
    echo "node$node validator address is not bound to private validator ID $((node + 1))." >&2
    exit 1
  fi

  sed -i \
    -e 's/^prometheus = false$/prometheus = true/' \
    -e 's/^pex = true$/pex = false/' \
    "$config"

  if ! grep -Eq '^prometheus = true$' "$config"; then
    echo "Failed to enable Prometheus for node$node." >&2
    exit 1
  fi

  if ! grep -Eq '^persistent_peers = ".+"$' "$config"; then
    echo "Persistent peers are missing for node$node." >&2
    exit 1
  fi

  chown -R "$COMET_UID:$COMET_GID" "$home"
  chmod 600 \
    "$home/config/node_key.json" \
    "$home/config/priv_validator_key.json" \
    "$home/data/priv_validator_state.json"
done

echo "CometBFT testnet '$CHAIN_ID' is initialized with four validators."
echo "Genesis SHA-256: $reference_hash"
