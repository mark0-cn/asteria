use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tendermint::{Hash, hash::Algorithm};
use tendermint_rpc::{Client, HttpClient, client::CompatMode};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

use crate::{
    chain_tx::{Command, SignedTransaction},
    consensus::{ChainHandle, ChainSnapshot},
    domain::{AuditReport, BookSnapshot, MarketState, RiskSnapshot},
    event::Event,
    private_order::ThresholdPublicKeySet,
    shielded_margin::{MarginPolicy, MarketId, MerkleProof, NoteCommitment, Nullifier, PublicNote},
    shielded_protocol::LedgerMode,
};

const COMET_HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
const COMET_BROADCAST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub struct AppState {
    chain: ChainHandle,
    rpc: Arc<HttpClient>,
    health_timeout: Duration,
    broadcast_timeout: Duration,
}

impl AppState {
    pub fn new(chain: ChainHandle, comet_rpc: &str) -> Result<Self, tendermint_rpc::Error> {
        let mut rpc = HttpClient::new(comet_rpc)?;
        rpc.set_compat_mode(CompatMode::V0_38);
        Ok(Self {
            chain,
            rpc: Arc::new(rpc),
            health_timeout: COMET_HEALTH_TIMEOUT,
            broadcast_timeout: COMET_BROADCAST_TIMEOUT,
        })
    }

    #[cfg(test)]
    fn with_rpc_timeouts(mut self, health_timeout: Duration, broadcast_timeout: Duration) -> Self {
        self.health_timeout = health_timeout;
        self.broadcast_timeout = broadcast_timeout;
        self
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/live", get(live))
        .route("/health", get(health))
        .route("/v1/chain", get(chain_info))
        .route("/v1/markets", get(markets))
        .route("/v1/markets/{symbol}/book", get(book))
        .route("/v1/tx", post(broadcast_transaction))
        .route("/v1/tx/{hash}", get(transaction_by_hash))
        .route("/v1/private/keyset", get(private_keyset))
        .route("/v1/private/batches", get(private_batches))
        .route("/v1/private/batches/{height}", get(private_batch))
        .route("/v1/private/orders", post(submit_private_order))
        .route("/v1/shielded", get(shielded_ledger))
        .route(
            "/v1/shielded/commitments/{commitment}",
            get(shielded_commitment),
        )
        .route(
            "/v1/shielded/nullifiers/{nullifier}",
            get(shielded_nullifier),
        )
        .route("/v1/shielded/markets/{market_id}", get(shielded_market))
        .route("/v1/shielded/deposits", post(shielded_deposit))
        .route("/v1/shielded/spends", post(shielded_spend))
        .route("/v1/orders", post(place_order))
        .route("/v1/orders/{order_id}", delete(cancel_order))
        .route("/v1/accounts/{account_id}", get(account))
        .route("/v1/accounts/{account_id}/nonce", get(account_nonce))
        .route("/v1/accounts/{account_id}/risk", get(risk))
        .route("/v1/events", get(events))
        .route("/v1/audit", get(audit))
        .route("/v1/ws", get(websocket))
        .route("/v1/admin/credits", post(credit))
        .route("/v1/admin/markets/{symbol}/oracle", post(publish_oracle))
        .route("/v1/admin/markets/{symbol}/funding", post(apply_funding))
        .route(
            "/v1/admin/shielded/markets",
            post(configure_shielded_market),
        )
        .route(
            "/v1/admin/liquidation-candidates",
            get(liquidation_candidates),
        )
        .route(
            "/v1/admin/accounts/{account_id}/liquidate/{symbol}",
            post(liquidate),
        )
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct LiveResponse {
    status: &'static str,
}

async fn live() -> Json<LiveResponse> {
    Json(LiveResponse { status: "ok" })
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    ready: bool,
    initialized: bool,
    comet_reachable: bool,
    catching_up: Option<bool>,
    chain_id: String,
    comet_chain_id: Option<String>,
    height: u64,
    comet_height: Option<u64>,
    app_hash: String,
    comet_app_height: Option<u64>,
    comet_app_hash: Option<String>,
    reason: Option<String>,
}

async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let snapshot = state.chain.snapshot();
    let rpc_result = tokio::time::timeout(state.health_timeout, async {
        tokio::try_join!(state.rpc.status(), state.rpc.abci_info())
    })
    .await;

    let initialized = snapshot.is_some();
    let chain_id = snapshot
        .as_ref()
        .map(|snapshot| snapshot.state.chain_id.clone())
        .unwrap_or_default();
    let height = snapshot
        .as_ref()
        .map(|snapshot| snapshot.state.height)
        .unwrap_or(0);
    let app_hash = snapshot
        .as_ref()
        .map(|snapshot| hex::encode(snapshot.app_hash))
        .unwrap_or_default();

    let (
        ready,
        comet_reachable,
        catching_up,
        comet_chain_id,
        comet_height,
        comet_app_height,
        comet_app_hash,
        reason,
    ) = match (snapshot.as_ref(), rpc_result) {
        (None, _) => (
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            Some("chain has not been initialized by CometBFT".into()),
        ),
        (Some(_), Err(_)) => (
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            Some(format!(
                "CometBFT readiness RPC timed out after {} ms",
                state.health_timeout.as_millis()
            )),
        ),
        (Some(_), Ok(Err(error))) => (
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            Some(format!("CometBFT readiness RPC failed: {error}")),
        ),
        (Some(snapshot), Ok(Ok((status, info)))) => {
            let comet_chain_id = status.node_info.network.to_string();
            let comet_height = status.sync_info.latest_block_height.value();
            let comet_app_height = info.last_block_height.value();
            let decoded_app_hash = STANDARD.decode(info.last_block_app_hash.as_bytes());
            let comet_app_hash = decoded_app_hash
                .as_ref()
                .map(hex::encode)
                .unwrap_or_else(|_| "invalid-base64".into());
            let reason = if comet_chain_id != snapshot.state.chain_id {
                Some(format!(
                    "CometBFT chain_id mismatch: local={}, comet={comet_chain_id}",
                    snapshot.state.chain_id
                ))
            } else if status.sync_info.catching_up {
                Some("CometBFT is catching up".into())
            } else if comet_height != snapshot.state.height
                || comet_app_height != snapshot.state.height
            {
                Some(format!(
                    "height mismatch: local={}, comet={comet_height}, comet_app={comet_app_height}",
                    snapshot.state.height
                ))
            } else if !decoded_app_hash
                .as_ref()
                .is_ok_and(|hash| hash.as_slice() == snapshot.app_hash)
            {
                Some(format!(
                    "app hash mismatch: local={}, comet_app={comet_app_hash}",
                    hex::encode(snapshot.app_hash)
                ))
            } else {
                None
            };
            (
                reason.is_none(),
                true,
                Some(status.sync_info.catching_up),
                Some(comet_chain_id),
                Some(comet_height),
                Some(comet_app_height),
                Some(comet_app_hash),
                reason,
            )
        }
    };

    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status_code,
        Json(HealthResponse {
            status: if ready {
                "ok"
            } else if initialized {
                "degraded"
            } else {
                "starting"
            },
            ready,
            initialized,
            comet_reachable,
            catching_up,
            chain_id,
            comet_chain_id,
            height,
            comet_height,
            app_hash,
            comet_app_height,
            comet_app_hash,
            reason,
        }),
    )
}

#[derive(Debug, Serialize)]
struct ChainInfoResponse {
    chain_id: String,
    protocol_version: u16,
    height: u64,
    app_hash: String,
    authority: String,
}

async fn chain_info(State(state): State<AppState>) -> Result<Json<ChainInfoResponse>, ApiError> {
    let snapshot = committed(&state)?;
    Ok(Json(ChainInfoResponse {
        chain_id: snapshot.state.chain_id,
        protocol_version: snapshot.state.protocol_version,
        height: snapshot.state.height,
        app_hash: hex::encode(snapshot.app_hash),
        authority: snapshot.state.authority,
    }))
}

async fn markets(State(state): State<AppState>) -> Result<Json<Vec<MarketState>>, ApiError> {
    Ok(Json(
        committed(&state)?.state.markets.values().cloned().collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct BookQuery {
    #[serde(default = "default_depth")]
    depth: usize,
}

fn default_depth() -> usize {
    20
}

async fn book(
    State(state): State<AppState>,
    Path(symbol): Path<String>,
    Query(query): Query<BookQuery>,
) -> Result<Json<BookSnapshot>, ApiError> {
    let snapshot = committed(&state)?;
    let book = snapshot
        .state
        .books
        .get(&symbol)
        .ok_or_else(|| ApiError::not_found(format!("market does not exist: {symbol}")))?;
    Ok(Json(book.snapshot(
        symbol,
        snapshot.state.sequence,
        query.depth.min(100),
    )))
}

async fn broadcast_transaction(
    State(state): State<AppState>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    broadcast(&state, transaction).await
}

async fn transaction_by_hash(
    State(state): State<AppState>,
    Path(encoded_hash): Path<String>,
) -> Result<Json<tendermint_rpc::endpoint::tx::Response>, ApiError> {
    let requested_hash = parse_transaction_hash(&encoded_hash)?;
    let response = tokio::time::timeout(state.health_timeout, state.rpc.tx(requested_hash, false))
        .await
        .map_err(|_| {
            ApiError::gateway_timeout(format!(
                "CometBFT tx query timed out after {} ms (tx_hash={encoded_hash})",
                state.health_timeout.as_millis()
            ))
        })?
        .map_err(|error| {
            if rpc_transaction_not_found(&error) {
                ApiError::not_found(format!("transaction not found: {encoded_hash}"))
            } else {
                ApiError::unavailable(format!(
                    "CometBFT tx query failed (tx_hash={encoded_hash}): {error}"
                ))
            }
        })?;
    let returned_transaction_hash: [u8; 32] = Sha256::digest(&response.tx).into();
    if response.hash != requested_hash || response.hash.as_ref() != returned_transaction_hash {
        return Err(ApiError::bad_gateway(format!(
            "CometBFT tx query hash mismatch: requested={}, response={}, transaction={}",
            requested_hash,
            response.hash,
            hex::encode_upper(returned_transaction_hash)
        )));
    }
    Ok(Json(response))
}

#[derive(Debug, Serialize)]
struct PrivateKeySetResponse {
    height: u64,
    private_order_fee: rust_decimal::Decimal,
    key_set: Option<ThresholdPublicKeySet>,
    validator_bindings: BTreeMap<String, u16>,
}

async fn private_keyset(
    State(state): State<AppState>,
) -> Result<Json<PrivateKeySetResponse>, ApiError> {
    let snapshot = committed(&state)?;
    Ok(Json(PrivateKeySetResponse {
        height: snapshot.state.height,
        private_order_fee: snapshot.state.private_order_fee,
        key_set: snapshot.state.private_order_key_set,
        validator_bindings: snapshot
            .state
            .private_validator_bindings
            .into_iter()
            .collect(),
    }))
}

#[derive(Debug, Serialize)]
struct PrivateBatchSummary {
    batch_height: u64,
    status: &'static str,
    submission_count: usize,
    submission_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PrivateBatchesResponse {
    height: u64,
    batches: Vec<PrivateBatchSummary>,
}

fn summarize_private_batch(
    batch_height: u64,
    status: &'static str,
    submissions: &[crate::private_protocol::PrivateOrderSubmission],
) -> Result<PrivateBatchSummary, ApiError> {
    let submission_ids = submissions
        .iter()
        .map(|submission| {
            submission
                .submission_id()
                .map(hex::encode)
                .map_err(|error| {
                    ApiError::internal(format!(
                        "committed private-order batch {batch_height} is invalid: {error}"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrivateBatchSummary {
        batch_height,
        status,
        submission_count: submissions.len(),
        submission_ids,
    })
}

async fn private_batches(
    State(state): State<AppState>,
) -> Result<Json<PrivateBatchesResponse>, ApiError> {
    let snapshot = committed(&state)?;
    let batches = snapshot
        .state
        .pending_private_orders
        .iter()
        .map(|(height, submissions)| summarize_private_batch(*height, "pending", submissions))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PrivateBatchesResponse {
        height: snapshot.state.height,
        batches,
    }))
}

async fn private_batch(
    State(state): State<AppState>,
    Path(height): Path<u64>,
) -> Result<Json<PrivateBatchSummary>, ApiError> {
    let snapshot = committed(&state)?;
    let response = match snapshot.state.pending_private_orders.get(&height) {
        Some(submissions) => summarize_private_batch(height, "pending", submissions)?,
        None if height > snapshot.state.height => summarize_private_batch(height, "future", &[])?,
        None => summarize_private_batch(height, "not_pending", &[])?,
    };
    Ok(Json(response))
}

#[derive(Debug, Serialize)]
struct ShieldedLedgerResponse {
    height: u64,
    enabled: bool,
    mode: Option<LedgerMode>,
    chain_domain: Option<String>,
    ledger_id: Option<String>,
    deposit_authority: Option<String>,
    root: Option<String>,
    note_count: usize,
    market_count: usize,
    shielded_collateral: String,
    fee_total: String,
}

async fn shielded_ledger(
    State(state): State<AppState>,
) -> Result<Json<ShieldedLedgerResponse>, ApiError> {
    let snapshot = committed(&state)?;
    let Some(ledger) = snapshot.state.shielded_ledger.as_ref() else {
        return Ok(Json(ShieldedLedgerResponse {
            height: snapshot.state.height,
            enabled: false,
            mode: None,
            chain_domain: None,
            ledger_id: None,
            deposit_authority: None,
            root: None,
            note_count: 0,
            market_count: 0,
            shielded_collateral: "0".into(),
            fee_total: "0".into(),
        }));
    };
    Ok(Json(ShieldedLedgerResponse {
        height: snapshot.state.height,
        enabled: true,
        mode: Some(ledger.mode()),
        chain_domain: Some(hex::encode(ledger.chain_domain)),
        ledger_id: Some(hex::encode(ledger.ledger_id)),
        deposit_authority: Some(hex::encode(ledger.deposit_authority)),
        root: Some(hex::encode(ledger.root())),
        note_count: ledger.note_count(),
        market_count: ledger.market_count(),
        shielded_collateral: ledger.shielded_collateral().to_string(),
        fee_total: ledger.fee_total().to_string(),
    }))
}

#[derive(Debug, Serialize)]
struct ShieldedCommitmentResponse {
    commitment: String,
    exists: bool,
    leaf_index: Option<u64>,
    note: Option<PublicNote>,
    proof: Option<MerkleProof>,
}

async fn shielded_commitment(
    State(state): State<AppState>,
    Path(encoded_commitment): Path<String>,
) -> Result<Json<ShieldedCommitmentResponse>, ApiError> {
    let commitment = NoteCommitment(parse_hash32("commitment", &encoded_commitment)?);
    let snapshot = committed(&state)?;
    let ledger = snapshot
        .state
        .shielded_ledger
        .as_ref()
        .ok_or_else(|| ApiError::not_found("shielded ledger is not enabled on this chain"))?;
    let leaf_index = ledger.leaf_index(commitment);
    let note = leaf_index
        .map(|index| {
            ledger.note(index).copied().ok_or_else(|| {
                ApiError::internal("shielded commitment index points to a missing committed note")
            })
        })
        .transpose()?;
    let proof = leaf_index
        .map(|index| {
            ledger.merkle_proof(index).map_err(|error| {
                ApiError::internal(format!(
                    "committed shielded note cannot produce a Merkle proof: {error}"
                ))
            })
        })
        .transpose()?;
    Ok(Json(ShieldedCommitmentResponse {
        commitment: hex::encode(commitment.0),
        exists: note.is_some(),
        leaf_index,
        note,
        proof,
    }))
}

#[derive(Debug, Serialize)]
struct ShieldedNullifierResponse {
    nullifier: String,
    spent: bool,
}

async fn shielded_nullifier(
    State(state): State<AppState>,
    Path(encoded_nullifier): Path<String>,
) -> Result<Json<ShieldedNullifierResponse>, ApiError> {
    let nullifier = Nullifier(parse_hash32("nullifier", &encoded_nullifier)?);
    let snapshot = committed(&state)?;
    let ledger = snapshot
        .state
        .shielded_ledger
        .as_ref()
        .ok_or_else(|| ApiError::not_found("shielded ledger is not enabled on this chain"))?;
    Ok(Json(ShieldedNullifierResponse {
        nullifier: hex::encode(nullifier.0),
        spent: ledger.is_spent(nullifier),
    }))
}

#[derive(Debug, Serialize)]
struct ShieldedMarketResponse {
    market_id: String,
    configured: bool,
    policy_hash: Option<String>,
    policy: Option<MarginPolicy>,
}

async fn shielded_market(
    State(state): State<AppState>,
    Path(encoded_market_id): Path<String>,
) -> Result<Json<ShieldedMarketResponse>, ApiError> {
    let market_id = MarketId(parse_hash32("market id", &encoded_market_id)?);
    let snapshot = committed(&state)?;
    let ledger = snapshot
        .state
        .shielded_ledger
        .as_ref()
        .ok_or_else(|| ApiError::not_found("shielded ledger is not enabled on this chain"))?;
    let policy = ledger.policy(market_id).copied();
    let policy_hash = policy
        .map(|policy| {
            policy.policy_hash().map(hex::encode).map_err(|error| {
                ApiError::internal(format!(
                    "committed shielded market policy is invalid: {error}"
                ))
            })
        })
        .transpose()?;
    Ok(Json(ShieldedMarketResponse {
        market_id: hex::encode(market_id.0),
        configured: policy.is_some(),
        policy_hash,
        policy,
    }))
}

fn parse_hash32(label: &str, encoded: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(encoded)
        .map_err(|_| ApiError::bad_request(format!("{label} must be hexadecimal")))?;
    bytes
        .try_into()
        .map_err(|_| ApiError::bad_request(format!("{label} must contain exactly 32 bytes")))
}

fn parse_transaction_hash(encoded_hash: &str) -> Result<Hash, ApiError> {
    let bytes = hex::decode(encoded_hash)
        .map_err(|_| ApiError::bad_request("transaction hash must be hexadecimal"))?;
    Hash::from_bytes(Algorithm::Sha256, &bytes)
        .map_err(|_| ApiError::bad_request("transaction hash must contain exactly 32 bytes"))
}

fn rpc_transaction_not_found(error: &tendermint_rpc::Error) -> bool {
    match error {
        tendermint_rpc::error::Error(tendermint_rpc::error::ErrorDetail::Response(detail), _) => {
            detail
                .source
                .data()
                .is_some_and(|data| data.starts_with("tx (") && data.ends_with(") not found"))
        }
        _ => false,
    }
}

async fn submit_private_order(
    State(state): State<AppState>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    match &transaction.command {
        Command::SubmitPrivateOrder { submission } => {
            submission
                .to_canonical_bytes()
                .map(|_| ())
                .map_err(|error| ApiError::bad_request(error.to_string()))?
        }
        _ => {
            return Err(ApiError::bad_request(
                "private orders endpoint requires a submit_private_order command",
            ));
        }
    }
    broadcast(&state, transaction).await
}

async fn configure_shielded_market(
    State(state): State<AppState>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    if !matches!(transaction.command, Command::ConfigureShieldedMarket { .. }) {
        return Err(ApiError::bad_request(
            "shielded market endpoint requires a configure_shielded_market command",
        ));
    }
    broadcast(&state, transaction).await
}

async fn shielded_deposit(
    State(state): State<AppState>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    if !matches!(transaction.command, Command::ShieldedDeposit { .. }) {
        return Err(ApiError::bad_request(
            "shielded deposits endpoint requires a shielded_deposit command",
        ));
    }
    broadcast(&state, transaction).await
}

async fn shielded_spend(
    State(state): State<AppState>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    if !matches!(transaction.command, Command::ShieldedSpend { .. }) {
        return Err(ApiError::bad_request(
            "shielded spends endpoint requires a shielded_spend command",
        ));
    }
    broadcast(&state, transaction).await
}

async fn place_order(
    State(state): State<AppState>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    if !matches!(transaction.command, Command::PlaceOrder { .. }) {
        return Err(ApiError::bad_request(
            "orders endpoint requires a place_order command",
        ));
    }
    broadcast(&state, transaction).await
}

async fn cancel_order(
    State(state): State<AppState>,
    Path(order_id): Path<Uuid>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    match &transaction.command {
        Command::CancelOrder {
            order_id: signed_order_id,
        } if *signed_order_id == order_id => {}
        Command::CancelOrder { .. } => {
            return Err(ApiError::bad_request(
                "path order id differs from signed order id",
            ));
        }
        _ => {
            return Err(ApiError::bad_request(
                "cancel endpoint requires a cancel_order command",
            ));
        }
    }
    broadcast(&state, transaction).await
}

async fn account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<Json<crate::domain::Account>, ApiError> {
    committed(&state)?
        .state
        .accounts
        .get(&account_id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("account does not exist: {account_id}")))
}

#[derive(Debug, Serialize)]
struct NonceResponse {
    account_id: String,
    next_nonce: u64,
    height: u64,
}

async fn account_nonce(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<Json<NonceResponse>, ApiError> {
    let snapshot = committed(&state)?;
    let next_nonce = snapshot
        .state
        .account_nonces
        .get(&account_id)
        .copied()
        .unwrap_or(0);
    Ok(Json(NonceResponse {
        account_id,
        next_nonce,
        height: snapshot.state.height,
    }))
}

async fn risk(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<Json<RiskSnapshot>, ApiError> {
    let snapshot = committed(&state)?;
    let account = snapshot
        .state
        .accounts
        .get(&account_id)
        .ok_or_else(|| ApiError::not_found(format!("account does not exist: {account_id}")))?;
    account
        .risk_snapshot(snapshot.state.markets.iter())
        .map(Json)
        .map_err(|error| ApiError::internal(error.to_string()))
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_event_limit")]
    limit: usize,
}

fn default_event_limit() -> usize {
    100
}

async fn events(
    State(state): State<AppState>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<Event>>, ApiError> {
    Ok(Json(
        committed(&state)?
            .state
            .event_log
            .after(query.after, query.limit.min(1_000)),
    ))
}

async fn audit(State(state): State<AppState>) -> Result<Json<AuditReport>, ApiError> {
    state
        .chain
        .audit()
        .map(Json)
        .ok_or_else(ApiError::not_initialized)
}

async fn websocket(State(state): State<AppState>, upgrade: WebSocketUpgrade) -> impl IntoResponse {
    let receiver = state.chain.subscribe();
    upgrade.on_upgrade(move |socket| stream_events(socket, receiver))
}

async fn stream_events(
    mut socket: WebSocket,
    mut receiver: tokio::sync::broadcast::Receiver<Event>,
) {
    loop {
        match receiver.recv().await {
            Ok(event) => {
                let Ok(payload) = serde_json::to_string(&event) else {
                    continue;
                };
                if socket.send(Message::Text(payload.into())).await.is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn credit(
    State(state): State<AppState>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    if !matches!(transaction.command, Command::CreditAccount { .. }) {
        return Err(ApiError::bad_request(
            "credits endpoint requires a credit_account command",
        ));
    }
    broadcast(&state, transaction).await
}

async fn publish_oracle(
    State(state): State<AppState>,
    Path(symbol): Path<String>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    match &transaction.command {
        Command::PublishOraclePrice {
            symbol: signed_symbol,
            ..
        } if *signed_symbol == symbol => {}
        Command::PublishOraclePrice { .. } => {
            return Err(ApiError::bad_request(
                "path symbol differs from signed oracle symbol",
            ));
        }
        _ => {
            return Err(ApiError::bad_request(
                "oracle endpoint requires a publish_oracle_price command",
            ));
        }
    }
    broadcast(&state, transaction).await
}

async fn apply_funding(
    State(state): State<AppState>,
    Path(symbol): Path<String>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    match &transaction.command {
        Command::ApplyFunding {
            symbol: signed_symbol,
            ..
        } if *signed_symbol == symbol => {}
        Command::ApplyFunding { .. } => {
            return Err(ApiError::bad_request(
                "path symbol differs from signed funding symbol",
            ));
        }
        _ => {
            return Err(ApiError::bad_request(
                "funding endpoint requires an apply_funding command",
            ));
        }
    }
    broadcast(&state, transaction).await
}

async fn liquidation_candidates(
    State(state): State<AppState>,
) -> Result<Json<Vec<RiskSnapshot>>, ApiError> {
    let snapshot = committed(&state)?;
    let snapshots = snapshot
        .state
        .accounts
        .values()
        .map(|account| account.risk_snapshot(snapshot.state.markets.iter()))
        .collect::<crate::error::Result<Vec<_>>>()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(Json(
        snapshots
            .into_iter()
            .filter(|risk| risk.liquidation_risk)
            .collect(),
    ))
}

async fn liquidate(
    State(state): State<AppState>,
    Path((account_id, symbol)): Path<(String, String)>,
    Json(transaction): Json<SignedTransaction>,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    match &transaction.command {
        Command::Liquidate {
            account_id: signed_account,
            symbol: signed_symbol,
        } if *signed_account == account_id && *signed_symbol == symbol => {}
        Command::Liquidate { .. } => {
            return Err(ApiError::bad_request(
                "path target differs from signed liquidation target",
            ));
        }
        _ => {
            return Err(ApiError::bad_request(
                "liquidation endpoint requires a liquidate command",
            ));
        }
    }
    broadcast(&state, transaction).await
}

async fn broadcast(
    state: &AppState,
    transaction: SignedTransaction,
) -> Result<Json<tendermint_rpc::endpoint::broadcast::tx_commit::Response>, ApiError> {
    transaction
        .verify()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let bytes = transaction
        .to_canonical_bytes()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let transaction_hash = transaction
        .tx_hash()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let transaction_hash_hex = hex::encode(transaction_hash);
    let response = tokio::time::timeout(
        state.broadcast_timeout,
        state.rpc.broadcast_tx_commit(bytes),
    )
        .await
        .map_err(|_| {
            ApiError::gateway_timeout(format!(
                "CometBFT broadcast_tx_commit timed out after {} ms; transaction outcome is unknown (tx_hash={transaction_hash})",
                state.broadcast_timeout.as_millis(),
                transaction_hash = transaction_hash_hex
            ))
        })?
        .map_err(|error| {
            ApiError::unavailable(format!(
                "CometBFT broadcast_tx_commit failed; transaction outcome is unknown (tx_hash={transaction_hash_hex}): {error}"
            ))
        })?;
    validate_broadcast_response(&response, transaction_hash)?;
    Ok(Json(response))
}

fn validate_broadcast_response(
    response: &tendermint_rpc::endpoint::broadcast::tx_commit::Response,
    expected_hash: [u8; 32],
) -> Result<(), ApiError> {
    if response.hash.as_ref() != expected_hash {
        return Err(ApiError::bad_gateway(format!(
            "CometBFT broadcast response hash mismatch: submitted={}, response={}",
            hex::encode(expected_hash),
            response.hash
        )));
    }
    if response.check_tx.code.is_err() {
        return Err(ApiError::transaction_rejected(
            "CheckTx",
            response.check_tx.code.value(),
            &response.check_tx.codespace,
            &response.check_tx.log,
            &response.check_tx.info,
            None,
        ));
    }
    if response.tx_result.code.is_err() {
        return Err(ApiError::transaction_rejected(
            "FinalizeBlock",
            response.tx_result.code.value(),
            &response.tx_result.codespace,
            &response.tx_result.log,
            &response.tx_result.info,
            Some((response.height.value(), response.hash.to_string())),
        ));
    }
    Ok(())
}

fn committed(state: &AppState) -> Result<ChainSnapshot, ApiError> {
    state.chain.snapshot().ok_or_else(ApiError::not_initialized)
}

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn gateway_timeout(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            message: message.into(),
        }
    }

    fn transaction_rejected(
        phase: &str,
        code: u32,
        codespace: &str,
        log: &str,
        info: &str,
        committed: Option<(u64, String)>,
    ) -> Self {
        let details = if !log.is_empty() {
            log
        } else if !info.is_empty() {
            info
        } else {
            "no rejection details"
        };
        let codespace = if codespace.is_empty() {
            String::new()
        } else {
            format!(", codespace={codespace}")
        };
        let location = committed.map_or_else(String::new, |(height, hash)| {
            format!(", height={height}, tx_hash={hash}")
        });
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message: format!(
                "transaction rejected during {phase} (code={code}{codespace}{location}): {details}"
            ),
        }
    }

    fn not_initialized() -> Self {
        Self::unavailable("chain has not been initialized by CometBFT")
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, header},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand_core::OsRng;
    use rust_decimal_macros::dec;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tendermint::{Hash, abci::Code};
    use tendermint_rpc::endpoint::broadcast::tx_commit::Response as BroadcastResponse;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::{
        chain_tx::{CURRENT_TRANSACTION_VERSION, UnsignedTransaction},
        consensus::{ChainApplication, ChainSnapshot},
        domain::{OracleObservation, OrderIntent, OrderKind, Side, TimeInForce},
        engine::{EngineState, compute_app_hash, default_markets},
        private_order::{PrivateOrderContext, encrypt_private_order, generate_dealer_key_set},
        private_protocol::{
            PRIVATE_PROTOCOL_VERSION, PrivateOrderKind, PrivateOrderPayload,
            PrivateOrderSubmission, anti_spam_commitment,
        },
        shielded_margin::{
            CollateralAssetId, NoteOpening, SHIELDED_MARGIN_VERSION, ShieldedSpend, SpendStatement,
        },
        shielded_protocol::{
            AuthorityDeposit, DepositStatement, DevelopmentShieldedLedger,
            SHIELDED_PROTOCOL_VERSION, TransparentDepositProof, TransparentDepositVerifier,
            derive_chain_domain,
        },
        store::StateStore,
    };

    const TEST_CHAIN_ID: &str = "asteria-api-test-1";

    fn successful_broadcast_response() -> BroadcastResponse {
        BroadcastResponse {
            check_tx: Default::default(),
            tx_result: Default::default(),
            hash: Hash::Sha256([7; 32]),
            height: 3_u32.into(),
        }
    }

    fn signed_transaction(command: Command, nonce: u64) -> SignedTransaction {
        let key = SigningKey::from_bytes(&[41; 32]);
        UnsignedTransaction {
            version: CURRENT_TRANSACTION_VERSION,
            chain_id: TEST_CHAIN_ID.into(),
            signer: key.verifying_key().to_bytes(),
            nonce,
            valid_until_height: 1_000,
            command,
        }
        .sign(&key)
        .unwrap()
    }

    fn private_order_fixture(
        nonce: u64,
        batch_height: u64,
    ) -> (ThresholdPublicKeySet, PrivateOrderSubmission) {
        let signing_key = SigningKey::from_bytes(&[41; 32]);
        let (key_set, _) = generate_dealer_key_set(7, &mut OsRng).unwrap();
        let fee_payer = signing_key.verifying_key().to_bytes();
        let commitment = anti_spam_commitment(TEST_CHAIN_ID, &fee_payer, nonce).unwrap();
        let payload = PrivateOrderPayload {
            client_id: "api-private-order".into(),
            side: crate::private_protocol::PrivateOrderSide::Buy,
            kind: PrivateOrderKind::Limit,
            price_ticks: 60_000,
            quantity_lots: 1,
            leverage: 2,
            ioc: true,
            fok: false,
            reduce_only: false,
        };
        let envelope = encrypt_private_order(
            &key_set,
            &PrivateOrderContext {
                chain_id: TEST_CHAIN_ID.into(),
                market_id: "BTCUSDT".into(),
                epoch: key_set.epoch,
                batch_height,
            },
            fee_payer,
            commitment,
            &payload.to_canonical_bytes().unwrap(),
            &mut OsRng,
        )
        .unwrap();
        let submission = PrivateOrderSubmission::sign(
            TEST_CHAIN_ID.into(),
            nonce,
            batch_height + 10,
            envelope,
            &signing_key,
        )
        .unwrap();
        assert_eq!(submission.version, PRIVATE_PROTOCOL_VERSION);
        (key_set, submission)
    }

    fn shielded_policy() -> MarginPolicy {
        MarginPolicy {
            version: SHIELDED_MARGIN_VERSION,
            market_id: MarketId([11; 32]),
            collateral_asset: CollateralAssetId([12; 32]),
            mark_price: 60_000,
            price_scale: 1,
            minimum_initial_margin_bps: 1_000,
            maximum_leverage: 20,
            minimum_fee: 1,
        }
    }

    fn shielded_fixture() -> (DevelopmentShieldedLedger, AuthorityDeposit, PublicNote) {
        let authority = SigningKey::from_bytes(&[51; 32]);
        let owner = SigningKey::from_bytes(&[52; 32]);
        let policy = shielded_policy();
        let mut ledger = DevelopmentShieldedLedger::new_development(
            derive_chain_domain(TEST_CHAIN_ID).unwrap(),
            [13; 32],
            authority.verifying_key().to_bytes(),
        )
        .unwrap();
        ledger.register_market(policy).unwrap();
        let opening = NoteOpening {
            owner: owner.verifying_key().to_bytes(),
            nullifier_key: [53; 32],
            collateral: 1_000,
            position: 0,
            leverage: 1,
            blinding: [54; 32],
        };
        let note = PublicNote::new(policy.market_id, policy.collateral_asset, &opening);
        let statement = DepositStatement {
            version: SHIELDED_PROTOCOL_VERSION,
            chain_domain: ledger.chain_domain,
            ledger_id: ledger.ledger_id,
            note,
            backing_amount: opening.collateral,
        };
        let deposit = AuthorityDeposit {
            authority_signature: authority
                .sign(&statement.authorization_digest())
                .to_bytes()
                .to_vec(),
            statement,
            proof: TransparentDepositProof { opening }
                .to_canonical_bytes()
                .unwrap(),
        };
        ledger
            .authority_deposit(&deposit, &TransparentDepositVerifier)
            .unwrap();
        let canonical = serde_jcs::to_vec(&ledger).unwrap();
        serde_json::from_slice::<DevelopmentShieldedLedger>(&canonical).unwrap_or_else(|error| {
            panic!(
                "canonical shielded ledger did not round trip: {error}; {}",
                String::from_utf8_lossy(&canonical)
            )
        });
        (ledger, deposit, note)
    }

    fn dummy_shielded_spend(policy: MarginPolicy) -> ShieldedSpend {
        ShieldedSpend {
            statement: SpendStatement {
                version: SHIELDED_MARGIN_VERSION,
                chain_domain: derive_chain_domain(TEST_CHAIN_ID).unwrap(),
                ledger_id: [13; 32],
                anchor_root: [14; 32],
                market_id: policy.market_id,
                collateral_asset: policy.collateral_asset,
                policy_hash: policy.policy_hash().unwrap(),
                nullifiers: Vec::new(),
                output_commitments: Vec::new(),
                fee: 0,
            },
            proof: Vec::new(),
        }
    }

    fn test_state(rpc_url: &str) -> (tempfile::TempDir, ChainApplication, AppState) {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::open(directory.path().join("chain.redb")).unwrap();
        let (application, chain) = ChainApplication::open(store).unwrap();
        let state = AppState::new(chain, rpc_url).unwrap();
        (directory, application, state)
    }

    fn test_snapshot(next_nonce: u64) -> ChainSnapshot {
        let mut state = EngineState::genesis(TEST_CHAIN_ID, default_markets());
        state.height = 3;
        state.block_time_ms = 1_700_000_000_000;
        state.account_nonces.insert("account-a".into(), next_nonce);
        let app_hash = compute_app_hash(&state).unwrap();
        ChainSnapshot { state, app_hash }
    }

    fn test_initialized_state(
        rpc_url: &str,
        snapshot: &ChainSnapshot,
    ) -> (tempfile::TempDir, ChainApplication, AppState) {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::open(directory.path().join("chain.redb")).unwrap();
        assert_eq!(
            store.commit_state(None, &snapshot.state).unwrap(),
            snapshot.app_hash
        );
        let (application, chain) = ChainApplication::open(store).unwrap();
        let state = AppState::new(chain, rpc_url).unwrap();
        (directory, application, state)
    }

    #[derive(Clone)]
    struct CommitRpcState {
        calls: Arc<AtomicUsize>,
        mismatch_hash: bool,
    }

    async fn mock_commit_rpc(
        State(state): State<CommitRpcState>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(request["method"], "broadcast_tx_commit");
        state.calls.fetch_add(1, Ordering::SeqCst);
        let transaction = STANDARD
            .decode(request["params"]["tx"].as_str().unwrap())
            .unwrap();
        let transaction_hash = if state.mismatch_hash {
            "07".repeat(32)
        } else {
            hex::encode_upper(Sha256::digest(transaction))
        };
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"].clone(),
            "result": {
                "check_tx": {
                    "code": 0,
                    "codespace": "",
                    "data": null,
                    "events": [],
                    "gas_used": "0",
                    "gas_wanted": "0",
                    "info": "",
                    "log": ""
                },
                "hash": transaction_hash,
                "height": "3",
                "tx_result": {
                    "code": 0,
                    "codespace": "",
                    "data": null,
                    "events": [],
                    "gas_used": "0",
                    "gas_wanted": "0",
                    "info": "",
                    "log": ""
                }
            }
        }))
    }

    async fn start_mock_commit_rpc(
        mismatch_hash: bool,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/", post(mock_commit_rpc))
            .with_state(CommitRpcState {
                calls: calls.clone(),
                mismatch_hash,
            });
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), calls, server)
    }

    #[derive(Clone)]
    struct ReadinessRpcState {
        chain_id: String,
        height: u64,
        catching_up: bool,
        app_height: u64,
        app_hash: Vec<u8>,
        transaction: Option<Vec<u8>>,
    }

    impl ReadinessRpcState {
        fn matching(snapshot: &ChainSnapshot) -> Self {
            Self {
                chain_id: snapshot.state.chain_id.clone(),
                height: snapshot.state.height,
                catching_up: false,
                app_height: snapshot.state.height,
                app_hash: snapshot.app_hash.to_vec(),
                transaction: None,
            }
        }
    }

    async fn mock_readiness_rpc(
        State(state): State<ReadinessRpcState>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let id = request["id"].clone();
        let result = match request["method"].as_str().unwrap() {
            "health" => json!({}),
            "status" => json!({
                "node_info": {
                    "protocol_version": { "p2p": "8", "block": "11", "app": "1" },
                    "id": "1111111111111111111111111111111111111111",
                    "listen_addr": "tcp://127.0.0.1:26656",
                    "network": state.chain_id,
                    "version": "0.38.23",
                    "channels": "40202122233038606100",
                    "moniker": "api-test",
                    "other": { "tx_index": "on", "rpc_address": "tcp://127.0.0.1:26657" }
                },
                "sync_info": {
                    "earliest_block_hash": "",
                    "earliest_app_hash": "",
                    "earliest_block_height": "0",
                    "earliest_block_time": "1970-01-01T00:00:00Z",
                    "latest_block_hash": "11".repeat(32),
                    "latest_app_hash": "00".repeat(32),
                    "latest_block_height": state.height.to_string(),
                    "latest_block_time": "2023-11-14T22:13:20Z",
                    "catching_up": state.catching_up
                },
                "validator_info": {
                    "address": "2222222222222222222222222222222222222222",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": STANDARD.encode([3_u8; 32])
                    },
                    "voting_power": "10"
                }
            }),
            "abci_info" => json!({
                "response": {
                    "data": "asteria-abci",
                    "version": env!("CARGO_PKG_VERSION"),
                    "app_version": "1",
                    "last_block_height": state.app_height.to_string(),
                    "last_block_app_hash": STANDARD.encode(&state.app_hash)
                }
            }),
            "tx" => {
                let transaction = state
                    .transaction
                    .as_ref()
                    .expect("mock transaction configured");
                let hash = hex::encode_upper(Sha256::digest(transaction));
                json!({
                    "hash": hash,
                    "height": state.height.to_string(),
                    "index": 0,
                    "tx_result": {
                        "code": 0,
                        "codespace": "",
                        "data": null,
                        "events": [],
                        "gas_used": "0",
                        "gas_wanted": "0",
                        "info": "",
                        "log": ""
                    },
                    "tx": STANDARD.encode(transaction)
                })
            }
            method => panic!("unexpected RPC method: {method}"),
        };
        Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    async fn start_readiness_rpc(
        state: ReadinessRpcState,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/", post(mock_readiness_rpc))
            .with_state(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), server)
    }

    async fn get_json(app: Router, uri: &str) -> (StatusCode, Value) {
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    async fn start_hanging_rpc() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_connection, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        (format!("http://{address}"), server)
    }

    #[test]
    fn check_tx_rejection_is_not_reported_as_http_success() {
        let mut response = successful_broadcast_response();
        response.check_tx.code = Code::from(4);
        response.check_tx.codespace = "asteria".into();
        response.check_tx.log = "nonce already used".into();

        let error = validate_broadcast_response(&response, [7; 32]).unwrap_err();

        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message.contains("CheckTx"));
        assert!(error.message.contains("code=4"));
        assert!(error.message.contains("nonce already used"));
    }

    #[test]
    fn finalize_block_rejection_includes_commit_location() {
        let mut response = successful_broadcast_response();
        response.tx_result.code = Code::from(7);
        response.tx_result.log = "execution rejected".into();

        let error = validate_broadcast_response(&response, [7; 32]).unwrap_err();

        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message.contains("FinalizeBlock"));
        assert!(error.message.contains("height=3"));
        assert!(error.message.contains(&response.hash.to_string()));
    }

    #[tokio::test]
    async fn every_http_write_route_broadcasts_without_mutating_local_state() {
        let (rpc_url, calls, server) = start_mock_commit_rpc(false).await;
        let (_directory, _application, state) = test_state(&rpc_url);
        let order_id = Uuid::from_bytes([9; 16]);
        let writes = vec![
            (
                Method::POST,
                "/v1/tx".to_string(),
                signed_transaction(
                    Command::CreditAccount {
                        account_id: "account-a".into(),
                        amount: dec!(1),
                    },
                    1,
                ),
            ),
            (
                Method::POST,
                "/v1/orders".to_string(),
                signed_transaction(
                    Command::PlaceOrder {
                        intent: OrderIntent {
                            client_order_id: "api-route-test".into(),
                            symbol: "BTCUSDT".into(),
                            side: Side::Buy,
                            kind: OrderKind::Limit,
                            quantity: dec!(0.01),
                            price: Some(dec!(60000)),
                            leverage: 2,
                            time_in_force: TimeInForce::Gtc,
                            reduce_only: false,
                        },
                    },
                    2,
                ),
            ),
            (
                Method::DELETE,
                format!("/v1/orders/{order_id}"),
                signed_transaction(Command::CancelOrder { order_id }, 3),
            ),
            (
                Method::POST,
                "/v1/admin/credits".to_string(),
                signed_transaction(
                    Command::CreditAccount {
                        account_id: "account-b".into(),
                        amount: dec!(1000),
                    },
                    4,
                ),
            ),
            (
                Method::POST,
                "/v1/admin/markets/BTCUSDT/oracle".to_string(),
                signed_transaction(
                    Command::PublishOraclePrice {
                        symbol: "BTCUSDT".into(),
                        observations: vec![OracleObservation {
                            source: "oracle-a".into(),
                            price: dec!(60000),
                            weight: 1,
                        }],
                    },
                    5,
                ),
            ),
            (
                Method::POST,
                "/v1/admin/markets/BTCUSDT/funding".to_string(),
                signed_transaction(
                    Command::ApplyFunding {
                        symbol: "BTCUSDT".into(),
                        rate: dec!(0.0001),
                    },
                    6,
                ),
            ),
            (
                Method::POST,
                "/v1/admin/accounts/account-b/liquidate/BTCUSDT".to_string(),
                signed_transaction(
                    Command::Liquidate {
                        account_id: "account-b".into(),
                        symbol: "BTCUSDT".into(),
                    },
                    7,
                ),
            ),
            (
                Method::POST,
                "/v1/private/orders".to_string(),
                signed_transaction(
                    Command::SubmitPrivateOrder {
                        submission: Box::new(private_order_fixture(8, 3).1),
                    },
                    8,
                ),
            ),
            (
                Method::POST,
                "/v1/admin/shielded/markets".to_string(),
                signed_transaction(
                    Command::ConfigureShieldedMarket {
                        policy: shielded_policy(),
                    },
                    9,
                ),
            ),
            (
                Method::POST,
                "/v1/shielded/deposits".to_string(),
                signed_transaction(
                    Command::ShieldedDeposit {
                        deposit: Box::new(shielded_fixture().1),
                    },
                    10,
                ),
            ),
            (
                Method::POST,
                "/v1/shielded/spends".to_string(),
                signed_transaction(
                    Command::ShieldedSpend {
                        spend: Box::new(dummy_shielded_spend(shielded_policy())),
                    },
                    11,
                ),
            ),
        ];
        let app = router(state.clone());

        for (method, uri, transaction) in writes {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&transaction).unwrap()))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            let status = response.status();
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert_eq!(
                status,
                StatusCode::OK,
                "unexpected response: {}",
                String::from_utf8_lossy(&body)
            );
        }

        assert_eq!(calls.load(Ordering::SeqCst), 11);
        assert!(state.chain.snapshot().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn privacy_write_routes_reject_the_wrong_signed_command_type() {
        let (rpc_url, calls, server) = start_mock_commit_rpc(false).await;
        let (_directory, _application, state) = test_state(&rpc_url);
        let transaction = signed_transaction(
            Command::CreditAccount {
                account_id: "account-a".into(),
                amount: dec!(1),
            },
            1,
        );
        let app = router(state);

        for uri in [
            "/v1/private/orders",
            "/v1/admin/shielded/markets",
            "/v1/shielded/deposits",
            "/v1/shielded/spends",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_vec(&transaction).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn privacy_queries_return_public_status_without_private_payloads() {
        let mut snapshot = test_snapshot(0);
        let (key_set, submission) = private_order_fixture(0, snapshot.state.height);
        let submission_id = hex::encode(submission.submission_id().unwrap());
        snapshot.state.private_order_key_set = Some(key_set.clone());
        for validator in &key_set.validators {
            snapshot.state.private_validator_bindings.insert(
                format!("{:02x}", validator.validator_id).repeat(20),
                validator.validator_id,
            );
        }
        snapshot
            .state
            .pending_private_orders
            .insert(snapshot.state.height, vec![submission]);
        let (ledger, _deposit, note) = shielded_fixture();
        let ledger_root_bytes = ledger.root();
        let ledger_root = hex::encode(ledger_root_bytes);
        snapshot.state.shielded_ledger = Some(ledger);
        snapshot.app_hash = compute_app_hash(&snapshot.state).unwrap();

        let (_directory, _application, state) =
            test_initialized_state("http://127.0.0.1:1", &snapshot);
        let app = router(state);

        let (status, keyset_body) = get_json(app.clone(), "/v1/private/keyset").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(keyset_body["height"], snapshot.state.height);
        assert_eq!(keyset_body["key_set"]["epoch"], key_set.epoch);
        assert_eq!(
            keyset_body["validator_bindings"].as_object().unwrap().len(),
            4
        );
        assert_eq!(
            keyset_body["validator_bindings"]["0101010101010101010101010101010101010101"],
            1
        );
        assert!(keyset_body.get("secret_shares").is_none());

        let (status, batches_body) = get_json(app.clone(), "/v1/private/batches").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(batches_body["batches"][0]["status"], "pending");
        assert_eq!(batches_body["batches"][0]["submission_count"], 1);
        assert_eq!(
            batches_body["batches"][0]["submission_ids"][0],
            submission_id
        );
        assert!(!batches_body.to_string().contains("encrypted_payload"));

        let (status, pending_body) = get_json(
            app.clone(),
            &format!("/v1/private/batches/{}", snapshot.state.height),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(pending_body["status"], "pending");
        let (_, future_body) = get_json(
            app.clone(),
            &format!("/v1/private/batches/{}", snapshot.state.height + 1),
        )
        .await;
        assert_eq!(future_body["status"], "future");

        let (status, ledger_body) = get_json(app.clone(), "/v1/shielded").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ledger_body["enabled"], true);
        assert_eq!(
            ledger_body["chain_domain"],
            hex::encode(derive_chain_domain(TEST_CHAIN_ID).unwrap())
        );
        assert_eq!(ledger_body["root"], ledger_root);
        assert_eq!(ledger_body["note_count"], 1);

        let commitment = hex::encode(note.commitment.0);
        let (status, commitment_body) = get_json(
            app.clone(),
            &format!("/v1/shielded/commitments/{commitment}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(commitment_body["exists"], true);
        assert_eq!(commitment_body["leaf_index"], 0);
        let proof: MerkleProof = serde_json::from_value(commitment_body["proof"].clone()).unwrap();
        proof.verify(&note, ledger_root_bytes).unwrap();
        assert!(!commitment_body.to_string().contains("blinding"));
        assert!(!commitment_body.to_string().contains("nullifier_key"));

        let nullifier = hex::encode([88; 32]);
        let (status, nullifier_body) =
            get_json(app.clone(), &format!("/v1/shielded/nullifiers/{nullifier}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(nullifier_body["spent"], false);

        let market_id = hex::encode(shielded_policy().market_id.0);
        let (status, market_body) =
            get_json(app.clone(), &format!("/v1/shielded/markets/{market_id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(market_body["configured"], true);
        assert!(market_body["policy_hash"].as_str().is_some());

        let (status, error_body) = get_json(app, "/v1/shielded/nullifiers/not-hex").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            error_body["error"]
                .as_str()
                .unwrap()
                .contains("hexadecimal")
        );
    }

    #[tokio::test]
    async fn broadcast_rejects_a_mismatched_comet_transaction_hash() {
        let (rpc_url, _calls, server) = start_mock_commit_rpc(true).await;
        let (_directory, _application, state) = test_state(&rpc_url);
        let transaction = signed_transaction(
            Command::CreditAccount {
                account_id: "account-a".into(),
                amount: dec!(1),
            },
            1,
        );

        let error = broadcast(&state, transaction).await.unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_GATEWAY);
        assert!(error.message.contains("hash mismatch"));
        server.abort();
    }

    #[tokio::test]
    async fn health_requires_matching_chain_height_app_hash_and_sync_status() {
        let snapshot = test_snapshot(7);
        let mut scenarios = Vec::new();

        let mut wrong_chain = ReadinessRpcState::matching(&snapshot);
        wrong_chain.chain_id = "another-chain".into();
        scenarios.push(("wrong chain", wrong_chain));

        let mut catching_up = ReadinessRpcState::matching(&snapshot);
        catching_up.catching_up = true;
        scenarios.push(("catching up", catching_up));

        let mut wrong_height = ReadinessRpcState::matching(&snapshot);
        wrong_height.height += 1;
        scenarios.push(("wrong height", wrong_height));

        let mut wrong_app_hash = ReadinessRpcState::matching(&snapshot);
        wrong_app_hash.app_hash = vec![99; 32];
        scenarios.push(("wrong app hash", wrong_app_hash));

        for (name, rpc_state) in scenarios {
            let (rpc_url, server) = start_readiness_rpc(rpc_state).await;
            let (_directory, _application, state) = test_initialized_state(&rpc_url, &snapshot);

            let (status, body) = get_json(router(state), "/health").await;

            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{name}");
            assert_eq!(body["ready"], false, "{name}");
            assert_eq!(body["status"], "degraded", "{name}");
            server.abort();
        }
    }

    #[tokio::test]
    async fn live_does_not_depend_on_chain_initialization_or_comet() {
        let (_directory, _application, state) = test_state("http://127.0.0.1:1");

        let (status, body) = get_json(router(state), "/live").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn health_is_ready_only_when_comet_and_local_state_match() {
        let snapshot = test_snapshot(7);
        let (rpc_url, server) = start_readiness_rpc(ReadinessRpcState::matching(&snapshot)).await;
        let (_directory, _application, state) = test_initialized_state(&rpc_url, &snapshot);

        let (status, body) = get_json(router(state), "/health").await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ready"], true);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["chain_id"], TEST_CHAIN_ID);
        assert_eq!(body["comet_chain_id"], TEST_CHAIN_ID);
        assert_eq!(body["height"], snapshot.state.height);
        assert_eq!(body["comet_height"], snapshot.state.height);
        server.abort();
    }

    #[tokio::test]
    async fn nonce_and_transaction_queries_recover_after_an_unknown_broadcast_outcome() {
        let snapshot = test_snapshot(7);
        let transaction = signed_transaction(
            Command::CreditAccount {
                account_id: "account-b".into(),
                amount: dec!(1),
            },
            6,
        );
        let transaction_bytes = transaction.to_canonical_bytes().unwrap();
        let transaction_hash = transaction.tx_hash_hex().unwrap();
        let mut rpc_state = ReadinessRpcState::matching(&snapshot);
        rpc_state.transaction = Some(transaction_bytes);
        let (rpc_url, server) = start_readiness_rpc(rpc_state).await;
        let (_directory, _application, state) = test_initialized_state(&rpc_url, &snapshot);
        let app = router(state);

        let (nonce_status, nonce_body) =
            get_json(app.clone(), "/v1/accounts/account-a/nonce").await;
        assert_eq!(nonce_status, StatusCode::OK);
        assert_eq!(nonce_body["account_id"], "account-a");
        assert_eq!(nonce_body["next_nonce"], 7);
        assert_eq!(nonce_body["height"], snapshot.state.height);

        let (tx_status, tx_body) = get_json(app, &format!("/v1/tx/{transaction_hash}")).await;
        assert_eq!(tx_status, StatusCode::OK);
        assert_eq!(
            tx_body["hash"].as_str().unwrap().to_ascii_lowercase(),
            transaction_hash
        );
        assert_eq!(tx_body["height"], snapshot.state.height.to_string());
        server.abort();
    }

    #[tokio::test]
    async fn broadcast_timeout_is_bounded_and_reports_unknown_outcome() {
        let (rpc_url, server) = start_hanging_rpc().await;
        let (_directory, _application, state) = test_state(&rpc_url);
        let state = state.with_rpc_timeouts(Duration::from_millis(25), Duration::from_millis(25));
        let transaction = signed_transaction(
            Command::CreditAccount {
                account_id: "account-a".into(),
                amount: dec!(1),
            },
            1,
        );
        let expected_hash = transaction.tx_hash_hex().unwrap();

        let error = broadcast(&state, transaction).await.unwrap_err();

        assert_eq!(error.status, StatusCode::GATEWAY_TIMEOUT);
        assert!(error.message.contains("outcome is unknown"));
        assert!(error.message.contains(&expected_hash));
        assert!(state.chain.snapshot().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn health_rpc_timeout_is_bounded() {
        let (rpc_url, server) = start_hanging_rpc().await;
        let (_directory, _application, state) = test_state(&rpc_url);
        let state = state.with_rpc_timeouts(Duration::from_millis(25), Duration::from_millis(25));

        let (status, Json(response)) = health(State(state)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.comet_reachable);
        assert_eq!(response.status, "starting");
        server.abort();
    }
}
