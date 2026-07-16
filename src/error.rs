use thiserror::Error;
use uuid::Uuid;

pub type Result<T, E = ExchangeError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("account does not exist: {0}")]
    AccountNotFound(String),
    #[error("market does not exist: {0}")]
    MarketNotFound(String),
    #[error("order does not exist: {0}")]
    OrderNotFound(Uuid),
    #[error("order {order_id} is owned by another account")]
    OrderOwnership { order_id: Uuid },
    #[error("duplicate client order id: {0}")]
    DuplicateClientOrderId(String),
    #[error("invalid order: {0}")]
    InvalidOrder(String),
    #[error("insufficient available margin: required {required}, available {available}")]
    InsufficientMargin { required: String, available: String },
    #[error("fill-or-kill order cannot be completely filled")]
    CannotFullyFill,
    #[error("account is not eligible for liquidation: {0}")]
    NotLiquidatable(String),
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("persistence failure: {0}")]
    Persistence(String),
    #[error(
        "database is already in use: {path}. Stop the other Asteria node or choose another file with --data <path>"
    )]
    DatabaseInUse { path: String },
    #[error("unauthorized")]
    Unauthorized,
    #[error("internal error: {0}")]
    Internal(String),
}
