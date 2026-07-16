use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{
    domain::{AccountId, OracleObservation, OrderIntent, Symbol},
    private_protocol::PrivateOrderSubmission,
    shielded_margin::{MarginPolicy, ShieldedSpend},
    shielded_protocol::AuthorityDeposit,
};
use uuid::Uuid;

pub const CURRENT_TRANSACTION_VERSION: u16 = 1;
pub const SIGNING_DOMAIN: &[u8] = b"ASTERIA_CHAIN_TRANSACTION_V1\0";
pub const MAX_DECIMAL_SCALE: u32 = 18;
pub const MAX_INPUT_VALUE: Decimal = dec!(1000000000000);
pub const MAX_ORDER_NOTIONAL: Decimal = dec!(1000000000000000000000000);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    PlaceOrder {
        intent: OrderIntent,
    },
    CancelOrder {
        order_id: Uuid,
    },
    CreditAccount {
        account_id: AccountId,
        amount: Decimal,
    },
    PublishOraclePrice {
        symbol: Symbol,
        observations: Vec<OracleObservation>,
    },
    ApplyFunding {
        symbol: Symbol,
        rate: Decimal,
    },
    Liquidate {
        account_id: AccountId,
        symbol: Symbol,
    },
    SubmitPrivateOrder {
        submission: Box<PrivateOrderSubmission>,
    },
    ConfigureShieldedMarket {
        policy: MarginPolicy,
    },
    ShieldedDeposit {
        deposit: Box<AuthorityDeposit>,
    },
    ShieldedSpend {
        spend: Box<ShieldedSpend>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    pub version: u16,
    pub chain_id: String,
    #[serde(with = "base64_32")]
    pub signer: [u8; 32],
    pub nonce: u64,
    pub valid_until_height: u64,
    pub command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub version: u16,
    pub chain_id: String,
    #[serde(with = "base64_32")]
    pub signer: [u8; 32],
    pub nonce: u64,
    pub valid_until_height: u64,
    pub command: Command,
    #[serde(with = "base64_64")]
    pub signature: [u8; 64],
}

#[derive(Debug, thiserror::Error)]
pub enum ChainTransactionError {
    #[error("canonical JSON serialization failed: {0}")]
    Serialization(String),
    #[error("transaction is not encoded as RFC 8785 canonical JSON")]
    NonCanonicalEncoding,
    #[error("unsupported transaction version {actual}; expected {expected}")]
    UnsupportedVersion { actual: u16, expected: u16 },
    #[error("chain_id must not be empty")]
    EmptyChainId,
    #[error("transaction signer does not match the signing key")]
    SignerMismatch,
    #[error("invalid Ed25519 public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid Ed25519 signature: {0}")]
    InvalidSignature(String),
    #[error("invalid Ed25519 account id: {0}")]
    InvalidAccountId(String),
    #[error("invalid numeric value for {field}: {reason}")]
    InvalidNumericValue {
        field: &'static str,
        reason: &'static str,
    },
}

pub type Result<T, E = ChainTransactionError> = std::result::Result<T, E>;

impl UnsignedTransaction {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_encode(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        canonical_decode(bytes)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        validate_header(self.version, &self.chain_id)?;
        let canonical = self.to_canonical_bytes()?;
        let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }

    pub fn sign(self, signing_key: &SigningKey) -> Result<SignedTransaction> {
        sign_transaction(self, signing_key)
    }
}

impl SignedTransaction {
    pub fn unsigned(&self) -> UnsignedTransaction {
        UnsignedTransaction {
            version: self.version,
            chain_id: self.chain_id.clone(),
            signer: self.signer,
            nonce: self.nonce,
            valid_until_height: self.valid_until_height,
            command: self.command.clone(),
        }
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_encode(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        canonical_decode(bytes)
    }

    pub fn verify(&self) -> Result<AccountId> {
        verify_transaction(self)
    }

    pub fn tx_hash(&self) -> Result<[u8; 32]> {
        transaction_hash(self)
    }

    pub fn tx_hash_hex(&self) -> Result<String> {
        self.tx_hash().map(hex::encode)
    }
}

impl Command {
    pub fn validate_numeric_bounds(&self) -> Result<()> {
        match self {
            Self::PlaceOrder { intent } => {
                validate_positive_decimal("order.quantity", intent.quantity)?;
                if let Some(price) = intent.price {
                    validate_positive_decimal("order.price", price)?;
                    let notional = intent.quantity.checked_mul(price).ok_or(
                        ChainTransactionError::InvalidNumericValue {
                            field: "order.notional",
                            reason: "multiplication exceeds Decimal range",
                        },
                    )?;
                    if notional > MAX_ORDER_NOTIONAL {
                        return Err(ChainTransactionError::InvalidNumericValue {
                            field: "order.notional",
                            reason: "exceeds protocol maximum",
                        });
                    }
                }
            }
            Self::CreditAccount { amount, .. } => {
                validate_positive_decimal("credit.amount", *amount)?;
            }
            Self::PublishOraclePrice { observations, .. } => {
                for observation in observations {
                    validate_positive_decimal("oracle.observations[].price", observation.price)?;
                }
            }
            Self::ApplyFunding { rate, .. } => {
                validate_decimal("funding.rate", *rate)?;
            }
            Self::CancelOrder { .. }
            | Self::Liquidate { .. }
            | Self::SubmitPrivateOrder { .. }
            | Self::ConfigureShieldedMarket { .. }
            | Self::ShieldedDeposit { .. }
            | Self::ShieldedSpend { .. } => {}
        }
        Ok(())
    }
}

pub fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value)
        .map_err(|error| ChainTransactionError::Serialization(error.to_string()))
}

pub fn canonical_decode<T>(bytes: &[u8]) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let decoded = serde_json::from_slice(bytes)
        .map_err(|error| ChainTransactionError::Serialization(error.to_string()))?;
    if canonical_encode(&decoded)? != bytes {
        return Err(ChainTransactionError::NonCanonicalEncoding);
    }
    Ok(decoded)
}

pub fn sign_transaction(
    unsigned: UnsignedTransaction,
    signing_key: &SigningKey,
) -> Result<SignedTransaction> {
    validate_header(unsigned.version, &unsigned.chain_id)?;
    if unsigned.signer != signing_key.verifying_key().to_bytes() {
        return Err(ChainTransactionError::SignerMismatch);
    }
    let signature = signing_key.sign(&unsigned.signing_bytes()?).to_bytes();
    Ok(SignedTransaction {
        version: unsigned.version,
        chain_id: unsigned.chain_id,
        signer: unsigned.signer,
        nonce: unsigned.nonce,
        valid_until_height: unsigned.valid_until_height,
        command: unsigned.command,
        signature,
    })
}

pub fn verify_transaction(transaction: &SignedTransaction) -> Result<AccountId> {
    validate_header(transaction.version, &transaction.chain_id)?;
    let verifying_key = VerifyingKey::from_bytes(&transaction.signer)
        .map_err(|error| ChainTransactionError::InvalidPublicKey(error.to_string()))?;
    let signature = Signature::from_bytes(&transaction.signature);
    verifying_key
        .verify_strict(&transaction.unsigned().signing_bytes()?, &signature)
        .map_err(|error| ChainTransactionError::InvalidSignature(error.to_string()))?;
    Ok(account_id_from_signer(&transaction.signer))
}

pub fn transaction_hash(transaction: &SignedTransaction) -> Result<[u8; 32]> {
    let digest = Sha256::digest(transaction.to_canonical_bytes()?);
    Ok(digest.into())
}

pub fn account_id_from_signer(signer: &[u8; 32]) -> AccountId {
    format!("ed25519:{}", hex::encode(signer))
}

pub fn verifying_key_from_account_id(account_id: &str) -> Result<VerifyingKey> {
    let encoded = account_id
        .strip_prefix("ed25519:")
        .ok_or_else(|| ChainTransactionError::InvalidAccountId("missing ed25519: prefix".into()))?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChainTransactionError::InvalidAccountId(
            "key must be exactly 64 lowercase hexadecimal characters".into(),
        ));
    }
    let decoded = hex::decode(encoded)
        .map_err(|error| ChainTransactionError::InvalidAccountId(error.to_string()))?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|decoded: Vec<u8>| {
        ChainTransactionError::InvalidAccountId(format!(
            "expected 32 key bytes, received {}",
            decoded.len()
        ))
    })?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| ChainTransactionError::InvalidAccountId(error.to_string()))
}

fn validate_header(version: u16, chain_id: &str) -> Result<()> {
    if version != CURRENT_TRANSACTION_VERSION {
        return Err(ChainTransactionError::UnsupportedVersion {
            actual: version,
            expected: CURRENT_TRANSACTION_VERSION,
        });
    }
    if chain_id.trim().is_empty() {
        return Err(ChainTransactionError::EmptyChainId);
    }
    Ok(())
}

fn validate_decimal(field: &'static str, value: Decimal) -> Result<()> {
    if value.scale() > MAX_DECIMAL_SCALE {
        return Err(ChainTransactionError::InvalidNumericValue {
            field,
            reason: "scale exceeds 18 decimal places",
        });
    }
    if value < -MAX_INPUT_VALUE || value > MAX_INPUT_VALUE {
        return Err(ChainTransactionError::InvalidNumericValue {
            field,
            reason: "absolute value exceeds protocol maximum",
        });
    }
    Ok(())
}

fn validate_positive_decimal(field: &'static str, value: Decimal) -> Result<()> {
    validate_decimal(field, value)?;
    if value <= Decimal::ZERO {
        return Err(ChainTransactionError::InvalidNumericValue {
            field,
            reason: "must be positive",
        });
    }
    Ok(())
}

fn serialize_base64<const N: usize, S>(
    bytes: &[u8; N],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&STANDARD.encode(bytes))
}

fn deserialize_base64<'de, const N: usize, D>(
    deserializer: D,
) -> std::result::Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = STANDARD
        .decode(&encoded)
        .map_err(serde::de::Error::custom)?;
    let bytes: [u8; N] = decoded.try_into().map_err(|decoded: Vec<u8>| {
        serde::de::Error::custom(format!(
            "expected {N} decoded bytes, received {}",
            decoded.len()
        ))
    })?;
    if STANDARD.encode(bytes) != encoded {
        return Err(serde::de::Error::custom("non-canonical base64 encoding"));
    }
    Ok(bytes)
}

mod base64_32 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_base64(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_base64(deserializer)
    }
}

mod base64_64 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_base64(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_base64(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use rust_decimal_macros::dec;
    use uuid::Uuid;

    use super::*;
    use crate::domain::{OrderKind, Side, TimeInForce};

    fn unsigned(signing_key: &SigningKey) -> UnsignedTransaction {
        UnsignedTransaction {
            version: CURRENT_TRANSACTION_VERSION,
            chain_id: "asteria-test-1".into(),
            signer: signing_key.verifying_key().to_bytes(),
            nonce: 7,
            valid_until_height: 1_000,
            command: Command::PlaceOrder {
                intent: OrderIntent {
                    client_order_id: "client-7".into(),
                    symbol: "BTCUSDT".into(),
                    side: Side::Buy,
                    kind: OrderKind::Limit,
                    quantity: dec!(0.01),
                    price: Some(dec!(60000)),
                    leverage: 10,
                    time_in_force: TimeInForce::Gtc,
                    reduce_only: false,
                },
            },
        }
    }

    #[test]
    fn signed_transaction_round_trips_and_verifies() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signed = unsigned(&signing_key).sign(&signing_key).unwrap();
        let bytes = signed.to_canonical_bytes().unwrap();
        let decoded = SignedTransaction::from_canonical_bytes(&bytes).unwrap();

        assert_eq!(
            decoded.to_canonical_bytes().unwrap(),
            signed.to_canonical_bytes().unwrap()
        );
        assert_eq!(
            decoded.verify().unwrap(),
            account_id_from_signer(&signing_key.verifying_key().to_bytes())
        );
    }

    #[test]
    fn signatures_and_hashes_are_deterministic() {
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let first = unsigned(&signing_key).sign(&signing_key).unwrap();
        let second = unsigned(&signing_key).sign(&signing_key).unwrap();

        assert_eq!(first.signature, second.signature);
        assert_eq!(first.tx_hash().unwrap(), second.tx_hash().unwrap());
        let expected_hash: [u8; 32] = Sha256::digest(first.to_canonical_bytes().unwrap()).into();
        assert_eq!(first.tx_hash().unwrap(), expected_hash);
    }

    #[test]
    fn tampering_is_detected() {
        let signing_key = SigningKey::from_bytes(&[13; 32]);
        let mut signed = unsigned(&signing_key).sign(&signing_key).unwrap();
        signed.nonce += 1;

        assert!(matches!(
            signed.verify(),
            Err(ChainTransactionError::InvalidSignature(_))
        ));
    }

    #[test]
    fn signer_must_match_signing_key() {
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let other_key = SigningKey::from_bytes(&[19; 32]);

        assert!(matches!(
            unsigned(&signing_key).sign(&other_key),
            Err(ChainTransactionError::SignerMismatch)
        ));
    }

    #[test]
    fn canonical_decoder_rejects_equivalent_noncanonical_json() {
        let signing_key = SigningKey::from_bytes(&[23; 32]);
        let signed = unsigned(&signing_key).sign(&signing_key).unwrap();
        let canonical = signed.to_canonical_bytes().unwrap();
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(&canonical);

        assert!(matches!(
            SignedTransaction::from_canonical_bytes(&noncanonical),
            Err(ChainTransactionError::NonCanonicalEncoding)
        ));
    }

    #[test]
    fn all_command_variants_have_canonical_round_trips() {
        let order_id = Uuid::from_bytes([3; 16]);
        let commands = vec![
            Command::CancelOrder { order_id },
            Command::CreditAccount {
                account_id: "ed25519:account".into(),
                amount: dec!(1000),
            },
            Command::PublishOraclePrice {
                symbol: "BTCUSDT".into(),
                observations: vec![OracleObservation {
                    source: "source-a".into(),
                    price: dec!(60000),
                    weight: 1,
                }],
            },
            Command::ApplyFunding {
                symbol: "BTCUSDT".into(),
                rate: dec!(0.0001),
            },
            Command::Liquidate {
                account_id: "ed25519:account".into(),
                symbol: "BTCUSDT".into(),
            },
        ];

        for command in commands {
            let bytes = canonical_encode(&command).unwrap();
            let decoded: Command = canonical_decode(&bytes).unwrap();
            assert_eq!(canonical_encode(&decoded).unwrap(), bytes);
        }
    }

    #[test]
    fn numeric_bounds_reject_values_that_can_overflow_consensus_arithmetic() {
        let oversized_credit = Command::CreditAccount {
            account_id: "ed25519:account".into(),
            amount: Decimal::MAX,
        };
        assert!(matches!(
            oversized_credit.validate_numeric_bounds(),
            Err(ChainTransactionError::InvalidNumericValue {
                field: "credit.amount",
                ..
            })
        ));

        let excessive_precision = Command::ApplyFunding {
            symbol: "BTCUSDT".into(),
            rate: "0.0000000000000000001".parse().unwrap(),
        };
        assert!(matches!(
            excessive_precision.validate_numeric_bounds(),
            Err(ChainTransactionError::InvalidNumericValue {
                field: "funding.rate",
                ..
            })
        ));
    }

    #[test]
    fn numeric_bounds_preserve_largest_supported_order_notional() {
        let command = Command::PlaceOrder {
            intent: OrderIntent {
                client_order_id: "max-supported".into(),
                symbol: "BTCUSDT".into(),
                side: Side::Buy,
                kind: OrderKind::Limit,
                quantity: MAX_INPUT_VALUE,
                price: Some(MAX_INPUT_VALUE),
                leverage: 1,
                time_in_force: TimeInForce::Gtc,
                reduce_only: false,
            },
        };

        assert!(command.validate_numeric_bounds().is_ok());
    }
}
