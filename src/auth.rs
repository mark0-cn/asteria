use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    domain::{AccountId, NewOrder, OrderIntent},
    error::{ExchangeError, Result},
};

pub const ORDER_DOMAIN: &[u8] = b"ASTERIA_ORDER_V1\n";
pub const CANCEL_DOMAIN: &[u8] = b"ASTERIA_CANCEL_V1\n";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope<T> {
    pub payload: T,
    /// Standard-base64 encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// Standard-base64 encoded 64-byte Ed25519 signature.
    pub signature: String,
}

pub fn verify_order(envelope: SignedEnvelope<OrderIntent>) -> Result<NewOrder> {
    let account_id = verify_envelope(&envelope, ORDER_DOMAIN)?;
    Ok(NewOrder {
        account_id,
        intent: envelope.payload,
    })
}

pub fn verify_envelope<T>(envelope: &SignedEnvelope<T>, domain: &[u8]) -> Result<AccountId>
where
    T: Serialize + DeserializeOwned,
{
    let public_key = STANDARD
        .decode(&envelope.public_key)
        .map_err(|error| ExchangeError::InvalidSignature(error.to_string()))?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| ExchangeError::InvalidSignature("public key must contain 32 bytes".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| ExchangeError::InvalidSignature(error.to_string()))?;

    let signature = STANDARD
        .decode(&envelope.signature)
        .map_err(|error| ExchangeError::InvalidSignature(error.to_string()))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|error| ExchangeError::InvalidSignature(error.to_string()))?;

    let mut message = domain.to_vec();
    message.extend(
        serde_jcs::to_vec(&envelope.payload)
            .map_err(|error| ExchangeError::InvalidSignature(error.to_string()))?,
    );
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|error| ExchangeError::InvalidSignature(error.to_string()))?;
    Ok(format!("ed25519:{}", hex::encode(public_key)))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rust_decimal_macros::dec;

    use super::*;
    use crate::domain::{OrderKind, Side, TimeInForce};

    #[test]
    fn verifies_canonical_order_signature() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let payload = OrderIntent {
            client_order_id: "client-1".into(),
            symbol: "BTCUSDT".into(),
            side: Side::Buy,
            kind: OrderKind::Limit,
            quantity: dec!(0.01),
            price: Some(dec!(60000)),
            leverage: 10,
            time_in_force: TimeInForce::Gtc,
            reduce_only: false,
        };
        let mut message = ORDER_DOMAIN.to_vec();
        message.extend(serde_jcs::to_vec(&payload).unwrap());
        let signature = signing_key.sign(&message);
        let envelope = SignedEnvelope {
            payload,
            public_key: STANDARD.encode(signing_key.verifying_key().to_bytes()),
            signature: STANDARD.encode(signature.to_bytes()),
        };

        let order = verify_order(envelope).unwrap();
        assert_eq!(
            order.account_id,
            format!(
                "ed25519:{}",
                hex::encode(signing_key.verifying_key().to_bytes())
            )
        );
    }
}
