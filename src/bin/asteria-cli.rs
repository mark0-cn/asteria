use std::{
    fs,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    time::Duration,
};

use asteria::{
    chain_tx::{
        CURRENT_TRANSACTION_VERSION, Command, SignedTransaction, UnsignedTransaction,
        account_id_from_signer,
    },
    domain::{OracleObservation, OrderIntent, OrderKind, Side, TimeInForce},
    private_order::{PrivateOrderContext, ThresholdPublicKeySet, encrypt_private_order},
    private_protocol::{
        PrivateOrderKind, PrivateOrderPayload, PrivateOrderSide, PrivateOrderSubmission,
        anti_spam_commitment,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use reqwest::{Client, Url, redirect::Policy};
use rust_decimal::Decimal;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_HTTP_TIMEOUT_SECONDS: u64 = 30;
const MAX_HTTP_TIMEOUT_SECONDS: u64 = 300;
const MAX_HTTP_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Sign, query, and broadcast Asteria chain transactions"
)]
struct Args {
    #[command(subcommand)]
    command: CommandLine,
}

#[derive(Debug, Clone, ClapArgs)]
struct SigningArgs {
    #[arg(
        long,
        env = "ASTERIA_SECRET_KEY",
        hide_env_values = true,
        conflicts_with = "secret_key_file"
    )]
    secret_key: Option<String>,
    #[arg(long, env = "ASTERIA_SECRET_KEY_FILE", conflicts_with = "secret_key")]
    secret_key_file: Option<PathBuf>,
    #[arg(long, env = "ASTERIA_CHAIN_ID", default_value = "asteria-localnet-1")]
    chain_id: String,
    #[arg(long)]
    nonce: u64,
    #[arg(long)]
    valid_until_height: u64,
}

#[derive(Debug, Clone, ClapArgs)]
struct ApiArgs {
    #[arg(long, env = "ASTERIA_API_URL", default_value = DEFAULT_API_URL)]
    api_url: String,
    #[arg(
        long,
        env = "ASTERIA_HTTP_TIMEOUT_SECONDS",
        default_value_t = DEFAULT_HTTP_TIMEOUT_SECONDS,
        value_parser = clap::value_parser!(u64).range(1..=MAX_HTTP_TIMEOUT_SECONDS)
    )]
    timeout_seconds: u64,
}

#[derive(Debug, Subcommand)]
enum CommandLine {
    /// Generate an Ed25519 development identity. Store the secret securely.
    Keygen {
        #[arg(long, default_value = "asteria-secret-key")]
        secret_key_file: PathBuf,
    },
    /// Sign any serialized Command. Use '-' to read encrypted/private data from stdin.
    SignCommand {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long, default_value = "-")]
        command_file: PathBuf,
    },
    /// Encrypt and sign a single-batch private order without exposing its payload.
    SignPrivateOrder {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long)]
        key_set_file: PathBuf,
        #[arg(long)]
        market_id: String,
        #[arg(long)]
        batch_height: u64,
        #[arg(long)]
        client_id: String,
        #[arg(long, value_enum)]
        side: CliSide,
        #[arg(long, value_enum)]
        kind: CliOrderKind,
        #[arg(long, default_value_t = 0)]
        price_ticks: u64,
        #[arg(long)]
        quantity_lots: u64,
        #[arg(long)]
        leverage: u16,
        #[arg(long, value_enum, default_value = "ioc")]
        time_in_force: CliPrivateTimeInForce,
        #[arg(long)]
        reduce_only: bool,
    },
    /// Query a JSON HTTP endpoint, for example /v1/private/keyset.
    Query {
        #[command(flatten)]
        api: ApiArgs,
        #[arg(long)]
        path: String,
    },
    /// Broadcast a signed transaction read from a file or stdin.
    Broadcast {
        #[command(flatten)]
        api: ApiArgs,
        #[arg(long, default_value = "-")]
        transaction_file: PathBuf,
        #[arg(long, value_enum, default_value = "transaction")]
        endpoint: BroadcastEndpoint,
    },
    SignOrder {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long)]
        client_order_id: String,
        #[arg(long)]
        symbol: String,
        #[arg(long, value_enum)]
        side: CliSide,
        #[arg(long, value_enum)]
        kind: CliOrderKind,
        #[arg(long)]
        quantity: Decimal,
        #[arg(long)]
        price: Option<Decimal>,
        #[arg(long)]
        leverage: u16,
        #[arg(long, value_enum, default_value = "gtc")]
        time_in_force: CliTimeInForce,
        #[arg(long)]
        reduce_only: bool,
    },
    SignCancel {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long)]
        order_id: Uuid,
    },
    SignCredit {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long)]
        account_id: String,
        #[arg(long)]
        amount: Decimal,
    },
    SignOracle {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long)]
        symbol: String,
        /// Repeat as --observation SOURCE:PRICE:WEIGHT (at least three sources).
        #[arg(long = "observation", value_parser = parse_observation)]
        observations: Vec<OracleObservation>,
    },
    SignFunding {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long)]
        symbol: String,
        #[arg(long)]
        rate: Decimal,
    },
    SignLiquidation {
        #[command(flatten)]
        signing: SigningArgs,
        #[arg(long)]
        account_id: String,
        #[arg(long)]
        symbol: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSide {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliOrderKind {
    Limit,
    Market,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliTimeInForce {
    Gtc,
    Ioc,
    Fok,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliPrivateTimeInForce {
    Ioc,
    Fok,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BroadcastEndpoint {
    Transaction,
    PrivateOrder,
    ShieldedMarket,
    ShieldedDeposit,
    ShieldedSpend,
}

impl BroadcastEndpoint {
    fn path(self) -> &'static str {
        match self {
            Self::Transaction => "/v1/tx",
            Self::PrivateOrder => "/v1/private/orders",
            Self::ShieldedMarket => "/v1/admin/shielded/markets",
            Self::ShieldedDeposit => "/v1/shielded/deposits",
            Self::ShieldedSpend => "/v1/shielded/spends",
        }
    }

    fn accepts(self, command: &Command) -> bool {
        match self {
            Self::Transaction => true,
            Self::PrivateOrder => matches!(command, Command::SubmitPrivateOrder { .. }),
            Self::ShieldedMarket => matches!(command, Command::ConfigureShieldedMarket { .. }),
            Self::ShieldedDeposit => matches!(command, Command::ShieldedDeposit { .. }),
            Self::ShieldedSpend => matches!(command, Command::ShieldedSpend { .. }),
        }
    }
}

#[derive(Serialize)]
struct Identity {
    account_id: String,
    public_key: String,
    secret_key_file: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        CommandLine::Keygen { secret_key_file } => {
            let signing_key = SigningKey::generate(&mut OsRng);
            let public_key = signing_key.verifying_key().to_bytes();
            let encoded_secret = Zeroizing::new(STANDARD.encode(signing_key.to_bytes()));
            write_secret_key(&secret_key_file, &encoded_secret)?;
            print_json(&Identity {
                account_id: account_id_from_signer(&public_key),
                public_key: STANDARD.encode(public_key),
                secret_key_file: secret_key_file.display().to_string(),
            })?;
        }
        CommandLine::SignCommand {
            signing,
            command_file,
        } => {
            let command = read_json::<Command>(&command_file)?;
            print_json(&sign_command(signing, command)?)?;
        }
        CommandLine::SignPrivateOrder {
            mut signing,
            key_set_file,
            market_id,
            batch_height,
            client_id,
            side,
            kind,
            price_ticks,
            quantity_lots,
            leverage,
            time_in_force,
            reduce_only,
        } => {
            let signing_key = load_signing_key(&mut signing)?;
            let key_set = read_json::<ThresholdPublicKeySet>(&key_set_file)?;
            key_set.validate()?;
            let payload = PrivateOrderPayload {
                client_id,
                side: match side {
                    CliSide::Buy => PrivateOrderSide::Buy,
                    CliSide::Sell => PrivateOrderSide::Sell,
                },
                kind: match kind {
                    CliOrderKind::Limit => PrivateOrderKind::Limit,
                    CliOrderKind::Market => PrivateOrderKind::Market,
                },
                price_ticks,
                quantity_lots,
                leverage,
                ioc: matches!(time_in_force, CliPrivateTimeInForce::Ioc),
                fok: matches!(time_in_force, CliPrivateTimeInForce::Fok),
                reduce_only,
            };
            let plaintext = Zeroizing::new(payload.to_canonical_bytes()?);
            let fee_payer = signing_key.verifying_key().to_bytes();
            let context = PrivateOrderContext {
                chain_id: signing.chain_id.clone(),
                market_id,
                epoch: key_set.epoch,
                batch_height,
            };
            let anti_spam = anti_spam_commitment(&signing.chain_id, &fee_payer, signing.nonce)?;
            let envelope = encrypt_private_order(
                &key_set, &context, fee_payer, anti_spam, &plaintext, &mut OsRng,
            )?;
            let submission = PrivateOrderSubmission::sign(
                signing.chain_id.clone(),
                signing.nonce,
                signing.valid_until_height,
                envelope,
                &signing_key,
            )?;
            let transaction = sign_command_with_key(
                signing,
                Command::SubmitPrivateOrder {
                    submission: Box::new(submission),
                },
                &signing_key,
            )?;
            print_json(&transaction)?;
        }
        CommandLine::Query { api, path } => {
            let client = http_client(api.timeout_seconds)?;
            let url = endpoint_url(&api.api_url, &path)?;
            let response = client.get(url).send().await?;
            print_http_response(response).await?;
        }
        CommandLine::Broadcast {
            api,
            transaction_file,
            endpoint,
        } => {
            let transaction = read_json::<SignedTransaction>(&transaction_file)?;
            transaction.verify()?;
            if let Command::SubmitPrivateOrder { submission } = &transaction.command {
                submission.to_canonical_bytes()?;
            }
            if !endpoint.accepts(&transaction.command) {
                return Err(format!(
                    "{} endpoint does not accept this signed command type",
                    endpoint.path()
                )
                .into());
            }
            let client = http_client(api.timeout_seconds)?;
            let url = endpoint_url(&api.api_url, endpoint.path())?;
            let response = client.post(url).json(&transaction).send().await?;
            print_http_response(response).await?;
        }
        CommandLine::SignOrder {
            signing,
            client_order_id,
            symbol,
            side,
            kind,
            quantity,
            price,
            leverage,
            time_in_force,
            reduce_only,
        } => print_json(&sign_command(
            signing,
            Command::PlaceOrder {
                intent: OrderIntent {
                    client_order_id,
                    symbol,
                    side: match side {
                        CliSide::Buy => Side::Buy,
                        CliSide::Sell => Side::Sell,
                    },
                    kind: match kind {
                        CliOrderKind::Limit => OrderKind::Limit,
                        CliOrderKind::Market => OrderKind::Market,
                    },
                    quantity,
                    price,
                    leverage,
                    time_in_force: match time_in_force {
                        CliTimeInForce::Gtc => TimeInForce::Gtc,
                        CliTimeInForce::Ioc => TimeInForce::Ioc,
                        CliTimeInForce::Fok => TimeInForce::Fok,
                    },
                    reduce_only,
                },
            },
        )?)?,
        CommandLine::SignCancel { signing, order_id } => {
            print_json(&sign_command(signing, Command::CancelOrder { order_id })?)?
        }
        CommandLine::SignCredit {
            signing,
            account_id,
            amount,
        } => print_json(&sign_command(
            signing,
            Command::CreditAccount { account_id, amount },
        )?)?,
        CommandLine::SignOracle {
            signing,
            symbol,
            observations,
        } => {
            if observations.len() < 3 {
                return Err("sign-oracle requires at least three --observation values".into());
            }
            print_json(&sign_command(
                signing,
                Command::PublishOraclePrice {
                    symbol,
                    observations,
                },
            )?)?
        }
        CommandLine::SignFunding {
            signing,
            symbol,
            rate,
        } => print_json(&sign_command(
            signing,
            Command::ApplyFunding { symbol, rate },
        )?)?,
        CommandLine::SignLiquidation {
            signing,
            account_id,
            symbol,
        } => print_json(&sign_command(
            signing,
            Command::Liquidate { account_id, symbol },
        )?)?,
    }
    Ok(())
}

fn sign_command(
    mut arguments: SigningArgs,
    command: Command,
) -> Result<SignedTransaction, Box<dyn std::error::Error>> {
    let signing_key = load_signing_key(&mut arguments)?;
    sign_command_with_key(arguments, command, &signing_key)
}

fn load_signing_key(arguments: &mut SigningArgs) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let encoded_secret = Zeroizing::new(
        match (
            arguments.secret_key.take(),
            arguments.secret_key_file.take(),
        ) {
            (Some(secret), None) => secret,
            (None, Some(path)) => fs::read_to_string(path)?.trim().to_owned(),
            (None, None) => {
                return Err("provide --secret-key-file (recommended) or ASTERIA_SECRET_KEY".into());
            }
            (Some(_), Some(_)) => return Err("provide exactly one secret key source".into()),
        },
    );
    let decoded_secret = Zeroizing::new(STANDARD.decode(encoded_secret.as_bytes())?);
    if decoded_secret.len() != 32 {
        return Err("secret key must contain exactly 32 bytes".into());
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret.copy_from_slice(&decoded_secret);
    Ok(SigningKey::from_bytes(&secret))
}

fn sign_command_with_key(
    arguments: SigningArgs,
    command: Command,
    signing_key: &SigningKey,
) -> Result<SignedTransaction, Box<dyn std::error::Error>> {
    if arguments.valid_until_height == 0 {
        return Err("valid-until-height must be greater than zero".into());
    }
    if let Command::SubmitPrivateOrder { submission } = &command {
        submission.to_canonical_bytes()?;
        let signer = signing_key.verifying_key().to_bytes();
        if submission.envelope.header.fee_payer != signer {
            return Err(
                "private-order fee payer does not match the transaction signing key".into(),
            );
        }
        if submission.chain_id != arguments.chain_id {
            return Err("private-order and transaction chain ids must match".into());
        }
        if submission.nonce != arguments.nonce {
            return Err("private-order and transaction nonces must match".into());
        }
        if submission.valid_until_height != arguments.valid_until_height {
            return Err("private-order and transaction valid-until heights must match".into());
        }
    }
    Ok(UnsignedTransaction {
        version: CURRENT_TRANSACTION_VERSION,
        chain_id: arguments.chain_id,
        signer: signing_key.verifying_key().to_bytes(),
        nonce: arguments.nonce,
        valid_until_height: arguments.valid_until_height,
        command,
    }
    .sign(signing_key)?)
}

fn write_secret_key(path: &Path, encoded_secret: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(encoded_secret.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let bytes = if path == Path::new("-") {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        bytes
    } else {
        fs::read(path)?
    };
    Ok(serde_json::from_slice(&bytes)?)
}

fn http_client(timeout_seconds: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .user_agent(concat!("asteria-cli/", env!("CARGO_PKG_VERSION")))
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(timeout_seconds.min(10)))
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
}

fn endpoint_url(api_url: &str, path: &str) -> Result<Url, Box<dyn std::error::Error>> {
    if !path.starts_with('/') || path.starts_with("//") {
        return Err("HTTP path must start with exactly one '/'".into());
    }
    let base = Url::parse(api_url)?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err("API URL must use http or https".into());
    }
    Ok(base.join(path)?)
}

async fn print_http_response(
    mut response: reqwest::Response,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_HTTP_RESPONSE_BYTES)
    {
        return Err(format!("HTTP response exceeds {} bytes", MAX_HTTP_RESPONSE_BYTES).into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or("HTTP response length overflow")?;
        if u64::try_from(next_length).unwrap_or(u64::MAX) > MAX_HTTP_RESPONSE_BYTES {
            return Err(format!("HTTP response exceeds {} bytes", MAX_HTTP_RESPONSE_BYTES).into());
        }
        body.extend_from_slice(&chunk);
    }
    let decoded = serde_json::from_slice::<Value>(&body);
    if !status.is_success() {
        let detail = decoded
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| {
                String::from_utf8_lossy(&body[..body.len().min(1_024)]).into_owned()
            });
        return Err(format!("HTTP {status}: {detail}").into());
    }
    let value = decoded.map_err(|error| format!("HTTP {status} returned invalid JSON: {error}"))?;
    print_json(&value)?;
    Ok(())
}

fn parse_observation(value: &str) -> Result<OracleObservation, String> {
    let mut parts = value.split(':');
    let source = parts.next().unwrap_or_default();
    let price = parts
        .next()
        .ok_or("expected SOURCE:PRICE:WEIGHT")?
        .parse::<Decimal>()
        .map_err(|error| error.to_string())?;
    let weight = parts
        .next()
        .ok_or("expected SOURCE:PRICE:WEIGHT")?
        .parse::<u32>()
        .map_err(|error| error.to_string())?;
    if source.is_empty() || parts.next().is_some() {
        return Err("expected SOURCE:PRICE:WEIGHT".into());
    }
    Ok(OracleObservation {
        source: source.into(),
        price,
        weight,
    })
}

fn print_json(value: &impl Serialize) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, http::StatusCode, routing::get};
    use rust_decimal_macros::dec;
    use serde_json::json;

    use super::*;

    #[test]
    fn generic_command_signing_produces_a_verifiable_transaction() {
        let key = SigningKey::from_bytes(&[61; 32]);
        let transaction = sign_command(
            SigningArgs {
                secret_key: Some(STANDARD.encode(key.to_bytes())),
                secret_key_file: None,
                chain_id: "asteria-cli-test-1".into(),
                nonce: 7,
                valid_until_height: 99,
            },
            Command::CreditAccount {
                account_id: "account-a".into(),
                amount: dec!(1),
            },
        )
        .unwrap();

        transaction.verify().unwrap();
        assert_eq!(transaction.nonce, 7);
        assert_eq!(transaction.signer, key.verifying_key().to_bytes());
    }

    #[test]
    fn endpoint_url_rejects_cross_origin_network_paths() {
        let url = endpoint_url("https://api.example/base", "/v1/private/keyset").unwrap();
        assert_eq!(url.as_str(), "https://api.example/v1/private/keyset");
        assert!(endpoint_url("https://api.example", "//other.example/path").is_err());
        assert!(endpoint_url("file:///tmp/api", "/v1/chain").is_err());
    }

    #[tokio::test]
    async fn non_success_http_response_is_returned_as_an_error() {
        async fn rejected() -> (StatusCode, Json<Value>) {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "transaction rejected" })),
            )
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/error", get(rejected))
                    .into_make_service(),
            )
            .await
            .unwrap();
        });
        let response = http_client(2)
            .unwrap()
            .get(format!("http://{address}/error"))
            .send()
            .await
            .unwrap();

        let error = print_http_response(response).await.unwrap_err();
        assert!(error.to_string().contains("HTTP 422"));
        assert!(error.to_string().contains("transaction rejected"));
        server.abort();
    }
}
