use std::{
    hint::black_box,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use asteria::{
    Engine,
    batch_auction::OrderId,
    domain::{Account, NewOrder, OrderIntent, OrderKind, Side, TimeInForce},
    engine::{EngineState, default_markets},
    private_market::{BatchContext, BatchParticipant, ParticipantVisibility, clear_private_batch},
    private_order::{
        PrivateOrderContext, create_decryption_share, encrypt_private_order,
        generate_dealer_key_set, verify_decryption_share,
    },
    store::StateStore,
};
use clap::Parser;
use rand_core::{CryptoRng, Error as RngError, RngCore};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use sha2::{Digest, Sha256};

const DEFAULT_SEED: u64 = 0xA57E_2026_0715;
const NORMAL_WARMUP: usize = 10;
const NORMAL_ITERATIONS: usize = 100;
const QUICK_WARMUP: usize = 1;
const QUICK_ITERATIONS: usize = 5;
const PRIVATE_BATCH_SIZES: [usize; 4] = [1, 16, 64, 128];
static TEMP_DATABASE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Parser)]
#[command(
    name = "asteria-bench",
    about = "Deterministic microbenchmarks for Asteria consensus hot paths"
)]
struct Args {
    /// Run every benchmark with smoke-test-sized fixtures and sample counts.
    #[arg(long)]
    quick: bool,

    /// Warmup samples per benchmark (defaults to 10, or 1 with --quick).
    #[arg(long)]
    warmup: Option<usize>,

    /// Timed samples per benchmark (defaults to 100, or 5 with --quick).
    #[arg(long)]
    iterations: Option<usize>,

    /// Fixed workload seed. Timings are never used as workload entropy.
    #[arg(long, default_value_t = DEFAULT_SEED)]
    seed: u64,
}

#[derive(Clone, Copy)]
struct BenchConfig {
    warmup: usize,
    iterations: usize,
    seed: u64,
    state_accounts: usize,
    store_accounts: usize,
}

struct BenchRow {
    name: String,
    workload: String,
    count: usize,
    p50_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if cfg!(debug_assertions) && !args.quick {
        bail!("benchmark measurements require --release; use --quick only for a debug smoke test");
    }
    if cfg!(debug_assertions) {
        eprintln!("warning: debug --quick run is a smoke test; timings are not representative");
    }

    let config = BenchConfig {
        warmup: args.warmup.unwrap_or(if args.quick {
            QUICK_WARMUP
        } else {
            NORMAL_WARMUP
        }),
        iterations: args.iterations.unwrap_or(if args.quick {
            QUICK_ITERATIONS
        } else {
            NORMAL_ITERATIONS
        }),
        seed: args.seed,
        state_accounts: if args.quick { 256 } else { 10_000 },
        store_accounts: if args.quick { 128 } else { 4_096 },
    };
    ensure!(
        config.iterations > 0,
        "--iterations must be greater than zero"
    );

    println!(
        "profile={} seed=0x{:016x} warmup={} iterations={}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        config.seed,
        config.warmup,
        config.iterations
    );

    let mut rows = vec![
        bench_state_clone(config)?,
        bench_store_preview(config)?,
        bench_store_commit(config)?,
        bench_public_resting_order(config)?,
        bench_public_match(config)?,
    ];
    for size in PRIVATE_BATCH_SIZES {
        rows.push(bench_private_batch(config, size)?);
    }
    rows.extend(bench_dleq(config)?);
    print_rows(&rows);
    Ok(())
}

fn bench_state_clone(config: BenchConfig) -> Result<BenchRow> {
    let state = populated_state(config.state_accounts)?;
    measure(
        "engine_state_clone",
        format!("{} accounts", config.state_accounts),
        config,
        |_| {
            let started = Instant::now();
            let cloned = black_box(state.clone());
            black_box(&cloned);
            let elapsed = started.elapsed();
            drop(cloned);
            Ok(elapsed)
        },
    )
}

fn bench_store_preview(config: BenchConfig) -> Result<BenchRow> {
    let database_path = TempDatabasePath::new("preview");
    let store =
        StateStore::open(database_path.as_path()).context("open preview benchmark store")?;
    let previous = populated_state(config.store_accounts)?;
    store
        .commit_state(None, &previous)
        .context("initialize preview benchmark store")?;
    let mut next = previous.clone();
    mutate_state(&mut next, 0)?;

    measure(
        "state_store_preview",
        format!("{} accounts, 1 account delta", config.store_accounts),
        config,
        |_| {
            let started = Instant::now();
            let root = store
                .preview_state_root(Some(&previous), &next)
                .context("preview JMT state root")?;
            black_box(root);
            Ok(started.elapsed())
        },
    )
}

fn bench_store_commit(config: BenchConfig) -> Result<BenchRow> {
    let database_path = TempDatabasePath::new("commit");
    let store = StateStore::open(database_path.as_path()).context("open commit benchmark store")?;
    let mut current = populated_state(config.store_accounts)?;
    store
        .commit_state(None, &current)
        .context("initialize commit benchmark store")?;

    measure(
        "state_store_commit",
        format!("{} accounts, 1 account delta", config.store_accounts),
        config,
        |sample| {
            let mut next = current.clone();
            mutate_state(&mut next, sample % config.store_accounts)?;
            let started = Instant::now();
            let root = store
                .commit_state(Some(&current), &next)
                .context("commit JMT state")?;
            let elapsed = started.elapsed();
            black_box(root);
            current = next;
            Ok(elapsed)
        },
    )
}

fn bench_public_resting_order(config: BenchConfig) -> Result<BenchRow> {
    measure(
        "public_clob_place",
        "1 resting limit order".into(),
        config,
        |sample| {
            let mut engine = Engine::in_memory(default_markets());
            engine.credit_account("trader".into(), dec!(1000000))?;
            let order = limit_order(
                "trader",
                &format!("resting-{sample}"),
                Side::Buy,
                dec!(1),
                dec!(59000),
            );
            let started = Instant::now();
            let result = engine.submit_order(order)?;
            let elapsed = started.elapsed();
            ensure!(
                result.trades.is_empty(),
                "resting benchmark unexpectedly matched"
            );
            black_box(result);
            Ok(elapsed)
        },
    )
}

fn bench_public_match(config: BenchConfig) -> Result<BenchRow> {
    measure(
        "public_clob_match",
        "1 maker x 1 taker".into(),
        config,
        |sample| {
            let mut engine = Engine::in_memory(default_markets());
            engine.credit_account("maker".into(), dec!(1000000))?;
            engine.credit_account("taker".into(), dec!(1000000))?;
            engine.submit_order(limit_order(
                "maker",
                &format!("maker-{sample}"),
                Side::Sell,
                dec!(1),
                dec!(60000),
            ))?;
            let started = Instant::now();
            let result = engine.submit_order(limit_order(
                "taker",
                &format!("taker-{sample}"),
                Side::Buy,
                dec!(1),
                dec!(60000),
            ))?;
            let elapsed = started.elapsed();
            ensure!(
                result.trades.len() == 1,
                "matching benchmark did not produce one trade"
            );
            black_box(result);
            Ok(elapsed)
        },
    )
}

fn bench_private_batch(config: BenchConfig, size: usize) -> Result<BenchRow> {
    let market = default_markets()
        .into_iter()
        .next()
        .context("default BTC market is missing")?;
    let context = BatchContext {
        chain_id: "asteria-benchmark".into(),
        height: 42,
        threshold_beacon: derive_seed(config.seed, b"private-threshold-beacon", 0),
        reference_price: market.mark_price,
    };
    let participants = private_participants(config.seed, size);
    measure(
        &format!("private_batch_{size}"),
        format!("{size} orders"),
        config,
        |_| {
            let started = Instant::now();
            let outcome = clear_private_batch(&market.config, &context, &participants)?;
            let elapsed = started.elapsed();
            black_box(outcome);
            Ok(elapsed)
        },
    )
}

fn bench_dleq(config: BenchConfig) -> Result<Vec<BenchRow>> {
    let context = PrivateOrderContext {
        chain_id: "asteria-benchmark".into(),
        market_id: "BTCUSDT".into(),
        epoch: 7,
        batch_height: 42,
    };
    let mut fixture_rng = DeterministicRng::new(derive_seed(config.seed, b"dleq-fixture", 0));
    let (public_keys, secret_shares) = generate_dealer_key_set(context.epoch, &mut fixture_rng)?;
    let envelope = encrypt_private_order(
        &public_keys,
        &context,
        [7; 32],
        [9; 32],
        br#"{"side":"buy","quantity":"0.001","price":"60000"}"#,
        &mut fixture_rng,
    )?;

    let create = measure(
        "threshold_dleq_create",
        "1 decryption share".into(),
        config,
        |sample| {
            let mut rng =
                DeterministicRng::new(derive_seed(config.seed, b"dleq-create", sample as u64));
            let started = Instant::now();
            let share = create_decryption_share(
                &public_keys,
                &secret_shares[0],
                &context,
                &envelope,
                &mut rng,
            )?;
            let elapsed = started.elapsed();
            black_box(share);
            Ok(elapsed)
        },
    )?;

    let mut share_rng = DeterministicRng::new(derive_seed(config.seed, b"dleq-verify", 0));
    let share = create_decryption_share(
        &public_keys,
        &secret_shares[0],
        &context,
        &envelope,
        &mut share_rng,
    )?;
    let verify = measure(
        "threshold_dleq_verify",
        "1 decryption share".into(),
        config,
        |_| {
            let started = Instant::now();
            verify_decryption_share(&public_keys, &context, &envelope, &share)?;
            Ok(started.elapsed())
        },
    )?;
    Ok(vec![create, verify])
}

fn measure(
    name: &str,
    workload: String,
    config: BenchConfig,
    mut operation: impl FnMut(usize) -> Result<Duration>,
) -> Result<BenchRow> {
    for sample in 0..config.warmup {
        black_box(operation(sample).with_context(|| format!("warm up {name}"))?);
    }
    let mut samples = Vec::with_capacity(config.iterations);
    for sample in 0..config.iterations {
        let elapsed = operation(sample).with_context(|| format!("measure {name}"))?;
        samples.push(elapsed.as_nanos());
    }
    samples.sort_unstable();
    Ok(BenchRow {
        name: name.into(),
        workload,
        count: samples.len(),
        p50_ns: percentile(&samples, 50),
        p95_ns: percentile(&samples, 95),
        p99_ns: percentile(&samples, 99),
    })
}

fn percentile(sorted: &[u128], percentile: usize) -> u128 {
    let rank = sorted
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

fn print_rows(rows: &[BenchRow]) {
    println!();
    println!(
        "{:<28} {:<28} {:>8} {:>12} {:>12} {:>12}",
        "benchmark", "workload", "count", "p50", "p95", "p99"
    );
    println!("{}", "-".repeat(106));
    for row in rows {
        println!(
            "{:<28} {:<28} {:>8} {:>12} {:>12} {:>12}",
            row.name,
            row.workload,
            row.count,
            format_duration(row.p50_ns),
            format_duration(row.p95_ns),
            format_duration(row.p99_ns)
        );
    }
}

fn format_duration(nanoseconds: u128) -> String {
    if nanoseconds < 1_000 {
        format!("{nanoseconds} ns")
    } else if nanoseconds < 1_000_000 {
        format!("{:.2} us", nanoseconds as f64 / 1_000.0)
    } else if nanoseconds < 1_000_000_000 {
        format!("{:.2} ms", nanoseconds as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", nanoseconds as f64 / 1_000_000_000.0)
    }
}

fn populated_state(account_count: usize) -> Result<EngineState> {
    let mut state = EngineState::genesis("asteria-benchmark", default_markets());
    for index in 0..account_count {
        let account_id = benchmark_account_id(index);
        let mut account = Account::new(account_id.clone());
        account.collateral = dec!(1000000);
        state.accounts.insert(account_id, account);
        state.total_credits = state
            .total_credits
            .checked_add(dec!(1000000))
            .context("benchmark total credit overflow")?;
    }
    Ok(state)
}

fn mutate_state(state: &mut EngineState, account_index: usize) -> Result<()> {
    let account_id = benchmark_account_id(account_index);
    let account = state
        .accounts
        .get_mut(&account_id)
        .with_context(|| format!("benchmark account {account_id} is missing"))?;
    account.collateral = account
        .collateral
        .checked_add(Decimal::ONE)
        .context("benchmark collateral overflow")?;
    state.total_credits = state
        .total_credits
        .checked_add(Decimal::ONE)
        .context("benchmark total credit overflow")?;
    state.height = state
        .height
        .checked_add(1)
        .context("benchmark height overflow")?;
    Ok(())
}

fn benchmark_account_id(index: usize) -> String {
    format!("benchmark-account-{index:08}")
}

fn limit_order(
    account_id: &str,
    client_order_id: &str,
    side: Side,
    quantity: Decimal,
    price: Decimal,
) -> NewOrder {
    NewOrder {
        account_id: account_id.into(),
        intent: OrderIntent {
            client_order_id: client_order_id.into(),
            symbol: "BTCUSDT".into(),
            side,
            kind: OrderKind::Limit,
            quantity,
            price: Some(price),
            leverage: 10,
            time_in_force: TimeInForce::Gtc,
            reduce_only: false,
        },
    }
}

fn private_participants(seed: u64, size: usize) -> Vec<BatchParticipant> {
    (0..size)
        .map(|index| {
            let side = if index.is_multiple_of(2) {
                Side::Buy
            } else {
                Side::Sell
            };
            BatchParticipant {
                visibility: ParticipantVisibility::Private {
                    ciphertext_id: derive_seed(seed, b"private-ciphertext", index as u64),
                },
                account_id: format!("private-account-{index:08}"),
                order_id: OrderId(derive_seed(seed, b"private-order", index as u64)),
                side,
                kind: OrderKind::Limit,
                time_in_force: TimeInForce::Ioc,
                quantity: dec!(0.001),
                limit_price: Some(dec!(60000)),
                leverage: 10,
                reduce_only: false,
            }
        })
        .collect()
}

fn derive_seed(seed: u64, domain: &[u8], index: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ASTERIA_BENCHMARK_SEED_V1\0");
    hasher.update(seed.to_be_bytes());
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(index.to_be_bytes());
    hasher.finalize().into()
}

struct DeterministicRng {
    seed: [u8; 32],
    counter: u64,
    buffer: [u8; 32],
    offset: usize,
}

impl DeterministicRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: [0; 32],
            offset: 32,
        }
    }

    fn refill(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(b"ASTERIA_BENCHMARK_RNG_V1\0");
        hasher.update(self.seed);
        hasher.update(self.counter.to_be_bytes());
        self.buffer = hasher.finalize().into();
        self.counter = self
            .counter
            .checked_add(1)
            .expect("benchmark RNG exhausted");
        self.offset = 0;
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        let mut written = 0;
        while written < destination.len() {
            if self.offset == self.buffer.len() {
                self.refill();
            }
            let available = self.buffer.len() - self.offset;
            let remaining = destination.len() - written;
            let copied = available.min(remaining);
            destination[written..written + copied]
                .copy_from_slice(&self.buffer[self.offset..self.offset + copied]);
            self.offset += copied;
            written += copied;
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}

struct TempDatabasePath(PathBuf);

impl TempDatabasePath {
    fn new(label: &str) -> Self {
        let counter = TEMP_DATABASE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "asteria-benchmark-{label}-{}-{counter}-{timestamp}.redb",
            std::process::id()
        ));
        Self(path)
    }

    fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDatabasePath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
