# Asteria performance benchmarks

`asteria-bench` is a dependency-free microbenchmark runner for the main execution and privacy hot paths. It uses `std::time::Instant`, deterministic workloads, and a common percentile report. It does not write benchmark results into the repository.

## Run

Use a release build for measurements:

```powershell
cargo run --release --bin asteria-bench -- --warmup 10 --iterations 100
```

Run the complete workload with small fixtures and sample counts as a smoke test:

```powershell
cargo run --release --bin asteria-bench -- --quick
```

Override the fixed workload seed and sample counts when comparing branches:

```powershell
cargo run --release --bin asteria-bench -- --seed 181961123825429 --warmup 20 --iterations 500
```

`--iterations` must be greater than zero. `--warmup` may be zero. A non-quick debug run is rejected because its timings would be misleading; debug `--quick` is allowed only for functional smoke testing.

## Workloads

| Result | Timed operation |
| --- | --- |
| `engine_state_clone` | Structurally shared `EngineState::clone`; clone destruction is excluded |
| `state_store_preview` | One-account state delta and JMT root preview against a committed state |
| `state_store_commit` | One-account state delta, JMT update, and redb transaction commit |
| `public_clob_place` | One non-crossing public GTC limit order through `Engine::submit_order` |
| `public_clob_match` | One crossing taker order and one maker fill through `Engine::submit_order` |
| `private_batch_{1,16,64,128}` | Uniform-price private batch clearing with the named order count |
| `threshold_dleq_create` | One threshold decryption share and Chaum-Pedersen proof |
| `threshold_dleq_verify` | Verification of one threshold decryption share and proof |

Fixture creation, account funding, initial JMT population, maker placement, key generation, and encryption are outside their target operation's timer. Each sample still performs the full named production operation and consumes its result through `black_box`.

## Output

The table reports `count` timed samples and nearest-rank `p50`, `p95`, and `p99` latency. `workload` is the amount of work inside each sample, not an operation count aggregated across samples.

Use the same release toolchain, seed, warmup, iterations, machine power mode, and background workload when comparing revisions. The JMT commit measurement includes the local redb and filesystem path, so disk hardware, antivirus scanning, and filesystem policy can dominate it. These are isolated latency measurements, not end-to-end block throughput or network TPS.

The deterministic RNG in the benchmark exists only to make cryptographic fixtures reproducible. It is not exposed by the library and must never be used for production keys or ciphertexts.
