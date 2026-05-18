This project is created as a part of a masters thesis written at OsloMet.

The goal is to benchmark asymmetric cryptography in two places:
- Signatures are measured through signed JWT payloads.
- TLS key agreement is measured through local TLS 1.3 loopback handshakes.

## Benchmarking

Run every benchmark, attach the default JMH `gc` profiler, and generate the CSV
and Markdown report with one command:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-benchmarks.ps1 -Suite all -Profiler gc
```

That command uses the JMH annotations in the benchmark classes. It is the most
complete sweep, but it can take a long time because the level-5 SLH-DSA
benchmarks are slow.

For thesis writing and level-3-vs-level-5 comparison, use the thesis preset:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-benchmarks.ps1 -Suite all -Preset thesis -Profiler gc
```

The thesis preset still runs every benchmark method and every configured
algorithm/profile, but fixes the signature payload and TLS message size to
1024 bytes. It also overrides JMH to use one warmup iteration, three
measurement iterations, one fork, and one-second iterations. This keeps the
full level comparison practical while making the iteration count explicit in
the generated CSV and report.

The output goes to `benchmark-results`:
- `*.json` is the raw JMH output.
- `*-summary.csv` is spreadsheet-friendly processed data.
- `*-report.md` is the human-readable report.
- `*-signature-size-metadata.csv` contains signature key, signature, and JWT sizes.
- `*-tls-size-metadata.csv` contains TLS authentication key, certificate, and key-share sizes.

You can run smaller suites when iterating:

```powershell
.\scripts\run-benchmarks.ps1 -Suite signatures -Profiler gc
.\scripts\run-benchmarks.ps1 -Suite keygen -Profiler gc
.\scripts\run-benchmarks.ps1 -Suite lifecycle -Profiler gc
.\scripts\run-benchmarks.ps1 -Suite tls -Profiler gc
```

Use `-SkipSummary` if you only want the raw JMH JSON. To summarize an existing
JSON file later:

```powershell
.\scripts\summarize-benchmarks.ps1 -InputPath .\benchmark-results\thesis-preset\all-20260517-054928.json
```

## Signature Benchmarks

The signature suite has three separate scenarios:
- `SignatureKeyGenerationBenchmark`: fresh key generation only.
- `SignatureServiceBenchmark`: steady-state sign, verify, and round trip with configured reusable keys.
- `SignatureFullLifecycleBenchmark`: fresh key generation, sign with the fresh private key, then verify with the matching fresh public key.

Default signature algorithms:

| Label | Family | Security level | Parameter set |
| --- | --- | ---: | --- |
| `RSA-L3` | RSA | 3 | RSA-7680 |
| `EC-L3` | ECDSA | 3 | secp384r1 |
| `ML-DSA-L3` | ML-DSA | 3 | ML-DSA-65 |
| `SLH-DSA-L3` | SLH-DSA | 3 | SLH-DSA-SHAKE-192s |
| `EC-L5` | ECDSA | 5 | secp521r1 |
| `ML-DSA-L5` | ML-DSA | 5 | ML-DSA-87 |
| `SLH-DSA-L5` | SLH-DSA | 5 | SLH-DSA-SHAKE-256s |

`RSA-L5` is defined as RSA-15360, but it is not part of the default sweep
because key generation is extremely slow and can dominate a complete run.
The older aliases `RSA`, `EC`, `ECC`, `ML-DSA`, and `SLH-DSA` still resolve to
their level-3 labels.

Signature payload sizes are `32`, `256`, `1024`, and `8192` bytes.

## TLS Benchmarks

`TlsHandshakeBenchmark` has two measured methods:
- `handshakeOnly`: opens a fresh loopback TLS connection and completes the TLS handshake.
- `handshakeAndMessage`: completes the handshake, sends random encrypted application data, and verifies the echo.

Default TLS profiles:

| Label | Provider | Key agreement level | Authentication level | Notes |
| --- | --- | ---: | ---: | --- |
| `RSA-L3` | JDK JSSE | 3 | 3 | RSA-7680 authentication, secp384r1 ECDHE |
| `ECC-L3` | JDK JSSE | 3 | 3 | ECDSA P-384 authentication, secp384r1 ECDHE |
| `ML-KEM-L3` | BCJSSE | 3 | 3 | RSA-7680 authentication, MLKEM768 key agreement |
| `X25519-ML-KEM-L3` | BCJSSE | 3 | 3 | RSA-7680 authentication, X25519MLKEM768 hybrid key agreement |
| `ECC-L5` | JDK JSSE | 5 | 5 | ECDSA P-521 authentication, secp521r1 ECDHE |
| `ML-KEM-L5` | BCJSSE | 5 | 3 | RSA-7680 authentication, MLKEM1024 key agreement |
| `P384-ML-KEM-L5` | BCJSSE | 5 | 3 | RSA-7680 authentication, SecP384r1MLKEM1024 hybrid key agreement |

The report includes key-agreement level, authentication level, and effective
level. Effective level is the lower of key-agreement and authentication. On the
current BCJSSE runtime, ML-KEM TLS handshakes work with RSA authentication but
fail with EC authentication, so the ML-KEM-L5 TLS profiles benchmark level-5 key
agreement with level-3 authentication and the report makes that visible.

`FrodoKEM` is listed as unsupported for TLS. Bouncy Castle 1.84 provides
FrodoKEM primitives, but BCJSSE does not expose a FrodoKEM TLS named group that
JSSE can negotiate.

## Profiling Data

The default `gc` profiler adds the most useful computational-cost columns:
- `gc.alloc.rate.norm`: bytes allocated per benchmark operation.
- `gc.alloc.rate`: allocation throughput in MB/sec.
- `gc.count`: garbage collections during the measured run.
- `gc.time`: total time spent in garbage collection during the measured run.

For deeper JVM profiling, add JFR:

```powershell
.\scripts\run-benchmarks.ps1 -Suite all -Profiler gc -Jfr
```

JFR is useful for method hot spots, allocation sites, GC events, and JVM event
timelines. When `-Jfr` is enabled, the runner uses JMH's JFR profiler and writes
small text summaries beside each `.jfr` recording:
- `*-jfr-summary.txt`
- `*-jfr-hot-methods.txt`
- `*-jfr-allocation-by-class.txt`
- `*-jfr-gc.txt`

The JMH `comp`, `pauses`, and `safepoints` profilers can also help explain
warmup behavior, pauses, and unstable tail measurements.

## Tests

Run the normal correctness suite with:

```powershell
mvn test
```

The tests are intentionally smaller than the benchmarks. Their job is to catch
broken wiring and invalid cryptographic round trips; the benchmark suite is the
main measurement surface.
