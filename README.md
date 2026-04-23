# por-benchmark

**Proof of Reserve Performance Benchmark — M.S. Thesis, Hari Priya Eati, YSU 2026**

## About

This repository contains the Rust implementation and benchmark results for the thesis:

**"A Comparative Study of Proof of Reserve Schemes with Post-Quantum Security Analysis"**

| | |
|---|---|
| **Author** | Hari Priya Eati |
| **Advisor** | Dr. Feng George Yu |
| **University** | Youngstown State University, 2026 |
| **Target Publication** | IEEE Blockchain 2026 / ACM BSCI 2026 |

## Overview

Benchmarks five Proof of Reserve proof generation schemes in Rust across user counts from 1,000 to 10,000 (step 1,000). Each data point is the average of 10 independent runs. Executed on the Ohio Supercomputer Center (OSC) Ascend Cluster.

## Schemes Compared

| Scheme | Approach | Trusted Setup | Post-Quantum | Implementation |
|---|---|---|---|---|
| Merkle Tree | SHA-256 hash tree | No | Yes | Native Rust (sha2) |
| Merkle Sum Tree | SHA-256 sum tree (Maxwell PoR style) | No | Yes | Native Rust (sha2) |
| zk-SNARK (Groth16) | BN254 EC pairing simulation | Yes | No | Simulated (field arithmetic) |
| zk-STARK (FRI) | FRI folding + AIR trace (SHA3) | No | Yes | Simulated (sha3 + FRI rounds) |
| Plonky2/3 | Poseidon hash + Goldilocks field + recursive proofs | No | Yes | Simulated (Poseidon over GF(2^64 - 2^32 + 1)) |

## Key Finding

Plonky2/3 is the first existing ZKP implementation satisfying all four PoR completeness criteria simultaneously:

- **Transparent setup** — no trusted setup ceremony required
- **Liability completeness** — all user accounts included in the commitment
- **Balance privacy** — individual balances not revealed
- **Post-quantum resistance** — no elliptic curve pairings; FRI-based

At 10,000 users, Plonky2/3 is ~30% faster than zk-STARK and ~2x faster than zk-SNARK (Groth16).

## Repository Structure

```
por-benchmark/
├── src/
│   ├── main.rs                          # Rust benchmark implementation
│   └── results/
│       └── por_benchmark_results.html   # Interactive chart + raw benchmark data
├── cargo.toml                           # Rust dependencies
├── .gitignore
└── README.md
```

## Dependencies

```toml
sha2 = "0.10"       # SHA-256 for Merkle Tree and Merkle Sum Tree
sha3 = "0.10"       # SHA3-256 for zk-STARK FRI simulation
rand = "0.8"        # Random user balance generation
serde = "1.0"       # Serialization
serde_json = "1.0"  # JSON output
```

## How to Run

```bash
cargo run --release
```

This will benchmark all five schemes across user counts 1,000 to 10,000 and generate `por_benchmark_results.html` in the project root.

## Results

See [`src/results/por_benchmark_results.html`](src/results/por_benchmark_results.html) for the full interactive benchmark chart and raw data table.

**Raw Data Summary (ms, averaged over 10 runs):**

| Users (N) | Merkle Tree | Merkle Sum Tree | zk-SNARK (Groth16) | zk-STARK (FRI) | Plonky2/3 |
|---|---|---|---|---|---|
| 1,000 | 0.2109 | 0.2104 | 1.4635 | 1.2147 | 0.7723 |
| 2,000 | 0.4461 | 0.4493 | 2.9447 | 2.2797 | 1.5356 |
| 3,000 | 0.8008 | 0.8892 | 4.4641 | 3.3596 | 2.2980 |
| 4,000 | 0.9219 | 0.9735 | 5.9646 | 4.3612 | 3.0499 |
| 5,000 | 1.5331 | 1.7666 | 7.4751 | 5.4369 | 3.8148 |
| 6,000 | 1.7562 | 1.8507 | 8.9729 | 6.4510 | 4.5857 |
| 7,000 | 1.6309 | 1.7423 | 10.5055 | 7.4939 | 5.3473 |
| 8,000 | 1.7007 | 1.7751 | 12.0175 | 8.4989 | 6.1263 |
| 9,000 | 3.4161 | 3.5917 | 13.5398 | 9.6099 | 6.8924 |
| 10,000 | 3.1027 | 3.5963 | 15.0574 | 10.6574 | 7.6455 |

*All times in milliseconds (ms). Lower is better.*

## Implementation Notes

- **zk-SNARK simulation** models BN254 elliptic curve scalar multiplication cost using iterative field arithmetic (~256 field multiplications per user, matching BN254 pairing cost)
- **zk-STARK simulation** implements full FRI folding rounds over a SHA3-based AIR trace with O(log n) query decommitment paths
- **Plonky2/3 simulation** implements the Poseidon hash function over the Goldilocks field (p = 2^64 - 2^32 + 1) with x^7 S-box and MDS matrix simulation, plus recursive proof aggregation
- All simulations are calibrated to match the asymptotic complexity of their respective cryptographic protocols
