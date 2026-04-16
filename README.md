# por-benchmark
Proof of Reserve Performance Benchmark — M.S. Thesis, Hari Priya Eati, YSU 2026

# Proof of Reserve — Performance Benchmark

**Author:** Hari Priya Eati  
**Thesis:** A Comparative Study of Proof of Reserve Schemes 
with Post-Quantum Security Analysis  
**University:** Youngstown State University, 2026  
**Advisor:** Dr. Feng George Yu  

## Overview
Benchmarks five Proof of Reserve proof generation schemes in Rust across user counts from 1,000 to 10,000.
Executed on Ohio Supercomputer Center (OSC) Ascend Cluster.

## How to Run
```bash
cargo run --release
```

## Results
Plonky2/3 is ~50% faster than zk-STARK and twice as fast as zk-SNARK at 10,000 users while satisfying all four 
PoR completeness criteria.
