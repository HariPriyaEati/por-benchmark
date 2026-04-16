use sha2::{Sha256, Digest};
use sha3::Sha3_256;
use rand::Rng;
use std::time::{Instant, Duration};

// DATA GENERATION

fn generate_user_balances(n: usize) -> Vec<u64> {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| rng.gen_range(100..1_000_000)).collect()
}

// SCHEME 1: MERKLE TREE

fn hash_leaf(balance: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(balance.to_le_bytes());
    hasher.finalize().to_vec()
}

fn hash_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

fn build_merkle_tree(balances: &[u64]) -> Vec<u8> {
    let mut leaves: Vec<Vec<u8>> = balances.iter().map(|b| hash_leaf(*b)).collect();

    // Pad to power of 2
    while leaves.len().count_ones() != 1 {
        let last = leaves.last().unwrap().clone();
        leaves.push(last);
    }

    let mut current_level = leaves;
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next_level.push(chunk[0].clone());
            }
        }
        current_level = next_level;
    }
    current_level.into_iter().next().unwrap_or_default()
}

fn benchmark_merkle(balances: &[u64]) -> Duration {
    let start = Instant::now();
    let _root = build_merkle_tree(balances);
    start.elapsed()
}

// SCHEME 2: MERKLE SUM TREE (Maxwell PoR style)

#[derive(Clone)]
struct SumNode {
    hash: Vec<u8>,
    sum: u64,
}

fn hash_sum_leaf(balance: u64, index: usize) -> SumNode {
    let mut hasher = Sha256::new();
    hasher.update(balance.to_le_bytes());
    hasher.update(index.to_le_bytes());
    SumNode {
        hash: hasher.finalize().to_vec(),
        sum: balance,
    }
}

fn hash_sum_pair(left: &SumNode, right: &SumNode) -> SumNode {
    let mut hasher = Sha256::new();
    hasher.update(&left.hash);
    hasher.update(&right.hash);
    hasher.update(left.sum.to_le_bytes());
    hasher.update(right.sum.to_le_bytes());
    SumNode {
        hash: hasher.finalize().to_vec(),
        sum: left.sum + right.sum,
    }
}

fn build_merkle_sum_tree(balances: &[u64]) -> SumNode {
    let mut nodes: Vec<SumNode> = balances
        .iter()
        .enumerate()
        .map(|(i, &b)| hash_sum_leaf(b, i))
        .collect();

    while nodes.len().count_ones() != 1 {
        let last = nodes.last().unwrap().clone();
        nodes.push(last);
    }

    while nodes.len() > 1 {
        let mut next = Vec::new();
        for chunk in nodes.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_sum_pair(&chunk[0], &chunk[1]));
            } else {
                next.push(chunk[0].clone());
            }
        }
        nodes = next;
    }
    nodes.into_iter().next().unwrap()
}

fn benchmark_merkle_sum(balances: &[u64]) -> Duration {
    let start = Instant::now();
    let _root = build_merkle_sum_tree(balances);
    start.elapsed()
}

// SCHEME 3: zk-SNARK SIMULATION (Groth16 style)

fn simulate_field_multiply(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 * b as u128) % modulus as u128) as u64
}

fn simulate_ec_pairing(value: u64, index: usize) -> Vec<u8> {
    // Simulate elliptic curve scalar multiplication cost
    // BN254 curve operations - modeled as iterative field operations
    let modulus: u64 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    let modulus = modulus % u64::MAX; // fit in u64 for simulation

    let mut acc = value;
    // Simulate ~256 field multiplications per pairing (matches BN254 cost)
    for i in 0..256 {
        acc = simulate_field_multiply(acc, (index + i + 1) as u64, modulus.max(2));
        acc ^= value.rotate_left((i % 64) as u32);
    }

    let mut hasher = Sha256::new();
    hasher.update(acc.to_le_bytes());
    hasher.update(value.to_le_bytes());
    hasher.finalize().to_vec()
}

fn simulate_zk_snark_prove(balances: &[u64]) -> Vec<u8> {
    // Phase 1: Witness generation - one pairing per user
    let witnesses: Vec<Vec<u8>> = balances
        .iter()
        .enumerate()
        .map(|(i, &b)| simulate_ec_pairing(b, i))
        .collect();

    // Phase 2: Proof aggregation - simulate trusted setup application
    // Groth16 requires combining witnesses with proving key
    let mut proof_hasher = Sha256::new();
    for w in &witnesses {
        proof_hasher.update(w);
    }

    // Phase 3: Simulate linear combination (A, B, C proof elements)
    let intermediate = proof_hasher.finalize();
    let mut final_hasher = Sha256::new();
    final_hasher.update(&intermediate);
    final_hasher.update(b"groth16_proof_element_A");
    let a = final_hasher.finalize();

    let mut final_hasher2 = Sha256::new();
    final_hasher2.update(&a);
    final_hasher2.update(b"groth16_proof_element_B");
    final_hasher2.finalize().to_vec()
}

fn benchmark_zk_snark(balances: &[u64]) -> Duration {
    let start = Instant::now();
    let _proof = simulate_zk_snark_prove(balances);
    start.elapsed()
}

// SCHEME 4: zk-STARK SIMULATION (FRI protocol style)

fn fri_hash_layer(data: &[u64]) -> Vec<Vec<u8>> {
    data.iter().map(|&v| {
        let mut h = Sha3_256::new();
        h.update(v.to_le_bytes());
        h.finalize().to_vec()
    }).collect()
}

fn fri_fold_layer(hashes: &[Vec<u8>]) -> Vec<Vec<u8>> {
    hashes.chunks(2).map(|chunk| {
        let mut h = Sha3_256::new();
        h.update(&chunk[0]);
        if chunk.len() == 2 {
            h.update(&chunk[1]);
        }
        h.finalize().to_vec()
    }).collect()
}

fn simulate_zk_stark_prove(balances: &[u64]) -> Vec<u8> {
    // Step 1: Arithmetic Intermediate Representation (AIR)
    // Convert balances to field elements (simulate trace polynomial)
    let trace: Vec<u64> = balances.iter().enumerate().map(|(i, &b)| {
        b.wrapping_add(i as u64).wrapping_mul(31337)
    }).collect();

    // Step 2: FRI commitment - hash the trace into a Merkle-like structure
    let mut current_layer = fri_hash_layer(&trace);

    // FRI folding rounds - O(log n) rounds, each halving the domain
    // This is the core of the STARK proof size and generation time
    let mut commitment_hashes = Vec::new();
    while current_layer.len() > 1 {
        // Commit to current layer (simulate Merkle root of this FRI layer)
        let mut layer_hasher = Sha3_256::new();
        for h in &current_layer {
            layer_hasher.update(h);
        }
        commitment_hashes.push(layer_hasher.finalize().to_vec());

        // Fold the layer (FRI halving step)
        current_layer = fri_fold_layer(&current_layer);
    }

    // Step 3: Generate query proofs (simulate STARK query phase)
    // STARK makes O(log n) queries, each requiring O(log n) hashes
    let num_queries = (balances.len() as f64).log2() as usize * 4;
    let mut query_hasher = Sha3_256::new();
    for (i, ch) in commitment_hashes.iter().enumerate() {
        query_hasher.update(ch);
        query_hasher.update(i.to_le_bytes());
        // Simulate query decommitment paths
        for j in 0..num_queries {
            let mut path_hasher = Sha3_256::new();
            path_hasher.update(ch);
            path_hasher.update(j.to_le_bytes());
            let path = path_hasher.finalize();
            query_hasher.update(&path);
        }
    }

    query_hasher.finalize().to_vec()
}

fn benchmark_zk_stark(balances: &[u64]) -> Duration {
    let start = Instant::now();
    let _proof = simulate_zk_stark_prove(balances);
    start.elapsed()
}

// SCHEME 5: PLONKY2/3 SIMULATION

fn poseidon_hash_simulate(inputs: &[u64]) -> u64 {
    // Simulate Poseidon hash over Goldilocks field (p = 2^64 - 2^32 + 1)
    // Poseidon uses fewer constraints than SHA256 inside ZK circuits
    const GOLDILOCKS_MOD: u64 = 0xFFFFFFFF00000001;
    let mut state = [0u64; 3]; // Poseidon t=3 (rate=2, capacity=1)

    for (i, &input) in inputs.iter().enumerate() {
        state[i % 3] ^= input % GOLDILOCKS_MOD;
        // Simulate round function (S-box + MDS matrix)
        for r in 0..8 {
            // S-box: x^7 mod p (Poseidon uses x^7 for Goldilocks)
            state[0] = state[0].wrapping_mul(state[0]).wrapping_mul(state[0])
                               .wrapping_mul(state[0]).wrapping_mul(state[0])
                               .wrapping_mul(state[0]).wrapping_mul(state[0])
                               % GOLDILOCKS_MOD.max(1);
            // MDS matrix multiplication (simulated)
            let t = state[0].wrapping_add(state[1]).wrapping_add(state[2]);
            state[0] = t.wrapping_add(state[0]).wrapping_add(r as u64);
            state[1] = t.wrapping_add(state[1].wrapping_mul(2));
            state[2] = t.wrapping_add(state[2].wrapping_mul(4));
        }
    }
    state[0]
}

fn simulate_plonky2_prove(balances: &[u64]) -> Vec<u8> {
    // Step 1: Plonkish arithmetization
    // Convert PoR circuit to PLONK wires (a, b, c) with custom gates
    // Custom gate: RangeCheck (balance >= 0) + SumCheck
    let wire_a: Vec<u64> = balances.to_vec();
    let wire_b: Vec<u64> = balances.iter().scan(0u64, |acc, &b| {
        *acc = acc.wrapping_add(b);
        Some(*acc)
    }).collect();
    let wire_c: Vec<u64> = wire_a.iter().zip(wire_b.iter())
        .map(|(&a, &b)| poseidon_hash_simulate(&[a, b]))
        .collect();

    // Step 2: Compute Plonkish constraint polynomial commitments
    // Uses Goldilocks field arithmetic (faster than BN254)
    let commitment_a = poseidon_hash_simulate(&wire_a);
    let commitment_b = poseidon_hash_simulate(&wire_b);
    let commitment_c = poseidon_hash_simulate(&wire_c);

    // Step 3: FRI-based polynomial commitment (same as STARK but
    // over Goldilocks field - smaller field = faster arithmetic)
    let combined: Vec<u64> = wire_c.chunks(2).map(|ch| {
        poseidon_hash_simulate(ch)
    }).collect();

    let mut fri_layer = fri_hash_layer(&combined);
    let mut plonk_commitments = Vec::new();
    while fri_layer.len() > 1 {
        let mut h = Sha3_256::new();
        for node in &fri_layer {
            h.update(node);
        }
        plonk_commitments.push(h.finalize().to_vec());
        fri_layer = fri_fold_layer(&fri_layer);
    }

    // Step 4: Simulate recursive proof composition
    // This is Plonky2/3's key feature - recursion is cheap
    let mut recursive_hasher = Sha3_256::new();
    recursive_hasher.update(commitment_a.to_le_bytes());
    recursive_hasher.update(commitment_b.to_le_bytes());
    recursive_hasher.update(commitment_c.to_le_bytes());
    for c in &plonk_commitments {
        recursive_hasher.update(c);
    }
    // Simulate one level of recursive proof wrapping
    let inner_proof = recursive_hasher.finalize();
    let mut outer_hasher = Sha3_256::new();
    outer_hasher.update(&inner_proof);
    outer_hasher.update(b"plonky2_recursive_wrapper");
    outer_hasher.finalize().to_vec()
}

fn benchmark_plonky2(balances: &[u64]) -> Duration {
    let start = Instant::now();
    let _proof = simulate_plonky2_prove(balances);
    start.elapsed()
}

// BENCHMARKING ENGINE

fn run_benchmark(name: &str, n: usize, runs: usize,
    bench_fn: impl Fn(&[u64]) -> Duration) -> f64 {
    let mut total = Duration::ZERO;
    for _ in 0..runs {
        let balances = generate_user_balances(n);
        total += bench_fn(&balances);
    }
    let avg_ms = total.as_secs_f64() * 1000.0 / runs as f64;
    println!("  {:12} | n={:6} | avg over {} runs: {:.4} ms", name, n, runs, avg_ms);
    avg_ms
}

// HTML CHART GENERATION

fn generate_html_chart(
    data_sizes: &[usize],
    merkle_times: &[f64],
    merkle_sum_times: &[f64],
    snark_times: &[f64],
    stark_times: &[f64],
    plonky2_times: &[f64],
) -> String {
    let labels = data_sizes.iter().map(|n| format!("{}", n)).collect::<Vec<_>>().join(",");
    let merkle_data = merkle_times.iter().map(|v| format!("{:.4}", v)).collect::<Vec<_>>().join(",");
    let merkle_sum_data = merkle_sum_times.iter().map(|v| format!("{:.4}", v)).collect::<Vec<_>>().join(",");
    let snark_data = snark_times.iter().map(|v| format!("{:.4}", v)).collect::<Vec<_>>().join(",");
    let stark_data = stark_times.iter().map(|v| format!("{:.4}", v)).collect::<Vec<_>>().join(",");
    let plonky2_data = plonky2_times.iter().map(|v| format!("{:.4}", v)).collect::<Vec<_>>().join(",");

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Proof of Reserve - Performance Benchmark</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #f4f6f9;
    margin: 0;
    padding: 30px;
    color: #333;
  }}
  h1 {{
    text-align: center;
    color: #2c3e50;
    margin-bottom: 5px;
    font-size: 24px;
  }}
  .subtitle {{
    text-align: center;
    color: #666;
    margin-bottom: 30px;
    font-size: 14px;
  }}
  .chart-container {{
    background: white;
    border-radius: 12px;
    padding: 30px;
    box-shadow: 0 2px 15px rgba(0,0,0,0.1);
    max-width: 1000px;
    margin: 0 auto 30px auto;
  }}
  .table-container {{
    background: white;
    border-radius: 12px;
    padding: 30px;
    box-shadow: 0 2px 15px rgba(0,0,0,0.1);
    max-width: 1000px;
    margin: 0 auto;
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  th {{
    background: #2c3e50;
    color: white;
    padding: 10px 14px;
    text-align: center;
  }}
  td {{
    padding: 8px 14px;
    text-align: center;
    border-bottom: 1px solid #eee;
  }}
  tr:hover {{ background: #f8f9fa; }}
  .note {{
    text-align: center;
    color: #888;
    font-size: 12px;
    margin-top: 15px;
  }}
</style>
</head>
<body>
<h1>Proof of Reserve Scheme — Performance Comparison</h1>
<p class="subtitle">Benchmark: Proof Generation Time (ms) vs Number of Users | Each point averaged over 10 runs</p>

<div class="chart-container">
  <canvas id="perfChart" height="400"></canvas>
</div>

<div class="table-container">
  <h3 style="margin-top:0; color:#2c3e50;">Raw Benchmark Data (ms)</h3>
  <table>
    <thead>
      <tr>
        <th>Users (N)</th>
        <th>Merkle Tree</th>
        <th>Merkle Sum Tree</th>
        <th>zk-SNARK (Groth16)</th>
        <th>zk-STARK (FRI)</th>
        <th>Plonky2/3</th>
      </tr>
    </thead>
    <tbody id="tableBody"></tbody>
  </table>
  <p class="note">All times in milliseconds (ms). Lower is better. Each result is the average of 10 independent runs.</p>
</div>

<script>
const labels = [{labels}];
const merkleData = [{merkle_data}];
const merkleSumData = [{merkle_sum_data}];
const snarkData = [{snark_data}];
const starkData = [{stark_data}];
const plonky2Data = [{plonky2_data}];

// Populate table
const tbody = document.getElementById('tableBody');
labels.forEach((n, i) => {{
  const row = `<tr>
    <td><strong>${{n}}</strong></td>
    <td>${{merkleData[i].toFixed(4)}}</td>
    <td>${{merkleSumData[i].toFixed(4)}}</td>
    <td>${{snarkData[i].toFixed(4)}}</td>
    <td>${{starkData[i].toFixed(4)}}</td>
    <td>${{plonky2Data[i].toFixed(4)}}</td>
  </tr>`;
  tbody.innerHTML += row;
}});

// Draw chart
const ctx = document.getElementById('perfChart').getContext('2d');
new Chart(ctx, {{
  type: 'line',
  data: {{
    labels: labels,
    datasets: [
      {{
        label: 'Merkle Tree',
        data: merkleData,
        borderColor: '#3498db',
        backgroundColor: 'rgba(52,152,219,0.1)',
        borderWidth: 2.5,
        pointRadius: 5,
        tension: 0.3,
        fill: false
      }},
      {{
        label: 'Merkle Sum Tree',
        data: merkleSumData,
        borderColor: '#2ecc71',
        backgroundColor: 'rgba(46,204,113,0.1)',
        borderWidth: 2.5,
        pointRadius: 5,
        tension: 0.3,
        fill: false
      }},
      {{
        label: 'zk-SNARK (Groth16)',
        data: snarkData,
        borderColor: '#e74c3c',
        backgroundColor: 'rgba(231,76,60,0.1)',
        borderWidth: 2.5,
        pointRadius: 5,
        tension: 0.3,
        fill: false
      }},
      {{
        label: 'zk-STARK (FRI)',
        data: starkData,
        borderColor: '#f39c12',
        backgroundColor: 'rgba(243,156,18,0.1)',
        borderWidth: 2.5,
        pointRadius: 5,
        tension: 0.3,
        fill: false
      }},
      {{
        label: 'Plonky2/3',
        data: plonky2Data,
        borderColor: '#9b59b6',
        backgroundColor: 'rgba(155,89,182,0.1)',
        borderWidth: 2.5,
        pointRadius: 5,
        tension: 0.3,
        fill: false
      }}
    ]
  }},
  options: {{
    responsive: true,
    interaction: {{ mode: 'index', intersect: false }},
    plugins: {{
      legend: {{
        position: 'top',
        labels: {{ font: {{ size: 13 }}, padding: 20 }}
      }},
      tooltip: {{
        callbacks: {{
          label: ctx => ` ${{ctx.dataset.label}}: ${{ctx.parsed.y.toFixed(4)}} ms`
        }}
      }}
    }},
    scales: {{
      x: {{
        title: {{
          display: true,
          text: 'Number of Users (N)',
          font: {{ size: 13, weight: 'bold' }}
        }},
        grid: {{ color: 'rgba(0,0,0,0.05)' }}
      }},
      y: {{
        title: {{
          display: true,
          text: 'Proof Generation Time (ms)',
          font: {{ size: 13, weight: 'bold' }}
        }},
        grid: {{ color: 'rgba(0,0,0,0.05)' }},
        ticks: {{
          callback: val => val.toFixed(3) + ' ms'
        }}
      }}
    }}
  }}
}});
</script>
</body>
</html>"#,
        labels = labels,
        merkle_data = merkle_data,
        merkle_sum_data = merkle_sum_data,
        snark_data = snark_data,
        stark_data = stark_data,
        plonky2_data = plonky2_data,
    )
}

// MAIN

fn main() {
    let data_sizes: Vec<usize> = (1..=10).map(|i| i * 1000).collect();
    let runs = 10;

    println!("================================================");
    println!(" Proof of Reserve - Performance Benchmark");
    println!(" Schemes: Merkle Tree | Merkle Sum Tree |");
    println!("          zk-SNARK | zk-STARK | Plonky2/3");
    println!(" Data sizes: 1000 to 10000 (step 1000)");
    println!(" Runs per data point: {}", runs);
    println!("================================================\n");

    let mut merkle_times = Vec::new();
    let mut merkle_sum_times = Vec::new();
    let mut snark_times = Vec::new();
    let mut stark_times = Vec::new();
    let mut plonky2_times = Vec::new();

    for &n in &data_sizes {
        println!("--- n = {} users ---", n);
        merkle_times.push(run_benchmark("Merkle Tree", n, runs, |b| benchmark_merkle(b)));
        merkle_sum_times.push(run_benchmark("Merkle Sum", n, runs, |b| benchmark_merkle_sum(b)));
        snark_times.push(run_benchmark("zk-SNARK", n, runs, |b| benchmark_zk_snark(b)));
        stark_times.push(run_benchmark("zk-STARK", n, runs, |b| benchmark_zk_stark(b)));
        plonky2_times.push(run_benchmark("Plonky2/3", n, runs, |b| benchmark_plonky2(b)));
        println!();
    }

    println!("================================================");
    println!(" Generating HTML report...");

    let html = generate_html_chart(
        &data_sizes,
        &merkle_times,
        &merkle_sum_times,
        &snark_times,
        &stark_times,
        &plonky2_times,
    );

    std::fs::write("por_benchmark_results.html", &html).expect("Failed to write HTML");
    println!(" Report saved: por_benchmark_results.html");
    println!(" Open this file in any browser to view the chart.");
    println!("================================================");
}
