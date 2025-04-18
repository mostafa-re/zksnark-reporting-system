//! Criterion benchmark: Groth16 prove & verify
//! 
//! Measures proof generation and verification time for circuits
//! hashing *n = 4 … 1024* elements (powers of two).

use std::path::Path;
use std::time::Duration;
use ark_bls12_377::{Bls12_377, Fr};
use ark_groth16::Groth16;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use zksnark_reporting_system::PoseidonCircuit;

// Benchmark configs
fn criterion_config() -> Criterion {
   Criterion::default()
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(120))
        .sample_size(100)
        .output_directory(Path::new("./docs/benchmark_data"))
}

/// Criterion entry‑point
fn groth16_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("groth16");
    let mut rng = StdRng::seed_from_u64(42);

    // n = 4 ... 1024  (powers of two)
    for exp in 2u32..=10 {
        let n = 1u32 << exp;

        // Trusted setup (once per n) -------------------------------
        let circuit = PoseidonCircuit::<Fr>::new(n);
        let (pk, vk) = Groth16::<Bls12_377>::setup(circuit, &mut rng).unwrap();
        let pvk = Groth16::<Bls12_377>::process_vk(&vk).unwrap();

        // Proving --------------------------------------------------
        group.bench_function(BenchmarkId::new("prove", n), |b| {
            b.iter(|| {
                let circuit = PoseidonCircuit::<Fr>::new(n);
                Groth16::<Bls12_377>::prove(&pk, circuit, &mut rng).unwrap();
            })
        });

        // pre‑build one proof so we can isolate verification timing
        let proof = {
            let circuit = PoseidonCircuit::<Fr>::new(n);
            Groth16::<Bls12_377>::prove(&pk, circuit, &mut rng).unwrap()
        };

        // Verification bench ---------------------------------------
        group.bench_function(BenchmarkId::new("verify", n), |b| {
            b.iter(|| {
                Groth16::<Bls12_377>::verify_with_processed_vk(&pvk, &[], &proof).unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!{
    name = benches;
    config = criterion_config();
    targets = groth16_bench
}
criterion_main!(benches);
