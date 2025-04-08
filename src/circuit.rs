#![deny(
    trivial_casts,
    trivial_numeric_casts,
    variant_size_differences,
    stable_features,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    unsafe_code
)]

use std::marker::PhantomData;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
// For randomness (during paramgen and proof generation)
use ark_std::rand::{SeedableRng};

// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-377 pairing-friendly elliptic curve.
use ark_bls12_377::{Fr};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_ff::{PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
// We'll use these interfaces to construct our circuit.
use ark_relations::{
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::prelude::StdRng;
use crate::hash::get_poseidon_config;

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
pub struct PoseidonCircuit<F: PrimeField> {
    n: u32,
    _field: PhantomData<F>,
}

impl<F: PrimeField> PoseidonCircuit<F> {
    pub fn new(n: u32) -> Self {
        Self {
            n,
            _field: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for PoseidonCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut rng = StdRng::seed_from_u64(42);

        // Generate random vector of size N
        let random_vector: Vec<F> = (0..self.n).map(|_| F::rand(&mut rng)).collect();

        // Allocate the random vector as FpVar
        let input_vars: Vec<FpVar<F>> = random_vector
            .into_iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(x)))
            .collect::<Result<Vec<FpVar<F>>, SynthesisError>>()?;

        // Initialize Poseidon Sponge
        let mut poseidon_var = PoseidonSpongeVar::new(cs.clone(), &get_poseidon_config::<F>());

        // Absorb the input variables
        poseidon_var.absorb(&input_vars)?;

        // Output the hash
        let _output = poseidon_var.squeeze_field_elements(1)?[0].clone();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as ScalarField;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_poseidon_circuit() {
        let cs = ConstraintSystem::<ScalarField>::new_ref();
        let circuit = PoseidonCircuit::<ScalarField>::new(10);

        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_poseidon_groth16() {
        use ark_groth16::Groth16;
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::SeedableRng;
        use ark_std::time::{Duration, Instant};
        use ark_bls12_377::Bls12_377;
        use std::marker::PhantomData;

        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let mut rng = StdRng::seed_from_u64(0u64);

        println!("Creating parameters...");

        // Define your circuit parameters
        let n = 128; // Set the value of `n` as needed for your circuit

        // Create parameters for our circuit
        let (pk, vk) = {
            let c = PoseidonCircuit::<Fr> {
                n,
                _field: PhantomData,
            };

            Groth16::<Bls12_377>::setup(c, &mut rng).unwrap()
        };

        // Prepare the verification key (for proof verification)
        let pvk = Groth16::<Bls12_377>::process_vk(&vk).unwrap();

        println!("Creating proofs...");

        // Let's benchmark stuff!
        const SAMPLES: u32 = 1;
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        for _ in 0..SAMPLES {
            let start = Instant::now();

            // Create a new circuit instance for each proof
            let c = PoseidonCircuit::<Fr> {
                n,
                _field: PhantomData,
            };

            // Create a groth16 proof with our parameters.
            let proof = Groth16::<Bls12_377>::prove(&pk, c, &mut rng).unwrap();
            total_proving += start.elapsed();

            let start = Instant::now();

            // Check the proof - assuming no public inputs for now
            assert!(
                Groth16::<Bls12_377>::verify_with_processed_vk(&pvk, &[], &proof).unwrap()
            );

            total_verifying += start.elapsed();
        }

        let proving_avg = total_proving / SAMPLES;
        let proving_avg = proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

        let verifying_avg = total_verifying / SAMPLES;
        let verifying_avg = verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);

        println!("Average proving time: {:?} seconds", proving_avg);
        println!("Average verifying time: {:?} seconds", verifying_avg);
    }
}
