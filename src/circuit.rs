
//! Constraint system used for the system.
//!
//! The circuit simply hashes an n‑length vector of random field
//! elements with Poseidon. It is intentionally minimal – its role
//! is to stress Groth16 proving/verification so we can observe the
//! asymptotic behavior as `n` grows.

#![deny(
    trivial_casts,
    trivial_numeric_casts,
    variant_size_differences,
    unstable_features,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    unsafe_code,
)]

use std::marker::PhantomData;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{prelude::StdRng, SeedableRng};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use crate::hash::get_poseidon_config;

/// Circuit hashing `n` random field elements.
#[derive(Clone)]
pub struct PoseidonCircuit<F: PrimeField> {
    n: u32,
    _field: PhantomData<F>,
}

impl<F: PrimeField> PoseidonCircuit<F> {
    /// Create a new circuit hashing `n` elements.
    pub fn new(n: u32) -> Self { Self { n, _field: PhantomData } }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for PoseidonCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Deterministic RNG to make the circuit re‑producible across runs.
        let mut rng = StdRng::seed_from_u64(42);

        let random_inputs: Vec<F> = (0..self.n).map(|_| F::rand(&mut rng)).collect();

        // Witness allocation --------------------------------------------------
        let witnesses: Vec<FpVar<F>> = random_inputs
            .into_iter()
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<Vec<FpVar<F>>, SynthesisError>>()?;

        // Poseidon hash gadget ------------------------------------------------
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &get_poseidon_config::<F>());
        sponge.absorb(&witnesses)?;
        let _hash = sponge.squeeze_field_elements(1)?[0].clone();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn circuit_satisfies() {
        let cs = ConstraintSystem::new_ref();
        PoseidonCircuit::<Fr>::new(10).generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
