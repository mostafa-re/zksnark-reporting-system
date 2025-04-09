//! Lightweight wrapper around Arkworks’ Poseidon sponge.
//!
//! This module provides native (PoseidonHash) and R1CS
//! gadget (PoseidonHashVar) variants with an ergonomic API
//! that mirrors the high‑level sponge operations while keeping
//! the underlying parameters Circom‑compatible (4‑ary state,
//! 120‑bit security).

use ark_crypto_primitives::sponge::constraints::{AbsorbGadget, CryptographicSpongeVar};
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{PoseidonSponge, find_poseidon_ark_and_mds};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, poseidon::PoseidonConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystemRef;

/// Returns a Poseidon configuration
/// * identical to Circom’s `Poseidon(4)` when `F` is BN254’s scalar field;
/// * targeting 120‑bit security as recommended in https://eprint.iacr.org/2019/458.pdf.
#[inline]
pub fn get_poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    const FULL_ROUNDS: u64 = 8;
    const PARTIAL_ROUNDS: u64 = 60;
    const ALPHA: u64 = 5;
    const RATE: usize = 4; // t = rate + 1  ⇒ 5‑width state

    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        RATE,
        FULL_ROUNDS,
        PARTIAL_ROUNDS,
        0, // seed
    );

    PoseidonConfig::new(
        FULL_ROUNDS as usize,
        PARTIAL_ROUNDS as usize,
        ALPHA,
        mds,
        ark,
        RATE,
        1, // capacity
    )
}

/// Native‑field Poseidon hash helper.
#[derive(Clone)]
pub struct PoseidonHash<F: Absorb + PrimeField> {
    pub sponge: PoseidonSponge<F>,
}

impl<F: Absorb + PrimeField> PoseidonHash<F> {
    /// Construct a new sponge initialized with the canonical parameters.
    pub fn new() -> Self {
        Self {
            sponge: PoseidonSponge::new(&get_poseidon_config::<F>()),
        }
    }

    /// Absorb an iterator of field elements
    pub fn absorb_many<I, A>(&mut self, iter: I) -> ()
    where
        I: IntoIterator<Item = A>,
        A: Absorb,
    {
        for elem in iter {
            self.sponge.absorb(&elem);
        }
    }

    /// Backwards‑compat alias (kept to avoid breaking external code).
    #[deprecated(note = "Use `absorb_many` instead")]
    pub fn update_sponge<A: Absorb>(&mut self, v: Vec<A>) {
        self.absorb_many(v);
    }

    /// Squeeze `one` field element from the sponge.
    pub fn squeeze(&mut self) -> F {
        let squeezed_field_element: Vec<F> = self.sponge.squeeze_field_elements(1);
        squeezed_field_element[0]
    }
}

/// Constraint‑system variant of `PoseidonHash`.
pub struct PoseidonHashVar<F: Absorb + PrimeField> {
    sponge: PoseidonSpongeVar<F>,
}

impl<F: Absorb + PrimeField> PoseidonHashVar<F> {
    /// Create a fresh sponge gadget inside the given constraint system.
    pub fn new(cs: ConstraintSystemRef<F>) -> Self {
        Self {
            sponge: PoseidonSpongeVar::new(cs, &get_poseidon_config::<F>()),
        }
    }

    /// Convert a native sponge into its constraint‑system counterpart.
    /// Useful when part of the computation runs off‑circuit.
    pub fn from_poseidon_hash(cs: ConstraintSystemRef<F>, native: PoseidonHash<F>) -> Self {
        let state = native
            .sponge
            .state
            .iter()
            .map(|&f| FpVar::new_input(cs.clone(), || Ok(f)).unwrap())
            .collect();

        Self {
            sponge: PoseidonSpongeVar {
                cs,
                parameters: native.sponge.parameters.clone(),
                state,
                mode: native.sponge.mode.clone(),
            },
        }
    }

    /// Absorb field gadgets.
    pub fn absorb_many<I, A>(&mut self, iter: I) -> ()
    where
        I: IntoIterator<Item = A>,
        A: AbsorbGadget<F>,
    {
        for elem in iter {
            self.sponge.absorb(&elem).expect("Error while sponge absorbing");
        }
    }

    /// Squeeze `one` element.
    pub fn squeeze(&mut self) -> FpVar<F> {
        let squeezed_field_element: Vec<FpVar<F>> = self.sponge.squeeze_field_elements(1).unwrap();
        squeezed_field_element[0].clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Field;
    use ark_r1cs_std::R1CSVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn poseidon_native_vs_r1cs() {
        let mut native = PoseidonHash::<Fr>::new();

        let cs = ConstraintSystem::new_ref();
        let mut gadget = PoseidonHashVar::new(cs.clone());

        native.absorb_many([Fr::ONE, Fr::ONE]);
        let one_on_first_curve_var = FpVar::Constant(Fr::ONE);
        gadget.absorb_many([
            one_on_first_curve_var.clone(),
            one_on_first_curve_var.clone(),
        ]);

        assert_eq!(gadget.squeeze().value().unwrap(), native.squeeze());

        let mut new_gadget =
            PoseidonHashVar::from_poseidon_hash(ConstraintSystem::new_ref(), native.clone());

        assert_eq!(
            new_gadget.squeeze().value().unwrap(),
            gadget.squeeze().value().unwrap()
        );
    }
}
