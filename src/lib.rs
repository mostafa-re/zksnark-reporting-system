//! Crate root for the zk‑SNARK powered privacy‑preserving
//! reporting system.
//!
//! # Modules
//! * [`hash`]    – Poseidon sponge configuration + helpers
//! * [`circuit`] – Constraint system used in Groth16 benches
//!
//! The public surface of this crate is intentionally small:
//! only items that are useful for down‑stream consumers are
//! re‑exported. Everything else stays `pub(crate)` to make the
//! API easier to navigate.

pub mod circuit;
pub mod hash;

pub use circuit::PoseidonCircuit;
