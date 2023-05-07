pub mod util;

pub mod econ_data;
pub mod constraints;
pub mod hash;
pub mod merkle;

use ark_r1cs_std::fields::fp::FpVar;

/// The bilinear pairing we will be using for our Groth16 proofs
pub type E = ark_bls12_381::Bls12_381;
/// A field element over BLS12-381. That is, the curve that our exercise uses for everything
pub type F = ark_bls12_381::Fr;

/// R1CS representation of a field element
pub type FV = FpVar<F>;