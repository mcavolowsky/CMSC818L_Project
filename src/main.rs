// Import arkworks crates
use ark_bls12_381::Bls12_381;
use ark_ff::Field;
use ark_groth16::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::Rng;
use ark_ec::PairingEngine;

// Define your circuit struct
#[derive(Clone)]
struct MyCircuit<F: Field> {
    // The secret inputs
    x: Option<F>,
    y: Option<F>,
    // The public input
    z: Option<F>,
}

// Implement ConstraintSynthesizer trait for your circuit
impl<F: Field> ConstraintSynthesizer<F> for MyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate variables for your secret inputs
        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y_var = cs.new_witness_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
        // Allocate variable for your public input
        let z_var = cs.new_input_variable(|| self.z.ok_or(SynthesisError::AssignmentMissing))?;
        // Enforce your constraint: x * y = z
        cs.enforce_constraint(x_var.into(), y_var.into(), z_var.into())?;
        Ok(())
    }
}

fn main() {
    // Create a random number generator
    let mut rng = &mut ark_std::test_rng();

    // Create an instance of your circuit with some inputs
    let circuit: MyCircuit<_> = MyCircuit {
        x: Some::<<Bls12_381 as PairingEngine>::Fr>(3u32.into()), // secret input
        y: Some::<<Bls12_381 as PairingEngine>::Fr>(5u32.into()), // secret input
        z: Some::<<Bls12_381 as PairingEngine>::Fr>(15u32.into()), // public input
    };

    // Generate the proving key and the verifying key
    let params = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);

    // Create a proof using the proving key and the circuit instance
    let proof = create_random_proof(circuit.clone(), &params, &mut rng).unwrap();

    // Extract the public input from the circuit instance
    let public_input = vec![circuit.z.unwrap()];

    // Verify the proof using the verifying key and the public input
    let result = verify_proof(&pvk, &proof, &public_input).unwrap();

    // Print the verification result
    println!("Verification result: {}", result);

    // Change the public input to a different value
    let public_input = vec![12345u32.into()];

    // Verify the proof using the verifying key and the new public input
    let result = verify_proof(&pvk, &proof, &public_input).unwrap();

    // Print the verification result
    println!("Verification result: {}", result);
}
