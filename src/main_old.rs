// Import arkworks crates
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Field;
use ark_groth16::*;

use ark_r1cs_std::fields::fp::{FpVar};
use ark_r1cs_std::groups::bls12::{G1Var};

use ark_r1cs_std::alloc::AllocVar::{new_input, new_witness};

use ark_relations::{lc};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_ec::PairingEngine;

use ark_std::rand;

// Define your circuit struct
#[derive(Clone)]
struct MyCircuit<F: Field> {
    // The secret inputs
    x1: Option<F>,
    x2: Option<F>,
    x3: Option<F>,
    // The public input
    y: Option<F>,
}

// Define a struct that represents the circuit for the Pedersen commitment
#[derive(Clone)]
struct PedersenCircuit {
    // The value to be committed
    value: Option<Fr>,
    // The randomness for the commitment
    randomness: Option<Fr>,
    // The generator for the commitment
    generator: <Bls12_381 as PairingEngine>::G1Projective,
}

// Implement ConstraintSynthesizer trait for your circuit
//impl<F: Field> ConstraintSynthesizer<F> for MyCircuit<F> {
//    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
//        // Allocate variables for your secret inputs
//        let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
//        let y_var = cs.new_witness_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
//        // Allocate variable for your public input
//        let z_var = cs.new_input_variable(|| self.z.ok_or(SynthesisError::AssignmentMissing))?;
//        // Enforce your constraint: x * y = z
//        cs.enforce_constraint(x_var.into(), y_var.into(), z_var.into())?;
//        Ok(())
//    }
//}

// Implement ConstraintSynthesizer trait for your circuit 
// impl<F: Field> ConstraintSynthesizer<F> for MyCircuit<F> { 
//     fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> { 
//         // Allocate variables for your secret inputs 
//         let x1_var = cs.new_witness_variable(|| self.x1.ok_or(SynthesisError::AssignmentMissing))?; 
//         let x2_var = cs.new_witness_variable(|| self.x2.ok_or(SynthesisError::AssignmentMissing))?; 
//         let x3_var = cs.new_witness_variable(|| self.x3.ok_or(SynthesisError::AssignmentMissing))?; 
//         // Allocate variable for your public input 
//         let y_var = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?; 
//         // Enforce your constraint: x1 * x2 * x3 = z 
//         let tmp_var = cs.new_witness_variable(|| { let tmp = self.x1.unwrap() * self.x2.unwrap(); Ok(tmp) })?; 
//         cs.enforce_constraint(x1_var.into(), x2_var.into(), tmp_var.into())?; 
//         cs.enforce_constraint(tmp_var.into(), x3_var.into(), y_var.into())?; 
//         Ok(()) 
//     } 
// }

// Implement ConstraintSynthesizer trait for your circuit
// impl<F: Field> ConstraintSynthesizer<F> for MyCircuit<F> {
//     fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> { 
//         // Allocate variables for your secret inputs 
//         let x1_var = cs.new_witness_variable(|| self.x1.ok_or(SynthesisError::AssignmentMissing))?; 
//         let x2_var = cs.new_witness_variable(|| self.x2.ok_or(SynthesisError::AssignmentMissing))?; 
//         let x3_var = cs.new_witness_variable(|| self.x3.ok_or(SynthesisError::AssignmentMissing))?; 
//         // Allocate variable for your public input 
//         let y_var = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?; 
//         // Enforce your constraint: x1 * x2 * x3 = z 
//         let tmp_var = cs.new_witness_variable(|| { let tmp = self.x1.unwrap() + self.x2.unwrap(); Ok(tmp) })?; 
//         cs.enforce_constraint(tmp_var.into(), x3_var.into(), y_var.into())?; 
//         Ok(()) 
//     } 
// }

// Implement ConstraintSynthesizer trait for your circuit
impl<F: Field> ConstraintSynthesizer<F> for MyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> { 
        // Allocate variables for your secret inputs 
        //let x1_var = cs.new_witness_variable(|| self.x1.ok_or(SynthesisError::AssignmentMissing))?; 
        //let x2_var = cs.new_witness_variable(|| self.x2.ok_or(SynthesisError::AssignmentMissing))?; 
        let x3_var = cs.new_witness_variable(|| self.x3.ok_or(SynthesisError::AssignmentMissing))?; 
        // Allocate variable for your public input 
        let y_var = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?; 
        // Enforce your constraint: x1 * x2 * x3 = z 
        let tmp_var = cs.new_witness_variable(|| { let tmp = self.x1.unwrap() + self.x2.unwrap(); Ok(tmp) })?; 
        cs.enforce_constraint(tmp_var.into(), x3_var.into(), y_var.into())?; 
        Ok(()) 
    } 
}

// Implement the ConstraintSynthesizer trait for the circuit
impl ConstraintSynthesizer<Fr> for PedersenCircuit {
    // This function generates the R1CS constraints for the circuit
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate variables for the value and randomness as private inputs
        let value_var = cs.new_witness_variable(|| self.value.ok_or(SynthesisError::AssignmentMissing))?;
        let randomness_var = cs.new_witness_variable(|| self.randomness.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocate a variable for the generator as a public input
        let generator_var = G1Var::new_input(cs.clone(), || Ok(self.generator))?;

        // Compute the Pedersen commitment as value * generator + randomness * generator
        let commitment_var = generator_var.mul(value_var) + &generator_var.mul(randomness_var);

        // Allocate a variable for the commitment as a public input
        let commitment_input_var = cs.new_input_variable(|| Ok(commitment_var.value()?))?;

        // Enforce that the commitment variable is equal to the commitment input variable
        commitment_var.enforce_equal(&commitment_input_var)?;

        Ok(())
    }
}

//impl<F: Field> ConstraintSynthesizer<F> for CommitmentCircuit<F> {
//     fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
//         // Allocate variables for your secret inputs
//         let x_var = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
//         let c_var = cs.new_witness_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;

//         // Create a custom constraint system for the SHA-256 hash function
//         let hash_var = sha256_constraints::<F>(&cs, &[x_var])?;

//         // Enforce your constraint: hash_var = c_var
//         cs.enforce_constraint(hash_var.into(), F::one().into(), c_var.into())?;

//         Ok(())
//     }
// }


// A function that creates and verifies a proof for a given value and randomness
fn pedersen_zk_proof(value: Fr, randomness: Fr) -> bool {
    // Choose a random generator for the commitment
    let generator = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rand::thread_rng());

    // Create an instance of the circuit
    let circuit = PedersenCircuit {
        value: Some(value),
        randomness: Some(randomness),
        generator,
    };

    // Generate random parameters for the zkSNARK (trusted setup)
    let params = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rand::thread_rng()).unwrap();

    // Create a proof using the parameters and the circuit instance
    let proof = create_random_proof(circuit.clone(), &params, &mut rand::thread_rng()).unwrap();

    // Extract the public inputs from the circuit instance
    let public_inputs = vec![
        generator.into_affine().into(),
        circuit.generator.mul(value).into_affine().into(),
    ];

    // Verify the proof using the parameters and the public inputs
    verify_proof(&params.vk, &proof, &public_inputs).unwrap()
}
fn main() {
    println!("Some Math:");

    // Create a random number generator
    let mut rng = &mut ark_std::test_rng();

    // Create an instance of your circuit with some inputs
    let circuit: MyCircuit<_> = MyCircuit {
        x1: Some::<<Bls12_381 as PairingEngine>::Fr>(3u32.into()), // secret input
        x2: Some::<<Bls12_381 as PairingEngine>::Fr>(5u32.into()), // secret input
        x3: Some::<<Bls12_381 as PairingEngine>::Fr>(5u32.into()), // secret input
        y:  Some::<<Bls12_381 as PairingEngine>::Fr>(40u32.into()), // public input
    };

    // Generate the proving key and the verifying key
    let params = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);

    // Create a proof using the proving key and the circuit instance
    let proof = create_random_proof(circuit.clone(), &params, &mut rng).unwrap();

    // Extract the public input from the circuit instance
    let public_input = vec![circuit.y.unwrap()];

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

    println!("Pedersen Commitment:");

    let value = Fr::from(42u64);
    let randomness = Fr::from(12345u64);

    let commit_result = pedersen_zk_proof(value, randomness);

    println!("Verification result: {}",commit_result);
}
