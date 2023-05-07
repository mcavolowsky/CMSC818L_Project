use crate::{
    econ_data::DataVar,
    hash::{
        LeafHash, 
        LeafHashParamsVar, 
        TwoToOneHash, 
        //TwoToOneHashParamsVar,
    },
    F, FV,
};

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, uint8::UInt8};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

/// Our ZK circuit. This is what we will create and pass to the Groth16 prover in order to do a ZK
/// proof of possession
#[derive(Clone)]
pub struct AnalysisCircuit {
    // These are constants that will be embedded into the circuit. They describe how the hash
    // function works. Don't worry about this.
    pub leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,

    // Public inputs to the circuit
    /// The leaf in that tree. In our case, the leaf is also a commitment to the data we're showing
    pub commitment: Vec<u8>,
    // Private inputs (aka "witnesses") for the circuit
    /// The amount the data was purchased for
    pub data_purchase_price: F,
    /// The private randomness used to commit to the data
    pub data_com_rand: F,
}

/// generate_constraints is where the circuit functionality is defined. It doesn't return any
/// value. Rather, it takes in a constraint system, and adds a bunch of constraints to that system
/// (implicitly or explicitly). A proof is valid if and only if the final constraint system is
/// satisfied.
impl ConstraintSynthesizer<F> for AnalysisCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // First, allocate the public parameters as constants
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        //let two_to_one_crh_params =
        //    TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        //
        // Next, allocate the public inputs. Note the ns! macros are just to create name spaces for
        // our constraints. It doesn't matter what this does, and it doesn't matter what string you
        // give it.
        //

        // Card commitment. This is also the leaf in our tree.
        let claimed_data_com_var = UInt8::new_witness_vec(ns!(cs, "data com"), &self.commitment)?;

        //
        // Now we witness our private inputs
        //

        // The amount the data was purchase for
        let data_purchase_price =
            FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price))?;
        // Commitment randomness
        let com_rand_var = FV::new_witness(ns!(cs, "data com_rand"), || Ok(&self.data_com_rand))?;

        //
        // Ok everything has been inputted. Now we do the logic of the circuit.
        //

        // Put the pieces of our data together into a CardVar
        let data_var = DataVar {
            amount: data_purchase_price,
        };

        // CHECK #1: Card opening.
        // We "open" the data commitment here. Concretely, we compute the commitment of our
        // data_var using com_rand_var. We then assert that this value is equal to the publicly
        // known commitment.

        // Generate a commitment to the message
        let computed_data_comm_var = data_var.commit(&leaf_crh_params, &com_rand_var);
        // Verify the commitment
        claimed_data_com_var.enforce_equal(&computed_data_comm_var.unwrap())?;

        // other code goes here
        

        // All done with the checks
        Ok(())
    }
}

//
// TESTS
//

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::{get_test_data, get_test_leaf};

    use ark_bls12_381::Fr as F;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::RngCore;

    // Sets up a legitimate possession circuit
    fn setup(mut rng: impl RngCore) -> AnalysisCircuit {
        // Let's set up an RNG for use within tests. Note that this is NOT safe for any production
        // use

        // First, let's sample the public parameters for the hash functions
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // Also imagine we possess the data that appears at index 7 in the tree
        let our_idx = 7;
        let (data, data_com_rand) = get_test_data(our_idx);

        //
        // Proof construction
        //

        // We'll reveal and prove membership of the 8th leaf in the tree, i.e., the data com we
        // just created.
        let idx_to_prove = our_idx;
        let claimed_leaf = get_test_leaf(&leaf_crh_params, idx_to_prove);

        // We have everything we need. Build the circuit
        AnalysisCircuit {
            // Constants for hashing
            leaf_crh_params,
            two_to_one_crh_params,

            // Public inputs
            commitment: claimed_leaf.to_vec(),

            // Private inputs
            data_purchase_price: data.purchase_price,
            data_com_rand,
        }
    }

    // Correctness test: Make a fresh constraint system and run the circuit.
    #[test]
    fn data_correctness() {
        let mut rng = ark_std::test_rng();
        let circuit = setup(&mut rng);

        // Run the circuit on a fresh constraint system
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        // The constraints should be satisfied. That is, the valid circuit should verify.
        assert!(
            cs.is_satisfied().unwrap(),
            "circuit correctness check failed; a valid circuit did not succeed"
        );
    }

    // Card soundness test: Modify the circuit to have a random amount. This should make the
    // proof fail, since the computed commitment up longer matches up with the claimed commitment.
    #[test]
    fn data_soundness() {
        // Make a new circuit and maul its purchase price
        let mut rng = ark_std::test_rng();
        let mut bad_data_circuit = setup(&mut rng);
        bad_data_circuit.data_purchase_price = F::rand(&mut rng);

        // Run the circuit on a fresh constraint system
        let cs = ConstraintSystem::new_ref();
        bad_data_circuit.generate_constraints(cs.clone()).unwrap();

        // At least one constraint should not be satisfied. That is, the invalid circuit should
        // fail to verify.
        assert!(
            !cs.is_satisfied().unwrap(),
            "circuit should not be satisfied after changing the data purchase price"
        );
    }
}
