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
use core::cmp::Ordering;

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
    pub com_jan: Vec<u8>,
    pub com_feb: Vec<u8>,
    pub com_mar: Vec<u8>,

    pub com_apr: Vec<u8>,
    pub com_may: Vec<u8>,
    pub com_jun: Vec<u8>,

    pub com_jul: Vec<u8>,
    pub com_aug: Vec<u8>,
    pub com_sep: Vec<u8>,

    pub com_oct: Vec<u8>,
    pub com_nov: Vec<u8>,
    pub com_dec: Vec<u8>,

    // Private inputs (aka "witnesses") for the circuit
    /// The amount the data was purchased for
    pub data_purchase_price_jan: F,
    pub data_purchase_price_feb: F,
    pub data_purchase_price_mar: F,
    
    pub data_purchase_price_apr: F,
    pub data_purchase_price_may: F,
    pub data_purchase_price_jun: F,
    
    pub data_purchase_price_jul: F,
    pub data_purchase_price_aug: F,
    pub data_purchase_price_sep: F,
    
    pub data_purchase_price_oct: F,
    pub data_purchase_price_nov: F,
    pub data_purchase_price_dec: F,
    
    /// The private randomness used to commit to the data
    pub data_com_rand_jan: F,
    pub data_com_rand_feb: F,
    pub data_com_rand_mar: F,

    pub data_com_rand_apr: F,
    pub data_com_rand_may: F,
    pub data_com_rand_jun: F,

    pub data_com_rand_jul: F,
    pub data_com_rand_aug: F,
    pub data_com_rand_sep: F,

    pub data_com_rand_oct: F,
    pub data_com_rand_nov: F,
    pub data_com_rand_dec: F,

    // The analysis output 
    pub output_purchase_price_avg: F,

    // The analysis bounds
    pub bounds_purchase_price_min: F,
    pub bounds_purchase_price_max: F,
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
        let claimed_data_com_var_jan = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_jan)?;
        let claimed_data_com_var_feb = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_feb)?;
        let claimed_data_com_var_mar = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_mar)?;

        let claimed_data_com_var_apr = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_apr)?;
        let claimed_data_com_var_may = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_may)?;
        let claimed_data_com_var_jun = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_jun)?;

        let claimed_data_com_var_jul = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_jul)?;
        let claimed_data_com_var_aug = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_aug)?;
        let claimed_data_com_var_sep = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_sep)?;

        let claimed_data_com_var_oct = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_oct)?;
        let claimed_data_com_var_nov = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_nov)?;
        let claimed_data_com_var_dec = UInt8::new_witness_vec(ns!(cs, "data com"), &self.com_dec)?;

        //
        // Now we witness our private inputs
        //

        // The amount the data was purchase for
        let data_purchase_price_jan = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_jan))?;
        let data_purchase_price_feb = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_feb))?;
        let data_purchase_price_mar = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_mar))?;

        let data_purchase_price_apr = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_apr))?;
        let data_purchase_price_may = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_may))?;
        let data_purchase_price_jun = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_jun))?;

        let data_purchase_price_jul = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_jul))?;
        let data_purchase_price_aug = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_aug))?;
        let data_purchase_price_sep = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_sep))?;

        let data_purchase_price_oct = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_oct))?;
        let data_purchase_price_nov = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_nov))?;
        let data_purchase_price_dec = FV::new_witness(ns!(cs, "purchase price"), || Ok(&self.data_purchase_price_dec))?;


        let data_com_rand_jan = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_jan))?;
        let data_com_rand_feb = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_feb))?;
        let data_com_rand_mar = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_mar))?;

        let data_com_rand_apr = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_apr))?;
        let data_com_rand_may = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_may))?;
        let data_com_rand_jun = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_jun))?;

        let data_com_rand_jul = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_jul))?;
        let data_com_rand_aug = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_aug))?;
        let data_com_rand_sep = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_sep))?;

        let data_com_rand_oct = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_oct))?;
        let data_com_rand_nov = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_nov))?;
        let data_com_rand_dec = FV::new_witness(ns!(cs, "com rand"), || Ok(&self.data_com_rand_dec))?;

        // create input for the result value

        let output_purchase_price_avg = FV::new_input(ns!(cs, "purchase price result"), || Ok(&self.output_purchase_price_avg))?;

        // create inputs for the threshold values

        let bounds_purchase_price_min = FV::new_input(ns!(cs, "bounds purchase price"), || Ok(&self.bounds_purchase_price_min))?;
        let bounds_purchase_price_max = FV::new_input(ns!(cs, "bounds purchase price"), || Ok(&self.bounds_purchase_price_max))?;


        //
        // Ok everything has been inputted. Now we do the logic of the circuit.
        //

        // Put the pieces of our data together into a CardVar
        let data_var_jan = DataVar {amount: data_purchase_price_jan.clone()};
        let data_var_feb = DataVar {amount: data_purchase_price_feb.clone()};
        let data_var_mar = DataVar {amount: data_purchase_price_mar.clone()};

        let data_var_apr = DataVar {amount: data_purchase_price_apr.clone()};
        let data_var_may = DataVar {amount: data_purchase_price_may.clone()};
        let data_var_jun = DataVar {amount: data_purchase_price_jun.clone()};

        let data_var_jul = DataVar {amount: data_purchase_price_jul.clone()};
        let data_var_aug = DataVar {amount: data_purchase_price_aug.clone()};
        let data_var_sep = DataVar {amount: data_purchase_price_sep.clone()};

        let data_var_oct = DataVar {amount: data_purchase_price_oct.clone()};
        let data_var_nov = DataVar {amount: data_purchase_price_nov.clone()};
        let data_var_dec = DataVar {amount: data_purchase_price_dec.clone()};

        // CHECK #1: Card opening.
        // We "open" the data commitment here. Concretely, we compute the commitment of our
        // data_var using com_rand_var. We then assert that this value is equal to the publicly
        // known commitment.

        // Generate a commitment to the message
        let computed_data_comm_var_jan = data_var_jan.commit(&leaf_crh_params, &data_com_rand_jan);
        let computed_data_comm_var_feb = data_var_feb.commit(&leaf_crh_params, &data_com_rand_feb);
        let computed_data_comm_var_mar = data_var_mar.commit(&leaf_crh_params, &data_com_rand_mar);

        let computed_data_comm_var_apr = data_var_apr.commit(&leaf_crh_params, &data_com_rand_apr);
        let computed_data_comm_var_may = data_var_may.commit(&leaf_crh_params, &data_com_rand_may);
        let computed_data_comm_var_jun = data_var_jun.commit(&leaf_crh_params, &data_com_rand_jun);

        let computed_data_comm_var_jul = data_var_jul.commit(&leaf_crh_params, &data_com_rand_jul);
        let computed_data_comm_var_aug = data_var_aug.commit(&leaf_crh_params, &data_com_rand_aug);
        let computed_data_comm_var_sep = data_var_sep.commit(&leaf_crh_params, &data_com_rand_sep);

        let computed_data_comm_var_oct = data_var_oct.commit(&leaf_crh_params, &data_com_rand_oct);
        let computed_data_comm_var_nov = data_var_nov.commit(&leaf_crh_params, &data_com_rand_nov);
        let computed_data_comm_var_dec = data_var_dec.commit(&leaf_crh_params, &data_com_rand_dec);

        // Verify the commitment
        claimed_data_com_var_jan.enforce_equal(&computed_data_comm_var_jan.unwrap())?;
        claimed_data_com_var_feb.enforce_equal(&computed_data_comm_var_feb.unwrap())?;
        claimed_data_com_var_mar.enforce_equal(&computed_data_comm_var_mar.unwrap())?;

        claimed_data_com_var_apr.enforce_equal(&computed_data_comm_var_apr.unwrap())?;
        claimed_data_com_var_may.enforce_equal(&computed_data_comm_var_may.unwrap())?;
        claimed_data_com_var_jun.enforce_equal(&computed_data_comm_var_jun.unwrap())?;

        claimed_data_com_var_jul.enforce_equal(&computed_data_comm_var_jul.unwrap())?;
        claimed_data_com_var_aug.enforce_equal(&computed_data_comm_var_aug.unwrap())?;
        claimed_data_com_var_sep.enforce_equal(&computed_data_comm_var_sep.unwrap())?;

        claimed_data_com_var_oct.enforce_equal(&computed_data_comm_var_oct.unwrap())?;
        claimed_data_com_var_nov.enforce_equal(&computed_data_comm_var_nov.unwrap())?;
        claimed_data_com_var_dec.enforce_equal(&computed_data_comm_var_dec.unwrap())?;

        // other code goes here

        // compute sum value
        let computed_sum_purchase_prices = FV::new_witness(ns!(cs, "intermediate calcs"), || { let tmp = 
                                                                            self.data_purchase_price_jan + 
                                                                            self.data_purchase_price_feb + 
                                                                            self.data_purchase_price_mar + 
                                                                            self.data_purchase_price_apr + 
                                                                            self.data_purchase_price_may + 
                                                                            self.data_purchase_price_jun + 
                                                                            self.data_purchase_price_jul + 
                                                                            self.data_purchase_price_aug + 
                                                                            self.data_purchase_price_sep + 
                                                                            self.data_purchase_price_oct + 
                                                                            self.data_purchase_price_nov + 
                                                                            self.data_purchase_price_dec;
                                                                            Ok(tmp) })?;


        // bounds constraints
        data_purchase_price_jan.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_jan.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;
        data_purchase_price_feb.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_feb.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;
        data_purchase_price_mar.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_mar.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;

        data_purchase_price_apr.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_apr.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;
        data_purchase_price_may.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_may.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;
        data_purchase_price_jun.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_jun.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;

        data_purchase_price_jul.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_jul.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;
        data_purchase_price_aug.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_aug.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;
        data_purchase_price_sep.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_sep.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;

        data_purchase_price_oct.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_oct.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;
        data_purchase_price_nov.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_nov.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;
        data_purchase_price_dec.enforce_cmp(&bounds_purchase_price_min, Ordering::Greater, true)?;
        data_purchase_price_dec.enforce_cmp(&bounds_purchase_price_max, Ordering::Less,    true)?;

        // check sum value
        computed_sum_purchase_prices.enforce_equal(&output_purchase_price_avg)?;

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

        let claimed_avg = data.purchase_price*F::from(12u32);

        // We have everything we need. Build the circuit
        AnalysisCircuit {
            // Constants for hashing
            leaf_crh_params,
            two_to_one_crh_params,

            // Public inputs to the circuit
            com_jan: claimed_leaf.to_vec(),
            com_feb: claimed_leaf.to_vec(),
            com_mar: claimed_leaf.to_vec(),

            com_apr: claimed_leaf.to_vec(),
            com_may: claimed_leaf.to_vec(),
            com_jun: claimed_leaf.to_vec(),

            com_jul: claimed_leaf.to_vec(),
            com_aug: claimed_leaf.to_vec(),
            com_sep: claimed_leaf.to_vec(),

            com_oct: claimed_leaf.to_vec(),
            com_nov: claimed_leaf.to_vec(),
            com_dec: claimed_leaf.to_vec(),

            // Witness to membership
            // Commitment opening details
            data_com_rand_jan: data_com_rand,       // The data's nonce
            data_com_rand_feb: data_com_rand,       // The data's nonce
            data_com_rand_mar: data_com_rand,       // The data's nonce

            data_com_rand_apr: data_com_rand,       // The data's nonce
            data_com_rand_may: data_com_rand,       // The data's nonce
            data_com_rand_jun: data_com_rand,       // The data's nonce

            data_com_rand_jul: data_com_rand,       // The data's nonce
            data_com_rand_aug: data_com_rand,       // The data's nonce
            data_com_rand_sep: data_com_rand,       // The data's nonce

            data_com_rand_oct: data_com_rand,       // The data's nonce
            data_com_rand_nov: data_com_rand,       // The data's nonce
            data_com_rand_dec: data_com_rand,       // The data's nonce

            data_purchase_price_jan: data.purchase_price, // The datas' purchase price
            data_purchase_price_feb: data.purchase_price, // The datas' purchase price
            data_purchase_price_mar: data.purchase_price, // The datas' purchase price

            data_purchase_price_apr: data.purchase_price, // The datas' purchase price
            data_purchase_price_may: data.purchase_price, // The datas' purchase price
            data_purchase_price_jun: data.purchase_price, // The datas' purchase price

            data_purchase_price_jul: data.purchase_price, // The datas' purchase price
            data_purchase_price_aug: data.purchase_price, // The datas' purchase price
            data_purchase_price_sep: data.purchase_price, // The datas' purchase price

            data_purchase_price_oct: data.purchase_price, // The datas' purchase price
            data_purchase_price_nov: data.purchase_price, // The datas' purchase price
            data_purchase_price_dec: data.purchase_price, // The datas' purchase price

            output_purchase_price_avg: claimed_avg,         // the output value

            bounds_purchase_price_min: F::from(0),          // the minimum bounds
            bounds_purchase_price_max: F::from(1000),       // the maximum bounds
        }
    }

    // Correctness test: Make a fresh constraint system and run the circuit.
    #[test]
    fn data_correctness() {
        let mut rng = ark_std::test_rng();
        let circuit = setup(&mut rng);

        println!("data_purchase_price_jan = {}",circuit.data_purchase_price_jan);

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
        bad_data_circuit.data_purchase_price_jan = F::rand(&mut rng);

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
