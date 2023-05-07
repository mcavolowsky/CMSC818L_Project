use arkworks_merkle_tree_example::{
    constraints::AnalysisCircuit,
    hash::{LeafHash, TwoToOneHash},
    merkle::{Leaf},
    util::{
        write_to_file, PEDERSEN_PARAMS_FILENAME, POSSESSION_PK_FILENAME,
        POSSESSION_VK_FILENAME,
    },
    E, F,
};

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::UniformRand;
use ark_groth16::{generate_random_parameters, prepare_verifying_key, ProvingKey};

fn main() {
    // Use a deterministic RNG
    let mut rng = ark_std::test_rng();

    //
    // First step is to generate the Pedersen hashing parameters
    //

    // Sample the Pedersen params randomly
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();

    // Write the CRH params to a file
    write_to_file(
        PEDERSEN_PARAMS_FILENAME,
        &(leaf_crh_params.clone(), two_to_one_crh_params.clone()),
    );
    println!("Wrote {PEDERSEN_PARAMS_FILENAME}");

    //
    // Now we generate the Groth16 CRS for PossessionCircuit. To do so, we have to make a
    // placeholder circuit. We will just fill in everything with random values
    //

    // Make a uniform leaf
    let zero_leaf: Leaf = [0u8; 64];

    // Now construct the circuit with all the random values
    let circuit = AnalysisCircuit {
        // Constants that the circuit needs
        leaf_crh_params,
        two_to_one_crh_params,

        // Public inputs to the circuit
        commitment: zero_leaf.to_vec(),

        // Commitment opening details
        data_com_rand: F::rand(&mut rng),       // Another field elememnt
        data_purchase_price: F::from(543), // Another field element
    };

    // Generate the Groth16 proving and verifying key and write to files
    let pk: ProvingKey<E> = generate_random_parameters(circuit.clone(), &mut rng).unwrap();
    let vk = prepare_verifying_key(&pk.vk);
    write_to_file(POSSESSION_PK_FILENAME, &pk);
    write_to_file(POSSESSION_VK_FILENAME, &vk);
    println!("Wrote {POSSESSION_PK_FILENAME}");
    println!("Wrote {POSSESSION_VK_FILENAME}");
}
