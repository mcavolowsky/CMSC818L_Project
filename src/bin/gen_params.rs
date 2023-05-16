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

    let claimed_avg = F::from(1200u32);

    // Now construct the circuit with all the random values
    let circuit = AnalysisCircuit {
        // Constants that the circuit needs
        leaf_crh_params,
        two_to_one_crh_params,

        // Public inputs to the circuit
        com_jan: zero_leaf.to_vec(),
        com_feb: zero_leaf.to_vec(),
        com_mar: zero_leaf.to_vec(),

        com_apr: zero_leaf.to_vec(),
        com_may: zero_leaf.to_vec(),
        com_jun: zero_leaf.to_vec(),

        com_jul: zero_leaf.to_vec(),
        com_aug: zero_leaf.to_vec(),
        com_sep: zero_leaf.to_vec(),

        com_oct: zero_leaf.to_vec(),
        com_nov: zero_leaf.to_vec(),
        com_dec: zero_leaf.to_vec(),

        // Commitment opening details
        data_com_rand_jan: F::rand(&mut rng),       // Another field elememnt
        data_com_rand_feb: F::rand(&mut rng),       // Another field elememnt
        data_com_rand_mar: F::rand(&mut rng),       // Another field elememnt

        data_com_rand_apr: F::rand(&mut rng),       // Another field elememnt
        data_com_rand_may: F::rand(&mut rng),       // Another field elememnt
        data_com_rand_jun: F::rand(&mut rng),       // Another field elememnt

        data_com_rand_jul: F::rand(&mut rng),       // Another field elememnt
        data_com_rand_aug: F::rand(&mut rng),       // Another field elememnt
        data_com_rand_sep: F::rand(&mut rng),       // Another field elememnt

        data_com_rand_oct: F::rand(&mut rng),       // Another field elememnt
        data_com_rand_nov: F::rand(&mut rng),       // Another field elememnt
        data_com_rand_dec: F::rand(&mut rng),       // Another field elememnt

        data_purchase_price_jan: F::from(543), // Another field element
        data_purchase_price_feb: F::from(543), // Another field element
        data_purchase_price_mar: F::from(543), // Another field element

        data_purchase_price_apr: F::from(543), // Another field element
        data_purchase_price_may: F::from(543), // Another field element
        data_purchase_price_jun: F::from(543), // Another field element

        data_purchase_price_jul: F::from(543), // Another field element
        data_purchase_price_aug: F::from(543), // Another field element
        data_purchase_price_sep: F::from(543), // Another field element

        data_purchase_price_oct: F::from(543), // Another field element
        data_purchase_price_nov: F::from(543), // Another field element
        data_purchase_price_dec: F::from(543), // Another field element

        output_purchase_price_avg: claimed_avg,         // the output value

        bounds_purchase_price_min: F::from(0),          // the minimum bounds
        bounds_purchase_price_max: F::from(1000),       // the maximum bounds

    };

    // Generate the Groth16 proving and verifying key and write to files
    let pk: ProvingKey<E> = generate_random_parameters(circuit.clone(), &mut rng).unwrap();
    let vk = prepare_verifying_key(&pk.vk);
    write_to_file(POSSESSION_PK_FILENAME, &pk);
    write_to_file(POSSESSION_VK_FILENAME, &vk);
    println!("Wrote {POSSESSION_PK_FILENAME}");
    println!("Wrote {POSSESSION_VK_FILENAME}");
}
