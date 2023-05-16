use arkworks_merkle_tree_example::{
    constraints::AnalysisCircuit,
    merkle::MerkleRoot,
    util::{
        gen_test_tree, get_test_data, get_test_leaf, read_from_file, write_to_file,
        POSSESSION_PROOF_FILENAME, POSSESSION_REVEALED_SERIAL_FILENAME, POSSESSION_VK_FILENAME,
    },
    E, F, 
};

use std::env;

use ark_ff::ToConstraintField;
use ark_groth16::{create_random_proof, verify_proof, ProvingKey};
use ark_serialize::CanonicalDeserialize;

const HELP_STR: &str = "\
Error: bad command line arguments

Usage:
    cargo run --release --bin prove -- PEDERSEN_PARAM_FILE PROVING_KEY_FILE MERKLE_ROOT
Example:
    cargo run --release --bin prove -- \\
        pedersen_params.bin \\
        possession_proving_key.bin \\
        f5pj64oh3m6anguhjb5rhfugwe44ximao17ya3wgx1fbmg1iobmo
";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("{}", HELP_STR);
        panic!("bad command line input");
    }
    // Unpack command line args
    let pedersen_params_filename = &args[1];
    let possession_pk_filename = &args[2];
    let given_merkle_root = {
        let bytes = zbase32::decode_full_bytes(args[3].as_bytes())
            .expect("could not decode Merkle root string");
        MerkleRoot::deserialize_compressed(bytes.as_slice())
            .expect("Merkle root string is an invalid hash")
    };

    //
    // Setup
    //

    let mut rng = rand::thread_rng();

    println!("Reading params and proving key...");
    // Read the hashing params from a file
    let (leaf_crh_params, two_to_one_crh_params) = read_from_file(&pedersen_params_filename);
    // Read the Groth16 CRS from a file
    let pk: ProvingKey<E> = read_from_file(&possession_pk_filename);

    // Generate a test tree and compute its root
    let tree = gen_test_tree(&leaf_crh_params, &two_to_one_crh_params);
    let root = tree.root();
    // Check that the root we generated is equal to the root that was given
    assert_eq!(
        root, given_merkle_root,
        "The Merkle root I'm trying to use is different than the one you gave me"
    );
    // Also imagine we possess the data that appears at index 7 in the tree
    let our_idx = 7;
    let (data, data_com_rand) = get_test_data(our_idx);

    //
    // Now generate a proof
    //

    // We'll prove membership of our data, i.e., the 7th item in the tree
    let idx_to_prove = our_idx;
    let claimed_leaf = &get_test_leaf(&leaf_crh_params, idx_to_prove);

    let claimed_avg = data.purchase_price*F::from(12u32)/F::from(12u32);

    // We now have everything we need to build the PossessionCircuit
    let circuit = AnalysisCircuit {
        // Constants that the circuit needs
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
    };

    // Create the proof
    println!("Proving...");
    let proof = create_random_proof(circuit.clone(), &pk, &mut rng).unwrap();

    //
    // Wrap-up
    //

    // Verify the proof package. This should succeed
    let vk = read_from_file(POSSESSION_VK_FILENAME);
    let public_inputs = [
        root.to_field_elements().unwrap(),
    ]
    .concat();
    assert!(
        verify_proof(&vk, &proof, &public_inputs).unwrap(),
        "honest proof failed to verify with supplied verifying key"
    );

    // Write the proof and serial to a file
    write_to_file(POSSESSION_PROOF_FILENAME, &proof);
    println!("Wrote {POSSESSION_PROOF_FILENAME}");
    println!("Wrote {POSSESSION_REVEALED_SERIAL_FILENAME}");
}
