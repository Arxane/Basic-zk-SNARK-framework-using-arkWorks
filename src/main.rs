use std::collections::HashMap; //Keep for var_index if needed, but r1cs_system will hold it
use zk_framework::{Circuit, ProvingKey, VerifyingKey, Proof, parse_circuit, setup, prove, verify}; //Import new items
use ark_bls12_381::Fr; // For Fr type if used directly
use ark_ff::One; 

fn main() {
    use tracing_subscriber::{EnvFilter, FmtSubscriber};
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,ark_relations::r1cs::trace=trace"))) // Corrected filter
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo run -- <path_to_circuit_file>");
        return;
    }

    let path = &args[1];
    println!("Parsing circuit from: {}", path);
    let circuit: Circuit = parse_circuit(path).expect("Failed to parse circuit");
    println!("Parsed Circuit: {:?}", circuit.name);

    println!("Converting circuit to R1CS system...");
    let r1cs = circuit.to_r1cs_system();
    println!("R1CS system generated: {} constraints, {} variables, {} public inputs.",
             r1cs.raw_constraints.len(), r1cs.num_variables, r1cs.num_public_inputs);
    println!("Public input names (excluding implicit '1'): {:?}", r1cs.public_input_names);


    println!("Generating Groth16 proving and verifying keys (setup)...");
    let (pk, vk): (ProvingKey, VerifyingKey) = setup(&r1cs).expect("Failed to generate keys (setup)");
    println!("Keys generated successfully.");

    println!("Computing witness for the circuit instance...");
    // Pass the var_map from the R1CS system to compute_witness
    let witness_by_idx: HashMap<usize, Fr> = circuit.compute_witness(&r1cs.var_map)
        .expect("Failed to compute witness");
    println!("Witness computed with {} assignments.", witness_by_idx.len());


    println!("Generating Groth16 proof...");
    let proof: Proof = prove(&r1cs, &pk, witness_by_idx.clone()).expect("Failed to generate proof");
    println!("Proof generated: {:?}", proof); // Proof struct is a wrapper, debug might not be very informative

    // Prepare public inputs for verification
    // The order must be: Fr::one(), then values for each name in r1cs.public_input_names
    let mut public_inputs_for_verification: Vec<Fr> = Vec::new();
    public_inputs_for_verification.push(Fr::one()); // The first public input is always 1

    for name in &r1cs.public_input_names {
        let original_idx = r1cs.var_map.get(name).unwrap_or_else(|| {
            panic!("Public input name '{}' from r1cs.public_input_names not found in r1cs.var_map", name);
        });
        let value = witness_by_idx.get(original_idx).unwrap_or_else(|| {
            panic!("Witness value for public input '{}' (original_idx {}) not found", name, original_idx);
        });
        public_inputs_for_verification.push(*value);
    }
    
    if public_inputs_for_verification.len() != r1cs.num_public_inputs {
         panic!("Error: Expected {} public inputs for verification, but got {}. Names: {:?}, Values: {:?}",
                r1cs.num_public_inputs, public_inputs_for_verification.len(), r1cs.public_input_names, public_inputs_for_verification);
    }


    println!("Verifying proof with public inputs: {:?}", public_inputs_for_verification);
    let is_valid = verify(&vk, &proof, &public_inputs_for_verification)
        .expect("Verification process failed");

    println!("Verification Result: {}", is_valid);

    if is_valid {
        println!("Proof is VALID!");
    } else {
        println!("Proof is INVALID!");
    }
}