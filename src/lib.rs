// No AI assistance used for this implementation (unlike the main.rs file)
use std::collections::HashMap;
use std::ops::Neg;
// Arkworks imports - v0.5.0
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{One, Zero};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef,
    LinearCombination, SynthesisError, Variable,
};
//zk-SNARK imports
use ark_groth16::{
    Groth16,
    ProvingKey as ArkGroth16ProvingKey,
    VerifyingKey as ArkGroth16VerifyingKey,
    Proof as ArkGroth16Proof,
};
use ark_crypto_primitives::snark::SNARK;
use ark_std::rand::rngs::OsRng;

//Parser imports
pub mod parser;
pub use parser::parse_circuit;

//Helper function for converting i32 to Fr
pub fn i32_to_fr(val: i32) -> Fr {
    if val < 0 {
        Fr::from((-val) as u64).neg()
    } else {
        Fr::from(val as u64)
    }
}

//Helper function for getting the index of a variable
fn get_index(var: &str, var_index: &mut HashMap<String, usize>, next_index: &mut usize) -> usize {
    if let Some(&idx) = var_index.get(var) {
        idx
    } else {
        let idx = *next_index;
        var_index.insert(var.to_string(), idx);
        *next_index += 1;
        idx
    }
}

//Enum for the gates (define the types of gate supported by the circuit)
#[derive(Debug, Clone)]
pub enum Gate {
    Add(String, String, String, Option<i32>),
    Mul(String, String, String, Option<i32>),
    Sub(String, String, String, Option<i32>),
    Xor(String, String, String),
    Const(String, i32),
    Hash(String, String),
    Eq(String, String, String),
}

//Struct for the circuit (define the circuit structure)
#[derive(Debug, Clone)]
pub struct Circuit {
    pub name: String,
    pub inputs: HashMap<String, i32>,
    pub outputs: HashMap<String, i32>,
    pub gates: Vec<Gate>,
    pub sender: String,
    pub receiver: String,
    pub transfer_amount: i32,
}

//Functions for the circuit struct
impl Circuit {
    //Validate the transfer (check if the sender has enough balance)
    pub fn validate_transfer(&self) -> bool {
        if let Some(sender_balance) = self.inputs.get(&self.sender) {
            *sender_balance >= self.transfer_amount
        } else {
            false
        }
    }

    //Execute the transfer (subtract the transfer amount from the sender's balance and add it to the receiver's balance)
    pub fn execute_transfer(&mut self) {
        if self.validate_transfer() {
            if let Some(sender_balance) = self.inputs.get_mut(&self.sender) {
                *sender_balance -= self.transfer_amount;
            }
            if let Some(receiver_balance) = self.inputs.get_mut(&self.receiver) {
                *receiver_balance += self.transfer_amount;
            }
        }
    }

    //Convert the circuit to an R1CS system for zk-SNARK
    pub fn to_r1cs_system(&self) -> R1CSSystem {
        //Initialize the variable map
        let mut var_map = HashMap::new();
        var_map.insert("1".to_string(), 0);
        let mut next_r1cs_idx = 1;

        //Initialize the constraints vector
        let mut temp_constraints: Vec<_R1CSConstraintInternal> = Vec::new();
        let mut public_input_names: Vec<String> = Vec::new();

        //Add the sender's initial balance to the constraints
        if self.inputs.contains_key(&self.sender) {
            let public_var_name = format!("{}_initial_balance", self.sender);
            public_input_names.push(public_var_name.clone());
            let sender_initial_idx = get_index(&public_var_name, &mut var_map, &mut next_r1cs_idx);
            let val_fr = i32_to_fr(*self.inputs.get(&self.sender).unwrap_or(&0));
            temp_constraints.push(_R1CSConstraintInternal {
                a: vec![(sender_initial_idx, Fr::one())].into_iter().collect(),
                b: vec![(var_map["1"], Fr::one())].into_iter().collect(),
                c: vec![(var_map["1"], val_fr)].into_iter().collect(),
            });
        }

        //Add the receiver's initial balance to the constraints
        if self.inputs.contains_key(&self.receiver) {
            let public_var_name = format!("{}_initial_balance", self.receiver);
            public_input_names.push(public_var_name.clone());
            let receiver_initial_idx = get_index(&public_var_name, &mut var_map, &mut next_r1cs_idx);
            let val_fr = i32_to_fr(*self.inputs.get(&self.receiver).unwrap_or(&0));
            temp_constraints.push(_R1CSConstraintInternal {
                a: vec![(receiver_initial_idx, Fr::one())].into_iter().collect(),
                b: vec![(var_map["1"], Fr::one())].into_iter().collect(),
                c: vec![(var_map["1"], val_fr)].into_iter().collect(),
            });
        }

        //Add the transfer amount to the constraints
        let transfer_amount_var_name = "transfer_amount_public".to_string();
        public_input_names.push(transfer_amount_var_name.clone());
        let transfer_amount_idx = get_index(&transfer_amount_var_name, &mut var_map, &mut next_r1cs_idx);
        temp_constraints.push(_R1CSConstraintInternal {
            a: vec![(transfer_amount_idx, Fr::one())].into_iter().collect(),
            b: vec![(var_map["1"], Fr::one())].into_iter().collect(),
            c: vec![(var_map["1"], i32_to_fr(self.transfer_amount))].into_iter().collect(),
        });

        //Add the gates to the constraints
        for gate_ref in &self.gates {
            match gate_ref {
                Gate::Add(a, b, c, _modulus) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let c_idx = get_index(c, &mut var_map, &mut next_r1cs_idx);
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx,Fr::one()),(b_idx,Fr::one())].into_iter().collect(),
                        b: vec![(var_map["1"],Fr::one())].into_iter().collect(),
                        c: vec![(c_idx,Fr::one())].into_iter().collect(),
                    });
                }
                Gate::Mul(a, b, c, _modulus) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let c_idx = get_index(c, &mut var_map, &mut next_r1cs_idx);
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx,Fr::one())].into_iter().collect(),
                        b: vec![(b_idx,Fr::one())].into_iter().collect(),
                        c: vec![(c_idx,Fr::one())].into_iter().collect(),
                    });
                }
                Gate::Sub(a, b, c, _modulus) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let c_idx = get_index(c, &mut var_map, &mut next_r1cs_idx);
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx,Fr::one()),(b_idx,Fr::one().neg())].into_iter().collect(),
                        b: vec![(var_map["1"],Fr::one())].into_iter().collect(),
                        c: vec![(c_idx,Fr::one())].into_iter().collect(),
                    });
                }
                Gate::Eq(a, b, out) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let out_idx = get_index(out, &mut var_map, &mut next_r1cs_idx);
                    // First constraint: a - b = diff
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx,Fr::one()),(b_idx,Fr::one().neg())].into_iter().collect(),
                        b: vec![(var_map["1"],Fr::one())].into_iter().collect(),
                        c: vec![(out_idx,Fr::one())].into_iter().collect(),
                    });
                    // Second constraint: diff * diff = 0 (enforces diff = 0)
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(out_idx,Fr::one())].into_iter().collect(),
                        b: vec![(out_idx,Fr::one())].into_iter().collect(),
                        c: vec![(var_map["1"],Fr::zero())].into_iter().collect(),
                    });
                }
                //Hash gate
                Gate::Hash(input, output) => {
                    let input_idx = get_index(input, &mut var_map, &mut next_r1cs_idx);
                    let output_idx = get_index(output, &mut var_map, &mut next_r1cs_idx);

                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(input_idx,Fr::one())].into_iter().collect(),
                        //Multiply the input by 7
                        b: vec![(var_map["1"],i32_to_fr(7))].into_iter().collect(),
                        c: vec![(output_idx,Fr::one())].into_iter().collect(),
                    });
                }
                Gate::Const(name, val) => {
                    let idx = get_index(name, &mut var_map, &mut next_r1cs_idx);
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(var_map["1"],i32_to_fr(*val))].into_iter().collect(),//convert the constant to Fr
                        b: vec![(var_map["1"],Fr::one())].into_iter().collect(),//multiply by 1
                        c: vec![(idx,Fr::one())].into_iter().collect(),//assign to the variable
                    });
                }
                Gate::Xor(a, b, c) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let ab_var_name = format!("{}_xor_prod_{}", a, b);
                    let ab_idx = get_index(&ab_var_name, &mut var_map, &mut next_r1cs_idx);
                    let c_idx = get_index(c, &mut var_map, &mut next_r1cs_idx);
                    //a*b = ab
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx,Fr::one())].into_iter().collect(),
                        b: vec![(b_idx,Fr::one())].into_iter().collect(),
                        c: vec![(ab_idx,Fr::one())].into_iter().collect(),
                    });
                    //a*b - 2*a*b = c
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx,Fr::one()), (b_idx, Fr::one()), (ab_idx, i32_to_fr(-2))].into_iter().collect(),
                        b: vec![(var_map["1"],Fr::one())].into_iter().collect(),
                        c: vec![(c_idx,Fr::one())].into_iter().collect(),
                    });
                    //boolean constraints to ensure a and b are either 0 or 1
                    //a*a = a
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx, Fr::one())].into_iter().collect(),
                        b: vec![(a_idx, Fr::one())].into_iter().collect(),
                        c: vec![(a_idx, Fr::one())].into_iter().collect(),
                    });
                    //b*b = b
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(b_idx, Fr::one())].into_iter().collect(),
                        b: vec![(b_idx, Fr::one())].into_iter().collect(),
                        c: vec![(b_idx, Fr::one())].into_iter().collect(),
                    });
                }
            }
        }
        //Return the R1CS system
        R1CSSystem {
            raw_constraints: temp_constraints,
            var_map: var_map.clone(),
            num_variables: next_r1cs_idx,
            num_public_inputs: 1 + public_input_names.len(),
            public_input_names,
        }
    }

    //Compute the witness for the circuit
    pub fn compute_witness(&self, r1cs_var_map: &HashMap<String, usize>) -> Result<HashMap<usize, Fr>, String> {
        let mut wire_values_by_name: HashMap<String, Fr> = HashMap::new();

        //Add the inputs to the wire values
        for (name, val) in &self.inputs {
            wire_values_by_name.insert(name.clone(), i32_to_fr(*val));
        }
        wire_values_by_name.insert("1".to_string(), Fr::one());

        //Add the sender's initial balance to the wire values
        let sender_initial_var_name = format!("{}_initial_balance", self.sender);
        if self.inputs.contains_key(&self.sender) {
             wire_values_by_name.insert(
                 sender_initial_var_name.clone(),
                 i32_to_fr(*self.inputs.get(&self.sender).unwrap())
             );
        }

        //Add the receiver's initial balance to the wire values
        let receiver_initial_var_name = format!("{}_initial_balance", self.receiver);
         if self.inputs.contains_key(&self.receiver) {
            wire_values_by_name.insert(
                receiver_initial_var_name.clone(),
                i32_to_fr(*self.inputs.get(&self.receiver).unwrap())
            );
        }

        //Add the transfer amount to the wire values
        let transfer_amount_public_var_name = "transfer_amount_public".to_string();
        wire_values_by_name.insert(
            transfer_amount_public_var_name.clone(),
            i32_to_fr(self.transfer_amount)
        );

        //Add the gates to the wire values
        for gate_ref in &self.gates {
            match gate_ref {
                Gate::Add(a_name, b_name, c_name, _) => {
                    let a_val = wire_values_by_name.get(a_name.as_str()).ok_or_else(|| format!("Var {} not found", a_name))?;
                    let b_val = wire_values_by_name.get(b_name.as_str()).ok_or_else(|| format!("Var {} not found", b_name))?;
                    wire_values_by_name.insert(c_name.clone(), *a_val + *b_val);
                }
                Gate::Mul(a_name, b_name, c_name, _) => {
                    let a_val = wire_values_by_name.get(a_name.as_str()).ok_or_else(|| format!("Var {} not found", a_name))?;
                    let b_val = wire_values_by_name.get(b_name.as_str()).ok_or_else(|| format!("Var {} not found", b_name))?;
                    wire_values_by_name.insert(c_name.clone(), *a_val * *b_val);
                }
                Gate::Sub(a_name, b_name, c_name, _) => {
                    let a_val = wire_values_by_name.get(a_name.as_str()).ok_or_else(|| format!("Var {} not found", a_name))?;
                    let b_val = wire_values_by_name.get(b_name.as_str()).ok_or_else(|| format!("Var {} not found", b_name))?;
                    wire_values_by_name.insert(c_name.clone(), *a_val - *b_val);
                }
                Gate::Eq(a_name, b_name, out_name) => {
                    let a_val = wire_values_by_name.get(a_name.as_str()).ok_or_else(|| format!("Var {} not found", a_name))?;
                    let b_val = wire_values_by_name.get(b_name.as_str()).ok_or_else(|| format!("Var {} not found", b_name))?;
                    // For equality to hold, a_val must equal b_val
                    if *a_val != *b_val {
                        return Err(format!("Equality constraint failed: {} ({:?}) != {} ({:?})", 
                            a_name, a_val, b_name, b_val));
                    }
                    wire_values_by_name.insert(out_name.clone(), Fr::zero());
                }
                Gate::Hash(in_name, out_name) => {
                    let in_val = wire_values_by_name.get(in_name.as_str()).ok_or_else(|| format!("Var {} not found", in_name))?;
                    wire_values_by_name.insert(out_name.clone(), *in_val * i32_to_fr(7));
                }
                Gate::Const(name, val) => {
                    wire_values_by_name.insert(name.clone(), i32_to_fr(*val));
                }
                Gate::Xor(a_name, b_name, c_name) => {
                    let a_val = *wire_values_by_name.get(a_name.as_str()).ok_or_else(|| format!("Var {} not found for XOR", a_name))?;
                    let b_val = *wire_values_by_name.get(b_name.as_str()).ok_or_else(|| format!("Var {} not found for XOR", b_name))?;
                    if !(a_val.is_zero() || a_val.is_one()) { return Err(format!("XOR input {} is not a bit (0 or 1)", a_name));} // Keep this
                    if !(b_val.is_zero() || b_val.is_one()) { return Err(format!("XOR input {} is not a bit (0 or 1)", b_name));} // Keep this

                    let ab_var_name_string = format!("{}_xor_prod_{}", a_name, b_name);
                    let ab_val = a_val * b_val;
                    wire_values_by_name.insert(ab_var_name_string.clone(), ab_val);

                    let c_val = a_val + b_val - (i32_to_fr(2) * ab_val);
                    wire_values_by_name.insert(c_name.clone(), c_val);
                }
            }
        }

        //Add the witness to the wire values
        let mut witness_by_idx: HashMap<usize, Fr> = HashMap::new();
        for (name, val_fr) in wire_values_by_name {
            if let Some(idx) = r1cs_var_map.get(&name) {
                witness_by_idx.insert(*idx, val_fr);
            }
        }
        //Check if all the variables in the R1CS var_map have a witness value
        for (name, idx) in r1cs_var_map {
            if !witness_by_idx.contains_key(idx) {
                return Err(format!("Variable '{}' (index {}) is in R1CS var_map but has no computed witness value.", name, idx));
            }
        }
        Ok(witness_by_idx)
    }
}

#[derive(Debug, Clone)]
pub struct _R1CSConstraintInternal { // Added pub as per previous fix
    pub a: HashMap<usize, Fr>,
    pub b: HashMap<usize, Fr>,
    pub c: HashMap<usize, Fr>,
}

#[derive(Debug, Clone)]
pub struct R1CSSystem {
    pub raw_constraints: Vec<_R1CSConstraintInternal>,
    pub var_map: HashMap<String, usize>,
    pub num_variables: usize,
    pub num_public_inputs: usize,
    pub public_input_names: Vec<String>,
}

// Wrapper structs using the CORRECT types from ark_groth16 v0.5.0 (assuming root export)
#[derive(Clone)]
pub struct ProvingKey(ArkGroth16ProvingKey<Bls12_381>);

#[derive(Clone)]
pub struct VerifyingKey(ArkGroth16VerifyingKey<Bls12_381>);

impl VerifyingKey {
    pub fn inner(&self) -> &ArkGroth16VerifyingKey<Bls12_381> {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Proof(ArkGroth16Proof<Bls12_381>);

#[derive(Clone)]
struct Groth16CircuitAdapter {
    r1cs_system: R1CSSystem,
    witness_assignment: Option<HashMap<usize, Fr>>,
}

//Implement the ConstraintSynthesizer trait for the Groth16CircuitAdapter
impl ConstraintSynthesizer<Fr> for Groth16CircuitAdapter {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut cs_vars: HashMap<usize, Variable> = HashMap::new();
        
        // Allocate constant 1
        let one_original_idx = *self.r1cs_system.var_map.get("1").ok_or_else(|| {
            eprintln!("[Setup/Prove Allocation Error] Variable '1' not found in var_map.");
            SynthesisError::AssignmentMissing
        })?;
        let one_cs_var = cs.new_input_variable(|| Ok(Fr::one()))?;
        cs_vars.insert(one_original_idx, one_cs_var);

        // Allocate public inputs
        for name in &self.r1cs_system.public_input_names {
            let original_idx = *self.r1cs_system.var_map.get(name).ok_or_else(|| {
                eprintln!("[Setup/Prove Allocation Error] Public input name '{}' not found in var_map.", name);
                SynthesisError::AssignmentMissing
            })?;
            
            let val = self.witness_assignment.as_ref()
                .and_then(|w| w.get(&original_idx).cloned())
                .unwrap_or_else(|| Fr::zero());
            
            let cs_var = cs.new_input_variable(|| Ok(val))?;
            cs_vars.insert(original_idx, cs_var);
        }

        // Allocate witness variables
        for (name, original_idx) in &self.r1cs_system.var_map {
            if name != "1" && !self.r1cs_system.public_input_names.contains(name) {
                let val = self.witness_assignment.as_ref()
                    .and_then(|w| w.get(original_idx).cloned())
                    .unwrap_or_else(|| Fr::zero());
                
                let cs_var = cs.new_witness_variable(|| Ok(val))?;
                cs_vars.insert(*original_idx, cs_var);
            }
        }

        // Enforce constraints
        for r1cs_constraint_internal in &self.r1cs_system.raw_constraints {
            let mut lc_a = LinearCombination::zero();
            let mut lc_b = LinearCombination::zero();
            let mut lc_c = LinearCombination::zero();

            for (original_idx, coeff) in &r1cs_constraint_internal.a {
                lc_a += (*coeff, cs_vars[original_idx]);
            }
            for (original_idx, coeff) in &r1cs_constraint_internal.b {
                lc_b += (*coeff, cs_vars[original_idx]);
            }
            for (original_idx, coeff) in &r1cs_constraint_internal.c {
                lc_c += (*coeff, cs_vars[original_idx]);
            }

            cs.enforce_constraint(lc_a, lc_b, lc_c)?;
        }

        Ok(())
    }
}
//setup and initialize proving key and verifying key
pub fn setup(r1cs_system: &R1CSSystem) -> Result<(ProvingKey, VerifyingKey), SynthesisError> {
    let rng = &mut OsRng;
    let circuit = Groth16CircuitAdapter {
        r1cs_system: r1cs_system.clone(),
        witness_assignment: None,
    };

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)?;
    Ok((ProvingKey(pk), VerifyingKey(vk)))
}
// to generate the proof
pub fn prove(
    r1cs_system: &R1CSSystem,
    pk: &ProvingKey,
    witness_by_original_idx: HashMap<usize, Fr>,
) -> Result<Proof, SynthesisError> {
    let rng = &mut OsRng;
    let circuit = Groth16CircuitAdapter {
        r1cs_system: r1cs_system.clone(),
        witness_assignment: Some(witness_by_original_idx),
    };

    let proof = Groth16::<Bls12_381>::prove(&pk.0, circuit, rng)?;
    Ok(Proof(proof))
}
//function to use the verifying key
pub fn verify(
    vk: &VerifyingKey,
    proof: &Proof,
    public_inputs_ordered: &[Fr],
) -> Result<bool, SynthesisError> {
    let processed_vk = Groth16::<Bls12_381>::process_vk(vk.inner())?;
    let result = Groth16::<Bls12_381>::verify_with_processed_vk(&processed_vk, public_inputs_ordered, &proof.0)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_circuit_groth16() {
        let circuit = Circuit {
            name: "test_add".to_string(),
            inputs: HashMap::from([("a".to_string(), 10), ("b".to_string(), 20)]),
            outputs: HashMap::new(),
            gates: vec![
                Gate::Add("a".to_string(), "b".to_string(), "c".to_string(), None),
                Gate::Add("c".to_string(), "transfer_amount_public".to_string(), "d".to_string(), None),
            ],
            sender: "alice".to_string(),
            receiver: "bob".to_string(),
            transfer_amount: 5,
        };

        println!("Generating R1CS...");
        let r1cs = circuit.to_r1cs_system();
        println!("R1CS generated with {} constraints, {} vars, {} public inputs (names: {:?})",
                 r1cs.raw_constraints.len(), r1cs.num_variables, r1cs.num_public_inputs, r1cs.public_input_names);

        assert!(r1cs.var_map.contains_key("1"));
        assert!(r1cs.var_map.contains_key("a"));
        assert!(r1cs.var_map.contains_key("b"));
        assert!(r1cs.var_map.contains_key("c"));
        assert!(r1cs.var_map.contains_key("d"));
        assert!(r1cs.var_map.contains_key("transfer_amount_public"));


        println!("Running Groth16 Setup...");
        let (pk, vk) = setup(&r1cs).expect("Setup failed");
        println!("Setup complete.");

        println!("Computing witness...");
        let witness_map_by_idx = circuit.compute_witness(&r1cs.var_map).expect("Witness computation failed");
        println!("Witness computed. {} assignments.", witness_map_by_idx.len());
        
        let c_idx = *r1cs.var_map.get("c").unwrap();
        assert_eq!(witness_map_by_idx.get(&c_idx), Some(&i32_to_fr(30)));

        let d_idx = *r1cs.var_map.get("d").unwrap();
        assert_eq!(witness_map_by_idx.get(&d_idx), Some(&i32_to_fr(35)));

        let transfer_public_idx = *r1cs.var_map.get("transfer_amount_public").unwrap();
        assert_eq!(witness_map_by_idx.get(&transfer_public_idx), Some(&i32_to_fr(5)));


        println!("Generating Groth16 Proof...");
        let proof_obj = prove(&r1cs, &pk, witness_map_by_idx.clone()).expect("Proof generation failed");
        println!("Proof generated.");

        let mut public_inputs_for_verification_ordered: Vec<Fr> = Vec::new();
        public_inputs_for_verification_ordered.push(Fr::one());

        for name in &r1cs.public_input_names {
            let original_idx = *r1cs.var_map.get(name)
                .unwrap_or_else(|| panic!("Public input name {} not in r1cs.var_map", name));
            let val = witness_map_by_idx.get(&original_idx)
                .unwrap_or_else(|| panic!("Value for public input {} (idx {}) not in witness map", name, original_idx));
            public_inputs_for_verification_ordered.push(*val);
        }
        
        assert_eq!(public_inputs_for_verification_ordered.len(), r1cs.num_public_inputs, "Mismatch in number of public inputs for verification.");

        println!("Verifying Proof with {} public inputs...", public_inputs_for_verification_ordered.len());
        let is_valid = verify(&vk, &proof_obj, &public_inputs_for_verification_ordered)
            .expect("Verification threw error");

        println!("Proof verification result: {}", is_valid);
        assert!(is_valid, "Proof should be valid!");
    }
}