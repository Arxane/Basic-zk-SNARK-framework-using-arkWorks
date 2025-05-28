// src/lib.rs
use std::collections::HashMap;
use std::ops::Neg;

// Arkworks imports - v0.5.0
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{One, Zero}; // Added PrimeField & UniformRand back for general use
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef,
    LinearCombination, SynthesisError, Variable,
};
use ark_groth16::{
    Groth16,
    ProvingKey as ArkGroth16ProvingKey,
    VerifyingKey as ArkGroth16VerifyingKey,
    Proof as ArkGroth16Proof,
    r1cs_to_qap::LibsnarkReduction,
};
use ark_crypto_primitives::snark::SNARK;
use ark_std::rand::rngs::OsRng;

pub mod parser;
pub use parser::parse_circuit;

pub fn i32_to_fr(val: i32) -> Fr {
    if val < 0 {
        Fr::from((-val) as u64).neg()
    } else {
        Fr::from(val as u64)
    }
}

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

impl Circuit {
    pub fn validate_transfer(&self) -> bool {
        if let Some(sender_balance) = self.inputs.get(&self.sender) {
            *sender_balance >= self.transfer_amount
        } else {
            false
        }
    }

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

    pub fn to_r1cs_system(&self) -> R1CSSystem {
        let mut var_map = HashMap::new();
        var_map.insert("1".to_string(), 0);
        let mut next_r1cs_idx = 1;

        let mut temp_constraints: Vec<_R1CSConstraintInternal> = Vec::new();
        let mut public_input_names: Vec<String> = Vec::new();

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
        let transfer_amount_var_name = "transfer_amount_public".to_string();
        public_input_names.push(transfer_amount_var_name.clone());
        let transfer_amount_idx = get_index(&transfer_amount_var_name, &mut var_map, &mut next_r1cs_idx);
        temp_constraints.push(_R1CSConstraintInternal {
            a: vec![(transfer_amount_idx, Fr::one())].into_iter().collect(),
            b: vec![(var_map["1"], Fr::one())].into_iter().collect(),
            c: vec![(var_map["1"], i32_to_fr(self.transfer_amount))].into_iter().collect(),
        });

        for gate_ref in &self.gates {
            match gate_ref {
                Gate::Add(a, b, c, _modulus) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let c_idx = get_index(c, &mut var_map, &mut next_r1cs_idx);
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx, Fr::one()), (b_idx, Fr::one())].into_iter().collect(),
                        b: vec![(var_map["1"], Fr::one())].into_iter().collect(),
                        c: vec![(c_idx, Fr::one())].into_iter().collect(),
                    });
                }
                Gate::Mul(a, b, c, _modulus) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let c_idx = get_index(c, &mut var_map, &mut next_r1cs_idx);
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx, Fr::one())].into_iter().collect(),
                        b: vec![(b_idx, Fr::one())].into_iter().collect(),
                        c: vec![(c_idx, Fr::one())].into_iter().collect(),
                    });
                }
                Gate::Sub(a, b, c, _modulus) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let c_idx = get_index(c, &mut var_map, &mut next_r1cs_idx);
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx, Fr::one()), (b_idx, Fr::one().neg())].into_iter().collect(),
                        b: vec![(var_map["1"], Fr::one())].into_iter().collect(),
                        c: vec![(c_idx, Fr::one())].into_iter().collect(),
                    });
                }
                Gate::Eq(a, b, out) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let out_idx = get_index(out, &mut var_map, &mut next_r1cs_idx);
                    // First constraint: a - b = diff
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx, Fr::one()), (b_idx, Fr::one().neg())].into_iter().collect(),
                        b: vec![(var_map["1"], Fr::one())].into_iter().collect(),
                        c: vec![(out_idx, Fr::one())].into_iter().collect(),
                    });
                    // Second constraint: diff * diff = 0 (enforces diff = 0)
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(out_idx, Fr::one())].into_iter().collect(),
                        b: vec![(out_idx, Fr::one())].into_iter().collect(),
                        c: vec![(var_map["1"], Fr::zero())].into_iter().collect(),
                    });
                }
                Gate::Hash(input, output) => {
                    let input_idx = get_index(input, &mut var_map, &mut next_r1cs_idx);
                    let output_idx = get_index(output, &mut var_map, &mut next_r1cs_idx);
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(input_idx, Fr::one())].into_iter().collect(),
                        b: vec![(var_map["1"], i32_to_fr(7))].into_iter().collect(),
                        c: vec![(output_idx, Fr::one())].into_iter().collect(),
                    });
                }
                Gate::Const(name, val) => {
                    let idx = get_index(name, &mut var_map, &mut next_r1cs_idx);
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(var_map["1"], i32_to_fr(*val))].into_iter().collect(),
                        b: vec![(var_map["1"], Fr::one())].into_iter().collect(),
                        c: vec![(idx, Fr::one())].into_iter().collect(),
                    });
                }
                Gate::Xor(a, b, c) => {
                    let a_idx = get_index(a, &mut var_map, &mut next_r1cs_idx);
                    let b_idx = get_index(b, &mut var_map, &mut next_r1cs_idx);
                    let ab_var_name = format!("{}_xor_prod_{}", a, b);
                    let ab_idx = get_index(&ab_var_name, &mut var_map, &mut next_r1cs_idx);
                    let c_idx = get_index(c, &mut var_map, &mut next_r1cs_idx);

                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx, Fr::one())].into_iter().collect(),
                        b: vec![(b_idx, Fr::one())].into_iter().collect(),
                        c: vec![(ab_idx, Fr::one())].into_iter().collect(),
                    });
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx, Fr::one()), (b_idx, Fr::one()), (ab_idx, i32_to_fr(-2))].into_iter().collect(),
                        b: vec![(var_map["1"], Fr::one())].into_iter().collect(),
                        c: vec![(c_idx, Fr::one())].into_iter().collect(),
                    });
                    temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(a_idx, Fr::one())].into_iter().collect(),
                        b: vec![(a_idx, Fr::one())].into_iter().collect(),
                        c: vec![(a_idx, Fr::one())].into_iter().collect(),
                    });
                     temp_constraints.push(_R1CSConstraintInternal {
                        a: vec![(b_idx, Fr::one())].into_iter().collect(),
                        b: vec![(b_idx, Fr::one())].into_iter().collect(),
                        c: vec![(b_idx, Fr::one())].into_iter().collect(),
                    });
                }
            }
        }

        R1CSSystem {
            raw_constraints: temp_constraints,
            var_map: var_map.clone(),
            num_variables: next_r1cs_idx,
            num_public_inputs: 1 + public_input_names.len(),
            public_input_names,
        }
    }

    pub fn compute_witness(&self, r1cs_var_map: &HashMap<String, usize>) -> Result<HashMap<usize, Fr>, String> {
        let mut wire_values_by_name: HashMap<String, Fr> = HashMap::new();

        for (name, val) in &self.inputs {
            wire_values_by_name.insert(name.clone(), i32_to_fr(*val));
        }
        wire_values_by_name.insert("1".to_string(), Fr::one());

        let sender_initial_var_name = format!("{}_initial_balance", self.sender);
        if self.inputs.contains_key(&self.sender) {
             wire_values_by_name.insert(
                 sender_initial_var_name.clone(),
                 i32_to_fr(*self.inputs.get(&self.sender).unwrap())
             );
        }

        let receiver_initial_var_name = format!("{}_initial_balance", self.receiver);
         if self.inputs.contains_key(&self.receiver) {
            wire_values_by_name.insert(
                receiver_initial_var_name.clone(),
                i32_to_fr(*self.inputs.get(&self.receiver).unwrap())
            );
        }
        
        let transfer_amount_public_var_name = "transfer_amount_public".to_string();
        wire_values_by_name.insert(
            transfer_amount_public_var_name.clone(),
            i32_to_fr(self.transfer_amount)
        );

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

        let mut witness_by_idx: HashMap<usize, Fr> = HashMap::new();
        for (name, val_fr) in wire_values_by_name {
            if let Some(idx) = r1cs_var_map.get(&name) {
                witness_by_idx.insert(*idx, val_fr);
            }
        }
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

#[derive(Debug, Clone)]
pub struct Proof(ArkGroth16Proof<Bls12_381>);

#[derive(Clone)]
struct Groth16CircuitAdapter {
    r1cs_system: R1CSSystem,
    witness_assignment: Option<HashMap<usize, Fr>>,
}

impl ConstraintSynthesizer<Fr> for Groth16CircuitAdapter {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut cs_vars: HashMap<usize, Variable> = HashMap::new();

        let one_original_idx = *self.r1cs_system.var_map.get("1").ok_or_else(|| {
            eprintln!("[Setup/Prove Allocation Error] Variable '1' not found in var_map.");
            SynthesisError::AssignmentMissing
        })?;
        let one_cs_var = cs.new_input_variable(|| Ok(Fr::one()))?;
        cs_vars.insert(one_original_idx, one_cs_var);

        for name in &self.r1cs_system.public_input_names {
            let original_idx = *self.r1cs_system.var_map.get(name).ok_or_else(|| {
                eprintln!("[Setup/Prove Allocation Error] Public input name '{}' not found in var_map.", name);
                SynthesisError::AssignmentMissing
            })?;
            
            let val = self.witness_assignment.as_ref()
                .and_then(|w| w.get(&original_idx).cloned())
                .unwrap_or_else(|| Fr::zero()); // Use Fr::zero() as dummy for setup if witness is None
            
            let cs_var = cs.new_input_variable(|| Ok(val))?;
            cs_vars.insert(original_idx, cs_var);
        }

        for original_idx in 0..self.r1cs_system.num_variables {
            if !cs_vars.contains_key(&original_idx) {
                let val = self.witness_assignment.as_ref()
                    .and_then(|w| w.get(&original_idx).cloned())
                    .unwrap_or_else(|| {
                        // This path should only be taken during setup. During proving, all witnesses must be present.
                        // If self.witness_assignment is Some (proving) and we still hit this unwrap_or_else,
                        // it means a variable was in var_map but not in witness_assignment.
                        // This shouldn't happen if compute_witness is correct.
                        if self.witness_assignment.is_none() { // Setup phase
                            Fr::zero()
                        } else { // Proving phase - this is an error state
                            let var_name = self.r1cs_system.var_map.iter().find(|(_, &v_idx)| v_idx == original_idx).map(|(k,_)|k.as_str()).unwrap_or("UNKNOWN_PRIV_VAR_IN_PROVE");
                            eprintln!("[PROVE Allocation Error] Private var '{}' (idx {}) missing from witness_assignment.", var_name, original_idx);
                            // This situation should ideally return an Err directly, but the closure needs to return Fr.
                            // The .ok_or_else further up for proving should catch this.
                            // For now, to satisfy type, but this indicates a logic flaw if hit during proving.
                            Fr::zero() // This will lead to an unsatisfied constraint if it's actually used.
                                       // A better approach for proving would be to ensure witness_assignment is complete
                                       // before calling this, or for the `and_then...ok_or_else` to propagate error.
                        }
                    });
                let cs_var = cs.new_witness_variable(|| Ok(val))?;
                cs_vars.insert(original_idx, cs_var);
            }
        }
        
        // Pre-check for constraints (especially for setup)
        for r1cs_constraint_internal in &self.r1cs_system.raw_constraints {
            for (original_idx, _) in &r1cs_constraint_internal.a {
                if !cs_vars.contains_key(original_idx) {
                    let var_name = self.r1cs_system.var_map.iter().find(|(_, &v_idx)| v_idx == *original_idx).map(|(k,_)|k.as_str()).unwrap_or("UNKNOWN_A_TERM_VAR");
                    eprintln!("[Constraint Error] A-term references unallocated original_idx {} (name: {})", original_idx, var_name);
                    return Err(SynthesisError::AssignmentMissing);
                }
            }
            // Similar checks for B and C terms
             for (original_idx, _) in &r1cs_constraint_internal.b {
                 if !cs_vars.contains_key(original_idx) {
                    let var_name = self.r1cs_system.var_map.iter().find(|(_, &v_idx)| v_idx == *original_idx).map(|(k,_)|k.as_str()).unwrap_or("UNKNOWN_B_TERM_VAR");
                    eprintln!("[Constraint Error] B-term references unallocated original_idx {} (name: {})", original_idx, var_name);
                    return Err(SynthesisError::AssignmentMissing);
                }
            }
            for (original_idx, _) in &r1cs_constraint_internal.c {
                 if !cs_vars.contains_key(original_idx) {
                    let var_name = self.r1cs_system.var_map.iter().find(|(_, &v_idx)| v_idx == *original_idx).map(|(k,_)|k.as_str()).unwrap_or("UNKNOWN_C_TERM_VAR");
                    eprintln!("[Constraint Error] C-term references unallocated original_idx {} (name: {})", original_idx, var_name);
                    return Err(SynthesisError::AssignmentMissing);
                }
            }
        }

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

pub fn setup(r1cs_system: &R1CSSystem) -> Result<(ProvingKey, VerifyingKey), SynthesisError> {
    let mut rng = OsRng;
    let circuit_for_setup = Groth16CircuitAdapter {
        r1cs_system: r1cs_system.clone(),
        witness_assignment: None, // No witness values needed for setup
    };

    // Using CircuitSpecificSetupSNARK trait method
    let (pk_internal, vk_internal) =
        Groth16::<Bls12_381, LibsnarkReduction>::circuit_specific_setup(circuit_for_setup, &mut rng)?;
    
    Ok((ProvingKey(pk_internal), VerifyingKey(vk_internal)))
}

pub fn prove(
    r1cs_system: &R1CSSystem,
    pk: &ProvingKey,
    witness_by_original_idx: HashMap<usize, Fr>,
) -> Result<Proof, SynthesisError> {
    let mut rng = OsRng;
    let circuit_for_proving = Groth16CircuitAdapter {
        r1cs_system: r1cs_system.clone(),
        witness_assignment: Some(witness_by_original_idx), // Full witness for proving
    };

    let proof_internal = Groth16::<Bls12_381, LibsnarkReduction>::prove(&pk.0, circuit_for_proving, &mut rng)?;
    Ok(Proof(proof_internal))
}

pub fn verify(
    vk: &VerifyingKey,
    proof: &Proof,
    public_inputs_ordered: &[Fr],
) -> Result<bool, SynthesisError> {
    let pvk_internal = Groth16::<Bls12_381, LibsnarkReduction>::process_vk(&vk.0)?;
    Groth16::<Bls12_381, LibsnarkReduction>::verify_with_processed_vk(&pvk_internal, public_inputs_ordered, &proof.0)
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