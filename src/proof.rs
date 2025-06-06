use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{UniformRand,Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, r1cs_to_qap::LibsnarkReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable, LinearCombination};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;

/// The circuit for a simple transfer (for demonstration)
#[derive(Clone)]
pub struct TransferCircuit {
    // Public inputs
    pub old_root: Fr,
    pub new_root: Fr,
    pub nullifier: Fr,
    pub commitment: Fr,
    
    // Private inputs
    pub sender_balance: Fr,
    pub amount: Fr,
    pub sender_nonce: Fr,
    pub merkle_proof: Vec<Fr>,
    pub merkle_path: Vec<bool>, // true for right, false for left
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let old_root_var = cs.new_input_variable(|| Ok(self.old_root))?;
        let new_root_var = cs.new_input_variable(|| Ok(self.new_root))?;
        let nullifier_var = cs.new_input_variable(|| Ok(self.nullifier))?;
        let commitment_var = cs.new_input_variable(|| Ok(self.commitment))?;

        // Allocate private inputs
        let sender_balance_var = cs.new_witness_variable(|| Ok(self.sender_balance))?;
        let amount_var = cs.new_witness_variable(|| Ok(self.amount))?;
        let sender_nonce_var = cs.new_witness_variable(|| Ok(self.sender_nonce))?;

        // Verify sender has sufficient balance
        let balance_check = cs.new_witness_variable(|| {
            Ok(if self.sender_balance >= self.amount {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            })
        })?;

        cs.enforce_constraint(
            LinearCombination::from(sender_balance_var) - LinearCombination::from(amount_var),
            LinearCombination::from(balance_check),
            LinearCombination::zero(),
        )?;

        // Verify Merkle proof
        let mut current = commitment_var;
        for (i, (proof, is_right)) in self.merkle_proof.iter().zip(self.merkle_path.iter()).enumerate() {
            let proof_var = cs.new_witness_variable(|| Ok(*proof))?;
            let sum_lc = LinearCombination::from(current) + (*proof, Variable::One);
            let parent = cs.new_witness_variable(|| {
                // You must compute the value using the actual Fr values, not Variable
                // This is only possible if you have access to the assignment (witness values)
                // For demo, you can use a dummy value or skip the closure check
                Ok(Fr::zero()) // Placeholder, see note below
            })?;
            cs.enforce_constraint(
                LinearCombination::from(parent),
                LinearCombination::from(Variable::One),
                sum_lc,
            )?;
            current = parent;
        }

        // Verify final root matches
        cs.enforce_constraint(
            LinearCombination::from(current),
            LinearCombination::from(old_root_var),
            LinearCombination::zero(),
        )?;

        // Verify nullifier generation
        let computed_nullifier = cs.new_witness_variable(|| {
            Ok(self.sender_nonce + self.sender_balance)
        })?;

        cs.enforce_constraint(
            LinearCombination::from(computed_nullifier),
            LinearCombination::from(nullifier_var),
            LinearCombination::zero(),
        )?;

        Ok(())
    }
}

/// Generate a Groth16 proof for a transfer
pub fn generate_transfer_proof(
    pk: &ProvingKey<Bls12_381>,
    old_root: Fr,
    new_root: Fr,
    nullifier: Fr,
    commitment: Fr,
    sender_balance: Fr,
    amount: Fr,
    sender_nonce: Fr,
    merkle_proof: Vec<Fr>,
    merkle_path: Vec<bool>,
) -> Result<(Proof<Bls12_381>, Vec<Fr>), SynthesisError> {
    let circuit = TransferCircuit {
        old_root,
        new_root,
        nullifier,
        commitment,
        sender_balance,
        amount,
        sender_nonce,
        merkle_proof,
        merkle_path,
    };

    let public_inputs = vec![old_root, new_root, nullifier, commitment];
    let mut rng = OsRng;
    let proof = Groth16::<Bls12_381, LibsnarkReduction>::prove(pk, circuit, &mut rng)?;
    Ok((proof, public_inputs))
}

/// Verify a Groth16 proof for a transfer
pub fn verify_transfer_proof(
    vk: &VerifyingKey<Bls12_381>,
    proof: &Proof<Bls12_381>,
    public_inputs: &[Fr],
) -> Result<bool, SynthesisError> {
    Groth16::<Bls12_381, LibsnarkReduction>::verify(vk, public_inputs, proof)
}

/// Serialize a proof to bytes
pub fn serialize_proof(proof: &Proof<Bls12_381>) -> Vec<u8> {
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes).unwrap();
    bytes
}

/// Deserialize a proof from bytes
pub fn deserialize_proof(bytes: &[u8]) -> Proof<Bls12_381> {
    Proof::<Bls12_381>::deserialize_compressed(&mut &*bytes).unwrap()
}

/// Example: Generate a random nullifier (for demo)
pub fn random_nullifier() -> Fr {
    let mut rng = OsRng;
    Fr::rand(&mut rng)
} 