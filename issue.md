Title: How to handle Variable and Fr operations in R1CS constraints for Merkle proof verification

I'm implementing a Merkle proof verification circuit using arkworks and encountering issues with variable operations. The circuit is part of a private asset transfer system using zkSNARKs.

## Current Implementation

```rust
use ark_bls12_381::{Bls12_381, Fr};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable, LinearCombination};

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
        // ... other constraints ...

        // Verify Merkle proof
        let mut current = commitment_var;
        for (proof, is_right) in self.merkle_proof.iter().zip(self.merkle_path.iter()) {
            let proof_var = cs.new_witness_variable(|| Ok(*proof))?;
            let parent = cs.new_witness_variable(|| {
                if *is_right {
                    Ok(current + *proof)  // Error: cannot add `Fp<MontBackend<FrConfig, 4>, 4>` to `Variable`
                } else {
                    Ok(*proof + current)  // Error: cannot add `Variable` to `Fp<MontBackend<FrConfig, 4>, 4>`
                }
            })?;
            current = parent;
        }
    }
}
```

## Error Messages

```
cannot add `Fp<MontBackend<FrConfig, 4>, 4>` to `Variable`
cannot add `Variable` to `Fp<MontBackend<FrConfig, 4>, 4>`
the trait `Add<Variable>` is not implemented for `Fp<MontBackend<FrConfig, 4>, 4>`
```

## Questions

1. What's the correct way to add a `Variable` with an `Fr` value in a constraint system?
2. How should we handle Merkle proof verification where we need to combine variables with field elements?
3. Is there an example of Merkle proof verification in the arkworks repository that we can reference?

## Attempted Solutions

I've tried:
1. Using `LinearCombination` to combine variables
2. Using `cs.enforce_constraint()` to create the relationship
3. Converting between `Variable` and `Fr` types

None of these approaches have worked so far. Any guidance or examples would be greatly appreciated.

## Environment

- arkworks-rs version: Latest from crates.io
- Rust version: 1.75.0
- OS: Windows 10 