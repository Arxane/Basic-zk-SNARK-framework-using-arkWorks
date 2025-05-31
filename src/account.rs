use ark_ff::Field;
use ark_bls12_381::Fr;
use std::collections::HashMap;
use std::sync::RwLock;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
    pub commitment: Fr,
}

#[derive(Debug)]
pub struct AccountSystem {
    accounts: RwLock<HashMap<Fr, Account>>,
    nullifiers: RwLock<HashMap<Fr, bool>>,
    merkle_root: RwLock<Fr>,
}

impl AccountSystem {
    pub fn new() -> Self {
        AccountSystem {
            accounts: RwLock::new(HashMap::new()),
            nullifiers: RwLock::new(HashMap::new()),
            merkle_root: RwLock::new(Fr::zero()),
        }
    }

    pub fn create_account(&self, commitment: Fr, initial_balance: u64) -> Result<(), String> {
        let mut accounts = self.accounts.write().unwrap();
        if accounts.contains_key(&commitment) {
            return Err("Account already exists".to_string());
        }

        accounts.insert(commitment, Account {
            balance: initial_balance,
            nonce: 0,
            commitment,
        });

        self.update_merkle_root();
        Ok(())
    }

    pub fn get_account(&self, commitment: &Fr) -> Option<Account> {
        self.accounts.read().unwrap().get(commitment).cloned()
    }

    pub fn verify_nullifier(&self, nullifier: &Fr) -> bool {
        !self.nullifiers.read().unwrap().contains_key(nullifier)
    }

    pub fn add_nullifier(&self, nullifier: Fr) {
        self.nullifiers.write().unwrap().insert(nullifier, true);
    }

    pub fn get_merkle_root(&self) -> Fr {
        *self.merkle_root.read().unwrap()
    }

    fn update_merkle_root(&self) {
        let accounts = self.accounts.read().unwrap();
        let mut hasher = Sha256::new();
        
        // Sort commitments for deterministic hashing
        let mut commitments: Vec<_> = accounts.keys().collect();
        commitments.sort();

        for commitment in commitments {
            hasher.update(commitment.to_string().as_bytes());
        }

        let result = hasher.finalize();
        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(&result);
        
        *self.merkle_root.write().unwrap() = Fr::from_le_bytes_mod_order(&root_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use ark_std::rand::thread_rng;

    #[test]
    fn test_account_creation() {
        let system = AccountSystem::new();
        let commitment = Fr::rand(&mut thread_rng());
        
        assert!(system.create_account(commitment, 100).is_ok());
        assert!(system.get_account(&commitment).is_some());
    }

    #[test]
    fn test_nullifier_verification() {
        let system = AccountSystem::new();
        let nullifier = Fr::rand(&mut thread_rng());
        
        assert!(system.verify_nullifier(&nullifier));
        system.add_nullifier(nullifier);
        assert!(!system.verify_nullifier(&nullifier));
    }
} 