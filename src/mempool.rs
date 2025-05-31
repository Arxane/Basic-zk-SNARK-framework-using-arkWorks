use ark_bls12_381::Fr;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Transaction {
    pub old_root: Fr,
    pub new_root: Fr,
    pub nullifier: Fr,
    pub commitment: Fr,
    pub proof: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug)]
pub struct Mempool {
    transactions: RwLock<HashMap<Fr, Transaction>>,
    max_size: usize,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Mempool {
            transactions: RwLock::new(HashMap::new()),
            max_size,
        }
    }

    pub fn add_transaction(&self, tx: Transaction) -> Result<(), String> {
        let mut transactions = self.transactions.write().unwrap();
        
        if transactions.len() >= self.max_size {
            return Err("Mempool is full".to_string());
        }

        if transactions.contains_key(&tx.nullifier) {
            return Err("Transaction with this nullifier already exists".to_string());
        }

        transactions.insert(tx.nullifier, tx);
        Ok(())
    }

    pub fn remove_transaction(&self, nullifier: &Fr) -> Option<Transaction> {
        self.transactions.write().unwrap().remove(nullifier)
    }

    pub fn get_transaction(&self, nullifier: &Fr) -> Option<Transaction> {
        self.transactions.read().unwrap().get(nullifier).cloned()
    }

    pub fn get_all_transactions(&self) -> Vec<Transaction> {
        self.transactions.read().unwrap().values().cloned().collect()
    }

    pub fn clear_old_transactions(&self, max_age_seconds: u64) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut transactions = self.transactions.write().unwrap();
        transactions.retain(|_, tx| current_time - tx.timestamp <= max_age_seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use ark_std::rand::thread_rng;

    #[test]
    fn test_add_remove_transaction() {
        let mempool = Mempool::new(100);
        let nullifier = Fr::rand(&mut thread_rng());
        
        let tx = Transaction {
            old_root: Fr::rand(&mut thread_rng()),
            new_root: Fr::rand(&mut thread_rng()),
            nullifier,
            commitment: Fr::rand(&mut thread_rng()),
            proof: vec![1, 2, 3],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        assert!(mempool.add_transaction(tx.clone()).is_ok());
        assert!(mempool.get_transaction(&nullifier).is_some());
        
        let removed = mempool.remove_transaction(&nullifier);
        assert!(removed.is_some());
        assert!(mempool.get_transaction(&nullifier).is_none());
    }
} 