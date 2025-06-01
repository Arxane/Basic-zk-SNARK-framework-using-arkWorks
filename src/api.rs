use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{State, Path},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::mempool::Mempool;
use ark_std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTransactionRequest {
    pub old_root: String,
    pub new_root: String,
    pub nullifier: String,
    pub commitment: String,
    pub proof: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub nullifier: String,
    pub status: String,
}

pub struct AppState {
    mempool: Arc<Mempool>,
}

pub fn create_router(mempool: Arc<Mempool>) -> Router {
    let state = Arc::new(AppState { mempool });
    
    Router::new()
        .route("/api/transactions", post(create_transaction))
        .route("/api/transactions/:nullifier", get(get_transaction))
        .route("/api/transactions", get(list_transactions))
        .with_state(state)
}

async fn create_transaction(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateTransactionRequest>,
) -> Result<Json<TransactionResponse>, StatusCode> {
    // Convert string fields to Fr
    let old_root = ark_bls12_381::Fr::from_str(&payload.old_root)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let new_root = ark_bls12_381::Fr::from_str(&payload.new_root)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let nullifier = ark_bls12_381::Fr::from_str(&payload.nullifier)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let commitment = ark_bls12_381::Fr::from_str(&payload.commitment)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let _tx = crate::mempool::Transaction {
        old_root,
        new_root,
        nullifier,
        commitment,
        proof: payload.proof,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    state.mempool
        .add_transaction(_tx)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(TransactionResponse {
        nullifier: payload.nullifier,
        status: "pending".to_string(),
    }))
}

async fn get_transaction(
    State(state): State<Arc<AppState>>,
    Path(nullifier): Path<String>,
) -> Result<Json<TransactionResponse>, StatusCode> {
    let nullifier = ark_bls12_381::Fr::from_str(&nullifier)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let _tx = state.mempool
        .get_transaction(&nullifier)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(TransactionResponse {
        nullifier: nullifier.to_string(),
        status: "confirmed".to_string(),
    }))
}

async fn list_transactions(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<TransactionResponse>> {
    let transactions = state.mempool.get_all_transactions();
    
    Json(transactions
        .into_iter()
        .map(|tx| TransactionResponse {
            nullifier: tx.nullifier.to_string(),
            status: "confirmed".to_string(),
        })
        .collect())
} 