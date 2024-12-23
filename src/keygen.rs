use crate::context::BteContext;
use gadget_sdk::{
    event_listener::tangle::{
        jobs::{services_post_processor, services_pre_processor},
        TangleEventListener,
    },
    job,
    network::round_based_compat::NetworkDeliveryWrapper,
    tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled,
    Error as GadgetError,
};
use sp_core::ecdsa::Public;
use std::collections::BTreeMap;

#[job(
    id = 0,
    params(t),
    event_listener(
        listener = TangleEventListener<BteContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Runs a distributed key generation (DKG) process for the BTE protocol
///
/// # Arguments
/// * `t` - Threshold value for the DKG process
/// * `context` - The DFNS context containing network and storage configuration
///
/// # Returns
/// Returns the generated public key as a byte vector on success
///
/// # Errors
/// Returns an error if:
/// - Failed to retrieve blueprint ID or call ID
/// - Failed to get party information
/// - MPC protocol execution failed
/// - Serialization of results failed
pub async fn keygen(t: u16, context: BteContext) -> Result<Vec<u8>, GadgetError> {
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;
    let call_id = context
        .current_call_id()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    // Setup party information
    let (i, operators) = context
        .get_party_index_and_operators()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();

    let n = parties.len() as u16;
    let i = i as u16;

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, KEYGEN_SALT);

    gadget_sdk::info!(
        "Starting BTE Keygen for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i,
        deterministic_hash,
        parties.clone(),
    );

    let party = round_based::party::MpcParty::connected(network);

    let output = crate::keygen_state_machine::bte_keygen_protocol(party, i, t, n, call_id).await?;

    gadget_sdk::info!(
        "Ending BTE Keygen for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let public_key = output
        .uncompressed_pk
        .clone()
        .ok_or_else(|| KeygenError::MpcError("Public key missing".to_string()))?;

    // Store the results
    let store_key = hex::encode(meta_hash);
    context.store.set(&store_key, output);

    Ok(public_key)
}

/// Configuration constants for the BTE keygen process
const KEYGEN_SALT: &str = "bls-keygen";

/// Error type for keygen-specific operations
#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("Failed to serialize data: {0}")]
    SerializationError(String),

    #[error("MPC protocol error: {0}")]
    MpcError(String),

    #[error("Context error: {0}")]
    ContextError(String),

    #[error("Delivery error: {0}")]
    DeliveryError(String),
}

impl From<KeygenError> for GadgetError {
    fn from(err: KeygenError) -> Self {
        GadgetError::Other(err.to_string())
    }
}
