use crate::context::BteContext;
use crate::keygen_state_machine::Msg;
use api::services::events::JobCalled;
use blueprint_sdk::alloy::primitives::Address;
use blueprint_sdk::alloy::providers::{ProviderBuilder, WsConnect};
use blueprint_sdk::crypto::hashing::keccak_256;
use blueprint_sdk::event_listeners::tangle::events::TangleEventListener;
use blueprint_sdk::event_listeners::tangle::services::{services_post_processor, services_pre_processor};
use blueprint_sdk::logging::info;
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::service::BlueprintServiceManager;
use blueprint_sdk::{self as sdk, job};
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::networking::InstanceMsgPublicKey;
use color_eyre::Result;
use round_based::PartyIndex;
use sdk::contexts::tangle::TangleClientContext;
use sdk::logging;
use sdk::error::Error;
use sdk::tangle_subxt::tangle_testnet_runtime::api;
use std::collections::{BTreeMap, HashMap};

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
pub async fn keygen(t: u16, context: BteContext) -> Result<Vec<u8>, Error> {
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

    let parties: HashMap<u16, InstanceMsgPublicKey> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as PartyIndex, InstanceMsgPublicKey(ecdsa)))
        .collect();

    let n = parties.len() as u16;
    let i = i as u16;

    info!("Starting BTE Keygen for party {i}, n={n}, t={t}");

    let network = RoundBasedNetworkAdapter::<Msg>::new(
        context.network_handle,
        i,
        parties.clone(),
        crate::context::BLS_BTE_NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    let output = crate::keygen_state_machine::bte_keygen_protocol(party, i, t, n, call_id).await?;

    info!("Ending BTE Keygen for party {i}, n={n}, t={t}");

    let public_key = output
        .uncompressed_pk
        .clone()
        .ok_or_else(|| KeygenError::MpcError("Public key missing".to_string()))?;

    // Store the results
    let store_key = hex::encode(keccak_256(
        format!("keygen-{}:{}", blueprint_id, call_id).as_bytes(),
    ));
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

impl From<KeygenError> for Error {
    fn from(err: KeygenError) -> Self {
        Error::Other(err.to_string())
    }
}
