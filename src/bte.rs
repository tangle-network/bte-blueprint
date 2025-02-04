use std::collections::BTreeMap;

use crate::context::BteContext;
use abi::Abi;
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use batch_threshold::encryption::Ciphertext;
use ethers::prelude::*;
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

use serde_json::Value;
use sha3::Keccak256;
use sp_core::ecdsa::Public;
use std::convert::TryFrom;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Context error: {0}")]
    ContextError(String),
    #[error("Key retrieval error: {0}")]
    KeyRetrievalError(String),
    #[error("MPC error: {0}")]
    MpcError(String),
}

/// Configuration constants for the BTE signing process
const SIGNING_SALT: &str = "bte-signing";

impl From<SigningError> for GadgetError {
    fn from(err: SigningError) -> Self {
        GadgetError::Other(err.to_string())
    }
}

#[job(
    id = 1,
    params(keygen_call_id, eid),
    event_listener(
        listener = TangleEventListener<BteContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Decrypt a batch of message using the BTE protocol with a previously generated key
///
/// # Arguments
/// * `context` - The DFNS context containing network and storage configuration
///
/// # Returns
/// Returns the signature as a byte vector on success
///
/// # Errors
/// Returns an error if:
/// - Failed to retrieve blueprint ID or call ID
/// - Failed to retrieve the key entry
/// - Signing process failed
pub async fn bte(
    keygen_call_id: u64,
    eid: u64,
    context: BteContext,
) -> Result<Vec<u8>, GadgetError> {
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let call_id = context
        .current_call_id()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    // Setup party information
    let (i, operators) = context
        .get_party_index_and_operators()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();

    let n = parties.len() as u16;
    let i = i as u16;

    // Compute hash for key retrieval. Must use the call_id of the keygen job
    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, keygen_call_id, SIGNING_SALT);

    // Retrieve the key entry
    let store_key = hex::encode(meta_hash);
    let mut state = context
        .store
        .get(&store_key)
        .ok_or_else(|| SigningError::KeyRetrievalError("Key entry not found".to_string()))?;

    let t = state.t;

    gadget_sdk::info!(
        "Starting BTE partial decryption for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i,
        deterministic_hash,
        parties.clone(),
    );

    let party = round_based::party::MpcParty::connected(network);

    let batch_size = context.crs.powers_of_g.len();
    let tx_domain = Radix2EvaluationDomain::<ark_bls12_381::Fr>::new(batch_size).unwrap();

    let msg = [1u8; 32];
    // hash eid to G1 get hid
    let hasher = MapToCurveBasedHasher::<
        ark_bls12_381::G1Projective,
        DefaultFieldHasher<Keccak256>,
        WBMap<ark_bls12_381::g1::Config>,
    >::new(b"")
    .unwrap();

    let hid = hasher.hash(&eid.to_le_bytes()).unwrap();

    let pk = ark_bls12_381::G2Projective::deserialize_compressed(
        &*state.uncompressed_pk.clone().unwrap(),
    )
    .unwrap();

    // get the ciphertexts from an RPC end point. Ideally the nodes operating the chain can just look at their local view

    // download ciphertexts using cast call 0xb4B46bdAA835F8E4b4d8e208B6559cD267851051 "getData(uint64 index)" eid --rpc-url "http://127.0.0.1:32845"
    let rpc_url_path = "rpc_url.txt";
    let rpc_url = std::fs::read_to_string(rpc_url_path).expect("Failed to read RPC URL from file");
    let rpc_url = rpc_url.trim(); // Remove any trailing newline characters
    let provider = Provider::<Http>::try_from(rpc_url).unwrap();

    // read the json file
    let json_path = "contracts/out/SecureStorage.sol/SecureStorage.json";

    // Read the JSON file
    let json = std::fs::read_to_string(json_path)
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    // Parse the JSON as a map
    let parsed_json: Value = serde_json::from_str(&json).unwrap();

    // Get the ABI from the JSON
    let abi: Abi = serde_json::from_value(parsed_json["abi"].clone()).unwrap();

    // Define the contract address
    let contract_address_path = "deployed_address.txt";
    let contract_address = std::fs::read_to_string(contract_address_path)
        .expect("Failed to read contract address from file");
    let contract_address = contract_address.trim(); // Remove any trailing newline characters
    let contract_address = contract_address.parse::<Address>().unwrap();

    // Create a new contract instance
    let contract: ContractInstance<std::sync::Arc<Provider<Http>>, _> =
        Contract::new(contract_address, abi, provider.into());

    // Call the `dataStore` mapping
    let ct_bytes: Bytes = contract
        .method::<_, Bytes>("dataStore", eid)
        .unwrap()
        .call()
        .await
        .unwrap();

    let ct = Vec::<Ciphertext<ark_bls12_381::Bls12_381>>::deserialize_compressed(&*ct_bytes.0)
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let output =
        crate::bte_state_machine::bte_pd_protocol(party, i, n, &mut state, &ct, &context.crs, eid)
            .await?;

    // finish decryption
    let recovered_msg = output.recover_messages(&ct, hid.into(), &context.crs);
    for i in 0..batch_size {
        assert_eq!(recovered_msg[i], msg);
    }

    gadget_sdk::info!(
        "Ending BTE partial decryption for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let signature = output
        .signature
        .ok_or_else(|| SigningError::KeyRetrievalError("Signature not found".to_string()))?;

    let mut signature_bytes = Vec::new();
    signature
        .serialize_compressed(&mut signature_bytes)
        .unwrap();
    // For now, return a placeholder
    Ok(signature_bytes)
}
