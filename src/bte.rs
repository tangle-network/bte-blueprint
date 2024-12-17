use std::collections::BTreeMap;

use crate::{context::BlsContext, elliptic_ark_bls::convert_bls_to_ark_bls_g1};
use ark_ec::PrimeGroup;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;
use batch_threshold::encryption::Ciphertext;
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

/// Configuration constants for the BLS signing process
const SIGNING_SALT: &str = "bls-signing";

impl From<SigningError> for GadgetError {
    fn from(err: SigningError) -> Self {
        GadgetError::Other(err.to_string())
    }
}

#[job(
    id = 2,
    params(keygen_call_id, message),
    event_listener(
        listener = TangleEventListener<BlsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Signs a message using the BLS protocol with a previously generated key
///
/// # Arguments
/// * `message` - The message to sign as a byte vector
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
    message: Vec<u8>,
    context: BlsContext,
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
        "Starting BLS Signing for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i,
        deterministic_hash,
        parties.clone(),
    );

    let party = round_based::party::MpcParty::connected(network);

    // create dummy ciphertexts and get a partial decryption for the batch

    let batch_size = context.crs.powers_of_g.len();
    // println!("batch_size: {}", batch_size);
    let tx_domain = Radix2EvaluationDomain::<ark_bls12_381::Fr>::new(batch_size).unwrap();

    let msg = [1u8; 32];
    let hid = ark_bls12_381::G1Projective::generator();

    // let as_pk = snowbridge_milagro_bls::PublicKey::from_uncompressed_bytes(
    //     &state.uncompressed_pk.clone().unwrap()[1..],
    // )
    // .map_err(|e| SigningError::MpcError(format!("Failed to create public key: {e:?}")))?;

    // assert!(as_pk.key_validate());
    // println!("as_pk: {:?}", as_pk);
    // let ark_pk = convert_bls_to_ark_bls_g1(&as_pk.point);
    // println!("ark_pk: {:?}", ark_pk);

    // generate ciphertexts for all points in tx_domain
    // let mut ct: Vec<Ciphertext<ark_bls12_381::Bls12_381>> = Vec::new();
    // for x in tx_domain.elements() {
    //     ct.push(batch_threshold::encryption::encrypt::<
    //         ark_bls12_381::Bls12_381,
    //     >(msg, x, hid, context.crs.htau, pk));
    // }

    // todo: update this
    let delta = ark_bls12_381::G1Projective::generator();

    let output = crate::bte_state_machine::bte_pd_protocol(party, i, n, &mut state, delta).await?;

    gadget_sdk::info!(
        "Ending BLS Signing for party {i}, n={n}, t={t}, eid={}",
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
