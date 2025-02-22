use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blueprint_sdk as sdk;
use blueprint_sdk::ext::subxt::tx::Signer;
use blueprint_sdk::macros::core::Gadget;
use blueprint_sdk::networking::service_handle::NetworkServiceHandle;
use blueprint_sdk::networking::InstanceMsgPublicKey;
use blueprint_sdk::stores::local_database::LocalDatabase;
use sdk::clients::GadgetServicesClient;
use sdk::config::GadgetConfiguration;
use sdk::contexts::keystore::KeystoreContext;
use sdk::contexts::tangle::TangleClientContext;
use sdk::crypto::sp_core::SpSr25519;
use sdk::crypto::tangle_pair_signer::sp_core;
use sdk::keystore::backends::Backend;
use sdk::logging;
use sdk::macros::contexts::{KeystoreContext, ServicesContext, TangleClientContext};
use sdk::tangle_subxt;
use sdk::tangle_subxt::tangle_testnet_runtime::api;
use sp_core::ecdsa;
use sp_core::ecdsa::Public;
use std::collections::btree_map::BTreeMap;
use std::collections::hash_set::HashSet;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tangle_subxt::subxt_core::utils::AccountId32;

use crate::keygen_state_machine::BteState;
use std::fs::File;
use std::io::Read;

/// The network protocol version for the BLS service
const NETWORK_PROTOCOL: &str = "/bls/gennaro/1.0.0";

/// BTE Service Context that holds all the necessary context for the service
/// to run. This structure implements various traits for keystore, client, and service
/// functionality.
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext)]
pub struct BteContext {
    #[config]
    pub config: GadgetConfiguration,
    #[call_id]
    pub call_id: Option<u64>,
    pub store: Arc<LocalDatabase<BteState>>,
    pub identity: ecdsa::Pair,
    pub crs: batch_threshold::dealer::CRS<ark_bls12_381::Bls12_381>,
    pub network_handle: Arc<NetworkServiceHandle>,
}

// Core context management implementation
impl BteContext {
    /// Creates a new service context with the provided configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - Network initialization fails
    /// - Configuration is invalid
    pub fn new(config: GadgetConfiguration) -> eyre::Result<Self> {
        let operator_keys: HashSet<InstanceMsgPublicKek> = config
            .tangle_client()
            .await?
            .get_operators()
            .await?
            .values()
            .map(|key| InstanceMsgPublicKey(*key))
            .collect();

        let network_config = config.libp2p_network_config(NETWORK_PROTOCOL)?;
        let identity = network_config.instance_key_pair.0.clone();

        let network_backend = config.libp2p_start_network(network_config, operator_keys)?;
        let keystore_dir = PathBuf::from(config.keystore_uri.clone()).join("bls.json");
        let store = Arc::new(LocalDatabase::open(keystore_dir));

        // todo: read the crs from file
        let crs_path = "crs.dat";
        let crs = if Path::new(crs_path).exists() {
            println!("Reading CRS from file");
            let mut crs_file = File::open(crs_path)
                .map_err(|err| eyre::eyre!("Failed to open CRS file: {err}"))?;
            let mut crs_bytes = Vec::new();
            crs_file
                .read_to_end(&mut crs_bytes)
                .map_err(|err| eyre::eyre!("Failed to read CRS file: {err}"))?;

            batch_threshold::dealer::CRS::<ark_bls12_381::Bls12_381>::deserialize_compressed(
                &crs_bytes[..],
            )
            .map_err(|err| eyre::eyre!("Failed to deserialize CRS: {err}"))?
        } else {
            // todo: change this to download a crs that has been setup via a decentralized process
            let batch_size = 32;
            let mut dealer = batch_threshold::dealer::Dealer::new(batch_size, 1, 1);
            let (crs, _) = dealer.setup(&mut ark_std::test_rng());
            let mut crs_bytes = Vec::new();
            crs.serialize_compressed(&mut crs_bytes)
                .map_err(|err| eyre::eyre!("Failed to serialize CRS: {err}"))?;

            std::fs::write(&crs_path, crs_bytes)
                .map_err(|err| eyre::eyre!("Failed to write CRS file: {err}"))?;
            crs
        };

        Ok(Self {
            store,
            identity,
            call_id: None,
            config,
            network_handle: Arc::new(network_backend),
            crs,
        })
    }

    /// Returns a reference to the configuration
    #[inline]
    pub fn config(&self) -> &GadgetConfiguration {
        &self.config
    }

    /// Returns a clone of the store handle
    #[inline]
    pub fn store(&self) -> Arc<LocalDatabase<BteState>> {
        self.store.clone()
    }

    /// Returns the network protocol version
    #[inline]
    pub fn network_protocol(&self) -> &str {
        NETWORK_PROTOCOL
    }
}

// Protocol-specific implementations
impl BteContext {
    /// Retrieves the current blueprint ID from the configuration
    ///
    /// # Errors
    /// Returns an error if the blueprint ID is not found in the configuration
    pub fn blueprint_id(&self) -> eyre::Result<u64> {
        self.config()
            .protocol_specific
            .tangle()
            .map(|c| c.blueprint_id)
            .map_err(|err| eyre::eyre!("Blueprint ID not found in configuration: {err}"))
    }

    /// Retrieves the current party index and operator mapping
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to retrieve operator keys
    /// - Current party is not found in the operator list
    pub async fn get_party_index_and_operators(
        &self,
    ) -> eyre::Result<(usize, BTreeMap<AccountId32, Public>)> {
        let parties = self.current_service_operators_ecdsa_keys().await?;
        let my_id = self.config.first_sr25519_signer()?.account_id();

        gadget_sdk::trace!(
            "Looking for {my_id:?} in parties: {:?}",
            parties.keys().collect::<Vec<_>>()
        );

        let index_of_my_id = parties
            .iter()
            .position(|(id, _)| id == &my_id)
            .ok_or_else(|| eyre::eyre!("Party not found in operator list"))?;

        Ok((index_of_my_id, parties))
    }

    /// Retrieves the ECDSA keys for all current service operators
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to connect to the Tangle client
    /// - Failed to retrieve operator information
    /// - Missing ECDSA key for any operator
    pub async fn current_service_operators_ecdsa_keys(
        &self,
    ) -> Result<BTreeMap<AccountId32, Public>> {
        let client = self.tangle_client().await?;
        let current_blueprint = self.blueprint_id()?;
        let storage = client.storage().at_latest().await?;

        let mut map = BTreeMap::new();
        for (operator, _) in client.get_operators().await? {
            let addr = api::storage()
                .services()
                .operators(current_blueprint, &operator);

            let maybe_pref = storage
                .fetch(&addr)
                .await
                .map_err(|err| eyre!("Failed to fetch operator storage for {operator}: {err}"))?;

            if let Some(pref) = maybe_pref {
                let public_key = Public::from_full(pref.key.as_slice())
                    .map_err(|_| Report::msg("Invalid key"))?;
                map.insert(operator, public_key);
            } else {
                return Err(eyre!("Missing ECDSA key for operator {operator}"));
            }
        }

        Ok(map)
    }

    /// Retrieves the current call ID for this job
    ///
    /// # Errors
    /// Returns an error if failed to retrieve the call ID from storage
    pub async fn current_call_id(&self) -> eyre::Result<u64> {
        let client = self.tangle_client().await?;
        let addr = api::storage().services().next_job_call_id();
        let storage = client.storage().at_latest().await?;

        let maybe_call_id = storage
            .fetch_or_default(&addr)
            .await
            .map_err(|err| eyre::eyre!("Failed to fetch current call ID: {err}"))?;

        Ok(maybe_call_id.saturating_sub(1))
    }
}
