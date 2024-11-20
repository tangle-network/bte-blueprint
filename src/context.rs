use color_eyre::eyre;
use gadget_sdk as sdk;
use gadget_sdk::ext::subxt::tx::Signer;
use gadget_sdk::network::NetworkMultiplexer;
use gadget_sdk::store::LocalDatabase;
use gadget_sdk::subxt_core::ext::sp_core::ecdsa;
use gadget_sdk::subxt_core::utils::AccountId32;
use sdk::ctx::{KeystoreContext, ServicesContext, TangleClientContext};
use sdk::tangle_subxt::tangle_testnet_runtime::api;
use sp_core::ecdsa::Public;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::state_machine::BlsState;

/// The network protocol version for the BLS service
const NETWORK_PROTOCOL: &str = "/bls/gennaro/1.0.0";

/// BLS Service Context that holds all the necessary context for the service
/// to run. This structure implements various traits for keystore, client, and service
/// functionality.
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext)]
pub struct BlsContext {
    #[config]
    pub config: sdk::config::StdGadgetConfiguration,
    pub network_backend: Arc<NetworkMultiplexer>,
    pub store: Arc<LocalDatabase<BlsState>>,
    pub identity: ecdsa::Pair,
}

// Core context management implementation
impl BlsContext {
    /// Creates a new service context with the provided configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - Network initialization fails
    /// - Configuration is invalid
    pub fn new(config: sdk::config::StdGadgetConfiguration) -> eyre::Result<Self> {
        let network_config = config
            .libp2p_network_config(NETWORK_PROTOCOL)
            .map_err(|err| eyre::eyre!("Failed to create network configuration: {err}"))?;

        let identity = network_config.ecdsa_key.clone();
        let gossip_handle = sdk::network::setup::start_p2p_network(network_config)
            .map_err(|err| eyre::eyre!("Failed to start the P2P network: {err}"))?;

        let keystore_dir = PathBuf::from(config.keystore_uri.clone()).join("bls.json");
        let store = Arc::new(LocalDatabase::open(keystore_dir));

        Ok(Self {
            store,
            identity,
            config,
            network_backend: Arc::new(NetworkMultiplexer::new(gossip_handle)),
        })
    }

    /// Returns a reference to the configuration
    #[inline]
    pub fn config(&self) -> &sdk::config::StdGadgetConfiguration {
        &self.config
    }

    /// Returns a clone of the store handle
    #[inline]
    pub fn store(&self) -> Arc<LocalDatabase<BlsState>> {
        self.store.clone()
    }

    /// Returns the network protocol version
    #[inline]
    pub fn network_protocol(&self) -> &str {
        NETWORK_PROTOCOL
    }
}

// Protocol-specific implementations
impl BlsContext {
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
    ) -> eyre::Result<BTreeMap<AccountId32, ecdsa::Public>> {
        let client = self.tangle_client().await?;
        let current_blueprint = self.blueprint_id()?;
        let current_service_op = self.current_service_operators(&client).await?;
        let storage = client.storage().at_latest().await?;

        let mut map = BTreeMap::new();
        for (operator, _) in current_service_op {
            let addr = api::storage()
                .services()
                .operators(current_blueprint, &operator);

            let maybe_pref = storage.fetch(&addr).await.map_err(|err| {
                eyre::eyre!("Failed to fetch operator storage for {operator}: {err}")
            })?;

            if let Some(pref) = maybe_pref {
                map.insert(operator, ecdsa::Public(pref.key));
            } else {
                return Err(eyre::eyre!("Missing ECDSA key for operator {operator}"));
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
