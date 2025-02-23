pub mod bte;
pub(crate) mod bte_state_machine;
pub mod context;
pub mod elliptic_ark_bls;
pub mod keygen;
pub(crate) mod keygen_state_machine;

use blueprint_sdk::alloy::sol;
use serde::{Deserialize, Serialize};

sol!(
    #[sol(rpc)]
    #[derive(Debug, Serialize, Deserialize)]
    BteBlueprint,
    "contracts/out/BteBlueprint.sol/BteBlueprint.json",
);
