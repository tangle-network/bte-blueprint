pub mod bte;
pub(crate) mod bte_state_machine;
pub mod context;
pub mod elliptic_ark_bls;
pub mod hasher;
pub mod keygen;
pub(crate) mod keygen_state_machine;
pub mod signing;
pub(crate) mod signing_state_machine;

const META_SALT: &str = "bls-protocol";
/// Helper function to compute deterministic hashes for the BLS processes.
/// Note: for signing, the "call_id" should be the call_id of the preceeding
/// keygen job
pub fn compute_deterministic_hashes(
    n: u16,
    blueprint_id: u64,
    call_id: u64,
    salt: &'static str,
) -> ([u8; 32], [u8; 32]) {
    let meta_hash = gadget_sdk::compute_sha256_hash!(
        n.to_be_bytes(),
        blueprint_id.to_be_bytes(),
        call_id.to_be_bytes(),
        META_SALT
    );

    let deterministic_hash = gadget_sdk::compute_sha256_hash!(meta_hash.as_ref(), salt);

    (meta_hash, deterministic_hash)
}
