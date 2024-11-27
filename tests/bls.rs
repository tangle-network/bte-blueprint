#[cfg(test)]
mod e2e {
    use std::sync::atomic::AtomicU64;

    use bls_blueprint::keygen::KEYGEN_JOB_ID;
    use bls_blueprint::signing::SIGN_JOB_ID;
    use blueprint_test_utils::*;
    use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::field::BoundedString;

    const N: usize = 3;
    const T: usize = 3;

    // The macro takes this variable as an argument, and will update it so that
    // when we pass the signing arguments, we can pass the associated keygen call id
    static KEYGEN_CALL_ID: AtomicU64 = AtomicU64::new(0);

    mpc_generate_keygen_and_signing_tests!(
        "./",
        N,
        T,
        KEYGEN_JOB_ID,
        [InputValue::Uint16(N as _)],
        [],
        SIGN_JOB_ID,
        [
            InputValue::Uint16(N as _),
            InputValue::Uint64(KEYGEN_CALL_ID.load(std::sync::atomic::Ordering::SeqCst)),
            InputValue::Bytes(BoundedVec(vec![1, 2, 3]))
        ],
        [],
        KEYGEN_CALL_ID,
    );
}
