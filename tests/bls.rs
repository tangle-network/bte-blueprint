#[cfg(test)]
mod e2e {
    use std::sync::atomic::AtomicU64;

    use bls_blueprint::keygen::KEYGEN_JOB_ID;
    use bls_blueprint::signing::SIGN_JOB_ID;
    use blueprint_test_utils::*;

    const N: usize = 3;
    const T: usize = 2;

    // The macro takes this variable as an argument, and will update it so that
    // when we pass the signing arguments, we can pass the associated keygen call id
    static KEYGEN_CALL_ID: AtomicU64 = AtomicU64::new(0);

    mpc_generate_keygen_and_signing_tests!(
        "./",
        N,
        T,
        KEYGEN_JOB_ID,
        [InputValue::Uint16(T as u16)],
        [],
        SIGN_JOB_ID,
        [
            InputValue::Uint64(KEYGEN_CALL_ID.load(std::sync::atomic::Ordering::SeqCst)),
            InputValue::List(BoundedVec(vec![
                InputValue::Uint8(1),
                InputValue::Uint8(2),
                InputValue::Uint8(3),
            ]))
        ],
        [],
        KEYGEN_CALL_ID,
    );
}
