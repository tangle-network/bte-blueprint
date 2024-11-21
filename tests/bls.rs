#[cfg(test)]
mod e2e {
    use api::runtime_types::tangle_primitives::services::field::Field;
    use bls_blueprint::keygen::KEYGEN_JOB_ID;
    use bls_blueprint::signing::SIGN_JOB_ID;
    use blueprint_test_utils::test_ext::*;
    use blueprint_test_utils::*;
    use cargo_tangle::deploy::Opts;
    use gadget_sdk::error;
    use gadget_sdk::info;
    use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api;
    use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;

    pub fn setup_testing_log() {
        use tracing_subscriber::util::SubscriberInitExt;
        let env_filter = tracing_subscriber::EnvFilter::from_default_env();
        let _ = tracing_subscriber::fmt::SubscriberBuilder::default()
            .without_time()
            .with_target(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NONE)
            .with_env_filter(env_filter)
            .with_test_writer()
            .finish()
            .try_init();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::needless_return)]
    async fn keygen() {
        setup_testing_log();
        let tangle = tangle::run().unwrap();
        let base_path = std::env::current_dir().expect("Failed to get current directory");
        let base_path = base_path
            .canonicalize()
            .expect("File could not be normalized");

        let manifest_path = base_path
            .join("Cargo.toml")
            .canonicalize()
            .expect("Cargo.toml not found");

        let ws_port = tangle.ws_port();
        let http_rpc_url = format!("http://127.0.0.1:{ws_port}");
        let ws_rpc_url = format!("ws://127.0.0.1:{ws_port}");

        let opts = Opts {
            pkg_name: option_env!("CARGO_BIN_NAME").map(ToOwned::to_owned),
            http_rpc_url,
            ws_rpc_url,
            manifest_path,
            signer: None,
            signer_evm: None,
        };

        const N: usize = 3;

        new_test_ext_blueprint_manager::<N, 1, _, _, _>("", opts, run_test_blueprint_manager)
            .await
            .execute_with_async(move |client, handles, svcs| async move {
                // At this point, blueprint has been deployed, every node has registered
                // as an operator for the relevant services, and, all gadgets are running

                let keypair = handles[0].sr25519_id().clone();
                let service = &svcs.services[KEYGEN_JOB_ID as usize];

                let service_id = service.id;
                let keygen_call_id = get_next_call_id(client)
                    .await
                    .expect("Failed to get next job id")
                    .saturating_sub(1);

                info!("Submitting job with params service ID: {service_id}, call ID: {keygen_call_id}");

                // Pass the arguments
                let n = Field::Uint16(N as u16);
                let job_args = vec![n];

                // Next step: submit a job under that service/job id
                if let Err(err) =
                    submit_job(client, &keypair, service_id, KEYGEN_JOB_ID, job_args).await
                {
                    error!("Failed to submit job: {err}");
                    panic!("Failed to submit job: {err}");
                }

                // Step 2: wait for the job to complete
                let job_results =
                    wait_for_completion_of_tangle_job(client, service_id, keygen_call_id, N - 1)
                        .await
                        .expect("Failed to wait for job completion");

                // Step 3: Get the job results, compare to expected value(s)
                assert_eq!(job_results.service_id, service_id);
                assert_eq!(job_results.call_id, keygen_call_id);
                assert!(matches!(job_results.result[0], Field::Bytes(_)));

                // Now, run a signing job
                let service = &svcs.services[SIGN_JOB_ID as usize];

                let service_id = service.id;
                let call_id = get_next_call_id(client)
                    .await
                    .expect("Failed to get next job id")
                    .saturating_sub(1);

                info!("Submitting job with params service ID: {service_id}, call ID: {call_id}");

                // Pass the arguments
                let n = Field::Uint16(N as u16);
                let keygen_call_id = Field::Uint64(keygen_call_id);
                let message = Field::Bytes(BoundedVec(vec![1, 2, 3]));
                let job_args = vec![n, keygen_call_id, message];

                // Next step: submit a job under that service/job id
                if let Err(err) =
                    submit_job(client, &keypair, service_id, SIGN_JOB_ID, job_args).await
                {
                    error!("Failed to submit job: {err}");
                    panic!("Failed to submit job: {err}");
                }

                // Step 2: wait for the job to complete
                let job_results =
                    wait_for_completion_of_tangle_job(client, service_id, call_id, N - 1)
                        .await
                        .expect("Failed to wait for job completion");

                // Step 3: Get the job results, compare to expected value(s)
                assert_eq!(job_results.service_id, service_id);
                assert_eq!(job_results.call_id, call_id);
                assert!(matches!(job_results.result[0], Field::Bytes(_)));
            })
            .await;
    }
}
