use std::sync::atomic::AtomicU64;

use bls_blueprint::keygen::KEYGEN_JOB_ID;
use bls_blueprint::signing::SIGN_JOB_ID;

const N: usize = 3;
const T: usize = 2;

// The macro takes this variable as an argument, and will update it so that
// when we pass the signing arguments, we can pass the associated keygen call id
static KEYGEN_CALL_ID: AtomicU64 = AtomicU64::new(0);

use blueprint_test_utils::test_ext::new_test_ext_blueprint_manager;
use blueprint_test_utils::{
    run_test_blueprint_manager, setup_log, submit_job, wait_for_completion_of_tangle_job,
    BoundedVec, InputValue, Job,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_blueprint() {
    setup_log();

    let tmp_dir = blueprint_test_utils::tempfile::TempDir::new().unwrap();
    let tmp_dir_path = tmp_dir.path().to_string_lossy().into_owned();

    new_test_ext_blueprint_manager::<N, 1, String, _, _>(
        tmp_dir_path,
        run_test_blueprint_manager,
    )
        .await
        .execute_with_async(|client, handles, blueprint| async move {
            let keypair = handles[0].sr25519_id().clone();
            let service = &blueprint.services[KEYGEN_JOB_ID as usize];

            let service_id = service.id;
            gadget_sdk::info!("Submitting KEYGEN job {} with service ID {service_id}" , KEYGEN_JOB_ID);

            let job_args = vec![(InputValue::Uint16(T as u16))];

            let job = submit_job(
                client,
                &keypair,
                service_id,
                Job::from(0),
                job_args,
            )
                .await
                .expect("Failed to submit job");

            let keygen_call_id = job.call_id;
            KEYGEN_CALL_ID.store(keygen_call_id, std::sync::atomic::Ordering::Relaxed);

            gadget_sdk::info!("Submitted KEYGEN job {} with service ID {service_id} has call id {keygen_call_id}", KEYGEN_JOB_ID);

            let job_results = wait_for_completion_of_tangle_job(client, service_id, keygen_call_id, T)
                .await
                .expect("Failed to wait for job completion");

            assert_eq!(job_results.service_id, service_id);
            assert_eq!(job_results.call_id, keygen_call_id);

            let expected_outputs = vec![];
            if !expected_outputs.is_empty() {
                assert_eq!(job_results.result.len(), expected_outputs.len(), "Number of keygen outputs doesn't match expected");

                for (result, expected) in job_results.result.into_iter().zip(expected_outputs.into_iter()) {
                    assert_eq!(result, expected);
                }
            } else {
                gadget_sdk::info!("No expected outputs specified, skipping keygen verification");
            }

            gadget_sdk::info!("Keygen job completed successfully! Moving on to signing ...");


            let service = &blueprint.services[0];

            let service_id = service.id;
            gadget_sdk::info!("Submitting SIGNING job {} with service ID {service_id}" , SIGN_JOB_ID);


            let job_args = vec![InputValue::Uint64(KEYGEN_CALL_ID.load(std::sync::atomic::Ordering::SeqCst)), InputValue::List(BoundedVec(vec![
                InputValue::Uint8(1),
                InputValue::Uint8(2),
                InputValue::Uint8(3),
            ]))];

            let job = submit_job(
                client,
                &keypair,
                service_id,
                Job::from(0),
                job_args,
            )
                .await
                .expect("Failed to submit job");

            let signing_call_id = job.call_id;

            gadget_sdk::info!("Submitted SIGNING job {} with service ID {service_id} has call id {signing_call_id}" , SIGN_JOB_ID);

            let job_results =
                wait_for_completion_of_tangle_job(client, service_id, signing_call_id, T)
                    .await
                    .expect("Failed to wait for job completion");

            let expected_outputs = vec![];
            if !expected_outputs.is_empty() {
                assert_eq!(job_results.result.len(), expected_outputs.len(), "Number of signing outputs doesn't match expected");

                for (result, expected) in job_results.result.into_iter().zip(expected_outputs.into_iter()) {
                    assert_eq!(result, expected);
                }
            } else {
                gadget_sdk::info!("No expected outputs specified, skipping signing verification");
            }
        })
        .await
}
