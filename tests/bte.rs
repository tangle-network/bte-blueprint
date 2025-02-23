use abi::Abi;
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::HashToCurve;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Read;
use batch_threshold::encryption::Ciphertext;
use blueprint_sdk::logging;
use blueprint_sdk::logging::info;
use blueprint_sdk::testing::tempfile::tempfile;
use blueprint_sdk::testing::utils::harness::TestHarness;
use blueprint_sdk::testing::utils::tangle::node::transactions::{
    get_next_call_id, submit_job, wait_for_completion_of_tangle_job,
};
use blueprint_sdk::testing::utils::tangle::InputValue;
use blueprint_sdk::testing::utils::tangle::TangleTestHarness;
use bte_blueprint::bte::BteEventHandler;
use bte_blueprint::bte::BTE_JOB_ID;
use bte_blueprint::keygen::KeygenEventHandler;
use bte_blueprint::keygen::KEYGEN_JOB_ID;

use ethers::prelude::*;
use ethers::providers::Http;
use ethers::providers::Provider;
use serde_json::Value;
use sha3::Keccak256;
use std::fs::File;

const N: usize = 3;
const T: usize = 2;

#[tokio::test(flavor = "multi_thread")]
async fn test_blueprint() {
    logging::setup_log();

    info!("Running BTE blueprint test");
    let tmp_dir = tempfile::TempDir::new()?;
    let harness = TangleTestHarness::setup(tmp_dir).await?;

    // Setup service
    let (mut test_env, service_id, blueprint_id) = harness.setup_services::<N>(false).await?;
    test_env.initialize().await?;

    let handles = test_env.node_handles().await;
    let binding = handles.clone();
    let first_signer = binding[0].signer();
    for handle in &handles {
        let config = handle.gadget_config().await;
        let blueprint_ctx = ServiceContext::new(config.clone(), params.clone(), service_id).await?;

        let keygen_job = KeygenEventHandler::new(&config, blueprint_ctx.clone()).await?;
        let bte_job = BteEventHandler::new(&config, blueprint_ctx).await?;
        handle.add_job(keygen_job).await;
        handle.add_job(bte_job).await
    }

    let keypair = handles[0].signer();
    let service = &blueprint.services[KEYGEN_JOB_ID as usize];

    let service_id = service.id;
    info!("Submitting KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id}",);

    let job_args = vec![(InputValue::Uint16(T as u16))];
    let call_id = get_next_call_id(client)
        .await
        .expect("Failed to get next job id")
        .saturating_sub(1);
    let job = submit_job(
        client,
        &keypair,
        service_id,
        Job::from(KEYGEN_JOB_ID),
        job_args,
        call_id,
    )
    .await
    .expect("Failed to submit job");

    let keygen_call_id = job.call_id;

    info!(
        "Submitted KEYGEN job {} with service ID {service_id} has call id {keygen_call_id}",
        KEYGEN_JOB_ID
    );

    let job_results = wait_for_completion_of_tangle_job(client, service_id, keygen_call_id, T)
        .await
        .expect("Failed to wait for job completion");

    assert_eq!(job_results.service_id, service_id);
    assert_eq!(job_results.call_id, keygen_call_id);

    let bounded_vec = job_results.result[0].clone();
    let pk_bytes: Vec<u8> = match bounded_vec {
        InputValue::List(BoundedVec(vec)) => vec
            .into_iter()
            .map(|v| match v {
                InputValue::Uint8(byte) => byte,
                _ => panic!("Unexpected type in BoundedVec"),
            })
            .collect(),
        _ => panic!("Expected BoundedVec"),
    };

    let pk = ark_bls12_381::G2Projective::deserialize_compressed(&pk_bytes[..])
        .expect("Failed to deserialize public key");

    let expected_outputs = vec![];
    if !expected_outputs.is_empty() {
        assert_eq!(
            job_results.result.len(),
            expected_outputs.len(),
            "Number of keygen outputs doesn't match expected"
        );

        for (result, expected) in job_results
            .result
            .into_iter()
            .zip(expected_outputs.into_iter())
        {
            assert_eq!(result, expected);
        }
    } else {
        info!("No expected outputs specified, skipping keygen verification");
    }

    info!("Keygen job completed successfully! Moving on to signing ...");

    // Creating dummy transactions and putting them on chain
    let crs_path = "crs.dat";
    let mut crs_file = File::open(crs_path).unwrap();
    let mut crs_bytes = Vec::new();
    crs_file.read_to_end(&mut crs_bytes).unwrap();

    let crs = batch_threshold::dealer::CRS::<ark_bls12_381::Bls12_381>::deserialize_compressed(
        &crs_bytes[..],
    )
    .unwrap();

    let batch_size = crs.powers_of_g.len();
    let tx_domain = Radix2EvaluationDomain::<ark_bls12_381::Fr>::new(batch_size).unwrap();

    let rpc_url_path = "rpc_url.txt";
    let rpc_url = std::fs::read_to_string(rpc_url_path).expect("Failed to read RPC URL from file");
    let rpc_url = rpc_url.trim(); // Remove any trailing newline characters

    let provider = Provider::<Http>::try_from(rpc_url).unwrap();

    let json_path = "contracts/out/SecureStorage.sol/SecureStorage.json";
    let json = std::fs::read_to_string(json_path).unwrap();
    let parsed_json: Value = serde_json::from_str(&json).unwrap();
    let abi: Abi = serde_json::from_value(parsed_json["abi"].clone()).unwrap();

    // Define the contract address
    // read contract address from file deployed_address.txt
    let contract_address_path = "deployed_address.txt";
    let contract_address = std::fs::read_to_string(contract_address_path)
        .expect("Failed to read contract address from file");
    let contract_address = contract_address.trim(); // Remove any trailing newline characters
    let contract_address = contract_address.parse::<Address>().unwrap();

    let chain_id = provider.get_chainid().await.unwrap();
    let wallet: LocalWallet = "39725efee3fb28614de3bacaffe4cc4bd8c436257e2c8bb887c4b5c4be45e76d"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(chain_id.as_u64());

    let eth_client = SignerMiddleware::new(provider.clone(), wallet);

    // Create a new contract instance
    let contract = Contract::new(contract_address, abi, eth_client.clone().into());

    // Retrieve the `currentIndex`
    let eid: u64 = contract
        .method::<_, u64>("currentIndex", ())
        .unwrap()
        .call()
        .await
        .unwrap();

    println!("Current index: {:?}", eid);

    let hasher = MapToCurveBasedHasher::<
        ark_bls12_381::G1Projective,
        DefaultFieldHasher<Keccak256>,
        WBMap<ark_bls12_381::g1::Config>,
    >::new(b"")
    .unwrap();

    let hid = hasher.hash(&eid.to_le_bytes()).unwrap();

    let rng = &mut ark_std::test_rng();
    let msg = [1u8; 32];
    let mut ct: Vec<Ciphertext<ark_bls12_381::Bls12_381>> = Vec::new();
    for x in tx_domain.elements() {
        ct.push(batch_threshold::encryption::encrypt::<
            ark_bls12_381::Bls12_381,
        >(msg, x, hid.into(), crs.htau, pk, rng));
    }

    let mut ct_bytes = Vec::new();
    ct.serialize_compressed(&mut ct_bytes).unwrap();
    let ct_bytes = Bytes::from(ct_bytes);

    // cast send 0xb4B46bdAA835F8E4b4d8e208B6559cD267851051 "storeData(bytes memory data)" "0x$(printf '00%.0s' {1..17000})" --private-key bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31 --rpc-url "http://127.0.0.1:32845"
    let fc = contract
        .method::<_, ()>("storeData", (ct_bytes,))
        .expect("Failed to create transaction");

    // send it!
    let pending_tx = eth_client.send_transaction(fc.tx, None).await.unwrap();

    // get the mined tx
    let _receipt = pending_tx.await.unwrap().unwrap();

    //////////////////////
    let service = &blueprint.services[0];
    let service_id = service.id;
    info!(
        "Submitting BTE job {} with service ID {service_id}",
        BTE_JOB_ID
    );

    let job_args = vec![InputValue::Uint64(keygen_call_id), InputValue::Uint64(eid)];

    let job = submit_job(
        client,
        &keypair,
        service_id,
        Job::from(BTE_JOB_ID),
        job_args,
        call_id + 1,
    )
    .await
    .expect("Failed to submit job");

    let bte_call_id = job.call_id;
    info!("Submitted BTE job {BTE_JOB_ID} with service ID {service_id} has call id {bte_call_id}",);

    let job_results = wait_for_completion_of_tangle_job(client, service_id, bte_call_id, T)
        .await
        .expect("Failed to wait for job completion");

    let expected_outputs = vec![];
    if !expected_outputs.is_empty() {
        assert_eq!(
            job_results.result.len(),
            expected_outputs.len(),
            "Number of signing outputs doesn't match expected"
        );

        for (result, expected) in job_results
            .result
            .into_iter()
            .zip(expected_outputs.into_iter())
        {
            assert_eq!(result, expected);
        }
    } else {
        info!("No expected outputs specified, skipping signing verification");
    }
}
