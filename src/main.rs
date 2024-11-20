use bls_blueprint::context::BlsContext;
use color_eyre::Result;
use gadget_sdk::info;
use gadget_sdk::runners::tangle::TangleConfig;
use gadget_sdk::runners::BlueprintRunner;
use sp_core::Pair;

#[gadget_sdk::main(env)]
async fn main() {
    let context = BlsContext::new(env.clone())?;

    info!(
        "Starting the Blueprint Runner for {} ...",
        hex::encode(context.identity.public().as_ref())
    );

    info!("~~~ Executing the BLS blueprint ~~~");

    let tangle_config = TangleConfig::default();
    let keygen = bls_blueprint::keygen::KeygenEventHandler::new(&env, context.clone()).await?;

    BlueprintRunner::new(tangle_config, env.clone())
        .job(keygen)
        .run()
        .await?;

    info!("Exiting...");
    Ok(())
}
