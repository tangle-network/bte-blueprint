use bte_blueprint::context::BteContext;
use color_eyre::Result;
use gadget_sdk::info;
use gadget_sdk::runners::tangle::TangleConfig;
use gadget_sdk::runners::BlueprintRunner;
use sp_core::Pair;

#[gadget_sdk::main(env)]
async fn main() {
    let context = BteContext::new(env.clone())?;

    info!(
        "Starting the Blueprint Runner for {} ...",
        hex::encode(context.identity.public().as_ref())
    );

    info!("~~~ Executing the BTE blueprint ~~~");

    let tangle_config = TangleConfig::default();
    let keygen = bte_blueprint::keygen::KeygenEventHandler::new(&env, context.clone()).await?;
    let bte = bte_blueprint::bte::BteEventHandler::new(&env, context.clone()).await?;

    BlueprintRunner::new(tangle_config, env.clone())
        .job(keygen)
        .job(bte)
        .run()
        .await?;

    info!("Exiting...");
    Ok(())
}
