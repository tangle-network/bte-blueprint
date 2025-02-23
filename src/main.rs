use blueprint_sdk::logging::info;
use blueprint_sdk::runners::{core::runner::BlueprintRunner, tangle::tangle::TangleConfig};
use bte_blueprint::context::BteContext;
use color_eyre::Result;

#[blueprint_sdk::main(env)]
async fn main() -> Result<()> {
    let context = BteContext::new(env.clone()).await?;

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
