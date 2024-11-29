use std::collections::BTreeMap;

use itertools::Itertools;
use round_based::rounds_router::{simple_store::RoundInput, RoundsRouter};
use round_based::MessageDestination;
use round_based::{Delivery, Mpc, MpcParty, PartyIndex, ProtocolMessage};
use serde::{Deserialize, Serialize};
use snowbridge_milagro_bls::{PublicKey, SecretKey, Signature};

use crate::keygen_state_machine::{BlsState, HasRecipient};
use crate::signing::SigningError;

#[derive(Default, Clone)]
pub struct BlsSigningState {
    pub secret_key: Option<SecretKey>,
    pub signature: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    received_pk_shares: BTreeMap<usize, PublicKey>,
    received_sig_shares: BTreeMap<usize, Signature>,
}

#[derive(ProtocolMessage, Serialize, Deserialize, Clone)]
pub enum Msg {
    Round1Broadcast(Msg1),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Msg1 {
    pub sender: u16,
    pub receiver: Option<u16>,
    pub body: (Vec<u8>, Vec<u8>), // (signature_share, public_key_share)
}

pub async fn bls_signing_protocol<M, T>(
    party: M,
    i: PartyIndex,
    n: u16,
    state: &mut BlsState,
    input_data_to_sign: T,
) -> Result<BlsSigningState, SigningError>
where
    M: Mpc<ProtocolMessage = Msg>,
    T: AsRef<[u8]>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut signing_state = BlsSigningState::default();

    // let threshold = state.t;

    // Extract secret key from state
    let secret_key = state
        .secret_key
        .as_ref()
        .ok_or_else(|| {
            SigningError::KeyRetrievalError("Secret key not found in state".to_string())
        })?
        .get_secret_share()
        .ok_or_else(|| SigningError::KeyRetrievalError("Failed to get secret share".to_string()))?;

    let secret_key = SecretKey::from_bytes(&secret_key.to_be_bytes())
        .map_err(|e| SigningError::MpcError(format!("Failed to create secret key: {e:?}")))?;

    // Step 1: Generate shares
    let sign_input = gadget_sdk::compute_sha256_hash!(input_data_to_sign.as_ref());
    let sig_share = Signature::new(&sign_input, &secret_key);
    let pk_share = PublicKey::from_secret_key(&secret_key);

    let my_msg = Msg1 {
        sender: i,
        receiver: None,
        body: (sig_share.as_bytes().to_vec(), pk_share.as_bytes().to_vec()),
    };
    // Step 2: Broadcast shares
    let msg = Msg::Round1Broadcast(my_msg.clone());

    send_message::<M, Msg>(msg, &mut outgoings)
        .await
        .map_err(|e| SigningError::MpcError(e.to_string()))?;

    // Step 3: Receive shares until there are t+1 total
    let mut rounds = RoundsRouter::builder();
    let round = rounds.add_round(RoundInput::<Msg1>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    let msgs = rounds
        .complete(round)
        .await
        .map_err(|e| SigningError::MpcError(format!("Failed to complete round: {}", e)))?;

    for msg in msgs.into_vec_including_me(my_msg) {
        let (sender, (sig, pk)) = (msg.sender, msg.body);
        let pk = PublicKey::from_bytes(&pk)
            .map_err(|e| SigningError::MpcError(format!("Failed to create public key: {e:?}")))?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|e| SigningError::MpcError(format!("Failed to create signature: {e:?}")))?;
        signing_state.received_pk_shares.insert(sender as usize, pk);
        signing_state
            .received_sig_shares
            .insert(sender as usize, sig);
    }

    // Step 4: Verify the combined signatures and public keys
    let sig_shares = signing_state
        .received_sig_shares
        .clone()
        .into_iter()
        .sorted_by_key(|r| r.0)
        .map(|r| r.1)
        .collect::<Vec<_>>();

    let pk_shares = signing_state
        .received_pk_shares
        .clone()
        .into_iter()
        .sorted_by_key(|r| r.0)
        .map(|r| r.1)
        .collect::<Vec<_>>();

    let combined_signature = snowbridge_milagro_bls::AggregateSignature::aggregate(
        &sig_shares.iter().collect::<Vec<_>>(),
    );

    let pk_agg = snowbridge_milagro_bls::AggregatePublicKey::aggregate(
        &pk_shares.iter().collect::<Vec<_>>(),
    )
    .map_err(|e| SigningError::MpcError(format!("Failed to aggregate public keys: {e:?}")))?;

    let mut input = [0u8; 97];
    pk_agg.point.to_bytes(&mut input, false);

    let as_pk = PublicKey::from_uncompressed_bytes(&input[1..])
        .map_err(|e| SigningError::MpcError(format!("Failed to create public key: {e:?}")))?;

    let as_sig = Signature::from_bytes(&combined_signature.as_bytes())
        .map_err(|e| SigningError::MpcError(format!("Failed to create signature: {e:?}")))?;

    if !as_sig.verify(&sign_input, &as_pk) {
        return Err(SigningError::MpcError(
            "Failed to verify signature locally".to_string(),
        ));
    }

    signing_state.public_key = Some(as_pk.as_uncompressed_bytes().to_vec());
    signing_state.signature = Some(as_sig.as_bytes().to_vec());
    signing_state.secret_key = Some(secret_key);

    Ok(signing_state)
}

impl HasRecipient for Msg {
    fn recipient(&self) -> MessageDestination {
        match self {
            Msg::Round1Broadcast(..) => MessageDestination::AllParties,
        }
    }
}

async fn send_message<M, Msg>(
    msg: Msg,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
) -> Result<(), SigningError>
where
    Msg: HasRecipient,
    M: Mpc<ProtocolMessage = Msg>,
{
    crate::keygen_state_machine::send_message::<M, Msg>(msg, tx)
        .await
        .map_err(|e| SigningError::MpcError(e.to_string()))
}
