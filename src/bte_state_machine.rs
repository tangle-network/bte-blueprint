use std::collections::BTreeMap;

use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::Itertools;
use round_based::rounds_router::{simple_store::RoundInput, RoundsRouter};
use round_based::MessageDestination;
use round_based::{Delivery, Mpc, MpcParty, PartyIndex, ProtocolMessage};
use serde::{Deserialize, Serialize};
use snowbridge_milagro_bls::{PublicKey, SecretKey, Signature};
// todo: replace the structs with E::G2, E::ScalarField, E::G1
// e(sig, h) = e(H(m), vk)
// use batch_threshold::

use crate::elliptic_ark_bls::convert_bls_to_ark_bls_fr;
use crate::hasher::hash_to_g1;
use crate::keygen_state_machine::{BlsState, HasRecipient};
use crate::signing::SigningError;

#[derive(Clone)]
pub struct BTEState {
    pub secret_key: Option<ark_bls12_381::Fr>,
    pub signature: Option<ark_bls12_381::G1Projective>,
    pub public_key: Option<ark_bls12_381::G2Projective>,
    received_pk_shares: BTreeMap<usize, ark_bls12_381::G2Projective>,
    received_sig_shares: BTreeMap<usize, ark_bls12_381::G1Projective>,
}

impl Default for BTEState {
    fn default() -> Self {
        Self {
            secret_key: None,
            signature: None,
            public_key: None,
            received_pk_shares: BTreeMap::new(),
            received_sig_shares: BTreeMap::new(),
        }
    }
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

pub async fn bte_pd_protocol<M, T>(
    party: M,
    i: PartyIndex,
    n: u16,
    state: &mut BlsState,
    input_data_to_sign: T,
) -> Result<BTEState, SigningError>
where
    M: Mpc<ProtocolMessage = Msg>,
    T: AsRef<[u8]>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut signing_state = BTEState::default();

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

    println!("secret_key: {:?}", secret_key);

    let ark_secret_key = convert_bls_to_ark_bls_fr(&secret_key);
    println!("ark_secret_key: {:?}", ark_secret_key);

    // let secret_key = SecretKey::from_bytes(&secret_key.to_be_bytes())
    //     .map_err(|e| SigningError::MpcError(format!("Failed to create secret key: {e:?}")))?;

    // Step 1: Generate shares
    let sign_input = gadget_sdk::compute_sha256_hash!(input_data_to_sign.as_ref());
    let sign_input_hash = hash_to_g1(&sign_input).unwrap();
    let sig_share = sign_input_hash * ark_secret_key;
    let pk_share = ark_bls12_381::G2Projective::generator() * ark_secret_key;

    let mut sig_share_bytes = Vec::new();
    let mut pk_share_bytes = Vec::new();

    sig_share
        .serialize_compressed(&mut sig_share_bytes)
        .unwrap();

    pk_share.serialize_compressed(&mut pk_share_bytes).unwrap();

    let my_msg = Msg1 {
        sender: i,
        receiver: None,
        body: (sig_share_bytes, pk_share_bytes),
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
        let pk = ark_bls12_381::G2Projective::deserialize_compressed(&*pk).unwrap();
        let sig = ark_bls12_381::G1Projective::deserialize_compressed(&*sig).unwrap();
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

    // let combined_signature = snowbridge_milagro_bls::AggregateSignature::aggregate(
    //     &sig_shares.iter().collect::<Vec<_>>(),
    // );

    // let pk_agg = snowbridge_milagro_bls::AggregatePublicKey::aggregate(
    //     &pk_shares.iter().collect::<Vec<_>>(),
    // )
    // .map_err(|e| SigningError::MpcError(format!("Failed to aggregate public keys: {e:?}")))?;

    // let mut input = [0u8; 97];
    // pk_agg.point.to_bytes(&mut input, false);

    // let as_pk = PublicKey::from_uncompressed_bytes(&input[1..])
    //     .map_err(|e| SigningError::MpcError(format!("Failed to create public key: {e:?}")))?;

    // let as_sig = Signature::from_bytes(&combined_signature.as_bytes())
    //     .map_err(|e| SigningError::MpcError(format!("Failed to create signature: {e:?}")))?;

    // if !as_sig.verify(&sign_input, &as_pk) {
    //     return Err(SigningError::MpcError(
    //         "Failed to verify signature locally".to_string(),
    //     ));
    // }

    // signing_state.public_key = Some(as_pk.as_uncompressed_bytes().to_vec());
    // signing_state.signature = Some(as_sig.as_bytes().to_vec());
    // signing_state.secret_key = Some(secret_key);

    // Ok(signing_state)

    todo!()
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
