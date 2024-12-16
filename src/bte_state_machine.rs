use ark_ec::PrimeGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::Zero;
use batch_threshold::dealer::CRS;
use batch_threshold::decryption::decrypt_all;
use batch_threshold::encryption::Ciphertext;
use batch_threshold::utils::lagrange_interp_eval;
use itertools::Itertools;
use round_based::rounds_router::{simple_store::RoundInput, RoundsRouter};
use round_based::MessageDestination;
use round_based::{Delivery, Mpc, MpcParty, PartyIndex, ProtocolMessage};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// todo: replace the structs with E::G2, E::ScalarField, E::G1
// e(sig, h) = e(H(m), vk)

use crate::elliptic_ark_bls::convert_bls_to_ark_bls_fr;
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

impl BTEState {
    pub fn recover_messages(
        &self,
        ct: &Vec<Ciphertext<ark_bls12_381::Bls12_381>>,
        hid: ark_bls12_381::G1Projective,
        crs: &CRS<ark_bls12_381::Bls12_381>,
    ) -> Vec<[u8; 32]> {
        if self.secret_key.is_none() {
            return vec![];
        }
        let sigma = self.signature.unwrap();
        decrypt_all(sigma, ct, hid, crs)
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

pub async fn bte_pd_protocol<M>(
    party: M,
    i: PartyIndex,
    n: u16,
    state: &mut BlsState,
    delta: ark_bls12_381::G1Projective,
) -> Result<BTEState, SigningError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    println!("Running BTE PD protocol");

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

    // Step 1: Generate shares
    let sig_share = delta * ark_secret_key;
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

    let eval_points = (0..n)
        .map(|i| ark_bls12_381::Fr::from((i + 1) as u64))
        .collect::<Vec<_>>();

    let combined_signature =
        lagrange_interp_eval(&eval_points, &vec![ark_bls12_381::Fr::zero()], &sig_shares)[0];

    let pk_agg =
        lagrange_interp_eval(&eval_points, &vec![ark_bls12_381::Fr::zero()], &pk_shares)[0];

    let mut sig_bytes = Vec::new();
    let mut pk_bytes = Vec::new();

    combined_signature
        .serialize_compressed(&mut sig_bytes)
        .unwrap();

    pk_agg.serialize_compressed(&mut pk_bytes).unwrap();

    signing_state.public_key = Some(pk_agg);
    signing_state.signature = Some(combined_signature);
    signing_state.secret_key = Some(ark_secret_key);

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
