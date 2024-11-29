use gennaro_dkg::{
    Parameters, Participant, Round1BroadcastData, Round1P2PData, Round2EchoBroadcastData,
    Round3BroadcastData, Round4EchoBroadcastData, SecretParticipantImpl,
};
use itertools::Itertools;
use round_based::rounds_router::{simple_store::RoundInput, Round, RoundsRouter};
use round_based::MessageDestination;
use round_based::SinkExt;
use round_based::{Delivery, Mpc, MpcParty, PartyIndex, ProtocolMessage};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::num::NonZeroUsize;

use crate::keygen::KeygenError;

type Group = bls12_381_plus::G1Projective;

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct BlsState {
    round1_broadcasts: BTreeMap<usize, Round1BroadcastData<Group>>,
    round1_p2p: BTreeMap<usize, Round1P2PData>,
    round2_broadcasts: BTreeMap<usize, Round2EchoBroadcastData>,
    round3_broadcasts: BTreeMap<usize, Round3BroadcastData<Group>>,
    round4_broadcasts: BTreeMap<usize, Round4EchoBroadcastData<Group>>,
    round5_broadcasts: BTreeMap<usize, Vec<u8>>,
    pub uncompressed_pk: Option<Vec<u8>>, // [u8; 97]
    pub secret_key: Option<Participant<SecretParticipantImpl<Group>, Group>>,
    pub call_id: u64,
    pub t: u16,
}

impl BlsState {
    pub fn new(call_id: u64, t: u16) -> Self {
        BlsState {
            call_id,
            t,
            ..Default::default()
        }
    }
}

#[derive(ProtocolMessage, Serialize, Deserialize, Clone)]
pub enum Msg {
    Round1Broadcast(Msg1),
    Round1P2P(Msg1P2P),
    Round2Broadcast(Msg2),
    Round3Broadcast(Msg3),
    Round4Broadcast(Msg4),
    Round5Broadcast(Msg5),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Msg1 {
    source: u16,
    data: Round1BroadcastData<Group>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Msg1P2P {
    source: u16,
    destination: u16,
    data: Round1P2PData,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Msg2 {
    source: u16,
    data: Round2EchoBroadcastData,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Msg3 {
    source: u16,
    data: Round3BroadcastData<Group>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Msg4 {
    source: u16,
    data: Round4EchoBroadcastData<Group>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Msg5 {
    source: u16,
    data: Vec<u8>,
}

pub async fn bls_keygen_protocol<M>(
    party: M,
    i: PartyIndex,
    t: u16,
    n: u16,
    call_id: u64,
) -> Result<BlsState, KeygenError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let MpcParty { delivery, .. } = party.into_party();

    let (incomings, mut outgoings) = delivery.split();
    let mut state = BlsState::new(call_id, t);

    let i = NonZeroUsize::new((i + 1) as usize).expect("I > 0");
    let n = NonZeroUsize::new(n as usize).expect("N > 0");
    let t = NonZeroUsize::new(t as usize).expect("T > 0");
    let parameters = Parameters::new(t, n);
    let mut me =
        Participant::new(i, parameters).map_err(|e| KeygenError::MpcError(e.to_string()))?;

    let (i, _t, n) = (i.get() as u16, t.get() as u16, n.get() as u16);
    let i = i - 1;

    // Build rounds
    let mut rounds = RoundsRouter::builder();
    let round1 = rounds.add_round(RoundInput::<Msg1>::broadcast(i, n));
    let round1_p2p_msg = rounds.add_round(RoundInput::<Msg1P2P>::p2p(i, n));
    let round2 = rounds.add_round(RoundInput::<Msg2>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<Msg3>::broadcast(i, n));
    let round4 = rounds.add_round(RoundInput::<Msg4>::broadcast(i, n));
    let round5 = rounds.add_round(RoundInput::<Msg5>::broadcast(i, n));

    let mut rounds = rounds.listen(incomings);

    let (round1_broadcasts, round1_p2p_messages) = me
        .round1()
        .map_err(|e| KeygenError::MpcError(e.to_string()))?;

    // Handle all rounds
    round1_broadcast::<M>(
        i,
        round1_broadcasts,
        &mut outgoings,
        &mut state,
        &mut rounds,
        round1,
    )
    .await?;
    round1_p2p::<M>(
        i,
        round1_p2p_messages,
        &mut outgoings,
        &mut state,
        &mut rounds,
        round1_p2p_msg,
    )
    .await?;

    let round2_broadcast_data = me
        .round2(state.round1_broadcasts.clone(), state.round1_p2p.clone())
        .map_err(|e| KeygenError::MpcError(e.to_string()))?;
    round2_broadcast::<M>(
        i,
        round2_broadcast_data,
        &mut outgoings,
        &mut state,
        &mut rounds,
        round2,
    )
    .await?;

    let round3_broadcast_data = me
        .round3(&state.round2_broadcasts)
        .map_err(|e| KeygenError::MpcError(e.to_string()))?;
    round3_broadcast::<M>(
        i,
        round3_broadcast_data,
        &mut outgoings,
        &mut state,
        &mut rounds,
        round3,
    )
    .await?;

    let round4_broadcast_data = me
        .round4(&state.round3_broadcasts)
        .map_err(|e| KeygenError::MpcError(e.to_string()))?;
    round4_broadcast::<M>(
        i,
        round4_broadcast_data,
        &mut outgoings,
        &mut state,
        &mut rounds,
        round4,
    )
    .await?;

    // Compile the secret
    let sk = me
        .get_secret_share()
        .ok_or_else(|| KeygenError::MpcError("Failed to get secret share".to_string()))?;
    let share = snowbridge_milagro_bls::SecretKey::from_bytes(&sk.to_be_bytes())
        .map_err(|e| KeygenError::MpcError(format!("Failed to create secret key: {e:?}")))?;
    let pk_share = snowbridge_milagro_bls::PublicKey::from_secret_key(&share);

    // Broadcast the key, aggregate shared pk
    round5_broadcast::<M>(
        i,
        pk_share.clone(),
        &mut outgoings,
        &mut state,
        &mut rounds,
        round5,
    )
    .await?;
    state.secret_key = Some(me);

    Ok(state)
}

async fn round1_broadcast<M>(
    i: u16,
    round1_broadcast_data: Round1BroadcastData<Group>,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
    state: &mut BlsState,
    rounds: &mut RoundsRouter<Msg, <<M as Mpc>::Delivery as Delivery<Msg>>::Receive>,
    round1: Round<RoundInput<Msg1>>,
) -> Result<(), KeygenError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let broadcast_msg = Msg::Round1Broadcast(Msg1 {
        source: i,
        data: round1_broadcast_data,
    });
    send_message::<M, Msg>(broadcast_msg, tx).await?;
    let round1_broadcasts = rounds
        .complete(round1)
        .await
        .map_err(|err| KeygenError::MpcError(err.to_string()))?;
    state.round1_broadcasts = round1_broadcasts
        .into_iter_indexed()
        .map(|r| ((r.2.source + 1) as _, r.2.data))
        .collect();

    gadget_sdk::info!(
        "[BLS] Received {} messages from round 1",
        state.round1_broadcasts.len()
    );
    Ok(())
}

async fn round1_p2p<M>(
    i: u16,
    round1_p2p_data: BTreeMap<usize, Round1P2PData>,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
    state: &mut BlsState,
    rounds: &mut RoundsRouter<Msg, <<M as Mpc>::Delivery as Delivery<Msg>>::Receive>,
    round1_p2p: Round<RoundInput<Msg1P2P>>,
) -> Result<(), KeygenError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    for (j, round1_p2p_data) in round1_p2p_data {
        let p2p_msg = Msg::Round1P2P(Msg1P2P {
            source: i,
            destination: (j - 1) as u16,
            data: round1_p2p_data,
        });
        send_message::<M, Msg>(p2p_msg, tx).await?;
    }

    let round1_p2p = rounds
        .complete(round1_p2p)
        .await
        .map_err(|err| KeygenError::MpcError(err.to_string()))?;
    state.round1_p2p = round1_p2p
        .into_iter_indexed()
        .map(|r| ((r.2.source + 1) as _, r.2.data))
        .collect();

    gadget_sdk::info!(
        "[BLS] Received {} messages from round 1 P2P",
        state.round1_p2p.len()
    );
    Ok(())
}

async fn round2_broadcast<M>(
    i: u16,
    round2_broadcast_data: Round2EchoBroadcastData,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
    state: &mut BlsState,
    rounds: &mut RoundsRouter<Msg, <<M as Mpc>::Delivery as Delivery<Msg>>::Receive>,
    round2: Round<RoundInput<Msg2>>,
) -> Result<(), KeygenError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let broadcast_msg = Msg::Round2Broadcast(Msg2 {
        source: i,
        data: round2_broadcast_data,
    });
    send_message::<M, Msg>(broadcast_msg, tx).await?;
    let round2_broadcasts = rounds
        .complete(round2)
        .await
        .map_err(|err| KeygenError::MpcError(err.to_string()))?;
    state.round2_broadcasts = round2_broadcasts
        .into_iter_indexed()
        .map(|r| ((r.2.source + 1) as _, r.2.data))
        .collect();

    gadget_sdk::info!(
        "[BLS] Received {} messages from round 2",
        state.round2_broadcasts.len()
    );
    Ok(())
}

async fn round3_broadcast<M>(
    i: u16,
    round3_broadcast_data: Round3BroadcastData<Group>,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
    state: &mut BlsState,
    rounds: &mut RoundsRouter<Msg, <<M as Mpc>::Delivery as Delivery<Msg>>::Receive>,
    round3: Round<RoundInput<Msg3>>,
) -> Result<(), KeygenError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let broadcast_msg = Msg::Round3Broadcast(Msg3 {
        source: i,
        data: round3_broadcast_data,
    });
    send_message::<M, Msg>(broadcast_msg, tx).await?;
    let round3_broadcasts = rounds
        .complete(round3)
        .await
        .map_err(|err| KeygenError::MpcError(err.to_string()))?;
    state.round3_broadcasts = round3_broadcasts
        .into_iter_indexed()
        .map(|r| ((r.2.source + 1) as _, r.2.data))
        .collect();

    gadget_sdk::info!(
        "[BLS] Received {} messages from round 3",
        state.round3_broadcasts.len()
    );
    Ok(())
}

async fn round4_broadcast<M>(
    i: u16,
    round4_broadcast_data: Round4EchoBroadcastData<Group>,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
    state: &mut BlsState,
    rounds: &mut RoundsRouter<Msg, <<M as Mpc>::Delivery as Delivery<Msg>>::Receive>,
    round4: Round<RoundInput<Msg4>>,
) -> Result<(), KeygenError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let broadcast_msg = Msg::Round4Broadcast(Msg4 {
        source: i,
        data: round4_broadcast_data,
    });
    send_message::<M, Msg>(broadcast_msg, tx).await?;
    let round4_broadcasts = rounds
        .complete(round4)
        .await
        .map_err(|err| KeygenError::MpcError(err.to_string()))?;
    state.round4_broadcasts = round4_broadcasts
        .into_iter_indexed()
        .map(|r| ((r.2.source + 1) as _, r.2.data))
        .collect();

    gadget_sdk::info!(
        "[BLS] Received {} messages from round 4",
        state.round4_broadcasts.len()
    );
    Ok(())
}

async fn round5_broadcast<M>(
    i: u16,
    round5_broadcast_data: snowbridge_milagro_bls::PublicKey,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
    state: &mut BlsState,
    rounds: &mut RoundsRouter<Msg, <<M as Mpc>::Delivery as Delivery<Msg>>::Receive>,
    round5: Round<RoundInput<Msg5>>,
) -> Result<(), KeygenError>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let key_share = round5_broadcast_data.as_uncompressed_bytes().to_vec();
    let mut my_broadcast = Msg5 {
        source: i,
        data: key_share,
    };
    let broadcast_msg = Msg::Round5Broadcast(my_broadcast.clone());
    send_message::<M, Msg>(broadcast_msg.clone(), tx).await?;

    my_broadcast.source += 1; // adjust for 1-indexed gennaro
    let round5_broadcasts = rounds
        .complete(round5)
        .await
        .map_err(|err| KeygenError::MpcError(err.to_string()))?;
    state.round5_broadcasts = round5_broadcasts
        .into_iter_including_me(my_broadcast)
        .map(|r| ((r.source + 1) as _, r.data))
        .collect();

    let mut received_pk_shares = HashMap::<usize, snowbridge_milagro_bls::PublicKey>::new();

    for (id, key_share) in state.round5_broadcasts.iter() {
        match snowbridge_milagro_bls::PublicKey::from_uncompressed_bytes(key_share) {
            Ok(pk) => {
                received_pk_shares.insert(*id, pk);
            }
            Err(e) => {
                gadget_sdk::warn!("Failed to deserialize public key: {e:?}");
            }
        }
    }

    let pk_shares = received_pk_shares
        .into_iter()
        .sorted_by_key(|x| x.0)
        .map(|r| r.1)
        .collect::<Vec<_>>();

    let pk_agg = snowbridge_milagro_bls::AggregatePublicKey::aggregate(
        &pk_shares.iter().collect::<Vec<_>>(),
    )
    .map_err(|e| KeygenError::MpcError(format!("Failed to aggregate public keys: {e:?}")))?;

    let uncompressed_public_key = &mut [0u8; 97];
    pk_agg.point.to_bytes(uncompressed_public_key, false);
    state.uncompressed_pk = Some(uncompressed_public_key.to_vec());

    gadget_sdk::info!(
        "[BLS] Received {} messages from round 5",
        state.round5_broadcasts.len()
    );
    Ok(())
}

pub trait HasRecipient {
    fn recipient(&self) -> MessageDestination;
}

impl HasRecipient for Msg {
    fn recipient(&self) -> MessageDestination {
        match self {
            Msg::Round1Broadcast(_) => MessageDestination::AllParties,
            Msg::Round1P2P(msg) => MessageDestination::OneParty(msg.destination),
            Msg::Round2Broadcast(_) => MessageDestination::AllParties,
            Msg::Round3Broadcast(_) => MessageDestination::AllParties,
            Msg::Round4Broadcast(_) => MessageDestination::AllParties,
            Msg::Round5Broadcast(_) => MessageDestination::AllParties,
        }
    }
}

pub async fn send_message<M, Msg>(
    msg: Msg,
    tx: &mut <<M as Mpc>::Delivery as Delivery<Msg>>::Send,
) -> Result<(), KeygenError>
where
    Msg: HasRecipient,
    M: Mpc<ProtocolMessage = Msg>,
{
    let recipient = msg.recipient();
    let msg = round_based::Outgoing { recipient, msg };
    tx.send(msg)
        .await
        .map_err(|e| KeygenError::DeliveryError(e.to_string()))?;

    Ok(())
}
