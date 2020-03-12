use crate::p2p::{SwarmOptions, SwarmTypes};
use crate::repo::Repo;
use bitswap::{Bitswap, Strategy};
use libipld::cid::Cid;
use libp2p::floodsub::{Floodsub, FloodsubEvent};
use libp2p::identify::{Identify, IdentifyEvent};
use libp2p::kad::record::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaEvent};
use libp2p::mdns::{Mdns, MdnsEvent};
use libp2p::ping::{Ping, PingEvent};
use libp2p::swarm::NetworkBehaviourEventProcess;
use libp2p::NetworkBehaviour;
use libp2p::PeerId;
use std::sync::Arc;

/// Behaviour type.
#[derive(NetworkBehaviour)]
pub struct Behaviour<TSwarmTypes: SwarmTypes> {
    mdns: Mdns,
    kademlia: Kademlia<MemoryStore>,
    bitswap: Bitswap<TSwarmTypes::TStrategy>,
    ping: Ping,
    identify: Identify,
    floodsub: Floodsub,
}

impl<TSwarmTypes: SwarmTypes> NetworkBehaviourEventProcess<MdnsEvent> for Behaviour<TSwarmTypes> {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _) in list {
                    debug!("mdns: Discovered peer {}", peer.to_base58());
                    self.bitswap.connect(peer.clone());
                    self.floodsub.add_node_to_partial_view(peer);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer, _) in list {
                    if !self.mdns.has_node(&peer) {
                        debug!("mdns: Expired peer {}", peer.to_base58());
                        self.floodsub.remove_node_from_partial_view(&peer);
                    }
                }
            }
        }
    }
}

impl<TSwarmTypes: SwarmTypes> NetworkBehaviourEventProcess<KademliaEvent>
    for Behaviour<TSwarmTypes>
{
    fn inject_event(&mut self, event: KademliaEvent) {
        use libp2p::kad::{GetProvidersError, GetProvidersOk};

        match event {
            KademliaEvent::Discovered { peer_id, ty, .. } => {
                debug!("kad: Discovered peer {} {:?}", peer_id.to_base58(), ty);
            }
            // FIXME: unsure what this has been superceded with... perhaps with GetRecordResult?
            /*
            KademliaEvent::FindNodeResult { key, closer_peers } => {
                if closer_peers.is_empty() {
                    info!("kad: Could not find closer peer to {}", key.to_base58());
                }
                for peer in closer_peers {
                    info!("kad: Found closer peer {} to {}", peer.to_base58(), key.to_base58());
                }
            }*/
            KademliaEvent::GetProvidersResult(Ok(GetProvidersOk {
                key,
                providers,
                closest_peers,
            })) => {
                // FIXME: really wasteful to run this through Vec
                let cid = PeerId::from_bytes(key.to_vec()).unwrap().to_base58();
                if providers.is_empty() {
                    // FIXME: not sure if this is possible
                    info!("kad: Could not find provider for {}", cid);
                } else {
                    for peer in closest_peers {
                        info!("kad: {} provided by {}", cid, peer.to_base58());
                        self.bitswap.connect(peer);
                    }
                }
            }
            KademliaEvent::GetProvidersResult(Err(GetProvidersError::Timeout { key, .. })) => {
                // FIXME: really wasteful to run this through Vec
                let cid = PeerId::from_bytes(key.to_vec()).unwrap().to_base58();
                warn!("kad: timed out get providers query for {}", cid);
            }
            x => {
                debug!("kad ignored event {:?}", x);
            }
        }
    }
}

impl<TSwarmTypes: SwarmTypes> NetworkBehaviourEventProcess<()> for Behaviour<TSwarmTypes> {
    fn inject_event(&mut self, _event: ()) {}
}

impl<TSwarmTypes: SwarmTypes> NetworkBehaviourEventProcess<PingEvent> for Behaviour<TSwarmTypes> {
    fn inject_event(&mut self, event: PingEvent) {
        use libp2p::ping::handler::{PingFailure, PingSuccess};
        match event {
            PingEvent {
                peer,
                result: Result::Ok(PingSuccess::Ping { rtt }),
            } => {
                debug!(
                    "ping: rtt to {} is {} ms",
                    peer.to_base58(),
                    rtt.as_millis()
                );
            }
            PingEvent {
                peer,
                result: Result::Ok(PingSuccess::Pong),
            } => {
                debug!("ping: pong from {}", peer.to_base58());
            }
            PingEvent {
                peer,
                result: Result::Err(PingFailure::Timeout),
            } => {
                warn!("ping: timeout to {}", peer.to_base58());
            }
            PingEvent {
                peer,
                result: Result::Err(PingFailure::Other { error }),
            } => {
                error!("ping: failure with {}: {}", peer.to_base58(), error);
            }
        }
    }
}

impl<TSwarmTypes: SwarmTypes> NetworkBehaviourEventProcess<IdentifyEvent>
    for Behaviour<TSwarmTypes>
{
    fn inject_event(&mut self, event: IdentifyEvent) {
        debug!("identify: {:?}", event);
    }
}

impl<TSwarmTypes: SwarmTypes> NetworkBehaviourEventProcess<FloodsubEvent>
    for Behaviour<TSwarmTypes>
{
    fn inject_event(&mut self, event: FloodsubEvent) {
        debug!("floodsub: {:?}", event);
    }
}

impl<TSwarmTypes: SwarmTypes> Behaviour<TSwarmTypes> {
    /// Create a Kademlia behaviour with the IPFS bootstrap nodes.
    pub async fn new(options: SwarmOptions<TSwarmTypes>, repo: Arc<Repo<TSwarmTypes>>) -> Self {
        info!("Local peer id: {}", options.peer_id.to_base58());

        let mdns = Mdns::new().expect("Failed to create mDNS service");

        let store = libp2p::kad::record::store::MemoryStore::new(options.peer_id.to_owned());

        let mut kademlia = Kademlia::new(options.peer_id.to_owned(), store);
        for (addr, peer_id) in &options.bootstrap {
            kademlia.add_address(peer_id, addr.to_owned());
        }

        let strategy = TSwarmTypes::TStrategy::new(repo);
        let bitswap = Bitswap::new(strategy);
        let ping = Ping::default();
        let identify = Identify::new(
            "/ipfs/0.1.0".into(),
            "rust-ipfs".into(),
            options.key_pair.public(),
        );
        let floodsub = Floodsub::new(options.peer_id);

        Behaviour {
            mdns,
            kademlia,
            bitswap,
            ping,
            identify,
            floodsub,
        }
    }

    pub fn want_block(&mut self, cid: Cid) {
        info!("Want block {}", cid.to_string());
        //let hash = Multihash::from_bytes(cid.to_bytes()).unwrap();
        //self.kademlia.get_providers(hash);
        self.bitswap.want_block(cid, 1);
    }

    pub fn provide_block(&mut self, cid: Cid) {
        info!("Providing block {}", cid.to_string());
        //let hash = Multihash::from_bytes(cid.to_bytes()).unwrap();
        //self.kademlia.add_providing(PeerId::from_multihash(hash).unwrap());
    }

    pub fn stop_providing_block(&mut self, cid: &Cid) {
        info!("Finished providing block {}", cid.to_string());
        //let hash = Multihash::from_bytes(cid.to_bytes()).unwrap();
        //self.kademlia.remove_providing(&hash);
    }
}

/// Create a IPFS behaviour with the IPFS bootstrap nodes.
pub async fn build_behaviour<TSwarmTypes: SwarmTypes>(
    options: SwarmOptions<TSwarmTypes>,
    repo: Arc<Repo<TSwarmTypes>>,
) -> Behaviour<TSwarmTypes> {
    Behaviour::new(options, repo).await
}
