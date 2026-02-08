use crate::config::NodeConfig;
use crate::error::TransportInitError;
use crate::proto;
use crate::protocols;
use crate::protocols::filter::FilterPushAck;
use futures::StreamExt;
use libp2p::core::transport::Boxed;
use libp2p::core::upgrade;
use libp2p::dns;
use libp2p::identify;
use libp2p::identity;
use libp2p::noise;
use libp2p::ping;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::tcp;
use libp2p::websocket;
use libp2p::yamux;
use libp2p::{Multiaddr, PeerId, Transport as _};
use libp2p_mplex as mplex;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error};

/// Internal request ID used by the coordinator to correlate responses.
pub type ReqId = u64;

/// Commands sent from coordinator to transport.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TransportCmd {
    Dial {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    },
    SendLightPush {
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::light_push::LightPushRequestV3,
    },
    SendPeerExchange {
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::peer_exchange::PeerExchangeRpc,
    },
    SendMetadataResponse {
        channel: ResponseChannel<proto::metadata::WakuMetadataResponse>,
        response: proto::metadata::WakuMetadataResponse,
    },
    SendLightPushResponse {
        channel: ResponseChannel<proto::light_push::LightPushResponseV3>,
        response: proto::light_push::LightPushResponseV3,
    },
    SendPeerExchangeResponse {
        channel: ResponseChannel<proto::peer_exchange::PeerExchangeRpc>,
        response: proto::peer_exchange::PeerExchangeRpc,
    },
    // Filter commands
    SendFilterSubscribe {
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::filter::FilterSubscribeRequest,
    },
    SendFilterPushAck {
        channel: ResponseChannel<FilterPushAck>,
    },
}

/// Events emitted from transport to coordinator.
#[derive(Debug)]
pub enum TransportEvent {
    ConnectionEstablished {
        peer_id: PeerId,
    },
    ConnectionClosed {
        peer_id: PeerId,
    },
    DialError {
        peer_id: PeerId,
    },
    IdentifyReceived {
        peer_id: PeerId,
        protocols: Vec<String>,
        addrs: Vec<Multiaddr>,
    },
    MetadataRequest {
        peer_id: PeerId,
        channel: ResponseChannel<proto::metadata::WakuMetadataResponse>,
    },
    LightPushRequest {
        peer_id: PeerId,
        channel: ResponseChannel<proto::light_push::LightPushResponseV3>,
    },
    PeerExchangeRequest {
        peer_id: PeerId,
        channel: ResponseChannel<proto::peer_exchange::PeerExchangeRpc>,
    },
    LightPushResponse {
        req_id: ReqId,
        peer_id: PeerId,
        result: Result<proto::light_push::LightPushResponseV3, request_response::OutboundFailure>,
    },
    PeerExchangeResponse {
        req_id: ReqId,
        result: Result<proto::peer_exchange::PeerExchangeRpc, request_response::OutboundFailure>,
    },
    // Filter events
    FilterSubscribeResponse {
        req_id: ReqId,
        peer_id: PeerId,
        result: Result<proto::filter::FilterSubscribeResponse, request_response::OutboundFailure>,
    },
    FilterPush {
        peer_id: PeerId,
        push: Box<proto::filter::MessagePush>,
        channel: ResponseChannel<FilterPushAck>,
    },
}

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    metadata: request_response::Behaviour<protocols::metadata::MetadataCodec>,
    lightpush: request_response::Behaviour<protocols::lightpush::LightPushCodec>,
    peer_exchange: request_response::Behaviour<protocols::peer_exchange::PeerExchangeCodec>,
    filter_subscribe: request_response::Behaviour<protocols::filter::FilterSubscribeCodec>,
    filter_push: request_response::Behaviour<protocols::filter::FilterPushCodec>,
}

/// Transport layer that owns the libp2p Swarm.
/// Receives commands from coordinator, emits raw events back.
pub struct Transport {
    swarm: Swarm<Behaviour>,
    pending_lightpush: HashMap<OutboundRequestId, (ReqId, PeerId)>,
    pending_px: HashMap<OutboundRequestId, ReqId>,
    pending_filter: HashMap<OutboundRequestId, (ReqId, PeerId)>,
}

impl Transport {
    /// Create a new transport.
    pub fn new(config: &NodeConfig) -> Result<Self, TransportInitError> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        let transport = build_transport(&local_key)?;

        let behaviour = Behaviour {
            identify: identify::Behaviour::new(
                identify::Config::new("waku-rust/0.1.0".to_string(), local_key.public())
                    .with_push_listen_addr_updates(true),
            ),
            ping: ping::Behaviour::new(ping::Config::new()),
            metadata: protocols::metadata::behaviour(),
            lightpush: protocols::lightpush::behaviour(),
            peer_exchange: protocols::peer_exchange::behaviour(),
            filter_subscribe: protocols::filter::filter_subscribe_behaviour(),
            filter_push: protocols::filter::filter_push_behaviour(),
        };

        let swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(config.idle_timeout_secs)),
        );

        Ok(Self {
            swarm,
            pending_lightpush: HashMap::new(),
            pending_px: HashMap::new(),
            pending_filter: HashMap::new(),
        })
    }

    /// Run the transport loop.
    /// Polls swarm events and handles commands from the coordinator.
    pub async fn run(
        mut self,
        mut cmd_rx: mpsc::Receiver<TransportCmd>,
        event_tx: mpsc::Sender<TransportEvent>,
    ) {
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else {
                        error!("transport command channel closed, stopping transport loop");
                        break;
                    };
                    self.handle_cmd(cmd);
                }
                ev = self.swarm.select_next_some() => {
                    if let Some(te) = self.map_event(ev)
                        && event_tx.send(te).await.is_err()
                    {
                        error!("transport event channel closed, stopping transport loop");
                        break;
                    }
                }
            }
        }
    }

    fn handle_cmd(&mut self, cmd: TransportCmd) {
        match cmd {
            TransportCmd::Dial { peer_id, addrs } => {
                let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
                    .addresses(addrs)
                    .build();
                if let Err(e) = self.swarm.dial(opts) {
                    debug!(?peer_id, error=?e, "dial failed");
                }
            }
            TransportCmd::SendLightPush {
                req_id,
                peer_id,
                request,
            } => {
                let out_id = self
                    .swarm
                    .behaviour_mut()
                    .lightpush
                    .send_request(&peer_id, request);
                self.pending_lightpush.insert(out_id, (req_id, peer_id));
            }
            TransportCmd::SendPeerExchange {
                req_id,
                peer_id,
                request,
            } => {
                let out_id = self
                    .swarm
                    .behaviour_mut()
                    .peer_exchange
                    .send_request(&peer_id, request);
                self.pending_px.insert(out_id, req_id);
            }
            TransportCmd::SendMetadataResponse { channel, response } => {
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .metadata
                    .send_response(channel, response)
                {
                    debug!(?error, "failed to send metadata response");
                }
            }
            TransportCmd::SendLightPushResponse { channel, response } => {
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .lightpush
                    .send_response(channel, response)
                {
                    debug!(?error, "failed to send lightpush response");
                }
            }
            TransportCmd::SendPeerExchangeResponse { channel, response } => {
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .peer_exchange
                    .send_response(channel, response)
                {
                    debug!(?error, "failed to send peer exchange response");
                }
            }
            TransportCmd::SendFilterSubscribe {
                req_id,
                peer_id,
                request,
            } => {
                let out_id = self
                    .swarm
                    .behaviour_mut()
                    .filter_subscribe
                    .send_request(&peer_id, request);
                self.pending_filter.insert(out_id, (req_id, peer_id));
            }
            TransportCmd::SendFilterPushAck { channel } => {
                if let Err(error) = self
                    .swarm
                    .behaviour_mut()
                    .filter_push
                    .send_response(channel, FilterPushAck)
                {
                    debug!(?error, "failed to send filter push ack");
                }
            }
        }
    }

    fn map_event(&mut self, ev: SwarmEvent<BehaviourEvent>) -> Option<TransportEvent> {
        match ev {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                Some(TransportEvent::ConnectionEstablished { peer_id })
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                Some(TransportEvent::ConnectionClosed { peer_id })
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                ..
            } => Some(TransportEvent::DialError { peer_id }),
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => Some(TransportEvent::IdentifyReceived {
                peer_id,
                protocols: info.protocols.iter().map(ToString::to_string).collect(),
                addrs: info.listen_addrs,
            }),
            SwarmEvent::Behaviour(BehaviourEvent::Metadata(request_response::Event::Message {
                peer,
                message: request_response::Message::Request { channel, .. },
                ..
            })) => Some(TransportEvent::MetadataRequest {
                peer_id: peer,
                channel,
            }),
            SwarmEvent::Behaviour(BehaviourEvent::Lightpush(
                request_response::Event::Message { peer, message, .. },
            )) => match message {
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let (req_id, peer_id) = self.pending_lightpush.remove(&request_id)?;
                    Some(TransportEvent::LightPushResponse {
                        req_id,
                        peer_id,
                        result: Ok(response),
                    })
                }
                request_response::Message::Request { channel, .. } => {
                    Some(TransportEvent::LightPushRequest {
                        peer_id: peer,
                        channel,
                    })
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::Lightpush(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let (req_id, peer_id) = self.pending_lightpush.remove(&request_id)?;
                Some(TransportEvent::LightPushResponse {
                    req_id,
                    peer_id,
                    result: Err(error),
                })
            }
            SwarmEvent::Behaviour(BehaviourEvent::PeerExchange(
                request_response::Event::Message { peer, message, .. },
            )) => match message {
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let req_id = self.pending_px.remove(&request_id)?;
                    Some(TransportEvent::PeerExchangeResponse {
                        req_id,
                        result: Ok(response),
                    })
                }
                request_response::Message::Request { channel, .. } => {
                    Some(TransportEvent::PeerExchangeRequest {
                        peer_id: peer,
                        channel,
                    })
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::PeerExchange(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let req_id = self.pending_px.remove(&request_id)?;
                Some(TransportEvent::PeerExchangeResponse {
                    req_id,
                    result: Err(error),
                })
            }
            // Filter subscribe events
            SwarmEvent::Behaviour(BehaviourEvent::FilterSubscribe(
                request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) => {
                let (req_id, peer_id) = self.pending_filter.remove(&request_id)?;
                Some(TransportEvent::FilterSubscribeResponse {
                    req_id,
                    peer_id,
                    result: Ok(response),
                })
            }
            SwarmEvent::Behaviour(BehaviourEvent::FilterSubscribe(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let (req_id, peer_id) = self.pending_filter.remove(&request_id)?;
                Some(TransportEvent::FilterSubscribeResponse {
                    req_id,
                    peer_id,
                    result: Err(error),
                })
            }
            // Filter push events (incoming pushes from server)
            SwarmEvent::Behaviour(BehaviourEvent::FilterPush(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => Some(TransportEvent::FilterPush {
                peer_id: peer,
                push: Box::new(request),
                channel,
            }),
            _ => None,
        }
    }
}

fn build_transport(
    local_key: &identity::Keypair,
) -> Result<Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>, TransportInitError> {
    let noise = noise::Config::new(local_key)?;
    let yamux = yamux::Config::default();
    let mplex = mplex::Config::new();
    let muxer = upgrade::SelectUpgrade::new(yamux, mplex);

    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let ws_transport = websocket::Config::new(tcp::tokio::Transport::new(
        tcp::Config::default().nodelay(true),
    ));

    let tcp_ws = tcp_transport
        .or_transport(ws_transport)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise)
        .multiplex(muxer)
        .timeout(Duration::from_secs(20))
        .boxed();

    let quic_transport = {
        let config = libp2p::quic::Config::new(local_key);
        libp2p::quic::tokio::Transport::new(config)
            .map(|(peer_id, conn), _| (peer_id, libp2p::core::muxing::StreamMuxerBox::new(conn)))
            .boxed()
    };

    let transport = quic_transport
        .or_transport(tcp_ws)
        .map(|either, _| match either {
            futures::future::Either::Left(v) | futures::future::Either::Right(v) => v,
        });

    let transport = dns::tokio::Transport::system(transport)?;

    Ok(transport.boxed())
}
