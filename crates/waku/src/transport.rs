use crate::config::{NodeConfig, WakuNetworkConfig, WakuTorClient, WakuTransportProfile};
use crate::error::TransportInitError;
use crate::proto;
use crate::protocols;
use crate::protocols::codec::ProstLengthDelimitedCodec;
use futures::StreamExt;
use futures::future::{BoxFuture, FutureExt};
use libp2p::core::multiaddr::Protocol;
use libp2p::core::transport::Boxed;
use libp2p::core::transport::{
    DialOpts, ListenerId, TransportError, TransportEvent as CoreTransportEvent,
};
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
use libp2p::{Multiaddr, PeerId, StreamProtocol, Transport as _};
use libp2p_mplex as mplex;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error};

/// Internal request ID used by the coordinator to correlate responses.
pub(crate) type ReqId = u64;

/// Commands sent from coordinator to transport.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum TransportCmd {
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
    SendStoreQuery {
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::store::StoreQueryRequest,
    },
}

/// Events emitted from transport to coordinator.
#[derive(Debug)]
pub(crate) enum TransportEvent {
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
    },
    StoreQueryResponse {
        req_id: ReqId,
        result: Result<proto::store::StoreQueryResponse, request_response::OutboundFailure>,
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
    store_query: request_response::Behaviour<protocols::store::StoreQueryCodec>,
    filter_push: libp2p_stream::Behaviour,
}

/// Transport layer that owns the libp2p Swarm.
/// Receives commands from coordinator, emits raw events back.
pub(crate) struct Transport {
    swarm: Swarm<Behaviour>,
    pending_lightpush: HashMap<OutboundRequestId, (ReqId, PeerId)>,
    pending_px: HashMap<OutboundRequestId, ReqId>,
    pending_filter: HashMap<OutboundRequestId, (ReqId, PeerId)>,
    pending_store: HashMap<OutboundRequestId, ReqId>,
}

impl Transport {
    /// Create a new transport.
    pub(crate) fn new(
        config: &NodeConfig,
        network: &WakuNetworkConfig,
    ) -> Result<Self, TransportInitError> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        let transport = build_transport(&local_key, network)?;

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
            store_query: protocols::store::behaviour(),
            filter_push: libp2p_stream::Behaviour::new(),
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
            pending_store: HashMap::new(),
        })
    }

    /// Run the transport loop.
    /// Polls swarm events and handles commands from the coordinator.
    pub(crate) async fn run(
        mut self,
        mut cmd_rx: mpsc::Receiver<TransportCmd>,
        event_tx: mpsc::Sender<TransportEvent>,
    ) {
        let mut filter_push_control = self.swarm.behaviour().filter_push.new_control();
        let Ok(mut filter_push_streams) =
            filter_push_control.accept(StreamProtocol::new(protocols::filter::FILTER_PUSH_CODEC))
        else {
            error!("failed to register filter push stream protocol");
            return;
        };

        loop {
            tokio::select! {
                stream = filter_push_streams.next() => {
                    let Some((peer_id, stream)) = stream else {
                        error!("filter push stream acceptor closed, stopping transport loop");
                        break;
                    };
                    tokio::spawn(handle_filter_push_stream(peer_id, stream, event_tx.clone()));
                }
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
            TransportCmd::SendStoreQuery {
                req_id,
                peer_id,
                request,
            } => {
                let out_id = self
                    .swarm
                    .behaviour_mut()
                    .store_query
                    .send_request(&peer_id, request);
                self.pending_store.insert(out_id, req_id);
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
            SwarmEvent::Behaviour(BehaviourEvent::StoreQuery(
                request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) => {
                let req_id = self.pending_store.remove(&request_id)?;
                Some(TransportEvent::StoreQueryResponse {
                    req_id,
                    result: Ok(response),
                })
            }
            SwarmEvent::Behaviour(BehaviourEvent::StoreQuery(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let req_id = self.pending_store.remove(&request_id)?;
                Some(TransportEvent::StoreQueryResponse {
                    req_id,
                    result: Err(error),
                })
            }
            _ => None,
        }
    }
}

async fn handle_filter_push_stream(
    peer_id: PeerId,
    mut stream: libp2p::Stream,
    event_tx: mpsc::Sender<TransportEvent>,
) {
    while let Ok(push) = ProstLengthDelimitedCodec::<
        proto::filter::MessagePush,
        proto::filter::FilterSubscribeResponse,
    >::read_request(&mut stream)
    .await
    {
        if event_tx
            .send(TransportEvent::FilterPush {
                peer_id,
                push: Box::new(push),
            })
            .await
            .is_err()
        {
            error!(%peer_id, "transport event channel closed, stopping filter push stream");
            break;
        }
    }
}

fn build_transport(
    local_key: &identity::Keypair,
    network: &WakuNetworkConfig,
) -> Result<Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>, TransportInitError> {
    match network.transport_profile {
        WakuTransportProfile::Direct => build_direct_transport(local_key),
        WakuTransportProfile::Tor => build_tor_transport(local_key, network),
    }
}

fn build_direct_transport(
    local_key: &identity::Keypair,
) -> Result<Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>, TransportInitError> {
    let tcp_transport = dns::tokio::Transport::system(tcp::tokio::Transport::new(
        tcp::Config::default().nodelay(true),
    ))?
    .upgrade(upgrade::Version::V1)
    .authenticate(noise::Config::new(local_key)?)
    .multiplex(upgrade::SelectUpgrade::new(
        yamux::Config::default(),
        mplex::Config::new(),
    ))
    .timeout(Duration::from_secs(20))
    .boxed();

    // Secure websockets must own DNS resolution so TLS validates the DNS name,
    // not the resolved IP address.
    let ws_transport = websocket::Config::new(dns::tokio::Transport::system(
        tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)),
    )?)
    .upgrade(upgrade::Version::V1)
    .authenticate(noise::Config::new(local_key)?)
    .multiplex(upgrade::SelectUpgrade::new(
        yamux::Config::default(),
        mplex::Config::new(),
    ))
    .timeout(Duration::from_secs(20))
    .boxed();

    let quic_transport = {
        let config = libp2p::quic::Config::new(local_key);
        libp2p::quic::tokio::Transport::new(config)
            .map(|(peer_id, conn), _| (peer_id, libp2p::core::muxing::StreamMuxerBox::new(conn)))
            .boxed()
    };

    let ws_quic = ws_transport
        .or_transport(quic_transport)
        .map(|either, _| match either {
            futures::future::Either::Left(v) | futures::future::Either::Right(v) => v,
        })
        .boxed();

    let transport = ws_quic
        .or_transport(tcp_transport)
        .map(|either, _| match either {
            futures::future::Either::Left(v) | futures::future::Either::Right(v) => v,
        });

    Ok(transport.boxed())
}

fn build_tor_transport(
    local_key: &identity::Keypair,
    network: &WakuNetworkConfig,
) -> Result<Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>, TransportInitError> {
    let tor_client = network
        .tor_client
        .clone()
        .ok_or(TransportInitError::MissingTorClient)?;
    let arti_transport = ArtiTcpTransport::new(tor_client);

    let tcp_transport = arti_transport
        .clone()
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(local_key)?)
        .multiplex(upgrade::SelectUpgrade::new(
            yamux::Config::default(),
            mplex::Config::new(),
        ))
        .timeout(Duration::from_secs(20))
        .boxed();

    let ws_transport = websocket::Config::new(arti_transport)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(local_key)?)
        .multiplex(upgrade::SelectUpgrade::new(
            yamux::Config::default(),
            mplex::Config::new(),
        ))
        .timeout(Duration::from_secs(20))
        .boxed();

    Ok(ws_transport
        .or_transport(tcp_transport)
        .map(|either, _| match either {
            futures::future::Either::Left(v) | futures::future::Either::Right(v) => v,
        })
        .boxed())
}

#[derive(Clone)]
struct ArtiTcpTransport {
    tor_client: WakuTorClient,
}

impl ArtiTcpTransport {
    const fn new(tor_client: WakuTorClient) -> Self {
        Self { tor_client }
    }
}

impl libp2p::Transport for ArtiTcpTransport {
    type Output = arti_client::DataStream;
    type Error = io::Error;
    type ListenerUpgrade = std::future::Pending<Result<Self::Output, Self::Error>>;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        _id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let target = ArtiDialTarget::from_multiaddr(&addr)?;
        let tor_client = self.tor_client.clone();
        Ok(async move {
            tor_client
                .connect((target.host.as_str(), target.port))
                .await
                .map_err(io::Error::other)
        }
        .boxed())
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<CoreTransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

struct ArtiDialTarget {
    host: String,
    port: u16,
}

impl ArtiDialTarget {
    fn from_multiaddr(addr: &Multiaddr) -> Result<Self, TransportError<io::Error>> {
        let mut protocols = addr.iter();
        let host = match protocols.next() {
            Some(Protocol::Dns(host) | Protocol::Dns4(host) | Protocol::Dns6(host)) => {
                host.to_string()
            }
            Some(Protocol::Ip4(host)) => host.to_string(),
            Some(Protocol::Ip6(host)) => host.to_string(),
            _ => return Err(TransportError::MultiaddrNotSupported(addr.clone())),
        };
        let Some(Protocol::Tcp(port)) = protocols.next() else {
            return Err(TransportError::MultiaddrNotSupported(addr.clone()));
        };
        Ok(Self { host, port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dial_target(value: &str) -> Result<ArtiDialTarget, TransportError<io::Error>> {
        let addr = value.parse().expect("valid multiaddr");
        ArtiDialTarget::from_multiaddr(&addr)
    }

    #[test]
    fn arti_dial_target_accepts_dns_and_ip_tcp_addrs() {
        let dns = dial_target("/dns4/support-4.rootedinprivacy.com/tcp/30304/p2p/12D3KooWPZAXp2aXSq7hh5iy8pxziTv1bxU8cg4pc4YEgkFiiixv")
            .expect("dns target");
        assert_eq!(dns.host, "support-4.rootedinprivacy.com");
        assert_eq!(dns.port, 30304);

        let ip4 = dial_target("/ip4/203.0.113.10/tcp/30304").expect("ip4 target");
        assert_eq!(ip4.host, "203.0.113.10");
        assert_eq!(ip4.port, 30304);

        let ip6 = dial_target("/ip6/2001:db8::1/tcp/30304").expect("ip6 target");
        assert_eq!(ip6.host, "2001:db8::1");
        assert_eq!(ip6.port, 30304);
    }

    #[test]
    fn arti_dial_target_rejects_non_tcp_addrs() {
        assert!(dial_target("/ip4/203.0.113.10/udp/30304/quic-v1").is_err());
    }
}
