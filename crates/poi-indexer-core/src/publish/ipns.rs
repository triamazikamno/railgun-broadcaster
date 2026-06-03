use crate::config::Config;
use cid::Cid;
use ed25519_dalek::SigningKey;
use libp2p::core::transport::Boxed;
use libp2p::core::{muxing::StreamMuxerBox, upgrade};
use libp2p::futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self, GetRecordOk, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, Transport as _, connection_limits, dns, identity,
    noise, tcp, yamux,
};
use multibase::Base;
use rust_ipns::Record as IpnsRecord;
use std::collections::VecDeque;
use std::str;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

const IPNS_RECORD_KEY_PREFIX: &[u8] = b"/ipns/";
const IPFS_PATH_PREFIX: &str = "/ipfs/";
const LIBP2P_KEY_CODEC: u64 = 0x72;
const IPFS_KAD_PROTOCOL: &str = "/ipfs/kad/1.0.0";
const IPNS_PUBLISH_QUEUE_CAPACITY: usize = 16;
const IPNS_REBOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);
const IPNS_MAX_ESTABLISHED_CONNECTIONS: u32 = 32;
const IPNS_MIN_CONNECTED_PEERS_FOR_PUBLISH: usize = 8;

pub const DEFAULT_IPNS_BOOTSTRAP_PEERS: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

type KadSwarm = Swarm<IpnsBehaviour>;
type IpnsTransport = Boxed<(PeerId, StreamMuxerBox)>;

#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct IpnsBehaviour {
    kad: kad::Behaviour<MemoryStore>,
    limits: connection_limits::Behaviour,
}

#[derive(Debug, Clone)]
pub struct IpnsPublisherConfig {
    pub bootstrap_peers: Vec<Multiaddr>,
    pub record_lifetime: Duration,
    pub record_ttl: Duration,
    pub publish_timeout: Duration,
}

impl IpnsPublisherConfig {
    pub fn from_indexer_config(config: &Config) -> Result<Self, IpnsError> {
        let bootstrap_peers = config
            .ipns_bootstrap_peers
            .iter()
            .map(|addr| {
                addr.parse::<Multiaddr>()
                    .map_err(|source| IpnsError::InvalidBootstrapAddress {
                        addr: addr.clone(),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            bootstrap_peers,
            record_lifetime: *config.ipns_record_lifetime,
            record_ttl: *config.ipns_record_ttl,
            publish_timeout: *config.ipns_publish_timeout,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IpnsPublisher {
    peer_id: PeerId,
    ipns_name: String,
    publish_timeout: Duration,
    requests: mpsc::Sender<PublishRequest>,
}

#[derive(Debug)]
pub struct IpnsPublisherTask {
    keypair: identity::Keypair,
    peer_id: PeerId,
    config: IpnsPublisherConfig,
    requests: mpsc::Receiver<PublishRequest>,
}

#[derive(Debug)]
struct PublishRequest {
    manifest_cid: String,
    sequence: u64,
    timeout: Duration,
    deadline: time::Instant,
    response: oneshot::Sender<Result<IpnsPublication, IpnsError>>,
}

impl IpnsPublisher {
    pub fn new(
        signing_key: &SigningKey,
        config: IpnsPublisherConfig,
    ) -> Result<(Self, IpnsPublisherTask), IpnsError> {
        let keypair = identity_keypair_from_signing_key(signing_key)?;
        let peer_id = PeerId::from(keypair.public());
        let ipns_name = ipns_name(peer_id)?;
        let (request_tx, request_rx) = mpsc::channel(IPNS_PUBLISH_QUEUE_CAPACITY);
        let publisher = Self {
            peer_id,
            ipns_name,
            publish_timeout: config.publish_timeout,
            requests: request_tx,
        };
        let task = IpnsPublisherTask {
            keypair,
            peer_id,
            config,
            requests: request_rx,
        };
        Ok((publisher, task))
    }

    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn ipns_name(&self) -> Result<String, IpnsError> {
        Ok(self.ipns_name.clone())
    }

    pub async fn publish_manifest_cid(
        &self,
        manifest_cid: &str,
        sequence: u64,
    ) -> Result<IpnsPublication, IpnsError> {
        let (response_tx, response_rx) = oneshot::channel();
        let deadline = time::Instant::now() + self.publish_timeout;
        let request = PublishRequest {
            manifest_cid: manifest_cid.to_string(),
            sequence,
            timeout: self.publish_timeout,
            deadline,
            response: response_tx,
        };

        time::timeout_at(deadline, self.requests.send(request))
            .await
            .map_err(|_| IpnsError::Timeout(self.publish_timeout))?
            .map_err(|_| IpnsError::PublisherUnavailable)?;

        response_rx
            .await
            .map_err(|_| IpnsError::PublisherResponseDropped)?
    }
}

impl IpnsPublisherTask {
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<(), IpnsError> {
        let mut swarm = build_swarm(&self.keypair, &self.config)?;
        dial_bootstrap_peers(&mut swarm, &self.config)?;
        start_bootstrap(&mut swarm);

        info!(
            peer_id = %self.peer_id,
            ipns_name = %ipns_name(self.peer_id)?,
            "started IPNS publisher DHT service"
        );

        let mut bootstrap_interval = time::interval_at(
            time::Instant::now() + IPNS_REBOOTSTRAP_INTERVAL,
            IPNS_REBOOTSTRAP_INTERVAL,
        );
        bootstrap_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut pending = VecDeque::new();
        let mut active = None;
        let mut bootstrap_completed = false;

        loop {
            maybe_start_publish(
                &self.keypair,
                &self.config,
                &mut swarm,
                &mut pending,
                &mut active,
                bootstrap_completed,
                time::Instant::now(),
            );
            let pending_deadline = next_pending_deadline(&pending);

            tokio::select! {
                () = sleep_until_deadline(pending_deadline), if pending_deadline.is_some() => {}
                _ = bootstrap_interval.tick() => {
                    dial_bootstrap_peers(&mut swarm, &self.config)?;
                    start_bootstrap(&mut swarm);
                }
                request = self.requests.recv() => {
                    match request {
                        Some(request) => {
                            pending.push_back(request);
                            if !has_enough_connected_peers_for_publish(&swarm, bootstrap_completed) {
                                dial_bootstrap_peers(&mut swarm, &self.config)?;
                                start_bootstrap(&mut swarm);
                            }
                        }
                        None => return Ok(()),
                    }
                }
                event = swarm.select_next_some() => {
                    handle_swarm_event(
                        event,
                        &self.keypair,
                        &self.config,
                        &mut swarm,
                        &mut pending,
                        &mut active,
                        &mut bootstrap_completed,
                    );
                }
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
struct ActivePublish {
    query_id: kad::QueryId,
    request: PublishRequest,
    publication: IpnsPublication,
    started_at: time::Instant,
}

impl PublishRequest {
    fn is_expired(&self, now: time::Instant) -> bool {
        now >= self.deadline
    }

    fn respond(self, result: Result<IpnsPublication, IpnsError>) {
        let _ = self.response.send(result);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpnsPublication {
    pub peer_id: PeerId,
    pub ipns_name: String,
    pub value: String,
    pub sequence: u64,
}

#[derive(Debug, Clone)]
pub struct SignedIpnsRecord {
    pub peer_id: PeerId,
    pub ipns_name: String,
    pub record_key: RecordKey,
    pub value: String,
    pub sequence: u64,
    pub bytes: Vec<u8>,
}

pub fn build_signed_record(
    keypair: &identity::Keypair,
    manifest_cid: &str,
    record_lifetime: Duration,
    record_ttl: Duration,
    sequence: u64,
) -> Result<SignedIpnsRecord, IpnsError> {
    let peer_id = PeerId::from(keypair.public());
    let value = manifest_ipfs_path(manifest_cid)?;
    let lifetime =
        chrono::Duration::from_std(record_lifetime).map_err(IpnsError::RecordLifetimeOutOfRange)?;
    let ttl = duration_nanos(record_ttl)?;
    let ipns_record = IpnsRecord::new(keypair, value.as_bytes(), lifetime, sequence, ttl)
        .map_err(IpnsError::CreateRecord)?;
    ipns_record
        .verify(peer_id)
        .map_err(IpnsError::VerifyRecord)?;
    let bytes = ipns_record.encode().map_err(IpnsError::EncodeRecord)?;

    Ok(SignedIpnsRecord {
        peer_id,
        ipns_name: ipns_name(peer_id)?,
        record_key: ipns_record_key(peer_id),
        value,
        sequence,
        bytes,
    })
}

pub async fn resolve_manifest_cid(
    peer_id: PeerId,
    config: &IpnsPublisherConfig,
) -> Result<String, IpnsError> {
    let timeout = config.publish_timeout;
    time::timeout(timeout, resolve_record(peer_id, config))
        .await
        .map_err(|_| IpnsError::Timeout(timeout))?
}

#[must_use]
pub fn ipns_record_key(peer_id: PeerId) -> RecordKey {
    RecordKey::new(&ipns_record_key_bytes(peer_id))
}

#[must_use]
pub fn ipns_record_key_bytes(peer_id: PeerId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(IPNS_RECORD_KEY_PREFIX.len() + peer_id.to_bytes().len());
    bytes.extend_from_slice(IPNS_RECORD_KEY_PREFIX);
    bytes.extend_from_slice(&peer_id.to_bytes());
    bytes
}

pub fn ipns_name(peer_id: PeerId) -> Result<String, IpnsError> {
    let cid = Cid::new_v1(LIBP2P_KEY_CODEC, *peer_id.as_ref());
    cid.to_string_of_base(Base::Base36Lower)
        .map_err(IpnsError::IpnsName)
}

fn identity_keypair_from_signing_key(
    signing_key: &SigningKey,
) -> Result<identity::Keypair, IpnsError> {
    let mut bytes = signing_key.to_bytes();
    identity::Keypair::ed25519_from_bytes(&mut bytes).map_err(IpnsError::Identity)
}

fn maybe_start_publish(
    keypair: &identity::Keypair,
    config: &IpnsPublisherConfig,
    swarm: &mut KadSwarm,
    pending: &mut VecDeque<PublishRequest>,
    active: &mut Option<ActivePublish>,
    bootstrap_completed: bool,
    now: time::Instant,
) {
    discard_unpublishable_pending(pending, now);
    if active.is_some()
        || pending.is_empty()
        || !has_enough_connected_peers_for_publish(swarm, bootstrap_completed)
    {
        return;
    }

    let request = pending
        .pop_front()
        .expect("pending publish queue checked as non-empty");
    let signed_record = match build_signed_record(
        keypair,
        &request.manifest_cid,
        config.record_lifetime,
        config.record_ttl,
        request.sequence,
    ) {
        Ok(record) => record,
        Err(error) => {
            request.respond(Err(error));
            return;
        }
    };
    let record = Record::new(
        signed_record.record_key.clone(),
        signed_record.bytes.clone(),
    );
    let query_id = match swarm.behaviour_mut().kad.put_record(record, Quorum::One) {
        Ok(query_id) => query_id,
        Err(error) => {
            request.respond(Err(IpnsError::Store(error)));
            return;
        }
    };

    info!(
        manifest_cid = %request.manifest_cid,
        peer_id = %signed_record.peer_id,
        ipns_name = %signed_record.ipns_name,
        sequence = request.sequence,
        "started IPNS DHT put_record"
    );

    *active = Some(ActivePublish {
        query_id,
        publication: IpnsPublication {
            peer_id: signed_record.peer_id,
            ipns_name: signed_record.ipns_name,
            value: signed_record.value,
            sequence: signed_record.sequence,
        },
        started_at: time::Instant::now(),
        request,
    });
}

fn handle_swarm_event(
    event: SwarmEvent<IpnsBehaviourEvent>,
    keypair: &identity::Keypair,
    config: &IpnsPublisherConfig,
    swarm: &mut KadSwarm,
    pending: &mut VecDeque<PublishRequest>,
    active: &mut Option<ActivePublish>,
    bootstrap_completed: &mut bool,
) {
    match event {
        SwarmEvent::Behaviour(IpnsBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
            id,
            result: kad::QueryResult::PutRecord(result),
            ..
        })) if active
            .as_ref()
            .is_some_and(|publish| publish.query_id == id) =>
        {
            let publish = active
                .take()
                .expect("active publish checked to match query id");
            match result {
                Ok(_) => {
                    info!(
                        peer_id = %publish.publication.peer_id,
                        ipns_name = %publish.publication.ipns_name,
                        value = %publish.publication.value,
                        sequence = publish.publication.sequence,
                        elapsed = ?publish.started_at.elapsed(),
                        "published manifest CID to IPNS"
                    );
                    publish.request.respond(Ok(publish.publication));
                }
                Err(error) => {
                    warn!(?error, "IPNS DHT put_record failed");
                    publish
                        .request
                        .respond(Err(IpnsError::PutRecord(Box::new(error))));
                }
            }
            maybe_start_publish(
                keypair,
                config,
                swarm,
                pending,
                active,
                *bootstrap_completed,
                time::Instant::now(),
            );
        }
        SwarmEvent::Behaviour(IpnsBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
            result: kad::QueryResult::Bootstrap(result),
            step,
            ..
        })) => match result {
            Ok(status) => {
                debug!(
                    peer_id = %status.peer,
                    remaining = status.num_remaining,
                    step = step.count,
                    last = step.last,
                    "IPNS DHT bootstrap progressed"
                );
                if step.last {
                    *bootstrap_completed = true;
                    debug!("IPNS DHT bootstrap completed");
                    maybe_start_publish(
                        keypair,
                        config,
                        swarm,
                        pending,
                        active,
                        *bootstrap_completed,
                        time::Instant::now(),
                    );
                }
            }
            Err(error) => {
                warn!(?error, "IPNS DHT bootstrap failed");
            }
        },
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            debug!(%peer_id, "IPNS publisher connected to DHT peer");
            maybe_start_publish(
                keypair,
                config,
                swarm,
                pending,
                active,
                *bootstrap_completed,
                time::Instant::now(),
            );
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            debug!(%peer_id, "IPNS publisher disconnected from DHT peer");
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            debug!(
                ?peer_id,
                ?error,
                "IPNS publisher failed to connect to DHT peer"
            );
        }
        _ => {}
    }
}

fn discard_unpublishable_pending(pending: &mut VecDeque<PublishRequest>, now: time::Instant) {
    let mut retained = VecDeque::with_capacity(pending.len());
    while let Some(request) = pending.pop_front() {
        if request.response.is_closed() {
            debug!(
                manifest_cid = %request.manifest_cid,
                sequence = request.sequence,
                "dropped canceled IPNS publish request"
            );
        } else if request.is_expired(now) {
            debug!(
                manifest_cid = %request.manifest_cid,
                sequence = request.sequence,
                "expired pending IPNS publish request"
            );
            let timeout = request.timeout;
            request.respond(Err(IpnsError::Timeout(timeout)));
        } else {
            retained.push_back(request);
        }
    }
    *pending = retained;
}

fn next_pending_deadline(pending: &VecDeque<PublishRequest>) -> Option<time::Instant> {
    pending
        .iter()
        .filter(|request| !request.response.is_closed())
        .map(|request| request.deadline)
        .min()
}

async fn sleep_until_deadline(deadline: Option<time::Instant>) {
    if let Some(deadline) = deadline {
        time::sleep_until(deadline).await;
    }
}

fn start_bootstrap(swarm: &mut KadSwarm) {
    match swarm.behaviour_mut().kad.bootstrap() {
        Ok(query_id) => debug!(?query_id, "started IPNS DHT bootstrap"),
        Err(error) => warn!(?error, "failed to start IPNS DHT bootstrap"),
    }
}

fn has_enough_connected_peers_for_publish(swarm: &KadSwarm, bootstrap_completed: bool) -> bool {
    let connected_peers = swarm.network_info().num_peers();
    if bootstrap_completed {
        connected_peers > 0
    } else {
        connected_peers >= IPNS_MIN_CONNECTED_PEERS_FOR_PUBLISH
    }
}

async fn resolve_record(
    peer_id: PeerId,
    config: &IpnsPublisherConfig,
) -> Result<String, IpnsError> {
    let resolver_keypair = identity::Keypair::generate_ed25519();
    let mut swarm = build_swarm(&resolver_keypair, config)?;
    dial_bootstrap_peers(&mut swarm, config)?;
    start_bootstrap(&mut swarm);
    let record_key = ipns_record_key(peer_id);
    let query_id = swarm.behaviour_mut().kad.get_record(record_key.clone());

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(IpnsBehaviourEvent::Kad(
                kad::Event::OutboundQueryProgressed {
                    id,
                    result: kad::QueryResult::GetRecord(result),
                    ..
                },
            )) if id == query_id => match result {
                Ok(GetRecordOk::FoundRecord(peer_record)) => {
                    if peer_record.record.key == record_key {
                        return decode_manifest_cid(&peer_record.record.value, peer_id);
                    }
                }
                Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                    return Err(IpnsError::ResolveNoRecord);
                }
                Err(error) => return Err(IpnsError::GetRecord(Box::new(error))),
            },
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!(%peer_id, "IPNS resolver connected to DHT peer");
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                debug!(
                    ?peer_id,
                    ?error,
                    "IPNS resolver failed to connect to DHT peer"
                );
            }
            _ => {}
        }
    }
}

fn build_swarm(
    keypair: &identity::Keypair,
    config: &IpnsPublisherConfig,
) -> Result<KadSwarm, IpnsError> {
    let local_peer_id = PeerId::from(keypair.public());
    let transport = build_transport(keypair)?;
    let store = MemoryStore::new(local_peer_id);
    let mut kad_config = kad::Config::new(StreamProtocol::new(IPFS_KAD_PROTOCOL));
    kad_config
        .set_query_timeout(config.publish_timeout)
        .set_record_ttl(Some(config.record_lifetime))
        .set_publication_interval(None)
        .set_periodic_bootstrap_interval(None);

    let mut kad = kad::Behaviour::with_config(local_peer_id, store, kad_config);
    kad.set_mode(Some(kad::Mode::Client));
    let behaviour = IpnsBehaviour {
        kad,
        limits: connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_established(Some(IPNS_MAX_ESTABLISHED_CONNECTIONS))
                .with_max_established_outgoing(Some(IPNS_MAX_ESTABLISHED_CONNECTIONS))
                .with_max_established_per_peer(Some(1)),
        ),
    };

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    add_bootstrap_addresses(&mut swarm, config)?;

    Ok(swarm)
}

fn add_bootstrap_addresses(
    swarm: &mut KadSwarm,
    config: &IpnsPublisherConfig,
) -> Result<(), IpnsError> {
    for addr in &config.bootstrap_peers {
        let peer_id = peer_id_from_addr(addr)?;
        swarm
            .behaviour_mut()
            .kad
            .add_address(&peer_id, addr.clone());
    }

    Ok(())
}

fn dial_bootstrap_peers(
    swarm: &mut KadSwarm,
    config: &IpnsPublisherConfig,
) -> Result<(), IpnsError> {
    for addr in &config.bootstrap_peers {
        let peer_id = peer_id_from_addr(addr)?;
        match swarm.dial(addr.clone()) {
            Ok(()) => debug!(%peer_id, addr = %addr, "dialing IPNS bootstrap peer"),
            Err(error) => debug!(
                %peer_id,
                addr = %addr,
                ?error,
                "could not start IPNS bootstrap peer dial"
            ),
        }
    }

    Ok(())
}

fn build_transport(keypair: &identity::Keypair) -> Result<IpnsTransport, IpnsError> {
    let tcp_transport = dns::tokio::Transport::system(tcp::tokio::Transport::new(
        tcp::Config::default().nodelay(true),
    ))
    .map_err(IpnsError::Dns)?
    .upgrade(upgrade::Version::V1)
    .authenticate(noise::Config::new(keypair).map_err(IpnsError::Noise)?)
    .multiplex(yamux::Config::default())
    .timeout(Duration::from_secs(20))
    .boxed();

    Ok(tcp_transport)
}

fn peer_id_from_addr(addr: &Multiaddr) -> Result<PeerId, IpnsError> {
    match addr.iter().last() {
        Some(Protocol::P2p(peer_id)) => Ok(peer_id),
        _ => Err(IpnsError::MissingPeerId(addr.clone())),
    }
}

fn manifest_ipfs_path(manifest_cid: &str) -> Result<String, IpnsError> {
    let trimmed = manifest_cid.trim();
    let cid = trimmed.strip_prefix(IPFS_PATH_PREFIX).unwrap_or(trimmed);
    let _parsed = Cid::try_from(cid).map_err(|source| IpnsError::InvalidManifestCid {
        cid: cid.to_string(),
        source,
    })?;
    Ok(format!("{IPFS_PATH_PREFIX}{cid}"))
}

fn decode_manifest_cid(record_bytes: &[u8], peer_id: PeerId) -> Result<String, IpnsError> {
    let record = IpnsRecord::decode(record_bytes).map_err(IpnsError::DecodeRecord)?;
    record.verify(peer_id).map_err(IpnsError::VerifyRecord)?;
    let data = record.data().map_err(IpnsError::ReadRecordData)?;
    let value = str::from_utf8(data.value()).map_err(IpnsError::RecordValueUtf8)?;
    Ok(value
        .strip_prefix(IPFS_PATH_PREFIX)
        .unwrap_or(value)
        .to_string())
}

fn duration_nanos(duration: Duration) -> Result<u64, IpnsError> {
    duration
        .as_nanos()
        .try_into()
        .map_err(|_| IpnsError::RecordTtlTooLarge(duration))
}

#[derive(Debug, Error)]
pub enum IpnsError {
    #[error("invalid IPNS bootstrap multiaddr {addr}")]
    InvalidBootstrapAddress {
        addr: String,
        #[source]
        source: libp2p::multiaddr::Error,
    },
    #[error("IPNS bootstrap multiaddr is missing a /p2p peer id: {0}")]
    MissingPeerId(Multiaddr),
    #[error("publisher signing key cannot be converted to a libp2p ed25519 identity")]
    Identity(#[source] identity::DecodingError),
    #[error("invalid manifest CID {cid}")]
    InvalidManifestCid {
        cid: String,
        #[source]
        source: cid::Error,
    },
    #[error("failed to encode publisher peer id as an IPNS name")]
    IpnsName(#[source] cid::Error),
    #[error("IPNS record lifetime is out of range")]
    RecordLifetimeOutOfRange(#[source] chrono::OutOfRangeError),
    #[error("IPNS record TTL {0:?} is too large for a u64 nanosecond field")]
    RecordTtlTooLarge(Duration),
    #[error("failed to create signed IPNS record")]
    CreateRecord(#[source] std::io::Error),
    #[error("failed to verify signed IPNS record")]
    VerifyRecord(#[source] std::io::Error),
    #[error("failed to encode signed IPNS record")]
    EncodeRecord(#[source] std::io::Error),
    #[error("failed to decode IPNS record from DHT response")]
    DecodeRecord(#[source] std::io::Error),
    #[error("failed to read signed IPNS record data")]
    ReadRecordData(#[source] std::io::Error),
    #[error("failed to build DNS transport for IPNS publisher")]
    Dns(#[source] std::io::Error),
    #[error("failed to build noise transport config for IPNS publisher")]
    Noise(#[source] noise::Error),
    #[error("failed to store IPNS record in local Kademlia store")]
    Store(#[from] kad::store::Error),
    #[error("failed to dial IPNS bootstrap peer {peer_id} at {addr}")]
    DialBootstrap {
        peer_id: PeerId,
        addr: Multiaddr,
        #[source]
        source: Box<DialError>,
    },
    #[error("IPNS DHT operation timed out after {0:?}")]
    Timeout(Duration),
    #[error("IPNS publisher service is not running")]
    PublisherUnavailable,
    #[error("IPNS publisher service dropped the publication response")]
    PublisherResponseDropped,
    #[error("IPNS DHT put_record failed")]
    PutRecord(#[source] Box<kad::PutRecordError>),
    #[error("IPNS DHT get_record failed")]
    GetRecord(#[source] Box<kad::GetRecordError>),
    #[error("IPNS DHT resolve completed without a record")]
    ResolveNoRecord,
    #[error("IPNS record value is not UTF-8")]
    RecordValueUtf8(#[source] str::Utf8Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_RAW_CID: &str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";

    #[test]
    fn signed_record_uses_publisher_key_and_ipfs_path_value() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let keypair = identity_keypair_from_signing_key(&signing_key).expect("identity keypair");
        let record = build_signed_record(
            &keypair,
            EMPTY_RAW_CID,
            Duration::from_secs(60 * 60),
            Duration::from_secs(60),
            42,
        )
        .expect("signed IPNS record");

        let decoded = IpnsRecord::decode(&record.bytes).expect("decode IPNS record");
        decoded
            .verify(record.peer_id)
            .expect("valid IPNS signature");
        let data = decoded.data().expect("signed data");

        assert_eq!(record.sequence, 42);
        assert_eq!(data.sequence(), 42);
        assert_eq!(data.value(), format!("/ipfs/{EMPTY_RAW_CID}").as_bytes());
        assert_eq!(
            record.record_key.to_vec(),
            ipns_record_key_bytes(record.peer_id)
        );
        assert!(record.ipns_name.starts_with('k'));
    }

    #[test]
    fn manifest_cid_accepts_ipfs_path_but_stores_single_path_prefix() {
        assert_eq!(
            manifest_ipfs_path(&format!("/ipfs/{EMPTY_RAW_CID}")).expect("valid cid"),
            format!("/ipfs/{EMPTY_RAW_CID}")
        );
    }

    #[tokio::test]
    async fn expired_pending_publish_request_is_failed_and_removed() {
        let now = time::Instant::now();
        let timeout = Duration::from_secs(1);
        let (response_tx, response_rx) = oneshot::channel();
        let mut pending = VecDeque::from([PublishRequest {
            manifest_cid: EMPTY_RAW_CID.to_string(),
            sequence: 1,
            timeout,
            deadline: now,
            response: response_tx,
        }]);

        discard_unpublishable_pending(&mut pending, now + Duration::from_millis(1));

        assert!(pending.is_empty());
        match response_rx.await.expect("timeout response") {
            Err(IpnsError::Timeout(actual_timeout)) => assert_eq!(actual_timeout, timeout),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn canceled_pending_publish_request_is_removed() {
        let now = time::Instant::now();
        let timeout = Duration::from_secs(1);
        let (response_tx, response_rx) = oneshot::channel();
        drop(response_rx);
        let mut pending = VecDeque::from([PublishRequest {
            manifest_cid: EMPTY_RAW_CID.to_string(),
            sequence: 1,
            timeout,
            deadline: now + timeout,
            response: response_tx,
        }]);

        discard_unpublishable_pending(&mut pending, now);

        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn queued_publish_timeout_is_owned_by_publisher_task()
    -> Result<(), Box<dyn std::error::Error>> {
        let timeout = Duration::from_millis(10);
        let config = IpnsPublisherConfig {
            bootstrap_peers: Vec::new(),
            record_lifetime: Duration::from_secs(60 * 60),
            record_ttl: Duration::from_secs(60),
            publish_timeout: timeout,
        };
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let (publisher, publisher_task) = IpnsPublisher::new(&signing_key, config)?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let publisher_task = tokio::spawn(async move { publisher_task.run(shutdown_rx).await });

        let result = publisher.publish_manifest_cid(EMPTY_RAW_CID, 1).await;

        let _ = shutdown_tx.send(true);
        publisher_task.await??;
        match result {
            Err(IpnsError::Timeout(actual_timeout)) => assert_eq!(actual_timeout, timeout),
            other => panic!("unexpected publish result: {other:?}"),
        }
        Ok(())
    }
}
