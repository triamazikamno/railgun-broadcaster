use super::DiscoveredPeer;
use super::error::EnrDecodeError;
use alloy_rlp::Decodable;
use bytes::Bytes;
use enr::Enr;
use enr::k256;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId, identity};

type DefaultEnr = Enr<k256::ecdsa::SigningKey>;

pub(crate) fn decode_enr_record(enr_text: &str) -> Result<DiscoveredPeer, EnrDecodeError> {
    let enr: DefaultEnr = enr_text.parse().map_err(EnrDecodeError::InvalidEnrText)?;

    decode_enr(&enr)
}

pub(crate) fn decode_enr_rlp(enr_bytes: &[u8]) -> Result<DiscoveredPeer, EnrDecodeError> {
    let mut slice = enr_bytes;
    let enr = DefaultEnr::decode(&mut slice)?;

    decode_enr(&enr)
}

fn decode_enr(enr: &DefaultEnr) -> Result<DiscoveredPeer, EnrDecodeError> {
    // Waku filters out ENRs without a `waku2` field.
    let has_waku2 = enr
        .get_decodable::<Bytes>("waku2")
        .and_then(Result::ok)
        .is_some_and(|b| !b.is_empty());

    if !has_waku2 {
        return Err(EnrDecodeError::MissingWaku2);
    }

    let secp256k1_pubkey = enr
        .get_decodable::<Bytes>("secp256k1")
        .and_then(Result::ok)
        .ok_or(EnrDecodeError::MissingSecp256k1)?;

    let libp2p_pub = identity::secp256k1::PublicKey::try_from_bytes(secp256k1_pubkey.as_ref())?;

    let peer_id = PeerId::from_public_key(&identity::PublicKey::from(libp2p_pub));

    let mut addrs = Vec::<Multiaddr>::new();

    if let Some(sock) = enr.tcp4_socket() {
        let ip = sock.ip();
        let port = sock.port();
        let ma: Multiaddr = format!("/ip4/{ip}/tcp/{port}").parse()?;
        addrs.push(ma);
    }

    if let Some(sock) = enr.tcp6_socket() {
        let ip = sock.ip();
        let port = sock.port();
        let ma: Multiaddr = format!("/ip6/{ip}/tcp/{port}").parse()?;
        addrs.push(ma);
    }

    if let Some(Ok(multiaddrs_bytes)) = enr.get_decodable::<Bytes>("multiaddrs") {
        addrs.extend(decode_multiaddrs(multiaddrs_bytes.as_ref()));
    }

    // Add /p2p/<peer_id> encapsulation where missing.
    let mut full_addrs = Vec::new();
    for addr in addrs {
        let has_p2p = addr.iter().any(|p| matches!(p, Protocol::P2p(_)));
        if has_p2p {
            full_addrs.push(addr);
        } else {
            let with_peer: Multiaddr = format!("{addr}/p2p/{peer_id}").parse().unwrap_or(addr);
            full_addrs.push(with_peer);
        }
    }

    Ok(DiscoveredPeer {
        peer_id,
        addrs: full_addrs,
    })
}

fn decode_multiaddrs(bytes: &[u8]) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    let mut i = 0;

    while i + 2 <= bytes.len() {
        let size = u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize;
        i += 2;
        if i + size > bytes.len() {
            break;
        }
        let ma_bytes = bytes[i..i + size].to_vec();
        i += size;

        if let Ok(ma) = Multiaddr::try_from(ma_bytes) {
            out.push(ma);
        }
    }

    out
}
