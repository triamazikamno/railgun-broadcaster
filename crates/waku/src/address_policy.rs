use libp2p::Multiaddr;
use libp2p::core::multiaddr::Protocol;

#[must_use]
pub(crate) fn tor_addr_rank(addr: &Multiaddr) -> Option<u8> {
    let mut protocols = addr.iter();
    match protocols.next()? {
        Protocol::Dns(_)
        | Protocol::Dns4(_)
        | Protocol::Dns6(_)
        | Protocol::Ip4(_)
        | Protocol::Ip6(_) => {}
        _ => return None,
    }

    let mut saw_tcp = false;
    let mut saw_ws = false;
    let mut saw_wss = false;
    let mut saw_tls = false;
    for protocol in protocols {
        match protocol {
            Protocol::Tcp(_) => saw_tcp = true,
            Protocol::Wss(_) => saw_wss = true,
            Protocol::Ws(_) => saw_ws = true,
            Protocol::Tls | Protocol::Sni(_) => saw_tls = true,
            Protocol::P2p(_) => {}
            _ => return None,
        }
    }

    if !saw_tcp {
        return None;
    }
    if saw_tls && !saw_ws && !saw_wss {
        return None;
    }
    if saw_wss {
        Some(0)
    } else if saw_ws {
        Some(1)
    } else {
        Some(2)
    }
}

#[must_use]
pub fn is_tor_safe_addr(addr: &Multiaddr) -> bool {
    tor_addr_rank(addr).is_some()
}

pub(crate) fn retain_tor_safe_addrs(addrs: &mut Vec<Multiaddr>) {
    addrs.retain(is_tor_safe_addr);
    sort_tor_safe_addrs(addrs);
}

pub(crate) fn sort_tor_safe_addrs(addrs: &mut [Multiaddr]) {
    addrs.sort_by(|left, right| {
        tor_addr_rank(left)
            .cmp(&tor_addr_rank(right))
            .then_with(|| left.cmp(right))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(value: &str) -> Multiaddr {
        value.parse().expect("valid multiaddr")
    }

    #[test]
    fn tor_policy_accepts_dns_wss_raw_dns_tcp_and_ip_tcp() {
        assert!(is_tor_safe_addr(&addr(
            "/dns4/support-4.rootedinprivacy.com/tcp/8000/wss"
        )));
        assert!(is_tor_safe_addr(&addr(
            "/dns4/support-4.rootedinprivacy.com/tcp/30304"
        )));
        assert!(is_tor_safe_addr(&addr("/ip4/203.0.113.10/tcp/30304")));
        assert!(is_tor_safe_addr(&addr("/ip6/2001:db8::1/tcp/30304")));
    }

    #[test]
    fn tor_policy_rejects_udp_quic_and_webtransport() {
        assert!(!is_tor_safe_addr(&addr(
            "/dns4/example.com/udp/9000/quic-v1"
        )));
        assert!(!is_tor_safe_addr(&addr("/ip4/203.0.113.10/udp/30304")));
        assert!(!is_tor_safe_addr(&addr(
            "/dns4/example.com/udp/443/quic-v1/webtransport"
        )));
    }

    #[test]
    fn tor_policy_rejects_tls_without_websocket() {
        assert!(!is_tor_safe_addr(&addr("/dns4/example.com/tcp/443/tls")));
        assert!(!is_tor_safe_addr(&addr(
            "/dns4/example.com/tcp/443/tls/sni/example.com"
        )));
        assert!(is_tor_safe_addr(&addr(
            "/dns4/example.com/tcp/443/tls/sni/example.com/ws"
        )));
    }

    #[test]
    fn tor_policy_prefers_wss_before_raw_tcp() {
        let mut addrs = vec![
            addr("/dns4/example.com/tcp/30304"),
            addr("/dns4/example.com/tcp/8000/wss"),
            addr("/dns4/example.com/tcp/8001/ws"),
        ];
        retain_tor_safe_addrs(&mut addrs);
        assert!(addrs[0].to_string().contains("/wss"));
        assert!(addrs[1].to_string().contains("/ws"));
        assert!(!addrs[2].to_string().contains("/ws"));
    }

    #[test]
    fn tor_policy_sorts_same_rank_duplicates_adjacent_for_dedup() {
        let a = addr("/ip4/203.0.113.10/tcp/30304");
        let b = addr("/ip4/203.0.113.11/tcp/30304");
        let c = addr("/ip4/203.0.113.12/tcp/30304");
        let mut addrs = vec![a.clone(), b, a.clone(), c];

        retain_tor_safe_addrs(&mut addrs);
        addrs.dedup();

        assert_eq!(addrs.iter().filter(|addr| *addr == &a).count(), 1);
        assert_eq!(addrs.len(), 3);
    }
}
