//! Self-loop protection.
//!
//! Prevents the proxy from connecting back to its *own* listening socket,
//! which would create an infinite proxy → proxy loop. It deliberately does
//! NOT block other services on the same machine — only targets that would
//! land on the proxy's own listener are denied.
//!
//! Detection rule (precise to which socket the listener actually accepts):
//! - Target port must equal the proxy's listen port. Different port → never a loop.
//! - If the proxy bound to a *specific* IP, only that IP loops (a listener bound
//!   to `1.2.3.4` does not accept connections to `127.0.0.1`).
//! - If the proxy bound to the *unspecified* address (`0.0.0.0` / `::`), it
//!   listens on every local interface, so any loopback or local-interface IP
//!   on that port loops.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, UdpSocket};

#[derive(Debug, Clone)]
pub struct SelfLoopGuard {
    port: u16,
    bind_ip: IpAddr,
    bind_unspecified: bool,
    /// Local-interface IPs (best-effort), used only when the bind is unspecified.
    local_ips: HashSet<IpAddr>,
}

impl SelfLoopGuard {
    /// Build a guard from the proxy's `proxy_bind` string (e.g. "0.0.0.0:1080").
    /// Returns `None` if the bind address can't be parsed — in that case the
    /// caller simply skips self-loop protection.
    pub fn from_bind(proxy_bind: &str) -> Option<Self> {
        let addr: SocketAddr = proxy_bind.parse().ok()?;
        let bind_ip = addr.ip();
        let bind_unspecified = bind_ip.is_unspecified();

        let mut local_ips = HashSet::new();
        if bind_unspecified {
            // Best-effort discovery of this host's primary interface IPs so we
            // can recognise e.g. a public IP target that loops back to us.
            for remote in ["8.8.8.8:80", "[2001:4860:4860::8888]:80"] {
                if let Some(ip) = primary_local_ip(remote) {
                    local_ips.insert(ip);
                }
            }
        } else {
            local_ips.insert(bind_ip);
        }

        Some(Self {
            port: addr.port(),
            bind_ip,
            bind_unspecified,
            local_ips,
        })
    }

    /// True if connecting to `target` would hit the proxy's own listener.
    pub fn is_self_loop(&self, target: SocketAddr) -> bool {
        if target.port() != self.port {
            return false;
        }
        let ip = target.ip();
        if self.bind_unspecified {
            // Listening on all interfaces: loopback or any local IP loops.
            ip.is_loopback() || self.local_ips.contains(&ip)
        } else {
            // Listening on one IP only: that exact IP loops. Loopback only
            // loops if we are actually bound to loopback.
            ip == self.bind_ip || (ip.is_loopback() && self.bind_ip.is_loopback())
        }
    }
}

/// Discover the local IP the kernel would use to reach `remote`, via a
/// connected (but never sending) UDP socket. No packets are sent.
fn primary_local_ip(remote: &str) -> Option<IpAddr> {
    let bind = if remote.starts_with('[') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(remote).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn specific_bind_blocks_only_that_ip_on_that_port() {
        let g = SelfLoopGuard::from_bind("1.2.3.4:1080").unwrap();
        // Same IP + port → loop.
        assert!(g.is_self_loop(sa("1.2.3.4:1080")));
        // Same IP, different port (the web service) → allowed.
        assert!(!g.is_self_loop(sa("1.2.3.4:8080")));
        // Loopback is not accepted by a listener bound to 1.2.3.4 → allowed.
        assert!(!g.is_self_loop(sa("127.0.0.1:1080")));
        // Different host, same port → allowed.
        assert!(!g.is_self_loop(sa("5.6.7.8:1080")));
    }

    #[test]
    fn unspecified_bind_blocks_loopback_on_port() {
        let g = SelfLoopGuard::from_bind("0.0.0.0:1080").unwrap();
        assert!(g.is_self_loop(sa("127.0.0.1:1080")));
        // Other ports on loopback (a local service) → allowed.
        assert!(!g.is_self_loop(sa("127.0.0.1:8080")));
    }

    #[test]
    fn loopback_bind_blocks_loopback() {
        let g = SelfLoopGuard::from_bind("127.0.0.1:1080").unwrap();
        assert!(g.is_self_loop(sa("127.0.0.1:1080")));
        assert!(!g.is_self_loop(sa("127.0.0.1:8080")));
    }

    #[test]
    fn bad_bind_returns_none() {
        assert!(SelfLoopGuard::from_bind("not-an-addr").is_none());
    }
}
