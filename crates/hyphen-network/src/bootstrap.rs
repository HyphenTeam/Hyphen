//! DNS seed resolution for boot-node multiaddrs.
//!
//! libp2p's DNS transport is deliberately absent from this workspace's feature
//! set: `.github/workflows/ci.yml` fails the build if any `hickory-*` crate
//! reaches the runtime graph. The consequence is easy to miss — an operator
//! writing the obvious
//!
//! ```text
//! --boot-nodes /dns4/seed.example.org/tcp/48334/p2p/12D3Koo…
//! ```
//!
//! gets a multiaddr that parses, is stored in Kademlia, and can never be
//! dialled, with no error anywhere. This module closes that gap without
//! re-introducing the dependency the CI guard exists to keep out: the host is
//! resolved with [`recurse_x`], a DNSSEC-validating resolver whose own
//! dependency graph is the HyphenTeam crates (`nextjson`, `tzcraft`, and
//! `courierust` for encrypted transports), and each address is rebuilt into the
//! `/ip4` or `/ip6` multiaddr that carries the same `/tcp/<port>[/p2p/<peer>]`
//! tail.
//!
//! Resolution is *fail-closed*: a boot node whose host cannot be resolved is an
//! error naming the host, never a silently dropped peer. A node that starts
//! with fewer seeds than the operator listed is a node the operator did not ask
//! for.
//!
//! ## Why a recursive resolver and not the OS stub
//!
//! The seed name decides which peers a node trusts to introduce it to the
//! network, and it is resolved once per boot. Asking the local stub resolver
//! means that answer is only as trustworthy as whatever recursive resolver the
//! host happens to use — plaintext, unvalidated, and shared with every other
//! application on the machine. `recurse-x` walks the delegation tree itself and
//! validates DNSSEC, so the seed answer is authenticated end to end.
//! Operators who must route DNS through their own infrastructure can name
//! upstreams instead (see [`SeedResolver::with_upstreams`]); plain, DoT and DoH
//! specs are accepted in `recurse-x`'s own format, e.g.
//! `tls://1.1.1.1:853#cloudflare-dns.com`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libp2p::multiaddr::{Multiaddr, Protocol};
use recurse_x::{Name, Rcode, Record, RrType};

/// Failure to resolve the DNS hosts of a boot-node set.
#[derive(Debug, thiserror::Error)]
pub enum SeedError {
    /// The resolver itself could not be built, usually a bad upstream spec.
    #[error("cannot build the seed resolver: {0}")]
    Resolver(String),
    /// A hostname produced no address of the requested family.
    #[error("seed host '{host}' has no {family} address ({rcode})")]
    NoAddress {
        /// Hostname that failed.
        host: String,
        /// Address family that was queried.
        family: &'static str,
        /// DNS response code, so an operator can tell NXDOMAIN from SERVFAIL.
        rcode: String,
    },
    /// A query could not be delivered at all.
    #[error("resolving seed host '{host}' failed: {reason}")]
    Lookup {
        /// Hostname that failed.
        host: String,
        /// Transport or resolver error.
        reason: String,
    },
}

/// A boot-node multiaddr whose host still has to be resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DnsSeed {
    host: String,
    family: AddressFamily,
    /// `/tcp/<port>[/p2p/<peer-id>]`, replayed verbatim after the address.
    tail: Vec<Protocol<'static>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressFamily {
    V4,
    V6,
    Both,
}

impl AddressFamily {
    fn label(self) -> &'static str {
        match self {
            AddressFamily::V4 => "A",
            AddressFamily::V6 => "AAAA",
            AddressFamily::Both => "A/AAAA",
        }
    }
}

/// Resolves `/dns4`, `/dns6` and `/dns` boot nodes into dialable addresses.
///
/// The resolver keeps its cache and maintenance thread alive for the lifetime
/// of the value, so a node that re-resolves its seeds on a reconnect tick pays
/// one query per TTL rather than one per attempt.
pub struct SeedResolver {
    resolver: recurse_x::Resolver,
    upstreams: usize,
}

impl SeedResolver {
    /// Builds a resolver that walks the delegation tree from the IANA roots.
    pub fn recursive() -> Result<Self, SeedError> {
        Self::build(Vec::new())
    }

    /// Builds a resolver that consults the given upstreams.
    ///
    /// Specs use `recurse-x`'s format: `udp://1.1.1.1:53`, `tls://1.1.1.1:853#cloudflare-dns.com`,
    /// `https://dns.google/dns-query#dns.google`. The `#name` fragment is the
    /// TLS identity for encrypted transports and is mandatory for them: the
    /// resolver refuses to trust a certificate that is not bound to the name
    /// the operator wrote down.
    pub fn with_upstreams<S: AsRef<str>>(specs: &[S]) -> Result<Self, SeedError> {
        Self::build(specs.iter().map(|s| s.as_ref().to_string()).collect())
    }

    fn build(upstreams: Vec<String>) -> Result<Self, SeedError> {
        let mut config = recurse_x::ResolverConfig::default();
        for spec in &upstreams {
            let forwarder = recurse_x::config::parse_upstream(spec)
                .map_err(|error| SeedError::Resolver(error.to_string()))?;
            config.engine.forwarders.push(forwarder);
        }
        let count = config.engine.forwarders.len();
        let resolver = recurse_x::Resolver::new(config);
        Ok(Self {
            resolver,
            upstreams: count,
        })
    }

    /// Number of configured upstreams; zero means iterative recursion from the
    /// root servers.
    pub fn upstream_count(&self) -> usize {
        self.upstreams
    }

    /// Rewrites every DNS boot node into concrete address multiaddrs.
    ///
    /// Addresses that already carry `/ip4` or `/ip6` are returned unchanged, in
    /// order. Each DNS address is replaced in place by its resolved siblings,
    /// so the caller's ordering intent survives.
    pub fn resolve(&self, boot_nodes: &[Multiaddr]) -> Result<Vec<Multiaddr>, SeedError> {
        let mut resolved = Vec::with_capacity(boot_nodes.len());
        for address in boot_nodes {
            match split_dns_seed(address) {
                None => resolved.push(address.clone()),
                Some(seed) => {
                    let mut expanded = Vec::new();
                    for family in seed.family.families().iter().copied() {
                        let records = self.query(&seed.host, family)?;
                        for record in records {
                            expanded.push(rebuild(address, record.ip(), &seed.tail));
                        }
                    }
                    if expanded.is_empty() {
                        return Err(SeedError::NoAddress {
                            host: seed.host.clone(),
                            family: seed.family.label(),
                            rcode: "no records".into(),
                        });
                    }
                    resolved.extend(expanded);
                }
            }
        }
        Ok(resolved)
    }

    /// Resolves one host for one family, keeping the response code for the error
    /// path so an operator can distinguish NXDOMAIN from a resolver timeout.
    fn query(&self, host: &str, family: AddressFamily) -> Result<Vec<ResolvedAddress>, SeedError> {
        let name = Name::from_ascii(host).map_err(|error| SeedError::Lookup {
            host: host.to_string(),
            reason: error.to_string(),
        })?;
        let rr_type = match family {
            AddressFamily::V6 => RrType::AAAA,
            _ => RrType::A,
        };
        let resolution =
            self.resolver
                .resolve(&name, rr_type)
                .map_err(|error| SeedError::Lookup {
                    host: host.to_string(),
                    reason: error.to_string(),
                })?;

        let addresses = resolution
            .answers
            .iter()
            .filter_map(record_address)
            .collect::<Vec<_>>();

        if addresses.is_empty() {
            if !matches!(resolution.rcode, Rcode::NOERROR) {
                return Err(SeedError::NoAddress {
                    host: host.to_string(),
                    family: family.label(),
                    rcode: resolution.rcode.to_string(),
                });
            }
            return Err(SeedError::NoAddress {
                host: host.to_string(),
                family: family.label(),
                rcode: "no records".into(),
            });
        }
        Ok(addresses)
    }

    /// Stops the maintenance thread. Call once, at shutdown.
    pub fn shutdown(&self) {
        self.resolver.shutdown();
    }
}

impl std::fmt::Debug for SeedResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The resolver's internals are not inspectable; the operator-relevant
        // fact is whether it forwards or recurses.
        f.debug_struct("SeedResolver")
            .field("upstreams", &self.upstreams)
            .finish_non_exhaustive()
    }
}

impl Drop for SeedResolver {
    fn drop(&mut self) {
        // `recurse-x` documents that a resolver must be shut down to join its
        // maintenance thread; dropping is the last chance to do it, and it is
        // idempotent.
        self.resolver.shutdown();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolvedAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl ResolvedAddress {
    fn ip(self) -> IpAddr {
        match self {
            ResolvedAddress::V4(addr) => IpAddr::V4(addr),
            ResolvedAddress::V6(addr) => IpAddr::V6(addr),
        }
    }
}

impl AddressFamily {
    fn families(self) -> &'static [AddressFamily] {
        match self {
            AddressFamily::V4 => &[AddressFamily::V4],
            AddressFamily::V6 => &[AddressFamily::V6],
            AddressFamily::Both => &[AddressFamily::V4, AddressFamily::V6],
        }
    }
}

/// Reads an A or AAAA address out of an answer record.
fn record_address(record: &Record) -> Option<ResolvedAddress> {
    match record.rdata {
        recurse_x::RData::A(addr) => Some(ResolvedAddress::V4(addr)),
        recurse_x::RData::Aaaa(addr) => Some(ResolvedAddress::V6(addr)),
        _ => None,
    }
}

/// Whether `address` names its host instead of carrying a concrete IP address.
///
/// `/dnsaddr` (a TXT-record indirection) is deliberately *not* treated as a
/// seed here: it returns a list of multiaddrs rather than an address, so it
/// needs its own resolution step and is rejected at parse time instead.
pub fn is_dns_seed(address: &Multiaddr) -> bool {
    matches!(
        address.iter().next(),
        Some(Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dns(_))
    )
}

/// Splits `/dns{4,6}/<host>/…` into the host and the protocol tail to replay.
fn split_dns_seed(address: &Multiaddr) -> Option<DnsSeed> {
    let mut protocols = address.iter();
    let first = protocols.next()?;
    let (host, family) = match first {
        Protocol::Dns4(host) => (host.to_string(), AddressFamily::V4),
        Protocol::Dns6(host) => (host.to_string(), AddressFamily::V6),
        Protocol::Dns(host) => (host.to_string(), AddressFamily::Both),
        _ => return None,
    };
    let tail = protocols
        .map(|protocol| protocol.acquire())
        .collect::<Vec<_>>();
    if tail.is_empty() {
        return None;
    }
    Some(DnsSeed { host, family, tail })
}

/// Rebuilds the multiaddr with a concrete address in front of the original tail.
fn rebuild(original: &Multiaddr, address: IpAddr, tail: &[Protocol<'static>]) -> Multiaddr {
    let mut rebuilt = Multiaddr::empty();
    rebuilt.push(match address {
        IpAddr::V4(addr) => Protocol::Ip4(addr),
        IpAddr::V6(addr) => Protocol::Ip6(addr),
    });
    for protocol in tail {
        rebuilt.push(protocol.clone());
    }
    debug_assert_ne!(
        rebuilt, *original,
        "resolved multiaddr must differ from the DNS form"
    );
    rebuilt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Multiaddr {
        s.parse().expect("valid multiaddr")
    }

    #[test]
    fn dns4_seed_splits_into_host_and_tail() {
        let seed = split_dns_seed(&addr("/dns4/seed.example.org/tcp/48334")).unwrap();
        assert_eq!(seed.host, "seed.example.org");
        assert_eq!(seed.family, AddressFamily::V4);
        assert_eq!(seed.tail, vec![Protocol::Tcp(48334)]);
    }

    #[test]
    fn dns6_seed_keeps_the_peer_id_tail() {
        let address =
            addr("/dns6/seed.example.org/tcp/48334/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN");
        let seed = split_dns_seed(&address).unwrap();
        assert_eq!(seed.family, AddressFamily::V6);
        assert!(matches!(seed.tail[0], Protocol::Tcp(48334)));
        assert!(matches!(seed.tail[1], Protocol::P2p(_)));
    }

    #[test]
    fn addresses_without_a_host_are_not_seeds() {
        assert!(split_dns_seed(&addr("/ip4/127.0.0.1/tcp/48334")).is_none());
        assert!(split_dns_seed(&addr("/dns4/seed.example.org")).is_none());
    }

    #[test]
    fn rebuild_keeps_the_protocol_tail() {
        let original = addr("/dns4/seed.example.org/tcp/48334");
        let rebuilt = rebuild(
            &original,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            &[Protocol::Tcp(48334)],
        );
        assert_eq!(rebuilt.to_string(), "/ip4/203.0.113.7/tcp/48334");
    }

    /// The resolver's own answer shape is what the rewrite depends on, so the
    /// mapping from records to addresses is pinned here: A and AAAA map, and a
    /// CNAME chain (which a recursive resolver returns in the same answer list)
    /// contributes nothing.
    #[test]
    fn only_address_records_produce_addresses() {
        let a = Record {
            name: Name::from_ascii("seed.example.org").unwrap(),
            rr_type: RrType::A,
            class: recurse_x::RrClass::IN,
            ttl: 60,
            rdata: recurse_x::RData::A(Ipv4Addr::new(198, 51, 100, 9)),
        };
        let cname = Record {
            name: Name::from_ascii("seed.example.org").unwrap(),
            rr_type: RrType::CNAME,
            class: recurse_x::RrClass::IN,
            ttl: 60,
            rdata: recurse_x::RData::Cname(Name::from_ascii("edge.example.net").unwrap()),
        };

        assert_eq!(
            record_address(&a),
            Some(ResolvedAddress::V4(Ipv4Addr::new(198, 51, 100, 9)))
        );
        assert_eq!(record_address(&cname), None);
    }

    #[test]
    fn unknown_upstream_scheme_is_rejected() {
        let error = SeedResolver::with_upstreams(&["gopher://127.0.0.1:70"]).unwrap_err();
        assert!(
            matches!(error, SeedError::Resolver(_)),
            "unexpected error: {error:?}"
        );
    }

    /// Live check against the public DNS root servers. Ignored by default: it
    /// needs outbound UDP/53 (or a configured upstream) and a working internet
    /// connection, neither of which CI guarantees.
    #[test]
    #[ignore = "requires network access to the DNS root servers"]
    fn resolves_a_public_host_iteratively() {
        let resolver = SeedResolver::recursive().expect("resolver");
        let resolved = resolver
            .resolve(&[addr("/dns4/one.one.one.one/tcp/443")])
            .expect("one.one.one.one must resolve");
        assert!(!resolved.is_empty());
        assert!(resolved
            .iter()
            .all(|address| address.to_string().starts_with("/ip4/")));
        resolver.shutdown();
    }
}
