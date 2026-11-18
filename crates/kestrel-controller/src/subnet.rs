// SPDX-License-Identifier: LGPL-2.1-or-later

//! Allocation of IPv4 subnets for links that Kestrel serves addresses on
//! (P2P Group Owner, and later SoftAP).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use kestrel_model::{InterfaceName, IpNet, Ipv4Net};

/// A pure allocator over a configured pool of candidate subnets.
///
/// Allocation is idempotent per link. A candidate is skipped when it
/// overlaps anything already in use on the host (reported by the L3
/// provider) or allocated to another link.
#[derive(Debug, Clone)]
pub(crate) struct SubnetAllocator {
    pool: Vec<Ipv4Net>,
    leased: BTreeMap<InterfaceName, Ipv4Net>,
}

impl SubnetAllocator {
    pub(crate) fn new(pool: Vec<Ipv4Net>) -> Self {
        Self {
            pool: pool.into_iter().map(|net| net.trunc()).collect(),
            leased: BTreeMap::new(),
        }
    }

    /// The default pool: `192.168.49.0/24` (the Wi-Fi Direct convention),
    /// then `10.49.N.0/24` for N in 0..16.
    pub(crate) fn default_pool() -> Vec<Ipv4Net> {
        let mut pool =
            vec![Ipv4Net::new(Ipv4Addr::new(192, 168, 49, 0), 24).expect("valid prefix")];
        pool.extend(
            (0..16).map(|n| Ipv4Net::new(Ipv4Addr::new(10, 49, n, 0), 24).expect("valid prefix")),
        );
        pool
    }

    pub(crate) fn allocate(&mut self, link: &InterfaceName, in_use: &[IpNet]) -> Option<Ipv4Net> {
        if let Some(existing) = self.leased.get(link) {
            return Some(*existing);
        }
        let candidate = self.pool.iter().copied().find(|candidate| {
            !self
                .leased
                .values()
                .any(|taken| overlaps(*taken, *candidate))
                && !in_use.iter().any(|used| match used {
                    IpNet::V4(used) => overlaps(used.trunc(), *candidate),
                    IpNet::V6(_) => false,
                })
        })?;
        self.leased.insert(link.clone(), candidate);
        Some(candidate)
    }

    pub(crate) fn release(&mut self, link: &InterfaceName) -> Option<Ipv4Net> {
        self.leased.remove(link)
    }
}

/// The first host address of `subnet`, with the subnet's prefix: the
/// address the serving side takes.
pub(crate) fn gateway_address(subnet: Ipv4Net) -> Ipv4Net {
    let first = u32::from(subnet.network()).saturating_add(1);
    Ipv4Net::new(Ipv4Addr::from(first), subnet.prefix_len()).expect("prefix is unchanged")
}

/// DHCP pool offset and size within `subnet`: everything except the
/// network, gateway, and broadcast addresses.
pub(crate) fn dhcp_pool(subnet: Ipv4Net) -> (u32, u32) {
    let hosts = 1u32
        .checked_shl(32 - u32::from(subnet.prefix_len()))
        .unwrap_or(0);
    let size = hosts.saturating_sub(3);
    (2, size)
}

fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(name: &str) -> InterfaceName {
        InterfaceName::new(name).unwrap()
    }

    #[test]
    fn allocates_first_free_and_is_idempotent() {
        let mut alloc = SubnetAllocator::new(SubnetAllocator::default_pool());
        let first = alloc.allocate(&link("p2p-0"), &[]).unwrap();
        assert_eq!(first.to_string(), "192.168.49.0/24");
        assert_eq!(alloc.allocate(&link("p2p-0"), &[]), Some(first));
        let second = alloc.allocate(&link("p2p-1"), &[]).unwrap();
        assert_eq!(second.to_string(), "10.49.0.0/24");
        alloc.release(&link("p2p-0"));
        assert_eq!(alloc.allocate(&link("p2p-2"), &[]), Some(first));
    }

    #[test]
    fn skips_subnets_in_use_on_the_host() {
        let mut alloc = SubnetAllocator::new(SubnetAllocator::default_pool());
        let in_use: Vec<IpNet> = vec![
            "192.168.49.77/24".parse().unwrap(),
            "10.0.0.5/8".parse().unwrap(),
        ];
        // 10.0.0.0/8 covers every 10.49.N.0/24 candidate.
        assert_eq!(alloc.allocate(&link("p2p-0"), &in_use), None);
        let in_use: Vec<IpNet> = vec!["192.168.49.77/24".parse().unwrap()];
        assert_eq!(
            alloc.allocate(&link("p2p-0"), &in_use).unwrap().to_string(),
            "10.49.0.0/24"
        );
    }

    #[test]
    fn gateway_and_pool_math() {
        let net: Ipv4Net = "192.168.49.0/24".parse().unwrap();
        assert_eq!(gateway_address(net).to_string(), "192.168.49.1/24");
        assert_eq!(dhcp_pool(net), (2, 253));
        let tiny: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        assert_eq!(dhcp_pool(tiny), (2, 1));
    }
}
