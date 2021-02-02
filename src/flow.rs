/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::net::{Ipv4Addr, Ipv6Addr};
use libc::c_void;
use c_ulong;

/// C timeval structure
#[repr(C)]
struct Timeval {
    tv_sec: c_ulong,
    tv_usec: c_ulong,
}

/// Tranalyzer2 internal per flow structure.
#[repr(C, packed)]
pub struct Flow {
    lru_next_flow: *mut c_void,
    lru_prev_flow: *mut c_void,

    last_seen: Timeval,
    first_seen: Timeval,
    duration: Timeval,

    #[cfg(feature = "IPV6_ACTIVATE")]
    src_ip: [u8; 16],
    #[cfg(feature = "IPV6_ACTIVATE")]
    dst_ip: [u8; 16],
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    src_ip: u32,
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    dst_ip: u32,

    #[cfg(feature = "ETH_ACTIVATE")]
    eth_dhost: [u8; 6],
    #[cfg(feature = "ETH_ACTIVATE")]
    eth_shost: [u8; 6],
    #[cfg(feature = "ETH_ACTIVATE")]
    eth_type: u16,

    /// flow inner VLAN tag
    pub vlan_id: u16,

    /// flow source port (UDP or TCP)
    pub src_port: u16,
    /// flow destination port (UDP or TCP)
    pub dst_port: u16,

    #[cfg(feature = "IPV6_ACTIVATE")]
    ip_ver: u8,

    #[cfg(feature = "SCTP_ACTIVATE")]
    sctp_strm: u16,

    /// [Protocol number](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
    /// of the layer 4 header.
    pub l4_proto: u8,

    /// Unique flow index: second column of Tranalyzer2 flow output.
    pub findex: u64,

    #[cfg(all(feature = "SCTP_ACTIVATE", feature = "SCTP_STATFINDEX"))]
    sctp_findex: c_ulong,

    #[cfg(feature = "IPV6_ACTIVATE")]
    last_frag_ipid: u32,
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    last_frag_ipid: u16,

    last_ipid: u32,

    last_trdo: u16, // teredo

    /// flow status bits.
    pub status: u64,

    /// Tranalyzer2 internal flow index: uniquely identify a flow in internal hashmap but is not
    /// unique over a Tranalyzer2 run.
    ///
    /// Use this value with the [`getflow`](../fn.getflow.html) function. Use `findex` for a unique
    /// flow index.
    ///
    pub flow_index: c_ulong,
    /// Similar to `flow_index` but identifies the opposite flow associated to this flow.
    ///
    /// Equals [`HASHTABLE_ENTRY_NOT_FOUND`](../constant.HASHTABLE_ENTRY_NOT_FOUND.html) if this flow
    /// has no opposite flow.
    pub opposite_flow_index: c_ulong,

    /// timeout of this flow in seconds
    timeout: f32,
}

impl Flow {
    /// Timestamp of the first seen packet (as the number of seconds since 1970-01-01).
    pub fn first_seen(&self) -> f64 {
        let ts = unsafe{ &self.first_seen };
        ts.tv_sec as f64 + (ts.tv_usec as f64 / 1000000.0)
    }
    /// Timestamp of the last seen packet (as the number of seconds since 1970-01-01).
    pub fn last_seen(&self) -> f64 {
        let ts = unsafe{ &self.last_seen };
        ts.tv_sec as f64 + (ts.tv_usec as f64 / 1000000.0)
    }
    /// Duration of this flow in seconds.
    ///
    /// This method should only be called after the flow termination. To compute the current flow
    /// duration before the flow termination, use [`first_seen`](#method.first_seen) and
    /// [`last_seen`](#method.last_seen).
    pub fn duration(&self) -> f64 {
        let ts = unsafe{ &self.duration };
        ts.tv_sec as f64 + (ts.tv_usec as f64 / 1000000.0)
    }

    /// Returns source IPv4 address for an IPv4 flow. None for an IPv6 flow.
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    pub fn src_ip4(&self) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::from(u32::from_be(self.src_ip)))
    }
    /// Returns source IPv4 address for an IPv4 flow. None for an IPv6 flow.
    #[cfg(feature = "IPV6_ACTIVATE")]
    pub fn src_ip4(&self) -> Option<Ipv4Addr> {
        None
    }
    /// Returns destination IPv4 address for an IPv4 flow. None for an IPv6 flow.
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    pub fn dst_ip4(&self) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::from(u32::from_be(self.dst_ip)))
    }
    /// Returns destination IPv4 address for an IPv4 flow. None for an IPv6 flow.
    #[cfg(feature = "IPV6_ACTIVATE")]
    pub fn dst_ip4(&self) -> Option<Ipv4Addr> {
        None
    }

    /// Returns source IPv6 address for an IPv6 flow. None for an IPv4 flow.
    #[cfg(feature = "IPV6_ACTIVATE")]
    pub fn src_ip6(&self) -> Option<Ipv6Addr> {
        Some(Ipv6Addr::from(self.src_ip))
    }
    /// Returns source IPv6 address for an IPv6 flow. None for an IPv4 flow.
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    pub fn src_ip6(&self) -> Option<Ipv6Addr> {
        None
    }
    /// Returns destination IPv6 address for an IPv6 flow. None for an IPv4 flow.
    #[cfg(feature = "IPV6_ACTIVATE")]
    pub fn dst_ip6(&self) -> Option<Ipv6Addr> {
        Some(Ipv6Addr::from(self.dst_ip))
    }
    /// Returns destination IPv6 address for an IPv6 flow. None for an IPv4 flow.
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    pub fn dst_ip6(&self) -> Option<Ipv6Addr> {
        None
    }

    /// Returns the IP version of this flow (4 or 6).
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    pub fn ip_ver(&self) -> u8 {
        4
    }
    /// Returns the IP version of this flow (4 or 6).
    #[cfg(feature = "IPV6_ACTIVATE")]
    pub fn ip_ver(&self) -> u8 {
        self.ip_ver
    }
}