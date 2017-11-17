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

use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::slice;
use libc::{c_void, c_char};
use c_ulong;

fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

fn ntohl(u: u32) -> u32 {
    u32::from_be(u)
}

/// C timeval structure
#[repr(C)]
struct Timeval {
    tv_sec: c_ulong,
    tv_usec: c_ulong,
}

/// Pcap packet header
#[repr(C, packed)]
struct PacketHeader {
    tv_sec: u32,
    tv_usec: u32,
    snap_len: u32,
    orig_len: u32,
}

/// Represents a packet with its different headers and associated lengths.
#[repr(C)]
pub struct Packet {
    #[cfg(feature = "T2_PRI_HDRDESC")]
    hdr_desc: [c_char; 128],

    raw_packet: *const u8,
    pcap_pkthdr: *const PacketHeader,
    l2_header: *const c_void,
    vlans: *const u32,
    ether_llc: *const c_void,
    mpls: *const u32,
    l3_header: *const c_void,
    l4_header: *const c_void,
    gre_header: *const c_void,
    l2tp_hdr: *const c_void,
    gre_l3_hdr: *const c_void,
    l2tp_l3_hdr: *const c_void,
    ppp_hdr: *const c_void,
    pppoe_hdr: *const c_void,

    ip6_hh_opt_hdr: *const c_void,
    ip6_d_opt_hdr: *const c_void,
    ip6_frag_hdr: *const c_void,
    ip6_route_hdr: *const c_void,

    trdo_oi_hdr: *const u8,
    trdo_a_hdr: *const u8,

    l7_header: *const u8,

    /// Raw pointer to SCTP header. Only present if `SCTP_ACTIVATE = 1`.
    #[cfg(feature = "SCTP_ACTIVATE")]
    pub l7_sctp_hdr: *const u8,

    /// SCTP L7 snapped length. Only present if `SCTP_ACTIVATE = 1`.
    #[cfg(feature = "SCTP_ACTIVATE")]
    pub snap_sctp_l7_len: u16,

    /// Length of the layer 2 header (Ethernet, ...).
    pub l2_hdr_len: u16,
    /// Length of the layer 3 header (IPv4, IPv6, ...).
    pub l3_hdr_len: u16,
    /// Length of the layer 4 header (TCP, UDP, ICMP, ...).
    pub l4_hdr_len: u16,
    /// Packet snapped length starting from layer 2.
    pub snap_l2_len: u16,
    /// Packet snapped length starting from layer 3.
    pub snap_l3_len: u16,
    /// Packet snapped length starting from layer 4.
    pub snap_l4_len: u16,
    /// Packet snapped length starting from layer 7.
    pub snap_l7_len: u16,
    /// On wire packet length starting from layer2.
    pub packet_l2_len: u16,
    /// On wire full packet length (from the per-packet PCAP header).
    pub packet_raw_len: u16,
    /// Packet payload length: layer 7 length.
    pub packet_l7_len: u16,
    /// Packet length depending on Tranalyzer2 `PACKETLENGTH` value, see `networkHeaders.h` for details.
    pub packet_len: u16,

    /// Source port in host order.
    pub src_port: u16,
    /// Destination port in host order.
    pub dst_port: u16,
    /// Inner VLAN ID
    pub inner_vlan: u16,
    /// Type of the layer 2 header.
    pub l2_type: u16,
    /// Type of the layer 3 header as defined in [`L3Type`](nethdr/enum.L3Type.html).
    l3_type: u16,
    /// Per packet status bits.
    pub status: u64,
    /// Type of the layer 4 header as defined in [`L4Type`](nethdr/enum.L4Type.html).
    l4_type: u8,

    vlan_hdr_count: u8,
    mpls_hdr_count: u8,
}

impl Packet {
    /// Timestamp of when the packet was captured (as the number of seconds since 1970-01-01).
    pub fn timestamp(&self) -> f64 {
        unsafe {
            let ref hdr = *self.pcap_pkthdr;
            hdr.tv_sec as f64 + (hdr.tv_usec as f64 / 1000000.0)
        }
    }

    /// Returns an [`EthernetHeader`](nethdr/struct.EthernetHeader.html) if the packet contains an
    /// Ethernet header and is long enough. Returns `None` otherwise.
    pub fn ethernethdr(&self) -> Option<&EthernetHeader> {
        // assumes that all traffic is ethernet
        let size = mem::size_of::<EthernetHeader>();
        if self.snap_l2_len as usize >= size && self.l2_header != 0 as *const c_void {
            unsafe {
                Some(&*(self.l2_header as *const EthernetHeader))
            }
        } else {
            None
        }
    }

    /// Returns an [`Ip4Header`](nethdr/struct.Ip4Header.html) if the packet contains an
    /// IPv4 header and is long enough. Returns `None` otherwise.
    pub fn ip4hdr(&self) -> Option<&Ip4Header> {
        let size = mem::size_of::<Ip4Header>();
        if self.l3_type() == L3Type::IPv4 && self.snap_l3_len as usize >= size && 
                self.l3_header != 0 as *const c_void {
            unsafe {
                Some(&*(self.l3_header as *const Ip4Header))
            }
        } else {
            None
        }
    }

    /// Returns an [`Ip4Header`](nethdr/struct.Ip6Header.html) if the packet contains an
    /// IPv6 header and is long enough. Returns `None` otherwise.
    pub fn ip6hdr(&self) -> Option<&Ip6Header> {
        let size = mem::size_of::<Ip6Header>();
        if self.l3_type() == L3Type::IPv6 && self.snap_l3_len as usize >= size &&
                self.l3_header != 0 as *const c_void {
            unsafe {
                Some(&*(self.l3_header as *const Ip6Header))
            }
        } else {
            None
        }
    }

    /// Returns an [`TcpHeader`](nethdr/struct.TcpHeader.html) if the packet contains a
    /// TCP header and is long enough. Returns `None` otherwise.
    pub fn tcphdr(&self) -> Option<&TcpHeader> {
        let size = mem::size_of::<TcpHeader>();
        if self.l4_type() == L4Type::TCP && self.snap_l4_len as usize >= size &&
                self.l4_header != 0 as *const c_void {
            unsafe {
                Some(&*(self.l4_header as *const TcpHeader))
            }
        } else {
            None
        }
    }

    /// Returns an [`UdpHeader`](nethdr/struct.UdpHeader.html) if the packet contains a
    /// UDP header and is long enough. Returns `None` otherwise.
    pub fn udphdr(&self) -> Option<&UdpHeader> {
        let size = mem::size_of::<UdpHeader>();
        if self.l4_type() == L4Type::UDP && self.snap_l4_len as usize >= size &&
                self.l4_header != 0 as *const c_void {
            unsafe {
                Some(&*(self.l4_header as *const UdpHeader))
            }
        } else {
            None
        }
    }

    /// Returns an [`IcmpHeader`](nethdr/struct.IcmpHeader.html) if the packet contains an
    /// ICMP header and is long enough. Returns `None` otherwise.
    pub fn icmphdr(&self) -> Option<&IcmpHeader> {
        let size = mem::size_of::<IcmpHeader>();
        if self.l4_type() == L4Type::ICMP && self.snap_l4_len as usize >= size &&
                self.l4_header != 0 as *const c_void {
            unsafe {
                Some(&*(self.l4_header as *const IcmpHeader))
            }
        } else {
            None
        }
    }

    /// Returns the layer 7 as a slice of bytes.
    ///
    /// This is how the layer 7 is typically accessed in content processing plugins.
    pub fn l7_header(&self) -> &[u8] {
        if self.snap_l7_len == 0 || self.l7_header == 0 as *const u8 {
            return &[];
        }
        unsafe {
            slice::from_raw_parts(self.l7_header, self.snap_l7_len as usize)
        }
    }

    /// Returns the layer 2 header as a slice of bytes.
    pub fn raw_l2_header(&self) -> &[u8] {
        let ptr = self.l2_header as *const u8;
        if self.snap_l2_len == 0 || ptr == 0 as *const u8 {
            return &[];
        }
        unsafe {
            slice::from_raw_parts(ptr, (self.snap_l2_len - self.snap_l3_len) as usize)
        }
    }

    /// Returns the layer 3 header as a slice of bytes.
    ///
    /// This function can be used to access the IP options as a Rust inferface is not yet
    /// implemented for IPv4 options and IPv6 extension headers.
    pub fn raw_l3_header(&self) -> &[u8] {
        let ptr = self.l3_header as *const u8;
        if self.snap_l3_len == 0 || ptr == 0 as *const u8 {
            return &[];
        }
        unsafe {
            slice::from_raw_parts(ptr, (self.snap_l3_len - self.snap_l4_len) as usize)
        }
    }

    /// Returns the layer 4 header as a slice of bytes.
    ///
    /// This function can be used to access TCP options as a Rust interface is not yet implemented.
    pub fn raw_l4_header(&self) -> &[u8] {
        let ptr = self.l4_header as *const u8;
        if self.snap_l4_len == 0 || ptr == 0 as *const u8 {
            return &[];
        }
        unsafe {
            slice::from_raw_parts(ptr, (self.snap_l4_len - self.snap_l7_len) as usize)
        }
    }

    /// Type of the layer 3 header as defined in [`L3Type`](nethdr/enum.L3Type.html).
    pub fn l3_type(&self) -> L3Type {
        L3Type::from_u16(self.l3_type)
    }

    /// Type of the layer 4 header as defined in [`L4Type`](nethdr/enum.L4Type.html).
    pub fn l4_type(&self) -> L4Type {
        L4Type::from_u8(self.l4_type)
    }
}

/// Type of layer 3 headers.
#[derive(PartialEq)]
pub enum L3Type {
    /// Internet Protocol version 4
    IPv4,
    /// Internet Protocol version 6
    IPv6,
    /// Other protocol not yet implemented in this module. The argument contains an
    /// [`EtherType`](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml).
    OTHER(u16),
}

impl L3Type {
    fn from_u16(val: u16) -> L3Type {
        match val {
            0x0800 => L3Type::IPv4,
            0x86dd => L3Type::IPv6,
            v      => L3Type::OTHER(v),
        }
    }
}

/// Type of layer 4 headers.
#[derive(PartialEq)]
pub enum L4Type {
    /// Internet Control Message
    ICMP,
    /// Internet Group Management
    IGMP,
    /// Transmission Control
    TCP,
    /// Exterior Gateway Protocol
    EGP,
    /// Interior Gateway Protocol (Cisco IGRP)
    IGP,
    /// User Datagram
    UDP,
    /// Generic Routing Encapsulation
    GRE,
    /// Encap Security Payload
    ESP,
    /// Authentication Header
    AH,
    /// ICMP for IPv6
    ICMPv6,
    /// IP-within-IP Encapsulation Protocol
    IPIP,
    /// Ethernet-within-IP Encapsulation
    ETHERIP,
    /// Layer Two Tunneling Protocol
    L2TP,
    /// Other protocol not yet implemented in this module. The argument contains an
    /// [`Protocol number`](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).
    OTHER(u8),
}

impl L4Type {
    fn from_u8(val: u8) -> L4Type {
        match val {
            1   => L4Type::ICMP,
            2   => L4Type::IGMP,
            6   => L4Type::TCP,
            8   => L4Type::EGP,
            9   => L4Type::IGP,
            17  => L4Type::UDP,
            47  => L4Type::GRE,
            50  => L4Type::ESP,
            51  => L4Type::AH,
            58  => L4Type::ICMPv6,
            94  => L4Type::IPIP,
            97  => L4Type::ETHERIP,
            115 => L4Type::L2TP,
            v   => L4Type::OTHER(v),
        }
    }
}

/// Ethernet header: https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
#[repr(C, packed)]
pub struct EthernetHeader {
    /// Destination MAC address
    pub dhost: [u8; 6],
    /// Source MAC address
    pub shost: [u8; 6],
    eth_type: u16,
}

impl EthernetHeader {
    /// [`EtherType`](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml) of
    /// the header following the Ethernet header.
    pub fn eth_type(&self) -> u16 {
        ntohs(self.eth_type)
    }
}

/// IPv4 header: https://tools.ietf.org/html/rfc791#section-3.1
#[repr(C, packed)]
pub struct Ip4Header {
    vhl: u8,
    /// Type of service in old traffic. DSCP and ECN flags in modern traffic.
    pub tos: u8,
    len: u16,
    ip_id: u16,
    ip_off: u16,
    /// Packet time to live
    pub ttl: u8,
    /// [Protocol number](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
    /// of the header following the IPv4 header.
    pub proto: u8,
    checksum: u16,
    src: u32,
    dst: u32,
}

impl Ip4Header {
    /// IP version. Must always be 4.
    pub fn version(&self) -> u8 {
        (self.vhl & 0xf0) >> 4
    }

    /// Length of the IPv4 header (with options) in bytes.
    pub fn header_len(&self) -> u8 {
        (self.vhl & 0x0f) << 2
    }

    /// Length of the packet in bytes, starting from the 1st byte of the IPv4 header.
    pub fn packet_len(&self) -> u16 {
        ntohs(self.len)
    }

    /// IP identification field, used for grouping fragmented packets.
    pub fn ipid(&self) -> u16 {
        ntohs(self.ip_id)
    }

    /// IPv4 source address
    pub fn src_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(ntohl(self.src))
    }

    /// IPv4 destination address
    pub fn dst_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(ntohl(self.dst))
    }
}

/// IPv6 header: https://tools.ietf.org/html/rfc2460#section-3
#[repr(C, packed)]
pub struct Ip6Header {
    vcl: u32,
    payload_len: u16,
    /// [Protocol number](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
    /// of the header following the IPv6 header.
    pub next_hdr: u8,
    /// Hop limit, equivalent of IPv4 TTL.
    pub hop_limit: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

impl Ip6Header {
    /// IP version. Must always be 6.
    pub fn version(&self) -> u8 {
        ((ntohl(self.vcl) & 0xf0000000) >> 28) as u8
    }

    /// IPv6 traffic class: service class + ECN bits
    pub fn traffic_class(&self) -> u8 {
        ((ntohl(self.vcl) & 0x0ff00000) >> 20) as u8
    }

    /// IPv6 flow label
    pub fn flow_label(&self) -> u32 {
        ntohl(self.vcl) & 0x000fffff
    }

    /// Length of the payload in bytes, starting at the end of this IPv6 header (including
    /// extension headers).
    pub fn payload_len(&self) -> u16 {
        ntohs(self.payload_len)
    }

    /// IPv6 source address
    pub fn src_ip(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.src)
    }

    /// IPv6 destination address
    pub fn dst_ip(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.dst)
    }
}

/// TCP header: https://tools.ietf.org/html/rfc793#section-3.1
#[repr(C, packed)]
pub struct TcpHeader {
    src: u16,
    dst: u16,
    seq: u32,
    ack: u32,
    off_res_flags: u16,
    win_size: u16,
    checksum: u16,
    urgent: u16
}

impl TcpHeader {
    /// TCP source port
    pub fn src_port(&self) -> u16 {
        ntohs(self.src)
    }

    /// TCP destination port
    pub fn dst_port(&self) -> u16 {
        ntohs(self.dst)
    }

    /// TCP sequence number
    pub fn seq(&self) -> u32 {
        ntohl(self.seq)
    }

    /// TCP acknowledgment number
    pub fn ack(&self) -> u32 {
        ntohl(self.ack)
    }

    /// TCP header length in bytes (including TCP options)
    pub fn header_len(&self) -> u8 {
        ((ntohs(self.off_res_flags) & 0xf000) >> 10) as u8
    }

    /// TCP flags (9 bits), [RFC 793](https://tools.ietf.org/html/rfc793#section-3.1) 6 bits +
    /// [ECE and CWR](https://tools.ietf.org/html/rfc3168#section-23.2) bits +
    /// [NS](https://tools.ietf.org/html/rfc3540#section-9) bit.
    pub fn flags(&self) -> u16 {
        ntohs(self.off_res_flags) &  0x01ff
    }

    /// TCP window size
    pub fn window_size(&self) -> u16 {
        ntohs(self.win_size)
    }

    /// TCP checksum
    pub fn checksum(&self) -> u16 {
        ntohs(self.checksum)
    }

    /// TCP urgent pointer
    pub fn urgent_ptr(&self) -> u16 {
        ntohs(self.urgent)
    }
}

/// UDP header: https://tools.ietf.org/html/rfc768
#[repr(C, packed)]
pub struct UdpHeader {
    src: u16,
    dst: u16,
    len: u16,
    checksum: u16,
}

impl UdpHeader {
    /// UDP source port
    pub fn src_port(&self) -> u16 {
        ntohs(self.src)
    }

    /// UDP destination port
    pub fn dst_port(&self) -> u16 {
        ntohs(self.dst)
    }

    /// Length of the packet in bytes starting from the UDP header 1st byte.
    pub fn length(&self) -> u16 {
        ntohs(self.len)
    }

    /// UDP checksum
    pub fn checksum(&self) -> u16 {
        ntohs(self.checksum)
    }
}

/// ICMP header: https://tools.ietf.org/html/rfc792
#[repr(C, packed)]
pub struct IcmpHeader {
    /// ICMP type
    pub typ: u8,
    /// ICMP code
    pub code: u8,
    checksum: u16,
    data: u32,
}

impl IcmpHeader {
    /// ICMP checksum
    pub fn checksum(&self) -> u16 {
        ntohs(self.checksum)
    }

    /// Identifier in [ICMP echo](https://tools.ietf.org/html/rfc792#page-14) messages.
    pub fn echo_id(&self) -> u16 {
        ((ntohl(self.data) & 0xffff0000) >> 16) as u16
    }

    /// Sequence number in [ICMP echo](https://tools.ietf.org/html/rfc792#page-14) messages.
    pub fn echo_seq(&self) -> u16 {
        (ntohl(self.data) & 0xffff) as u16
    }

    /// Gateway Internet Address in [ICMP redirect](https://tools.ietf.org/html/rfc792#page-12)
    /// messages.
    pub fn gateway(&self) -> u32 {
        ntohl(self.data)
    }

    /// Next-hop MTU in [ICMP destination unreachable](https://tools.ietf.org/html/rfc1191#section-4)
    /// messages.
    pub fn path_mtu(&self) -> u16 {
        (ntohl(self.data) & 0xffff) as u16
    }
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

    #[cfg(feature = "MULTIPKTSUP")]
    last_ipid: u16,

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

    timeout: f32,
}

impl Flow {
    /// Timestamp of the first seen packet (as the number of seconds since 1970-01-01).
    pub fn first_seen(&self) -> f64 {
        let ts = &self.first_seen;
        ts.tv_sec as f64 + (ts.tv_usec as f64 / 1000000.0)
    }
    /// Timestamp of the last seen packet (as the number of seconds since 1970-01-01).
    pub fn last_seen(&self) -> f64 {
        let ts = &self.last_seen;
        ts.tv_sec as f64 + (ts.tv_usec as f64 / 1000000.0)
    }
    /// Duration of this flow in seconds.
    ///
    /// This method should only be called after the flow termination. To compute the current flow
    /// duration before the flow termination, use [`first_seen`](#method.first_seen) and
    /// [`last_seen`](#method.last_seen).
    pub fn duration(&self) -> f64 {
        let ts = &self.duration;
        ts.tv_sec as f64 + (ts.tv_usec as f64 / 1000000.0)
    }

    /// Returns source IPv4 address for an IPv4 flow. None for an IPv6 flow.
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    pub fn src_ip4(&self) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::from(ntohl(self.src_ip)))
    }
    /// Returns source IPv4 address for an IPv4 flow. None for an IPv6 flow.
    #[cfg(feature = "IPV6_ACTIVATE")]
    pub fn src_ip4(&self) -> Option<Ipv4Addr> {
        None
    }
    /// Returns destination IPv4 address for an IPv4 flow. None for an IPv6 flow.
    #[cfg(not(feature = "IPV6_ACTIVATE"))]
    pub fn dst_ip4(&self) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::from(ntohl(self.dst_ip)))
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
