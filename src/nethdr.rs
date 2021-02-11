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
    /// Type of the header following the Ethernet header as defined in [`L3Type`](nethdr/enum.L3Type.html).
    pub fn eth_type(&self) -> L3Type {
        L3Type::from_u16(u16::from_be(self.eth_type))
    }
}

/// Tranalyzer2 ipAddr_t IPv6/IPv4 dual mode header (for internal use only)
#[repr(C, packed)]
pub(super) union T2IpAddr {
    pub(super) ipv4: [u8; 4],
    pub(super) ipv6: [u8; 16],
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
    proto: u8,
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
        u16::from_be(self.len)
    }

    /// IP identification field, used for grouping fragmented packets.
    pub fn ipid(&self) -> u16 {
        u16::from_be(self.ip_id)
    }

    /// Type of the layer 4 header as defined in [`L4Type`](nethdr/enum.L4Type.html).
    pub fn proto(&self) -> L4Type {
        L4Type::from_u8(self.proto)
    }

    /// IPv4 source address
    pub fn src_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(self.src))
    }

    /// IPv4 destination address
    pub fn dst_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(self.dst))
    }
}

/// IPv6 header: https://tools.ietf.org/html/rfc2460#section-3
#[repr(C, packed)]
pub struct Ip6Header {
    vcl: u32,
    payload_len: u16,
    next_hdr: u8,
    /// Hop limit, equivalent of IPv4 TTL.
    pub hop_limit: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

impl Ip6Header {
    /// IP version. Must always be 6.
    pub fn version(&self) -> u8 {
        ((u32::from_be(self.vcl) & 0xf0000000) >> 28) as u8
    }

    /// IPv6 traffic class: service class + ECN bits
    pub fn traffic_class(&self) -> u8 {
        ((u32::from_be(self.vcl) & 0x0ff00000) >> 20) as u8
    }

    /// IPv6 flow label
    pub fn flow_label(&self) -> u32 {
        u32::from_be(self.vcl) & 0x000fffff
    }

    /// Length of the payload in bytes, starting at the end of this IPv6 header (including
    /// extension headers).
    pub fn payload_len(&self) -> u16 {
        u16::from_be(self.payload_len)
    }

    /// Type of the header following the IPv6 header as defined in [`L4Type`](nethdr/enum.L4Type.html).
    pub fn next_hdr(&self) -> L4Type {
        L4Type::from_u8(self.next_hdr)
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
        u16::from_be(self.src)
    }

    /// TCP destination port
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dst)
    }

    /// TCP sequence number
    pub fn seq(&self) -> u32 {
        u32::from_be(self.seq)
    }

    /// TCP acknowledgment number
    pub fn ack(&self) -> u32 {
        u32::from_be(self.ack)
    }

    /// TCP header length in bytes (including TCP options)
    pub fn header_len(&self) -> u8 {
        ((u16::from_be(self.off_res_flags) & 0xf000) >> 10) as u8
    }

    /// TCP flags (9 bits), [RFC 793](https://tools.ietf.org/html/rfc793#section-3.1) 6 bits +
    /// [ECE and CWR](https://tools.ietf.org/html/rfc3168#section-23.2) bits +
    /// [NS](https://tools.ietf.org/html/rfc3540#section-9) bit.
    pub fn flags(&self) -> u16 {
        u16::from_be(self.off_res_flags) &  0x01ff
    }

    /// TCP window size
    pub fn window_size(&self) -> u16 {
        u16::from_be(self.win_size)
    }

    /// TCP checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
    }

    /// TCP urgent pointer
    pub fn urgent_ptr(&self) -> u16 {
        u16::from_be(self.urgent)
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
        u16::from_be(self.src)
    }

    /// UDP destination port
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dst)
    }

    /// Length of the packet in bytes starting from the UDP header 1st byte.
    pub fn length(&self) -> u16 {
        u16::from_be(self.len)
    }

    /// UDP checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
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
        u16::from_be(self.checksum)
    }

    /// Identifier in [ICMP echo](https://tools.ietf.org/html/rfc792#page-14) messages.
    pub fn echo_id(&self) -> u16 {
        ((u32::from_be(self.data) & 0xffff0000) >> 16) as u16
    }

    /// Sequence number in [ICMP echo](https://tools.ietf.org/html/rfc792#page-14) messages.
    pub fn echo_seq(&self) -> u16 {
        (u32::from_be(self.data) & 0xffff) as u16
    }

    /// Gateway Internet Address in [ICMP redirect](https://tools.ietf.org/html/rfc792#page-12)
    /// messages.
    pub fn gateway(&self) -> u32 {
        u32::from_be(self.data)
    }

    /// Next-hop MTU in [ICMP destination unreachable](https://tools.ietf.org/html/rfc1191#section-4)
    /// messages.
    pub fn path_mtu(&self) -> u16 {
        (u32::from_be(self.data) & 0xffff) as u16
    }
}

/// Type of layer 3 headers.
#[allow(non_camel_case_types)]
#[derive(Debug,PartialEq)]
pub enum L3Type {
    /// Internet Protocol version 4
    IPv4,
    /// Internet Protocol version 6
    IPv6,
    /// Address Resolution Protocol (ARP)
    ARP,
    /// IEEE 802.1Q Customer VLAN Tag Type
    VLAN,
    /// Link Layer Discovery Protocol (LLDP)
    LLDP,
    /// MPLS
    MPLS,
    /// MPLS multicast
    MPLS_MCAST,
    /// PPP over Ethernet (PPPoE) Discovery Stage
    PPPOE_DISCO,
    /// PPP over Ethernet (PPPoE) Session Stage
    PPPOE,
    /// LLC jumbo frame (draft-ietf-isis-ext-eth-01)
    JUMBO_LLC,
    /// Other protocol not yet implemented in this module. The argument contains an
    /// [`EtherType`](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml).
    OTHER(u16),
}

impl L3Type {
    pub fn from_u16(val: u16) -> L3Type {
        match val {
            0x0800 => L3Type::IPv4,
            0x0806 => L3Type::ARP,
            0x8100 => L3Type::VLAN,
            0x86dd => L3Type::IPv6,
            0x8847 => L3Type::MPLS,
            0x8848 => L3Type::MPLS_MCAST,
            0x8863 => L3Type::PPPOE_DISCO,
            0x8864 => L3Type::PPPOE,
            0x8870 => L3Type::JUMBO_LLC,
            0x88cc => L3Type::LLDP,
            v      => L3Type::OTHER(v),
        }
    }
}

/// Type of layer 4 headers.
#[derive(Debug,PartialEq)]
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
    /// IPsec Encap Security Payload
    ESP,
    /// IPsec Authentication Header
    AH,
    /// ICMP for IPv6
    ICMPv6,
    /// IP-within-IP Encapsulation Protocol
    IPIP,
    /// Ethernet-within-IP Encapsulation
    ETHERIP,
    /// Layer Two Tunneling Protocol
    L2TP,
    /// Other protocol not yet implemented in this module. The argument contains a
    /// [`Protocol number`](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).
    OTHER(u8),
}

impl L4Type {
    pub fn from_u8(val: u8) -> L4Type {
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
