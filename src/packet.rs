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
use std::slice;
use libc::c_void;
#[cfg(feature = "T2_PRI_HDRDESC")]
use libc::c_char;
use nethdr::{EthernetHeader, Ip4Header, Ip6Header, UdpHeader, TcpHeader, IcmpHeader, L3Type, L4Type, T2IpAddr};

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
    #[cfg(feature = "T2_PRI_HDRDESC")]
    hdr_desc_pos: u16,
    #[cfg(feature = "T2_PRI_HDRDESC")]
    num_hdr_desc: u16,

    raw_packet: *const u8,
    end_packet: *const u8,
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
    /// On wire full packet length (from the per-packet PCAP header).
    pub packet_raw_len: u32,
    /// Packet snapped length
    pub snap_len: u32,
    /// Packet snapped length starting from layer 2.
    pub snap_l2_len: u32,
    /// Packet snapped length starting from layer 3.
    pub snap_l3_len: u32,
    /// On wire packet length starting from layer2.
    pub packet_l2_len: u32,
    /// Packet length depending on Tranalyzer2 `PACKETLENGTH` value, see `networkHeaders.h` for details.
    pub packet_len: u32,

    /// Packet snapped length starting from layer 4.
    pub snap_l4_len: u16,
    /// Packet snapped length starting from layer 7.
    pub snap_l7_len: u16,
    /// Packet payload length: layer 7 length.
    pub packet_l7_len: u16,

    /// Source port in host order.
    pub src_port: u16,
    /// Destination port in host order.
    pub dst_port: u16,
    /// Inner VLAN ID
    pub inner_vlan: u16,
    /// Outer type of the layer 2 header.
    pub outer_l2_type: u16,
    /// Type of the layer 2 header.
    pub l2_type: u16,
    /// Type of the layer 3 header as defined in [`L3Type`](nethdr/enum.L3Type.html).
    l3_type: u16,
    /// Per packet status bits.
    pub status: u64,

    #[cfg(feature = "FLOW_LIFETIME")]
    findex: u64,

    #[cfg(any(feature = "IPV6_ACTIVATE", feature = "IPV6_DUALMODE"))]
    src_ip: T2IpAddr,
    #[cfg(any(feature = "IPV6_ACTIVATE", feature = "IPV6_DUALMODE"))]
    dst_ip: T2IpAddr,
    #[cfg(not(any(feature = "IPV6_ACTIVATE", feature = "IPV6_DUALMODE")))]
    src_ip: [u8; 4],
    #[cfg(not(any(feature = "IPV6_ACTIVATE", feature = "IPV6_DUALMODE")))]
    dst_ip: [u8; 4],

    #[cfg(all(feature = "FLOW_AGGREGATION", any(feature = "IPV6_ACTIVATE", feature = "IPV6_DUALMODE")))]
    src_ip_c: T2IpAddr,
    #[cfg(all(feature = "FLOW_AGGREGATION", any(feature = "IPV6_ACTIVATE", feature = "IPV6_DUALMODE")))]
    dst_ip_c: T2IpAddr,
    #[cfg(all(feature = "FLOW_AGGREGATION", not(any(feature = "IPV6_ACTIVATE", feature = "IPV6_DUALMODE"))))]
    src_ip_c: T2IpAddr,
    #[cfg(all(feature = "FLOW_AGGREGATION", not(any(feature = "IPV6_ACTIVATE", feature = "IPV6_DUALMODE"))))]
    dst_ip_c: T2IpAddr,

    #[cfg(feature = "FLOW_AGGREGATION")]
    subnet_num_src: u32,
    #[cfg(feature = "FLOW_AGGREGATION")]
    subnet_num_dst: u32,
    #[cfg(feature = "FLOW_AGGREGATION")]
    src_port_c: u16,
    #[cfg(feature = "FLOW_AGGREGATION")]
    dst_port_c: u16,
    #[cfg(feature = "FLOW_AGGREGATION")]
    l4_type_c: u8,

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
            slice::from_raw_parts(ptr, (self.snap_l3_len - (self.snap_l4_len as u32)) as usize)
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
