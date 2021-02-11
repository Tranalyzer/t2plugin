// globalStat, packet and flow status
pub const L3FLOWINVERT        : u64 = 0x0000000000000001;  // Inverted flow, did not initiate connection
pub const L2_NO_ETH           : u64 = 0x0000000000000002;  // No Ethernet header
pub const L2_FLOW             : u64 = 0x0000000000000004;  // Pure L2 Flow
pub const L2_PPPOE_D          : u64 = 0x0000000000000008;  // Point to Point Protocol over Ethernet Discovery (PPPoED)
pub const L2_PPPOE_S          : u64 = 0x0000000000000010;  // Point to Point Protocol over Ethernet Service (PPPoES)
pub const L2_LLDP             : u64 = 0x0000000000000020;  // Link Layer Discovery Protocol (LLDP)
pub const L2_ARP              : u64 = 0x0000000000000040;  // ARP present
pub const L2_RARP             : u64 = 0x0000000000000080;  // Reverse ARP present
pub const L2_VLAN             : u64 = 0x0000000000000100;  // VLANs present
pub const L2_MPLS_UCAST       : u64 = 0x0000000000000200;  // MPLS unicast present
pub const L2_MPLS_MCAST       : u64 = 0x0000000000000400;  // MPLS multicast present
pub const L2_L2TP             : u64 = 0x0000000000000800;  // L2TP v2/3 present
pub const L2_GRE              : u64 = 0x0000000000001000;  // GRE v1/2 present
pub const L2_PPP              : u64 = 0x0000000000002000;  // PPP header present after L2TP or GRE
pub const L2_IPV4             : u64 = 0x0000000000004000;  // IPv4 packets present
pub const L2_IPV6             : u64 = 0x0000000000008000;  // IPv6 packets present
pub const L3_IPVX             : u64 = 0x0000000000010000;  // IPvX bogus packets present
pub const L3_IPIP             : u64 = 0x0000000000020000;  // IPv4/6 in IPv4/6
pub const L3_ETHIPF           : u64 = 0x0000000000040000;  // Ethernet via IP
pub const L3_TRDO             : u64 = 0x0000000000080000;  // Teredo Tunnel
pub const L3_AYIYA            : u64 = 0x0000000000100000;  // Anything in Anything (AYIYA) Tunnel
pub const L3_GTP              : u64 = 0x0000000000200000;  // GPRS Tunneling Protocol (GTP)
pub const L3_VXLAN            : u64 = 0x0000000000400000;  // Virtual eXtensible Local Area Network (VXLAN)
pub const L3_CAPWAP           : u64 = 0x0000000000800000;  // Control And Provisioning of Wireless Access Points (CAPWAP),
                                                           // Lightweight Access Point Protocol (LWAPP)
pub const L4_SCTP             : u64 = 0x0000000001000000;  // Stream Control Transmission Flows
pub const L4_UPNP             : u64 = 0x0000000002000000;  // SSDP/UPnP
pub const L2_ERSPAN           : u64 = 0x0000000004000000;  // Encapsulated Remote Switch Packet ANalysis (ERSPAN)
pub const L2_WCCP             : u64 = 0x0000000008000000;  // Cisco Web Cache Communication Protocol (WCCP)
pub const L7_SIPRTP           : u64 = 0x0000000010000000;  // SIP/RTP
pub const L3_GENEVE           : u64 = 0x0000000020000000;  // Generic Network Virtualization Encapsulation (GENEVE)
pub const L3_IPSEC_AH         : u64 = 0x0000000040000000;  // IPsec Authentication Header (AH)
pub const L3_IPSEC_ESP        : u64 = 0x0000000080000000;  // IPsec Encapsulating Security Payload (ESP)

// globalWarn, packet and flow Warning
pub const L2SNAPLENGTH        : u64 = 0x0000000100000000;  // Acquired packet length < minimal L2 datagram
pub const L3SNAPLENGTH        : u64 = 0x0000000200000000;  // Acquired packet length < packet length in L3 header
pub const L3HDRSHRTLEN        : u64 = 0x0000000400000000;  // Acquired packet length < minimal L3 Header
pub const L4HDRSHRTLEN        : u64 = 0x0000000800000000;  // Acquired packet length < minimal L4 Header
pub const IPV4_FRAG           : u64 = 0x0000001000000000;  // IPv4 fragmentation present
pub const IPV4_FRAG_ERR       : u64 = 0x0000002000000000;  // IPv4 fragmentation Error (detailed err s. tcpFlags plugin)
pub const IPV4_FRAG_HDSEQ_ERR : u64 = 0x0000004000000000;  // IPv4 1. fragment out of sequence or missing
pub const IPV4_FRAG_PENDING   : u64 = 0x0000008000000000;  // Packet fragmentation pending / fragmentation sequence not completed when flow timeouts
pub const FLWTMOUT            : u64 = 0x0000010000000000;  // Flow timeout instead of protocol termination
pub const RMFLOW              : u64 = 0x0000020000000000;  // Alarm mode: remove this flow instantly
pub const RMFLOW_HFULL        : u64 = 0x0000040000000000;  // Autopilot: Flow removed to free space in main hash map
pub const STPDSCT             : u64 = 0x0000080000000000;  // Stop dissecting
pub const DUPIPID             : u64 = 0x0000100000000000;  // Consequtive duplicate IP ID
pub const PPP_NRHD            : u64 = 0x0000200000000000;  // PPPL3 header not readable, compressed
pub const HDOVRN              : u64 = 0x0001000000000000;  // Header description overrun
pub const FL_ALARM            : u64 = 0x0002000000000000;  // pcapd and PD_ALARM=1: if set dumps the packets from this flow to a new pcap
pub const LANDATTACK          : u64 = 0x0004000000000000;  // Same src IP && dst IP and src port && dst port
pub const TIMEJUMP            : u64 = 0x0008000000000000;  // Time slip possibly due to NTP operations on the capture machine
pub const __RESERVED__        : u64 = 0x0010000000000000;  // RESERVED, do not use
pub const SUBN_FLW_TST        : u64 = 0x0080000000000000;  // Subnet tested for that flow
pub const TORADD              : u64 = 0x0100000000000000;  // Tor address detected
pub const FS_VLAN0            : u64 = 0x0200000000000000;  // A packet had a priority tag (VLAN tag with ID 0)
pub const FS_IPV4_PKT         : u64 = 0x0400000000000000;  // IPv4 packet
pub const FS_IPV6_PKT         : u64 = 0x0800000000000000;  // IPv6 packet
pub const FDLSIDX             : u64 = 0x4000000000000000;  // Flow duration limit, same findex for all subflows
pub const PCAPSNPD            : u64 = 0x8000000000000000;  // PCAP packet length > MAX_MTU in ioBuffer.h, caplen reduced

pub const SNAPLENGTH          : u64 = L2SNAPLENGTH | L3SNAPLENGTH;
pub const L2_MPLS             : u64 = L2_MPLS_UCAST | L2_MPLS_MCAST;
