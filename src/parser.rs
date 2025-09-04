use std::{
    collections::{HashSet},
    net::{Ipv4Addr, Ipv6Addr, IpAddr},
};
use pcap::Packet as PcapPkt;
use crate::packet::{
    Packet, 
    EtherHdr, 
    TcpHdr,
    UdpHdr,
    Ipv4Hdr, 
    Ipv6Hdr,
    Protocol
};

pub struct PacketParser {
    addresses: HashSet<IpAddr>, 
}

impl PacketParser {
    pub fn new (address_list: HashSet<IpAddr>) -> Self {
        Self {
            addresses: address_list,
        }
    }

    pub fn parse_pkt(&self, pkt: &PcapPkt)-> Option<Packet> 
    { 
        // let header = pkt.header; 
        let ethernet: EtherHdr = match EtherHdr::to_ether(pkt.data) {
            Ok(hdr) => hdr,
            Err(_) => {
                return None;
            }
        };

        let ipslice = &pkt.data[14..]; 
        if ethernet.is_ipv4()? {
            self.parse_ipv4(ipslice) 
        } else {
            self.parse_ipv6(ipslice)
        }
    }

    fn parse_ipv4(&self, ipslice: &[u8]) -> Option<Packet>
    {
        let ipv4: Ipv4Hdr = match Ipv4Hdr::to_ipv4(ipslice) {
            Ok(hdr) => hdr,
            Err(_) => {
                return None;
            }
        };

        let pclslice: &[u8] = &ipslice[ipv4.header_len()..];
        let src_addr = IpAddr::V4(Ipv4Addr::from(ipv4.src_addr));
        let dst_addr = IpAddr::V4(Ipv4Addr::from(ipv4.dst_addr));

        let outgoing = if self.addresses.contains(&src_addr) {
            true
        } else if self.addresses.contains(&dst_addr) {
            false
        } else {
            return None // update address table?
        };


        match ipv4.is_tcp()? {
            true => {
                let tcp: TcpHdr = match TcpHdr::to_tcp(pclslice) {
                    Ok(hdr) => hdr,
                    Err(_) => {
                        return None;
                    }
                };

                let payload_len = ipv4.pay_len as usize - ipv4.header_len() - tcp.header_len();
                Some(Packet::new(
                    src_addr,
                    dst_addr,
                    tcp.src_p,
                    tcp.dst_p,
                    payload_len as u32, // Correct payload length calculation
                    outgoing,
                    Protocol::TCP,
                ))
            },
            false => {
                let udp: UdpHdr = match UdpHdr::to_udp(pclslice) {
                    Ok(hdr) => hdr,
                    Err(_) => {
                        return None;
                    }
                };

                let payload_len = ipv4.pay_len as usize - ipv4.header_len() - 8;
                Some(Packet::new(
                    src_addr,
                    dst_addr,
                    udp.src_p,
                    udp.dst_p,
                    payload_len as u32, // Correct payload length calculation
                    outgoing,
                    Protocol::UDP,
                ))
            },
        }
    }

    fn parse_ipv6(&self, ipslice: &[u8]) -> Option<Packet>
    {
        let ipv6: Ipv6Hdr = match Ipv6Hdr::to_ipv6(ipslice) {
            Ok(hdr) => hdr,
            Err(_) => {
                return None;
            }
        };

        let pclslice: &[u8] = &ipslice[40..];
        let src_addr = IpAddr::V6(Ipv6Addr::from(ipv6.src_addr));
        let dst_addr = IpAddr::V6(Ipv6Addr::from(ipv6.dst_addr));

        let outgoing = if self.addresses.contains(&src_addr) {
            true 
        } else if self.addresses.contains(&dst_addr) {
            false
        } else {
            return None
        };

        match ipv6.is_tcp()? {
            true => {
                let tcp: TcpHdr = match TcpHdr::to_tcp(pclslice) {
                    Ok(hdr) => hdr,
                    Err(_) => {
                        return None;
                    }
                };

                Some(Packet::new(
                    src_addr, 
                    dst_addr, 
                    tcp.src_p, 
                    tcp.dst_p, 
                    ipv6.pay_len.into(), 
                    outgoing,
                    Protocol::TCP,
                ))
            },
            false => {
                let udp: UdpHdr = match UdpHdr::to_udp(pclslice) {
                    Ok(hdr) => hdr,
                    Err(_) => {
                        return None;
                    }
                };

                Some(Packet::new(
                    src_addr, 
                    dst_addr, 
                    udp.src_p, 
                    udp.dst_p, 
                    ipv6.pay_len.into(), 
                    outgoing,
                    Protocol::UDP,
                ))
            },
        }
    }
}
