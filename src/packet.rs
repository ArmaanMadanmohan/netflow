use std::{
    net::{Ipv4Addr, Ipv6Addr, IpAddr},
    time,
};
// etherparse?

const ETHER_ADDR_LEN: usize = 6;
const IPV6_ADDR_LEN: usize = 16;

const IPV4_PROTOCOL: u16 = 0x0800;
const IPV6_PROTOCOL: u16 = 0x86DD;

const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;

#[derive(Debug, Copy, Clone)]
pub enum Protocol {
    TCP, 
    UDP,
}

#[repr(C)]
#[derive(Debug)]
pub struct EtherHdr {
    pub dst_addr: [u8; ETHER_ADDR_LEN], 
    pub src_addr: [u8; ETHER_ADDR_LEN],     
    pub ether_type: u16,
}

impl EtherHdr 
{
    pub fn to_ether(data: &[u8]) -> Self 
    {
        // sanity checks (len etc..)
        Self {
            dst_addr: data[0..ETHER_ADDR_LEN].try_into().unwrap(),
            src_addr: data[ETHER_ADDR_LEN..(ETHER_ADDR_LEN*2)].try_into().unwrap(),
            ether_type: u16::from_be_bytes(
                [data[ETHER_ADDR_LEN*2], data[ETHER_ADDR_LEN*2 + 1]]
            ),
        }
    }

    pub fn is_ipv4(&self) -> Option<bool> 
    {
        match self.ether_type {
            IPV4_PROTOCOL => Some(true),
            IPV6_PROTOCOL => Some(false),
            _ => None,
        }
    }
}


#[repr(C)]
#[derive(Debug)]
pub struct Ipv4Hdr
{
    pub v_hl: u8, // version or header len; ordered by BE/LE
    pub tos: u8,
    pub pay_len: u16,
    pub id: u16,
    pub off: u16,
    pub ttl: u8,
    pub pcl: u8, 
    pub chk: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

impl Ipv4Hdr 
{
    pub fn to_ipv4(data: &[u8]) -> Self 
    {
        // sanity checks (len etc..)
        Self {
            v_hl: data[0],
            tos: data[1],
            pay_len: u16::from_be_bytes(
                [data[2], data[3]]
            ),
            id: u16::from_be_bytes(
                [data[4], data[5]]
            ),
            off: u16::from_be_bytes(
                [data[6], data[7]]
            ),
            ttl: data[8],
            pcl: data[9],
            chk: u16::from_be_bytes(
                [data[10], data[11]]
            ),
            src_addr: u32::from_be_bytes(
                [data[12], data[13], data[14], data[15]]
            ),
            dst_addr: u32::from_be_bytes(
                [data[16], data[17], data[18], data[19]]
            ),
        }
    }

    pub fn version(&self) -> u8 
    {
        self.v_hl >> 4
    }

    pub fn ihl(&self) -> u8
    {
        self.v_hl & 0x0F
    }

    pub fn header_len(&self) -> usize 
    {
        self.ihl().into()  
    }

    pub fn is_tcp(&self) -> Option<bool> 
    {
        match self.pcl {
            TCP_PROTOCOL => Some(true),
            UDP_PROTOCOL => Some(false),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Ipv6Hdr
{
    pub v_tc_flow: u32, // version, traffic class, flow control
    pub pay_len: u16, 
    pub nxt: u8,
    pub hop: u8,
    pub src_addr: [u8; IPV6_ADDR_LEN],
    pub dst_addr: [u8; IPV6_ADDR_LEN],
}

impl Ipv6Hdr 
{
    pub fn to_ipv6(data: &[u8]) -> Self
    {
        // sanity checks (len etc..)
        Self {
            v_tc_flow: u32::from_be_bytes(
                [data[0], data[1], data[2], data[3]]
            ),
            pay_len: u16::from_be_bytes(
                [data[4], data[5]]
            ),
            nxt: data[6],
            hop: data[7],
            src_addr: data[8..(IPV6_ADDR_LEN+8)].try_into().unwrap(),
            dst_addr: data[(IPV6_ADDR_LEN+8)..(IPV6_ADDR_LEN*2 + 8)].try_into().unwrap(),
        }
    }

    pub fn version(&self) -> u8
    {
        (self.v_tc_flow >> 28) as u8
    }

    pub fn tc(&self) -> u8
    {
        (self.v_tc_flow >> 20 & 0xFF) as u8
    }

    pub fn flow(&self) -> u32 
    {
        self.v_tc_flow & 0xFFFFF
    }

    pub fn is_tcp(&self) -> Option<bool> // enum for protocol?
    {
        match self.nxt {
            TCP_PROTOCOL => Some(true),
            UDP_PROTOCOL => Some(false),
            _ => None,
        }
    }
} 

#[repr(C)]
#[derive(Debug)]
pub struct TcpHdr {
    pub src_p: u16, 
    pub dst_p: u16, 
    pub seq: u32,
    pub ack: u32,
    pub off: u8, // offset or reserved; ordered by BE/LE
    pub win: u16,
    pub chk: u16,
    pub urp: u16,
}

impl TcpHdr 
{
    pub fn to_tcp(data: &[u8]) -> Self 
    {
        // sanity checks (len etc..)
        Self {
            src_p: u16::from_be_bytes(
                [data[0], data[1]]
            ),
            dst_p: u16::from_be_bytes(
                [data[2], data[3]]
            ),
            seq: u32::from_be_bytes(
                [data[4], data[5], data[6], data[7]]
            ),
            ack: u32::from_be_bytes(
                [data[8], data[9], data[10], data[11]]
            ),
            off: data[12],
            win: u16::from_be_bytes(
                [data[13], data[14]]
            ),
            chk: u16::from_be_bytes(
                [data[15], data[16]]
            ),
            urp: u16::from_be_bytes(
                [data[17], data[18]]
            ),
        }   
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct UdpHdr {
    pub src_p: u16,
    pub dst_p: u16,
    pub len: u16,
    pub chk: u16,
}

impl UdpHdr 
{
    pub fn to_udp(data: &[u8]) -> Self 
    {
        Self {
            src_p: u16::from_be_bytes(
                [data[0], data[1]]
            ),
            dst_p: u16::from_be_bytes(
                [data[2], data[3]]
            ),
            len: u16::from_be_bytes(
                [data[4], data[5]]
            ),
            chk: u16::from_be_bytes(
                [data[6], data[7]]
            ),
        }
    }
}

/**
* Lightweight packet representation passed around the application
*/  
#[repr(C)]
#[derive(Debug)]
pub struct Packet {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u32,
    timestamp: time::SystemTime, 
    pub outgoing: bool, 
    pub protocol: Protocol,
}

impl Packet 
{
    pub fn new(
        src_addr: IpAddr, 
        dst_addr: IpAddr,
        src_port: u16,
        dst_port: u16,
        len: u32,
        outgoing: bool,
        protocol: Protocol,
    ) -> Self
    {
       Self {
            src_addr, 
            dst_addr, 
            src_port, 
            dst_port, 
            len, 
            timestamp: time::SystemTime::now(),
            outgoing,
            protocol,
        } 
    }

    pub fn is_older_than(&self, time: time::SystemTime) -> bool {
        if self.timestamp < time {
            true
        } else {
            false
        }
    }
}




