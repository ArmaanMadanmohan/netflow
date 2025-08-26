use std::{
    hash::{Hash, Hasher},
};
use crate::packet::Packet;
use netlink_packet_sock_diag::inet::SocketId;

impl From<&Packet> for SocketId {
    fn from(pack: &Packet) -> Self {
        SocketId {
            source_port: pack.src_port,
            destination_port: pack.dst_port,
            source_address: pack.src_addr,
            destination_address: pack.dst_addr,
            interface_id: 0,
            cookie: [0; 8],
        }
    }
}

#[derive(Debug)]
pub struct SocketWrapper(pub SocketId);

impl Hash for SocketWrapper {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.source_port.hash(state);
        self.0.destination_port.hash(state);
        self.0.source_address.hash(state);
        self.0.destination_address.hash(state);
    }
}

impl PartialEq for SocketWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.source_port == other.0.source_port &&
        self.0.destination_port == other.0.destination_port &&
        self.0.source_address == other.0.source_address &&
        self.0.destination_address == other.0.destination_address
    }
}

impl Eq for SocketWrapper {}

