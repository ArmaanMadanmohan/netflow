use crate::packet::{
    Packet, 
    Protocol,
};

use std::{
    collections::{VecDeque}
};

pub struct Connection {
    pub sent: VecDeque<Packet>, 
    pub recv: VecDeque<Packet>,
    pub bytes_sent: u32,
    pub bytes_recvd: u32,
    pub conn_type: Protocol, 
}

impl Connection {
    pub fn new(protocol: Protocol) -> Connection {
        let new_sent: VecDeque<Packet> = VecDeque::new();
        let new_recv: VecDeque<Packet> = VecDeque::new();
        Connection {
            sent: new_sent, 
            recv: new_recv,
            bytes_sent: 0,
            bytes_recvd: 0,
            conn_type: protocol, 
        }
    }

    pub fn add_packet() {
        
    }

    pub fn total_packets() {

    }

    pub fn refresh_packets() {

    }

    pub fn del_packet() {

    }
}



// capture packet. SocketId::from to convert to SocketId, if there is a matching SocketId (would
// probably need to impl Eq for that.. and Hash! which i can't so.. i guess i have an intermediate
// storage type for hash then?) then take corresponding Connection and add the packet to
// the Deque. Else create connection and add packet to empty Deque, link with SocketId  
