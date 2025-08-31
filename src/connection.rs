use crate::packet::{
    Packet, 
    Protocol,
};

use std::{
    collections::VecDeque, time::{Duration, SystemTime}
};

#[derive(Debug)]
pub struct Connection {
    pub sent: VecDeque<Packet>, 
    pub recv: VecDeque<Packet>,
    pub bytes_sent: u32,
    pub bytes_recvd: u32,
    pub conn_type: Protocol,
    pub process_name: Option<String>,
    pub inode: Option<u32>,
    pub pid: Option<u32>,
}

impl Connection {
    pub fn new(pkt: Packet) -> Self {
        let new_sent: VecDeque<Packet> = VecDeque::new();
        let new_recv: VecDeque<Packet> = VecDeque::new();
        let mut conn = Connection {
            sent: new_sent, 
            recv: new_recv,
            bytes_sent: 0,
            bytes_recvd: 0,
            conn_type: pkt.protocol, 
            process_name: None,
            inode: None,
            pid: None,
        };
        conn.add_packet(pkt);
        conn
    }

    pub fn add_packet(&mut self, pkt: Packet) {    
        if pkt.outgoing {
            self.bytes_sent += pkt.len;
            self.sent.push_front(pkt);
        } else {
            self.bytes_recvd += pkt.len;
            self.recv.push_front(pkt);
        }
    }

    pub fn refresh_packets(&mut self, period: Duration) {
        let cutoff = SystemTime::now() - period;
        while let Some(oldest_sent) = self.sent.back() {
            if oldest_sent.is_older_than(cutoff) {
                if let Some(popped) = self.sent.pop_back() {
                    self.bytes_sent -= popped.len;    
                }
            } else {
                break;
            }
        }

        while let Some(oldest_recvd) = self.recv.back() {
            if oldest_recvd.is_older_than(cutoff) {
                if let Some(popped) = self.recv.pop_back() {
                    self.bytes_recvd -= popped.len;
                }
            } else {
                break;
            } 
        }
    }
}
