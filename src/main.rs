mod packet;
mod connection;
mod parser;
mod socketwrapper;

use std::{
    collections::{HashSet, HashMap, hash_map}, 
    io::{Error, ErrorKind}, 
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use pcap::Device;
use netlink_packet_core::{
    NetlinkPayload,
    NetlinkHeader,
    NetlinkMessage,
    NLM_F_DUMP, 
    NLM_F_REQUEST,
};
use std::net::{IpAddr};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};
use netlink_packet_sock_diag::{
    inet::{ExtensionFlags, InetRequest, InetResponse, SocketId, StateFlags}, 
    SockDiagMessage, 
    AF_INET, 
    IPPROTO_TCP, IPPROTO_UDP
};

use crate::{
    connection::Connection, packet::Protocol, parser::PacketParser, socketwrapper::SocketWrapper
};

use getifaddrs::{getifaddrs, InterfaceFlags};

type SockInode = Arc<Mutex<HashMap<SocketWrapper, u32>>>;

// if neither src nor dst are in the address table maybe update table?

fn main() {
    let mut address_table: HashSet<IpAddr> = HashSet::new();
    update_addresses(&mut address_table);
    handle_packet(address_table);
}

fn start_inode_query(mapping: SockInode) {
    thread::spawn(move || {
        let mut socket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
        if let Err(e) = socket.bind_auto() {
            eprintln!("BIND ERROR: {e}");
            return;
        }

        socket.connect(&SocketAddr::new(0, 0)).unwrap();

        loop {
            { // mutex guard
                let mut cache = mapping.lock().unwrap();
                cache.clear();
            }

            // start off with socket dump then see about querying individually 
            if let Err(e) = send_dump_msg(&socket, Protocol::TCP) { 
                eprintln!("SEND ERROR: {e}");
                continue;
            }

            match recv_dump_msg(&socket) {
                Ok(responses) => {
                    let mut cache = mapping.lock().unwrap();

                    for res in responses {
                        let sock_id = res.header.socket_id;
                        let inode = res.header.inode;
                        let socket_wrapper = SocketWrapper(sock_id);
                        cache.insert(socket_wrapper, inode);
                    }
                }
                Err(e) => {
                    eprintln!("TCP RECV ERROR: {e}");
                }
            }

            if let Err(e) = send_dump_msg(&socket, Protocol::UDP) {
                eprintln!("SEND ERROR: {e}");
                continue;
            }

            match recv_dump_msg(&socket) {
                Ok(responses) => {
                    let mut cache = mapping.lock().unwrap();
                    for res in responses {
                        let sock_id = res.header.socket_id;
                        let inode = res.header.inode;
                        let socket_wrapper = SocketWrapper(sock_id);
                        cache.insert(socket_wrapper, inode);
                    }
                }
                Err(e) => {
                    eprintln!("UDP RECV ERROR: {e}");
                }
    }
            thread::sleep(Duration::from_millis(100));
        }
    });
}

fn update_addresses(address_table: &mut HashSet<IpAddr>) {
    for interface in getifaddrs().unwrap() { // store addresses in address table
        if interface.flags.contains(InterfaceFlags::UP) || interface.flags.contains(InterfaceFlags::RUNNING) {
            address_table.insert(interface.address);
        }
    }
}

fn handle_packet(address_table: HashSet<IpAddr>) {
    let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
    let mut socket_to_conn: HashMap<SocketWrapper, Connection> = HashMap::new();
    let parser: PacketParser = PacketParser::new(address_table); 

    let inode_cache = Arc::new(Mutex::new(HashMap::new()));

    start_inode_query(inode_cache.clone());
    
    let mut socket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
    if let Err(e) = socket.bind_auto() {
        eprintln!("BIND ERROR: {e}");
        return;
    }

    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    while let Ok(packet) = cap.next_packet() {
        if let Some(mut pack) = parser.parse_pkt(&packet) {
            let sock_id: SocketId = SocketId::from(&pack);
            let socket_wrapper = SocketWrapper(sock_id);

            let cache_lock = inode_cache.lock().unwrap();
            if let Some(inode) = cache_lock.get(&socket_wrapper).cloned() {
                println!("{}", inode);
            }

            match socket_to_conn.entry(socket_wrapper) {
                hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().add_packet(pack);
                }
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(Connection::new(pack));
                }
            }
        }
    }
}

fn send_dump_msg(socket: &Socket, pcl: Protocol) -> Result<(), Error> {
    let mut nl_hdr = NetlinkHeader::default(); 
    nl_hdr.sequence_number = 0;
    nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let protocol = match pcl {
        Protocol::TCP => IPPROTO_TCP,
        Protocol::UDP => IPPROTO_UDP,
    };
    
    let mut packet = NetlinkMessage::new(
        nl_hdr,
        SockDiagMessage::InetRequest(InetRequest {
            family: AF_INET,
            protocol: protocol,
            extensions: ExtensionFlags::empty(),
            states: StateFlags::all(),
            socket_id: SocketId::new_v4(), 
        })
        .into(),
    );

    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];
    assert_eq!(buf.len(), packet.buffer_len());

    packet.serialize(&mut buf[..]);

    socket.send(&buf[..], 0)?;

    Ok(())
}

fn recv_dump_msg(socket: &Socket) -> Result<Vec<InetResponse>, Error> {
    let mut receive_buffer = vec![0; 4096];
    let mut res =  Vec::new();
    loop {
        let size = socket.recv(&mut &mut receive_buffer[..], 0)?;
        let mut offset = 0;
        while offset < size {
            let bytes = &receive_buffer[offset..]; 
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
            
            match rx_packet.payload {
                NetlinkPayload::InnerMessage(
                    SockDiagMessage::InetResponse(response_box)
                ) => {
                    res.push(*response_box);
                }
                NetlinkPayload::Done(_) => {
                    return Ok(res);
                }
                NetlinkPayload::Error(_) => {
                    return Err(Error::new(ErrorKind::NotFound, "Socket not found"));
                }
                _ => {}
            }
            offset += rx_packet.header.length as usize;
        }
        // println!("{:?}\n", res);
    }
}

