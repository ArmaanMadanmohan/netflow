mod packet;
mod connection;

use std::{
    collections::{HashMap, hash_map}, fmt::write, fs::{read_dir, File}, io::{BufRead, BufReader, Error, ErrorKind, Read}, option
};

use pcap::Device;
use netlink_packet_core::{
    NetlinkPayload,
    NetlinkHeader,
    NetlinkMessage,
    NLM_F_DUMP, 
    NLM_F_REQUEST,
};
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
// use netlink_sys;
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};
use netlink_packet_sock_diag::{
    // constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags, InetResponse}, 
    SockDiagMessage, 
    AF_INET, 
    IPPROTO_TCP
};
use packet as pkt;
// use rufl::string;

use crate::packet::{
    Protocol, SocketWrapper,
};

use crate::connection::{
    Connection,
};

use getifaddrs::{getifaddrs, Interface, InterfaceFlags};

// if neither src nor dst are in the address table maybe update table?


fn main() {
    let interface_list: HashMap<IpAddr, Interface> = HashMap::new();
    get_interfaces(interface_list);
    // handle_packet();
}

fn get_interfaces(interface_list: HashMap<IpAddr, Interface>) {
    for interface in getifaddrs().unwrap() { // store addresses in address table
        println!("Interface: {}", interface.name);
        println!("Address: {}", interface.address);
        if let Some(netmask) = interface.netmask {
            println!("  Netmask: {}", netmask);
        }
        println!("  Flags: {:?}", interface.flags);
        if interface.flags.contains(InterfaceFlags::UP) {
            println!("  Status: Up");
        } else {
            println!("  Status: Down");
        }
        println!();
    }
}

fn handle_packet() {
    let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
    let mut socket_to_conn: HashMap<SocketWrapper, Connection> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        if let Some(pack) = pkt::parse_pkt(&packet) {
            let mut socket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
            if let Err(e) = socket.bind_auto() {
                eprintln!("BIND ERROR: {e}");
                return;
            }

            socket.connect(&SocketAddr::new(0, 0)).unwrap();

            let sock_id: SocketId = SocketId::from(&pack);
            let socket_wrapper = SocketWrapper(sock_id);

            // matching on `entry` uses one lookup compared to `contains_key`
            // followed by `get_mut`
            match socket_to_conn.entry(socket_wrapper) {
                hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().add_packet(pack);
                }
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(Connection::new(pack));
                }
            }

            println!("{:?}", socket_to_conn);
            return;

            // if let Err(e) = send_msg(sock_id.clone(), &socket) { // worth cloning or not
            //     eprintln!("SEND ERROR: {e}");
            //     return;
            // }
            // 
            // match recv_msg(&socket) {
            //     Ok(Some(response)) => {
            //         println!("Response: {:#?}", response);
            //     }
            //     Ok(None) => {
            //         println!("Done!");
            //     }
            //     Err(e) => {
            //         eprintln!("RECV ERROR: {e}");
            //     }
            // }
        }
    }
}


fn send_msg(sockid: SocketId, socket: &Socket) -> Result<(), Error> {
    let mut nl_hdr = NetlinkHeader::default(); 
    nl_hdr.sequence_number = 0;
    nl_hdr.flags = NLM_F_REQUEST;
    
    let mut packet = NetlinkMessage::new(
        nl_hdr,
        SockDiagMessage::InetRequest(InetRequest {
            family: AF_INET,
            protocol: IPPROTO_TCP,
            extensions: ExtensionFlags::empty(),
            states: StateFlags::all(),
            socket_id: sockid, 
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


fn recv_msg(socket: &Socket) -> Result<Option<InetResponse>, Error> {
    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet =
                <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
            println!("<<< {rx_packet:?}");

            match rx_packet.payload {
                NetlinkPayload::Noop => {}
                NetlinkPayload::InnerMessage(
                    SockDiagMessage::InetResponse(response_box),
                ) => {
                    let response = *response_box;
                    return Ok(Some(response));
                }
                NetlinkPayload::Error(_) => {
                    return Err(Error::new(ErrorKind::NotFound, "Socket not found"));
                }
                NetlinkPayload::Done(_) => {
                    return Ok(None);
                }
                _ => return Err(Error::new(ErrorKind::InvalidData, "Unexpected payload")) 
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
    Ok(None)
}

// receive pkt, get port and tcp/udp, address
// look at respective net file and get corresponding inode. 
// keep track of sources, if it is in existing source then add to the list of packets for that
// source
// after a period of time, sum all packets in list together and clear list?
// keep list of process to inodes
