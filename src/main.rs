mod packet;
// use std::process::exit;

use std::{
    fs::{read_dir, File}, 
    io::{BufRead, BufReader, Read}, option, 
};

use pcap::Device;
use netlink_packet_core::{
    NetlinkPayload,
    NetlinkHeader,
    NetlinkMessage,
    NLM_F_DUMP, 
    NLM_F_REQUEST,
};
// use netlink_sys;
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};
use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags}, 
    SockDiagMessage, 
    AF_INET, 
    IPPROTO_TCP
};
use packet as pkt;
use rufl::string;


fn main() {
    let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        if let Some(pack) = pkt::parse_pkt(&packet) {
            let mut socket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
            let port_number = socket.bind_auto().unwrap().port_number();
            socket.connect(&SocketAddr::new(0, 0)).unwrap();

            let sockid = SocketId {
                source_port: pack.src_port,
                destination_port: pack.dst_port,
                source_address: pack.src_addr,
                destination_address: pack.dst_addr,
                interface_id: 0,
                cookie: [0; 8],
            };

            // Also prepare reverse direction
            let reverse_sockid = SocketId {
                source_port: pack.dst_port,
                destination_port: pack.src_port,
                source_address: pack.dst_addr,
                destination_address: pack.src_addr,
                interface_id: 0,
                cookie: [0; 8],
            };

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

            println!(">>> {packet:?}");
            if let Err(e) = socket.send(&buf[..], 0) {
                println!("SEND ERROR {e}");
                return;
            }

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
                            SockDiagMessage::InetResponse(response),
                        ) => {
                            println!("{response:#?}");
                        }
                        NetlinkPayload::Done(_) => {
                            println!("Done!");
                            return;
                        }
                        _ => return,
                    }

                    offset += rx_packet.header.length as usize;
                    if offset == size || rx_packet.header.length == 0 {
                        offset = 0;
                        break;
                    }
                }
            }
            // query_socket(&socket, sockid);
        }
    }
}

// fn query_socket(socket: &Socket, sockid: SocketId) {

// }

// fn main()
// {
//
//     // process_proc();
//     let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
//
//     while let Ok(packet) = cap.next_packet() {
//         if let Some(pack) = pkt::parse_pkt(&packet) {
//             let sockid = SocketId {
//                 source_port: pack.src_port,
//                 destination_port: pack.dst_port,
//                 source_address: pack.src_addr,
//                 destination_address: pack.dst_addr,
//                 interface_id: 0,
//                 cookie: [0; 8],
//             };
//
//             let req = InetRequest {
//                 family: AF_INET,
//                 protocol: IPPROTO_TCP,
//                 extensions: ExtensionFlags::INFO,
//                 states: StateFlags::all(),
//                 socket_id: sockid,
//             }; 
//
//             let sd_msg = SockDiagMessage::InetRequest(req);
//
//             let mut nl_msg = NetlinkMessage::new(
//                 NetlinkHeader::default(),
//                 NetlinkPayload::InnerMessage(sd_msg),
//             );
//             nl_msg.finalize();
//
//             let mut socket = netlink_sys::Socket::new(netlink_sys::protocols::NETLINK_SOCK_DIAG).unwrap();
//             let _ = socket.bind_auto().unwrap(); // address not needed?
//             let kernel_addr = netlink_sys::SocketAddr::new(0, 0); // bind to random port
//             let _ = socket.connect(&kernel_addr).expect("Failed to connect");
//
//             let mut send_buf = vec![0u8; nl_msg.header.length as usize]; // 0? 
//
//             // [..] converts Vec<u8> to [u8]
//             nl_msg.serialize(&mut send_buf[..]); // error handling?
//             let nl_sent = socket.send(&send_buf, 0).unwrap();
//             assert_eq!(nl_sent, nl_msg.header.length as usize);
//             println!("{:?}", nl_msg);
//
//             let mut receive_buffer = vec![0; 4096];
//             let mut offset = 0;
//             while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
//                 loop {
//                     let bytes = &receive_buffer[offset..];
//                     let rx_packet =
//                         <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
//                     println!("<<< {rx_packet:?}");
//
//                     match rx_packet.payload {
//                         NetlinkPayload::Noop => {}
//                         NetlinkPayload::InnerMessage(
//                             SockDiagMessage::InetResponse(response),
//                         ) => {
//                             println!("{response:#?}");
//                         }
//                         NetlinkPayload::Done(_) => {
//                             println!("Done!");
//                             return;
//                         }
//                         _ => return,
//                     }
//
//                     offset += rx_packet.header.length as usize;
//                     if offset == size || rx_packet.header.length == 0 {
//                         offset = 0;
//                         break;
//                     }
//                 }
//             }
//         } 
//     }
// }

// fn prepSockDiag(packet: pkt::Packet) {
//
// }

// fn port_to_inode(port: u32) 
// {
//     let path = String::from("/proc/net/tcp");
//     let f = File::open(path).unwrap();
//     let buf = BufReader::new(f);
//
//     for line in buf.lines() {
//
//     }
// }

fn process_proc() 
{
    let path = String::from("/proc/");
    // let fd = File::open(path).expect("Error opening filepath");
    let folder = read_dir(path).expect("Error opening path");
    for file in folder {
        let fd = file.unwrap().file_name().into_string().unwrap();
        if let Some(true) = is_process(&fd) {
            println!("{}", fd);  
        }
    }
}

fn is_process(entry: &str) -> Option<bool> {
    let pid = entry.split('/').next()?;
    if string::is_numeric(pid) {
        Some(true)
    } else {
        Some(false)
    }
}

// receive pkt, get port and tcp/udp, address
// look at respective net file and get corresponding inode. 
// keep track of sources, if it is in existing source then add to the list of packets for that
// source
// after a period of time, sum all packets in list together and clear list?
// keep list of process to inodes

// netsock ??


// like this?
//
//         let sd_msg = SockDiagMessage::InetRequest(req);
//         let nl_msg = NetlinkMessage::new(
//             NetlinkHeader::default(),
//             NetlinkPayload::InnerMessage(sd_msg),
//         );
//         let mut socket = netlink_sys::Socket::new(netlink_sys::protocols::NETLINK_SOCK_DIAG).unwrap();
//         let _ = socket.bind_auto().unwrap(); // address not needed?
//         let kernel_addr = netlink_sys::SocketAddr::new(0, 0); // bind to random port
//         let _ = socket.connect(&kernel_addr).unwrap();
//         let nl_sent = socket.send(, 0).unwrap();
//
// use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
// use std::process;
//
// let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
// let _ = socket.bind_auto().unwrap();
// let kernel_addr = SocketAddr::new(0, 0);
// socket.connect(&kernel_addr).unwrap();
// // This is a valid message for listing the network links on the system
// let msg = vec![
//     0x14, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x03, 0xfd, 0xfe, 0x38, 0x5c, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x00,
// ];
// let n_sent = socket.send(&msg[..], 0).unwrap();
// assert_eq!(n_sent, msg.len());
// // buffer for receiving the response
// let mut buf = vec![0; 4096];
// loop {
//     let mut n_received = socket.recv(&mut &mut buf[..], 0).unwrap();
//     println!("received {:?}", &buf[..n_received]);
//     if buf[4] == 2 && buf[5] == 0 {
//         println!("the kernel responded with an error");
//         return;
//     }
//     if buf[4] == 3 && buf[5] == 0 {
//         println!("end of dump");
//         return;
//     }
// }
//
// only issue is the types.. netlinkmessage cant be used as a parameter, only &[u8] buffer apparently.
//
// presumably serialise netlinkmessage into a buffer?
//
// pub fn serialize(&self, buffer: &mut [u8])
//
// Serialize this message and write the serialized data into the given buffer. buffer must big large enough for the whole message to fit, otherwise, this method will panic. To know how big the serialized message is, call buffer_len().
// Panic
//
// This method panics if the buffer is not big enough.
//
// whats the point of nl_msg then? do i bypass it and somehow turn the inetrequest into a bytestream ddirectly? or is my proposed approach correct
