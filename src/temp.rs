// fn process_proc() 
// {
//     let path = String::from("/proc/");
//     // let fd = File::open(path).expect("Error opening filepath");
//     let folder = read_dir(path).expect("Error opening path");
//     for file in folder {
//         let fd = file.unwrap().file_name().into_string().unwrap();
//         if let Some(true) = is_process(&fd) {
//             println!("{}", fd);  
//         }
//     }
// }
//
// fn is_process(entry: &str) -> Option<bool> {
//     let pid = entry.split('/').next()?;
//     if string::is_numeric(pid) {
//         Some(true)
//     } else {
//         Some(false)
//     }
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

// -----------------------------

// from_be_bytes or try_into?
// impl fmt::Display?

// thread 'main' panicked at src/packet.rs:72:19: index out of bounds: the len is 0 but the index is 0

// Packet { src_addr: 172.217.16.227, dst_addr: 138.251.223.62, src_port: 18688, dst_port: 117, len: 52, timestamp: SystemTime { tv_sec: 1750274311, tv_nsec: 318677449 }, outgoing: false }
// error parsing packet
// error parsing packet
// Packet { src_addr: 138.251.223.62, dst_addr: 172.67.74.64, src_port: 60736, dst_port: 64, len: 52, timestamp: SystemTime { tv_sec: 1750274311, tv_nsec: 318682850 }, outgoing: false }
