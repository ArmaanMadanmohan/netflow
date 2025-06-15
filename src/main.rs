mod packet;
// use std::process::exit;

use pcap::Device;
use packet as pkt;


fn main()
{
    let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        pkt::parse_pkt(&packet)
            .map(|p| println!("{:?}", p))
            .unwrap_or_else(|| eprint!("Error parsing packet\n"));
    } 
}

