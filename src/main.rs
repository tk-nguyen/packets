use pnet::packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols::Icmp;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType};
use std::net::{IpAddr, Ipv4Addr};

fn main() {
    let (mut tx, mut rx) = match transport_channel(1500, TransportChannelType::Layer3(Icmp)) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating transport channel: {}", e),
    };
    let mut payload = [0u8; 64];
    let dst = "192.168.100.101".parse::<Ipv4Addr>().unwrap();
    let mut recv = icmp_packet_iter(&mut rx);
    loop {
        let mut ping = MutableEchoRequestPacket::new(&mut payload).unwrap();
        ping.set_icmp_type(IcmpTypes::EchoRequest);
        ping.set_payload(b"hello");
        println!("Bytes sent: {}", tx.send_to(ping, IpAddr::V4(dst)).unwrap());
        match recv.next() {
            Ok((pkt, addr)) => println!("{:#?} {}", pkt, addr),
            Err(e) => eprintln!("Error: {} ", e),
        }
    }
}
