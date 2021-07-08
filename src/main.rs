use pnet::packet::icmp::{
    echo_reply::EchoReplyPacket, echo_request::MutableEchoRequestPacket, IcmpTypes,
};
use pnet::packet::ip::IpNextHeaderProtocols::Icmp;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
};
use pnet::util::checksum;
use std::net::{IpAddr, Ipv4Addr};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn main() {
    let (mut tx, mut rx) = match transport_channel(1500, Layer4(Ipv4(Icmp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating transport channel: {}", e),
    };

    let mut payload = [0u8; 64];
    let dst = IpAddr::V4("192.168.100.101".parse::<Ipv4Addr>().unwrap());
    let mut recv = icmp_packet_iter(&mut rx);

    const IDENT_NUM: u16 = 111;
    const TTL: u8 = 64;
    let mut counter: u16 = 1;
    println!("PING {}: {} data bytes", dst, payload.len());
    loop {
        let mut ping = MutableEchoRequestPacket::new(&mut payload).unwrap();

        ping.set_icmp_type(IcmpTypes::EchoRequest);
        ping.set_payload(b"hello");
        ping.set_identifier(IDENT_NUM);
        ping.set_sequence_number(counter);
        ping.set_checksum(checksum(ping.packet(), 1));

        let curr_time = Instant::now();
        tx.set_ttl(TTL).unwrap();
        tx.send_to(ping, dst).unwrap();

        match recv.next() {
            Ok((pkt, addr)) => {
                let pong = EchoReplyPacket::new(pkt.packet()).unwrap();
                if pong.get_icmp_type() == IcmpTypes::EchoReply
                    && pong.get_identifier() == IDENT_NUM
                    && pong.get_sequence_number() == counter
                {
                    counter += 1;
                    let elapsed = curr_time.elapsed();
                    println!(
                        "{} bytes from {}: icmp_seq={} ttl={} time={} ms",
                        payload.len() - 8,
                        addr,
                        counter,
                        TTL,
                        if elapsed.as_millis() == 0 {
                            format!("0.{:3}", elapsed.as_micros())
                        } else {
                            elapsed.as_millis().to_string()
                        }
                    );
                }
            }
            Err(e) => eprintln!("Error: {} ", e),
        }
        sleep(Duration::from_secs(1));
    }
}
