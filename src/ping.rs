use pnet::packet::icmp::{
    echo_reply::EchoReplyPacket, echo_request::MutableEchoRequestPacket, IcmpTypes,
};
use pnet::packet::ip::IpNextHeaderProtocols::Icmp;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4,
};
use pnet::util::checksum;

use trust_dns_resolver::{config::ResolverConfig, config::ResolverOpts, Resolver};

use ctrlc::set_handler;

use std::net::{IpAddr, Ipv4Addr};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// The ping function of this program
pub fn ping(query: String) {
    // Create a channel to send ping packets
    let (mut tx, mut rx) = match transport_channel(1500, Layer4(Ipv4(Icmp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating transport channel: {}", e),
    };

    // Typical ICMP packet size
    let mut payload = [0u8; 64];
    let input = Arc::new(query);

    // Iterate through received ping packets
    // If `ip` is not an IP address, try to resolve the domain name first
    let dst = match input.parse::<Ipv4Addr>() {
        Ok(addr) => IpAddr::V4(addr.to_owned()),
        Err(_e) => {
            let resolver =
                Resolver::new(ResolverConfig::cloudflare(), ResolverOpts::default()).unwrap();
            let lookup_res = match resolver.ipv4_lookup(input.to_string()) {
                Ok(lookup) => lookup,
                Err(e) => panic!("{}", e),
            };
            let ip = match lookup_res.iter().next() {
                Some(ip) => ip.to_owned(),
                None => panic!("No IP address found for your query!"),
            };
            IpAddr::V4(ip)
        }
    };
    let mut recv = icmp_packet_iter(&mut rx);

    // Random identifier
    const IDENT_NUM: u16 = 111;
    const TTL: u8 = 64;
    let counter = Arc::new(Mutex::new(0));
    let packet_loss = Arc::new(Mutex::new(0));
    let time: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::from(false));

    // Mimicking the `ping` utility in unix
    println!(
        "PING {}: {}({}) data bytes",
        // See if input is a domain name or IP address, and output accordingly
        if input.to_string() == dst.to_string() {
            dst.to_string()
        } else {
            format!("{} ({})", input, dst)
        },
        payload.len(),
        payload.len() - 8
    );

    // Handle ctrl+c
    let output = input.clone();
    let time_out = time.clone();
    let counter_out = counter.clone();
    let packet_loss_out = packet_loss.clone();
    let stop_out = stop.clone();
    set_handler(move || {
        stop_out.store(true, Ordering::SeqCst);
        let time_out = time_out.lock().unwrap();
        let counter_out = counter_out.lock().unwrap();
        let packet_loss_out = packet_loss_out.lock().unwrap();
        println!("-- {} ping statistics --", output);
        println!(
            "{} packets transmitted, {} packet received, {}% packet loss",
            counter_out,
            *counter_out - *packet_loss_out,
            *packet_loss_out / *counter_out
        );
        println!(
            "round-trip min/avg/max = {:.3}/{:.3}/{:.3} ms",
            time_out[0],
            time_out.iter().sum::<f64>() / time_out.len() as f64,
            time_out[time_out.len() - 1]
        );
        exit(0);
    })
    .unwrap();

    while !stop.load(Ordering::SeqCst) {
        let mut ping = MutableEchoRequestPacket::new(&mut payload).unwrap();

        ping.set_icmp_type(IcmpTypes::EchoRequest);
        ping.set_payload(b"hello");
        ping.set_identifier(IDENT_NUM);
        ping.set_sequence_number(*counter.lock().unwrap());
        ping.set_checksum(checksum(ping.packet(), 1));

        let curr_time = Instant::now();
        tx.set_ttl(TTL).unwrap();
        tx.send_to(ping, dst).unwrap();

        match recv.next() {
            Ok((pkt, addr)) => {
                let pong = EchoReplyPacket::new(pkt.packet()).unwrap();
                if pong.get_icmp_type() == IcmpTypes::EchoReply
                    && pong.get_identifier() == IDENT_NUM
                    && pong.get_sequence_number() == *counter.lock().unwrap()
                {
                    let elapsed = curr_time.elapsed();
                    *counter.lock().unwrap() += 1;
                    time.lock()
                        .unwrap()
                        .push(elapsed.as_micros() as f64 / 1000 as f64);
                    println!(
                        "{} bytes from {}: icmp_seq={} ttl={} time={:.1} ms",
                        payload.len() - 8,
                        // Same as above
                        if input.to_string() == addr.to_string() {
                            addr.to_string()
                        } else {
                            format!("{} ({})", input, addr)
                        },
                        counter.lock().unwrap(),
                        TTL,
                        elapsed.as_micros() as f64 / 1000 as f64
                    );
                } else {
                    *packet_loss.lock().unwrap() += 1;
                }
            }
            Err(e) => eprintln!("Error: {} ", e),
        }
        sleep(Duration::from_secs(1));
    }
}
