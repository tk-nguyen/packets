use clap::Clap;

mod ping;
use ping::*;

#[derive(Clap, Debug)]
#[clap(
    name = "packets",
    version = "0.1.0",
    author = "Thai Nguyen",
    about = "A program to interact with packets on the wire"
)]
struct PacketOpt {
    /// The destination IP address
    #[clap(long, short, value_name = "IP ADDRESS")]
    ping: String,
}

fn main() {
    let opts = PacketOpt::parse();
    match opts {
        PacketOpt { ping: ip } => ping(ip),
    }
}
