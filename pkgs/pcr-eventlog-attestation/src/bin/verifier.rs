use clap::{App, Arg};
use pcr_eventlog_attestation::{client::verifier, VERSION};

#[tokio::main]
async fn main() {
    let matches = App::new("pea-client")
        .version(VERSION)
        .about("Client for PCR eventlog attestation")
        .arg(
            Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("SERVER")
                .help("The PEA server to authenticate to")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("capath")
                .short("c")
                .long("capath")
                .value_name("FILE")
                .help("The path to a root ca or a capath directory")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let server = matches.value_of("server").unwrap();
    let capath = matches.value_of("capath").unwrap();

    let _ = verifier(server, capath).await.map_err(|e| {
        eprintln!("error: {}", e);
        e
    });
}
