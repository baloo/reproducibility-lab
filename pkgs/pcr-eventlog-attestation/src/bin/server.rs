use clap::{App, Arg};
use pcr_eventlog_attestation::{verifier::server, VERSION};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("pea-server")
        .version(VERSION)
        .about("Server for authenticating clients off PCRs measurement")
        .arg(
            Arg::with_name("rootca")
                .short("r")
                .long("root-ca")
                .value_name("FILE")
                .help("The file storing the root ca to trust")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen")
                .short("l")
                .long("listen")
                .value_name("LISTEN")
                .help("The addr:port to run server onto")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let listen = matches.value_of("listen").unwrap();
    let root_ca = matches.value_of("rootca").unwrap();

    server(listen, root_ca).await?;
    Ok(())
}
