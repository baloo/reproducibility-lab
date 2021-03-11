use clap::{App, Arg};
use pcr_eventlog_attestation::{attestor::signer, VERSION};
use tss_esapi::Tcti;

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
            Arg::with_name("eventlog")
                .short("e")
                .long("eventlog")
                .value_name("FILE")
                .help("The UEFI event log")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let server = matches.value_of("server").unwrap();
    let eventlog = matches.value_of("eventlog").unwrap();
    let tcti = Tcti::Swtpm(Default::default());

    let _ = signer(server, tcti, eventlog).await;
}
