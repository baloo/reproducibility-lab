use std::env;
use std::fs;

use pcr_eventlog_attestation::tpm::eventlog::{parse_log, recompute};

fn main() {
    let args: Vec<String> = env::args().collect();
    let ref filename = args[1];
    let contents = fs::read(filename).expect("Something went wrong reading the file");
    let out = parse_log(&contents);
    let pcr = recompute(out);
    println!("expected pcr[4]: {:02x?}", pcr);
}
