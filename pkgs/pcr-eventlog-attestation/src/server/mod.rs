use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use lazy_static::lazy_static;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use rand::{thread_rng, Rng};
use tonic::{transport::Server, Request, Response, Status};
use tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256;
use tss_esapi::utils::AsymSchemeUnion;

use crate::tpm::{
    eventlog::{parse_log, recompute},
    quote::Quote,
};

use self::pea::pea_server::{Pea, PeaServer};
use self::pea::{AuthChallenge, AuthRequest, NonceRequest, NonceResponse};
use self::verification::verify_quote;

mod verification;
pub mod pea {
    tonic::include_proto!("grpc.pea");
}

#[derive(Debug, Clone)]
struct Session {
    nonce: [u8; 32],
}

impl Session {
    fn new() -> Session {
        let mut nonce = [0u8; 32];
        thread_rng().fill(&mut nonce);
        Self { nonce }
    }
}

type SessionKey = [u8; 8];

lazy_static! {
    // Serious business, reliable storage
    static ref SESSIONS: Mutex<HashMap<SessionKey, Session>> = {
        Mutex::new(HashMap::new())
    };
}

pub struct Service {
    root_ca: X509,
}

#[tonic::async_trait]
impl Pea for Service {
    async fn nonce(
        &self,
        request: Request<NonceRequest>,
    ) -> Result<Response<NonceResponse>, Status> {
        let mut session_key = [0u8; 8];
        thread_rng().fill(&mut session_key);
        // Ideally check for conflict in AUTH_REQUESTS, and regen but ... it's a prototype and if
        // you get a clash in a 2^64 field, play lottery.
        let session = Session::new();

        let reply = NonceResponse {
            session_key: session_key.to_vec(),
            nonce: session.nonce.to_vec(),
        };
        match SESSIONS.lock() {
            Ok(mut sessions) => {
                sessions.insert(session_key, session);
            }
            Err(_) => panic!("mutex poisoned"),
        }

        Ok(Response::new(reply))
    }

    async fn auth(&self, request: Request<AuthRequest>) -> Result<Response<AuthChallenge>, Status> {
        let mut session_key = [0u8; 8];
        session_key.copy_from_slice(&request.get_ref().session_key);

        let session = match SESSIONS.lock() {
            // Remove the session off the storage. A nonce should not be reused.
            Ok(mut sessions) => sessions.remove(&session_key),
            Err(_) => {
                panic!("mutex poisoned");
            }
        };

        let session = session.ok_or(Status::not_found("session not found"))?;

        let message = request.get_ref();

        // First let's start by verifying the quote is valid
        verify_quote(
            &message.attestation_key_pub,
            &message.quote,
            (AsymSchemeUnion::RSAPSS(Sha256), &message.quote_signature),
        )
        .map_err(|_| Status::invalid_argument("quote signature invalid"))?;

        // Parse the quote itself
        let quote = Quote::read(&message.quote)
            .map_err(|_| Status::invalid_argument("unable to parse quote"))?;

        // Did we hash the nonce as expected?
        if quote.extra_data != session.nonce {
            return Err(Status::invalid_argument("invalid nonce"));
        }

        // Parse the eventlog
        let out = parse_log(&message.eventlog);
        let pcr = recompute(out);
        println!("pcr_expected[4]= {:02x?}", pcr);

        // Then compare to the value in the quote
        if !quote.compare_sha256(&pcr) && false
        // TODO: check disabled for dev (I cant reset the tpm (using the swtpm control channel
        // maybe?))
        {
            return Err(Status::invalid_argument("unexpected PCR value"));
        } else {
            println!("success");
        }

        // Ensure we got a chain from root CA to ek
        let endorsement_key_cert = X509::from_pem(message.endorsement_key_cert.as_bytes()).unwrap();
        //TODO: this is not nearly enough to verify a certificate chain
        let chain_verified = endorsement_key_cert.verify(&self.root_ca.public_key().unwrap());
        println!("chain_verified: {:?}", chain_verified);

        // Check the ek pub is a match
        // NOTE: is that really necessary, do we really need to carry the public key separately?
        // the public key is already present in the certificate.
        // The Makecredentials needs to check the attributes of the key carry the decrypt and
        // restricted flags, but ... they're not signed. Or is that just used in a KDF or some
        // sort?
        let endorsement_key_pub =
            Rsa::public_key_from_pem(message.endorsement_key_pub.as_bytes()).unwrap();
        if endorsement_key_pub.n() != endorsement_key_cert.public_key().unwrap().rsa().unwrap().n() {
            return Err(Status::invalid_argument("endorsement key pub does not match the certificate"));
        }

        let secret = "42 is a pronic number, but shhhh don't tell anyone.";       

        
        println!("session: {:?}", session);

        unimplemented!("aljkalskjd");
    }
}

pub async fn server<P: AsRef<Path>>(
    listen: &str,
    root_ca: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = listen.parse().unwrap();
    let content = fs::read(root_ca).unwrap();
    let root_ca = X509::from_pem(&content).unwrap();
    let service = Service { root_ca };

    Server::builder()
        .add_service(PeaServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
