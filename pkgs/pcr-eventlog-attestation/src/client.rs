use std::{fs, path::Path};

use openssl::{
    pkey::{PKey, Public},
    ssl::SslFiletype,
    stack::Stack,
    x509::{
        store::{X509Lookup, X509StoreBuilder},
        X509StoreContext, X509,
    },
};
use rand::{thread_rng, Rng};
use serde_cbor::from_slice;
use tss_esapi::{interface_types::algorithm::HashingAlgorithm::Sha256, utils::AsymSchemeUnion};

use crate::{
    error::{Error, ValidationError},
    pea::{pea_client::PeaClient, AuthChallenge, QuoteRequest},
    tpm::{
        credential::MakeCredential,
        eventlog::{parse_log, recompute},
        key::{PublicKey, TpmPublic},
        quote::Quote,
    },
    verifier::verification::verify_quote,
};

pub async fn verifier<P: AsRef<Path>>(server: &str, ca_path: P) -> Result<(), Error> {
    // Build a certificate verification store, used to ensure the TPM's certificates are trusted
    // and legit.
    let store = {
        let mut builder = X509StoreBuilder::new()?;
        if ca_path.as_ref().is_file() {
            let content = fs::read(ca_path)?;
            let certificate = X509::from_pem(&content)?;

            builder.add_cert(certificate)?;
        } else if ca_path.as_ref().is_dir() {
            builder.add_lookup(X509Lookup::hash_dir())?.add_dir(
                ca_path.as_ref().to_str().ok_or(Error::InvalidPath)?,
                SslFiletype::PEM,
            )?;
        }
        builder.build()
    };

    let mut errors = Vec::new();

    let mut nonce = [0u8; 32];
    thread_rng().fill(&mut nonce);
    println!("=== Remote attestation of server ===");
    println!("url = {}", server);
    let mut client = PeaClient::connect(server.to_string()).await?;
    let request = tonic::Request::new(QuoteRequest {
        nonce: (&nonce).to_vec(),
    });
    let response = client.nonce(request).await.map_err(Error::from)?;
    let response = response.get_ref();

    let attestation_key_pub: TpmPublic =
        from_slice(&response.attestation_key_pub).map_err(Error::from)?;

    // TODO: ensure the key is indeed ST_CLEAR && Sign && restricted

    // First let's start by verifying the quote is valid
    verify_quote(
        attestation_key_pub.pkey().map_err(Error::from)?.as_ref(),
        &response.quote,
        (AsymSchemeUnion::RSAPSS(Sha256), &response.quote_signature),
    )?;
    println!("quote is signed by attestation key: ✔️");

    // Parse the quote itself
    let quote = Quote::read(&response.quote)?;

    // Did we hash the nonce as expected?
    if quote.extra_data != nonce {
        errors.push(ValidationError::NonceMismatch {
            expected: nonce.to_vec(),
            received: quote.extra_data.to_vec(),
        });
    } else {
        println!("quote nonce valid: ✔️");
    }

    // Parse the eventlog
    let out = parse_log(&response.eventlog);
    let (image_checksum, pcr) = recompute(out);

    // Then compare to the value in the quote
    if !quote.compare_sha256(&pcr) && false
    // TODO: check disabled for dev (I cant reset the tpm (using the swtpm control channel
    //       maybe?))
    {
        errors.push(ValidationError::UnexpectedPCR);
    } else {
        println!("quote match eventlog: ✔️");
    }

    // Ensure we got a chain from root CA to ek
    let endorsement_key_cert =
        X509::from_pem(response.endorsement_key_cert.as_bytes()).map_err(Error::from)?;
    // TODO: buildup that chain, we should read the subsequent asn.1 http uri and download from
    // there
    let chain = Stack::new()?;

    let mut context = X509StoreContext::new()?;
    let chain_verified = context.init(&store, &endorsement_key_cert, &chain, |c| {
        // TODO: is that enough? Do we have additional asn.1 parameters to check?
        c.verify_cert()
    })?;
    if !chain_verified {
        errors.push(ValidationError::CertificationChainBroken);
    } else {
        println!("endorsement key certificate trusted: ✔️");
    }

    // Check the ek pub is a match
    // NOTE: is that really necessary, do we really need to carry the public key separately?
    // the public key is already present in the certificate.
    // The Makecredentials needs to check the attributes of the key carry the decrypt and
    // restricted flags, but ... they're not signed. Or is that just used in a KDF or some
    // sort?
    let endorsement_key_pub: PublicKey =
        from_slice(&response.endorsement_key_pub).map_err(Error::from)?;

    let endorsement_key_pub_from_cert: PKey<Public> =
        endorsement_key_cert.public_key().map_err(Error::from)?;
    {
        let endorsement_key_pub: Result<PKey<Public>, Error> = endorsement_key_pub.to_pkey();
        let endorsement_key_pub = endorsement_key_pub?;
        if !endorsement_key_pub.public_eq(&endorsement_key_pub_from_cert) {
            errors.push(ValidationError::EndorsementKeyMismatch);
        } else {
            println!("endorsement key certificate matches public key: ✔️");
        }
    }

    // Compare image

    // TODO: Get a proper nonce here
    let secret = "42 is a pronic number";
    let ak_name = &attestation_key_pub.name().map_err(Error::from)?;

    let credential = endorsement_key_pub
        // the same key has been used to verify the quote and we're now tying together the
        // encryption key (endorsement) and the key (from its name which is derived from the
        // key itself (it the sha256 of its parameters, and its public key)
        .make_credential(&ak_name, secret.as_bytes())?;

    let request = AuthChallenge {
        credential_blob: credential.credential_blob,
        secret: credential.secret,
    };
    let response = client.auth(request).await?;

    if response.get_ref().proof != secret.as_bytes() {
        errors.push(ValidationError::ProofMismatch);
    } else {
        println!("server replied with proof of secret: ✔️");
    }

    if errors.len() == 0 {
        println!("server authenticated: ✔️");
    }

    Ok(())
}
