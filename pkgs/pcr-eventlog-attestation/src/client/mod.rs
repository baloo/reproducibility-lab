use std::convert::TryFrom;
use std::fs;
use std::path::Path;

use tss_esapi::{
    abstraction::{
        ak::{create_ak, load_ak},
        ek::{create_ek_object, retrieve_ek_pubcert},
        KeyCustomization,
    },
    attributes::ObjectAttributesBuilder,
    constants::tss::*,
    handles::{KeyHandle, PcrHandle},
    interface_types::algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureScheme},
    structures::{Auth, Data, Digest, DigestValues, PcrSelectionListBuilder, PcrSlot},
    tss2_esys::TPMT_SIG_SCHEME,
    utils::{Signature, SignatureData},
    Context, Result as TPMResult, Tcti,
};

use crate::utils::openssl::{der_to_x509, tpm_public_to_public_rsa};

pub mod pea {
    tonic::include_proto!("grpc.pea");
}

use self::pea::{pea_client::PeaClient, AuthRequest, NonceRequest};

struct StClearKeys;
impl KeyCustomization for &StClearKeys {
    fn attributes(&self, attributes_builder: ObjectAttributesBuilder) -> ObjectAttributesBuilder {
        // https://safeboot.dev/attestation/#why-is-generating-a-quote-so-slow
        // By creating an ephemeral AK (with the stclear bit set in the
        // attributes), the TPM will not allow it to be persisted and will refuse
        // to reload it when the reboot counter increments.
        attributes_builder.with_st_clear(true)
    }
}

type AttestationData = Vec<u8>;

fn pcr_quote(
    context: &mut Context,
    nonce: &[u8],
    key_handle: KeyHandle,
) -> TPMResult<(AttestationData, Signature)> {
    // Quote PCR 4
    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot4])
        .build();
    let scheme = TPMT_SIG_SCHEME {
        scheme: TPM2_ALG_NULL,
        details: Default::default(),
    };

    let res = context.quote(
        key_handle,
        &Data::try_from(&nonce[..]).unwrap(),
        scheme,
        pcr_selection_list,
    )?;

    let attestation_data = (&res.0.attestationData[..res.0.size as usize]).to_vec();
    Ok((attestation_data, res.1))
}

pub async fn signer<P: AsRef<Path>>(
    server: &str,
    eventlog: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let tcti = Tcti::Swtpm(Default::default());
    let mut context = unsafe { Context::new(tcti) }.unwrap();

    let mut client = PeaClient::connect(server.to_string()).await?;

    let request = tonic::Request::new(NonceRequest {});
    let response = client.nonce(request).await?;

    // Extend the PCR.
    //context
    //    .execute_with_nullauth_session(|ctx| ctx.pcr_reset(PcrHandle::Pcr4))
    //    .expect("Call to pcr_reset failed");
    let pcrs: &[[u8; 32]] = &[
        [
            0x3d, 0x67, 0x72, 0xb4, 0xf8, 0x4e, 0xd4, 0x75, 0x95, 0xd7, 0x2a, 0x2c, 0x4c, 0x5f,
            0xfd, 0x15, 0xf5, 0xbb, 0x72, 0xc7, 0x50, 0x7f, 0xe2, 0x6f, 0x2a, 0xae, 0xe2, 0xc6,
            0x9d, 0x56, 0x33, 0xba,
        ],
        [
            0xdf, 0x3f, 0x61, 0x98, 0x4, 0xa9, 0x2f, 0xdb, 0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d,
            0xd7, 0x48, 0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c, 0xe8, 0x5, 0x24, 0xc0,
            0x14, 0xb8, 0x11, 0x19,
        ],
        [
            0x70, 0x44, 0xf0, 0x63, 0x3, 0xe5, 0x4f, 0xa9, 0x6c, 0x3f, 0xcd, 0x1a, 0xf, 0x11, 0x4,
            0x7c, 0x3, 0xd2, 0x9, 0x7, 0x44, 0x70, 0xb1, 0xfd, 0x60, 0x46, 0xc, 0x9f, 0x0, 0x7e,
            0x28, 0xa6,
        ],
        [
            0x3d, 0x67, 0x72, 0xb4, 0xf8, 0x4e, 0xd4, 0x75, 0x95, 0xd7, 0x2a, 0x2c, 0x4c, 0x5f,
            0xfd, 0x15, 0xf5, 0xbb, 0x72, 0xc7, 0x50, 0x7f, 0xe2, 0x6f, 0x2a, 0xae, 0xe2, 0xc6,
            0x9d, 0x56, 0x33, 0xba,
        ],
        [
            0x70, 0x44, 0xf0, 0x63, 0x3, 0xe5, 0x4f, 0xa9, 0x6c, 0x3f, 0xcd, 0x1a, 0xf, 0x11, 0x4,
            0x7c, 0x3, 0xd2, 0x9, 0x7, 0x44, 0x70, 0xb1, 0xfd, 0x60, 0x46, 0xc, 0x9f, 0x0, 0x7e,
            0x28, 0xa6,
        ],
        [
            0x3d, 0x67, 0x72, 0xb4, 0xf8, 0x4e, 0xd4, 0x75, 0x95, 0xd7, 0x2a, 0x2c, 0x4c, 0x5f,
            0xfd, 0x15, 0xf5, 0xbb, 0x72, 0xc7, 0x50, 0x7f, 0xe2, 0x6f, 0x2a, 0xae, 0xe2, 0xc6,
            0x9d, 0x56, 0x33, 0xba,
        ],
        [
            0x98, 0x25, 0xd3, 0xbf, 0xde, 0x7f, 0x88, 0x27, 0xe9, 0x55, 0x3d, 0xf0, 0x40, 0x99,
            0x5a, 0x7, 0xa6, 0x40, 0x44, 0xab, 0x55, 0x90, 0x58, 0xd7, 0xfc, 0xfd, 0xd7, 0x52,
            0x7f, 0x60, 0xbc, 0x42,
        ],
        [
            0xdc, 0x1d, 0x3, 0xe0, 0xb6, 0x23, 0xd9, 0x17, 0x6b, 0x16, 0x4, 0x67, 0xa2, 0xbe, 0xae,
            0x1c, 0xa1, 0x46, 0x22, 0xe4, 0xa1, 0x71, 0x6f, 0x72, 0xb6, 0xa7, 0x87, 0xbb, 0xd9,
            0x37, 0x7d, 0x96,
        ],
        [
            0x70, 0x44, 0xf0, 0x63, 0x3, 0xe5, 0x4f, 0xa9, 0x6c, 0x3f, 0xcd, 0x1a, 0xf, 0x11, 0x4,
            0x7c, 0x3, 0xd2, 0x9, 0x7, 0x44, 0x70, 0xb1, 0xfd, 0x60, 0x46, 0xc, 0x9f, 0x0, 0x7e,
            0x28, 0xa6,
        ],
        [
            0x3d, 0x67, 0x72, 0xb4, 0xf8, 0x4e, 0xd4, 0x75, 0x95, 0xd7, 0x2a, 0x2c, 0x4c, 0x5f,
            0xfd, 0x15, 0xf5, 0xbb, 0x72, 0xc7, 0x50, 0x7f, 0xe2, 0x6f, 0x2a, 0xae, 0xe2, 0xc6,
            0x9d, 0x56, 0x33, 0xba,
        ],
        [
            0x8, 0xc, 0x2, 0x49, 0x8e, 0x99, 0xf2, 0x68, 0x23, 0x34, 0x76, 0xd5, 0x4d, 0x8e, 0xc3,
            0x40, 0xb1, 0x65, 0x19, 0xdc, 0x19, 0x6d, 0x9b, 0x78, 0x1a, 0x6e, 0xb4, 0x1f, 0xce,
            0xb7, 0x54, 0xc3,
        ],
    ];
    context
        .execute_with_nullauth_session(|ctx| {
            for pcr in pcrs {
                let digest_sha256 =
                    Digest::try_from(&pcr[..]).expect("Failed to create Sha256 Digest from data");

                let mut vals = DigestValues::new();
                vals.set(HashingAlgorithm::Sha256, digest_sha256);

                ctx.pcr_extend(PcrHandle::Pcr4, vals)?;
            }
            Ok(())
        })
        .expect("Call to pcr_extend failed");

    // Read back the PCR.
    let out = context.execute_without_session(|ctx| {
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[
                    PcrSlot::Slot0,
                    PcrSlot::Slot1,
                    PcrSlot::Slot2,
                    PcrSlot::Slot3,
                    PcrSlot::Slot4,
                    PcrSlot::Slot5,
                    PcrSlot::Slot6,
                    PcrSlot::Slot7,
                    PcrSlot::Slot8,
                ],
            )
            .build();
        ctx.pcr_read(&pcr_selection_list)
    });
    println!("pcrs: {:02x?}", out);

    // Grab the certificate chain to the manufacturer CA.
    let ek_cert = retrieve_ek_pubcert(&mut context, AsymmetricAlgorithm::Rsa).unwrap();
    let ek_cert = der_to_x509(&ek_cert);
    let ek_cert = String::from_utf8(ek_cert.to_pem().unwrap()).unwrap();

    // Create the endorsement key, signed by the manufacturer
    let (ek_key_handle, ek_pub_key) = context
        .execute_with_nullauth_session(|ctx| {
            let key_handle = create_ek_object(ctx, AsymmetricAlgorithm::Rsa, None)?;
            let (public, name, qualified_name) = ctx.read_public(key_handle)?;
            let pub_key = unsafe { tpm_public_to_public_rsa(&public) };

            Ok((key_handle, pub_key))
        })
        .unwrap();
    let ek_pub_key = String::from_utf8(ek_pub_key.public_key_to_pem().unwrap()).unwrap();

    // TODO: Can we bind this to the session?
    //       Could we just bind it to a nonce?
    let auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();
    let auth = Some(&auth);
    let auth = None;

    let (key_handle, ak_name, ak_pub_key) = context
        .execute_with_nullauth_session(|ctx| {
            let ak = create_ak(
                ctx,
                ek_key_handle,
                HashingAlgorithm::Sha256,
                SignatureScheme::RsaPss,
                auth,
                &StClearKeys,
            )?;

            let key_handle = load_ak(ctx, ek_key_handle, auth, ak.out_private, ak.out_public)?;

            let (public, name, qualified_name) = ctx.read_public(key_handle)?;

            let pub_key = unsafe { tpm_public_to_public_rsa(&public) };

            Ok((key_handle, name, pub_key))
        })
        .unwrap();

    // TODO flush transient?

    let ak_pub_key = String::from_utf8(ak_pub_key.public_key_to_pem().unwrap()).unwrap();

    let ref nonce = response.get_ref().nonce;
    let quote = context
        .execute_with_nullauth_session(|ctx| pcr_quote(ctx, nonce, key_handle))
        .unwrap();

    // TODO: we need to carry the signature scheme and ... overall get a better serializer here
    let rsa_signature = if let SignatureData::RsaSignature(ref s) = quote.1.signature {
        s.clone()
    } else {
        panic!("ecc not implemented yet");
    };

    let eventlog = fs::read(eventlog).unwrap();

    println!("ek_cert:\n{}\nek_pub:\n{}", ek_cert, ek_pub_key);

    let request = tonic::Request::new(AuthRequest {
        session_key: response.get_ref().session_key.clone(),
        endorsement_key_cert: ek_cert,
        endorsement_key_pub: ek_pub_key,
        attestation_key_pub: ak_pub_key,
        attestation_key_name: ak_name.value().to_vec(),
        eventlog,
        quote: quote.0,
        quote_signature: rsa_signature,
    });
    println!("send auth");
    let response = client.auth(request).await?;
    println!("got? auth");

    println!("response: {:?}", response);

    Ok(())
}
