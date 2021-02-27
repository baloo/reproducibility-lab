use std::convert::TryFrom;

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
    utils::Signature,
    Context, Result, Tcti,
};

use crate::utils::openssl::{der_to_x509, tpm_public_to_public_rsa};

struct StClearKeys;
impl KeyCustomization for StClearKeys {
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
    nonce: &[u8; 16],
    key_handle: KeyHandle,
) -> Result<(AttestationData, Signature)> {
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

pub fn signer() {
    let tcti = Tcti::Swtpm(Default::default());

    let mut context = unsafe { Context::new(tcti) }.unwrap();

    // Extend the PCR.
    context
        .execute_with_nullauth_session(|ctx| {
            let digest_sha256 = Digest::try_from(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ])
            .expect("Failed to create Sha256 Digest from data");

            let mut vals = DigestValues::new();
            vals.set(HashingAlgorithm::Sha256, digest_sha256);

            ctx.pcr_extend(PcrHandle::Pcr4, vals)
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
    println!(
        "ek_cert:\n{}",
        String::from_utf8(ek_cert.to_pem().unwrap()).unwrap()
    );

    // Create the endorsement key, signed by the manufacturer
    let (ek_key_handle, ek_pub_key) = context
        .execute_with_nullauth_session(|ctx| {
            let key_handle = create_ek_object::<()>(ctx, AsymmetricAlgorithm::Rsa, None)?;
            let (public, name, qualified_name) = ctx.read_public(key_handle)?;
            let pub_key = unsafe { tpm_public_to_public_rsa(&public) };

            Ok((key_handle, pub_key))
        })
        .unwrap();
    println!(
        "EK pub_key:\n{}",
        String::from_utf8(ek_pub_key.public_key_to_pem().unwrap()).unwrap()
    );

    // TODO: Can we bind this to the session?
    //       Could we just bind it to a nonce?
    let auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();
    let auth = Some(&auth);
    let auth = None;

    let (key_handle, pub_key) = context
        .execute_with_nullauth_session(|ctx| {
            // TODO: this miss the ST_CLEAR attribute, so you can reboot the tpm and replay PCRs
            let ak = create_ak(
                ctx,
                ek_key_handle,
                HashingAlgorithm::Sha256,
                SignatureScheme::RsaPss,
                auth,
                Some(StClearKeys),
            )?;

            let key_handle = load_ak(ctx, ek_key_handle, auth, ak.out_private, ak.out_public)?;

            let (public, name, qualified_name) = ctx.read_public(key_handle)?;

            let pub_key = unsafe { tpm_public_to_public_rsa(&public) };

            Ok((key_handle, pub_key))
        })
        .unwrap();

    // TODO flush transient?

    println!(
        "AK pub_key:\n{}",
        String::from_utf8(pub_key.public_key_to_pem().unwrap()).unwrap()
    );

    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let quote = context
        .execute_with_nullauth_session(|ctx| pcr_quote(ctx, &nonce, key_handle))
        .unwrap();
    println!("quote: {:x?}", quote);
}
