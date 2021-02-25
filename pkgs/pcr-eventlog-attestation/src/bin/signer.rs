use std::convert::TryFrom;

use tss_esapi::{Tcti, Context, Result};
use tss_esapi::abstraction::{ak::{create_ak, load_ak}, ek::create_ek_object};
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::{algorithm::{Cipher, HashingAlgorithm, AsymmetricAlgorithm, RsaSignatureScheme, SignatureScheme}, SessionType, tss::*};
use tss_esapi::handles::{KeyHandle, PcrHandle};
use tss_esapi::structures::{PcrSelectionListBuilder, Data, PcrSlot, Auth, Digest, DigestValues};
use tss_esapi::tss2_esys::TPMT_SIG_SCHEME;
use tss_esapi::utils::Signature;

type AttestationData = Vec<u8>;

fn pcr_quote(context: &mut Context, nonce: &[u8; 16], key_handle: KeyHandle) -> Result<(AttestationData, Signature)> {

    // Quote PCR 4
    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot4])
        .build();
    let scheme = TPMT_SIG_SCHEME {
        scheme: TPM2_ALG_NULL,
        details: Default::default(),
    };

    let res = context
        .quote(
            key_handle,
            &Data::try_from(&nonce[..]).unwrap(),
            scheme,
            pcr_selection_list,
        )?;

    let attestation_data = (&res.0.attestationData[..res.0.size as usize]).to_vec();
    Ok((attestation_data, res.1))
}

fn main() {
    let tcti = Tcti::Swtpm(Default::default());

    let mut context = unsafe { Context::new(tcti) }.unwrap();

    let pcr_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            Cipher::aes_256_cfb(),
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();

    let digest_sha256 = Digest::try_from(vec![
           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
           24, 25, 26, 27, 28, 29, 30, 31, 32,
    ]).expect("Failed to create Sha256 Digest from data");
    let mut vals = DigestValues::new();
    vals.set(
        HashingAlgorithm::Sha256,
        digest_sha256,
    );
    context.execute_with_session(pcr_session, |ctx| {
        ctx.pcr_extend(PcrHandle::Pcr4, vals).expect("Call to pcr_extend failed");
    });

    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[
          PcrSlot::Slot0,
          PcrSlot::Slot1,
          PcrSlot::Slot2,
          PcrSlot::Slot3,
          PcrSlot::Slot4,
          PcrSlot::Slot5,
          PcrSlot::Slot6,
          PcrSlot::Slot7,
          PcrSlot::Slot8,
        ])
        .build();
    let out = context.pcr_read(&pcr_selection_list).expect("pcr");
    println!("out {:?}", out);

    let ek = create_ek_object(&mut context, AsymmetricAlgorithm::Rsa).unwrap();

    // Can we bind this to the session?
    let auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();
    let auth = Some(&auth);

    // NOTE: this miss the ST_CLEAR attribute, so you can reboot the tpm.
    let ak = create_ak(&mut context, ek, HashingAlgorithm::Sha256, SignatureScheme::Rsa(RsaSignatureScheme::RsaPss), auth).unwrap();

    let key_handle = load_ak(&mut context, ek, auth, ak.out_private, ak.out_public).unwrap();

    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            Cipher::aes_256_cfb(),
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context.tr_sess_set_attributes(
        session.unwrap(),
        session_attributes,
        session_attributes_mask,
    ).unwrap();
    context.set_sessions((session, None, None));

    let quote = pcr_quote(&mut context, &[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], key_handle);
    println!("quote: {:?}", quote);
}
