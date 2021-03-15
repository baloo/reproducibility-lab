use std::convert::TryFrom;

use tss_esapi::{
    abstraction::{
        ak::{create_ak, load_ak},
        ek::{create_ek_object, retrieve_ek_pubcert},
        KeyCustomization,
    },
    attributes::ObjectAttributesBuilder,
    constants::tss::*,
    handles::KeyHandle,
    interface_types::algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureScheme},
    structures::{Auth, Data, PcrSelectionListBuilder, PcrSlot},
    tss2_esys::TPMT_SIG_SCHEME,
    utils::Signature,
    Context, Result as TPMResult,
};

use crate::{
    error::Error,
    tpm::key::{PublicKey, TpmPublic},
    utils::openssl::der_to_x509,
};

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

pub fn pcr_quote(
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
        &Data::try_from(&nonce[..])?,
        scheme,
        pcr_selection_list,
    )?;

    let attestation_data = (&res.0.attestationData[..res.0.size as usize]).to_vec();
    Ok((attestation_data, res.1))
}

pub fn get_static_keys(
    context: &mut Context,
) -> Result<(String, KeyHandle, PublicKey, TpmPublic, KeyHandle), Error> {
    // Grab the certificate chain to the manufacturer CA.
    let ek_cert = retrieve_ek_pubcert(context, AsymmetricAlgorithm::Rsa)?;
    let ek_cert = der_to_x509(&ek_cert).to_pem()?;
    let ek_cert = String::from_utf8(ek_cert)?;

    // Create the endorsement key, signed by the manufacturer
    let ek_key_handle = create_ek_object(context, AsymmetricAlgorithm::Rsa, None)?;
    let (ek_pub_key, _, _) = context.read_public(ek_key_handle).map_err(Error::from)?;

    let ek_pub_key = PublicKey::try_from(&ek_pub_key)?;

    let ak_auth = Auth::try_from(vec![0x1, 0x2, 0x42])?;
    let ak_auth = Some(&ak_auth);

    let (ak_key_handle, ak_public) = context.execute_with_nullauth_session(|ctx| {
        let ak = create_ak(
            ctx,
            ek_key_handle,
            HashingAlgorithm::Sha256,
            SignatureScheme::RsaPss,
            ak_auth,
            &StClearKeys,
        )?;

        let key_handle = load_ak(ctx, ek_key_handle, ak_auth, ak.out_private, ak.out_public)?;

        let (public, _name, _qualified_name) = ctx.read_public(key_handle)?;

        let public = TpmPublic::from(public);
        Ok((key_handle, public))
    })?;

    Ok((ek_cert, ek_key_handle, ek_pub_key, ak_public, ak_key_handle))
}
