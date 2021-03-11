use std::convert::{TryFrom, TryInto};

use tss_esapi::{
    abstraction::{ak, ek},
    attributes::SessionAttributesBuilder,
    constants::SessionType,
    handles::AuthHandle,
    interface_types::algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureScheme},
    structures::{Auth, Digest, SymmetricDefinition},
    Context, Tcti,
};

pub fn create_tcti() -> Tcti {
    Tcti::Swtpm(Default::default())
}
pub fn create_ctx_without_session() -> Context {
    let tcti = create_tcti();
    unsafe { Context::new(tcti).unwrap() }
}

pub fn create_ctx_with_session() -> Context {
    let mut ctx = create_ctx_without_session();
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(
        session.unwrap(),
        session_attributes,
        session_attributes_mask,
    )
    .unwrap();
    ctx.set_sessions((session, None, None));

    ctx
}

fn main() {
    let mut context = create_ctx_without_session();

    let ek_rsa = context
        .execute_with_nullauth_session(|ctx| {
            ek::create_ek_object(ctx, AsymmetricAlgorithm::Rsa, None)
        })
        .unwrap();
    let ak_auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();

    let (key_name, loaded_ak) = context
        .execute_with_nullauth_session(|ctx| {
            let att_key = ak::create_ak(
                ctx,
                ek_rsa,
                HashingAlgorithm::Sha256,
                SignatureScheme::RsaPss,
                Some(&ak_auth),
                None,
            )
            .unwrap();

            let loaded_ak = ak::load_ak(
                ctx,
                ek_rsa,
                Some(&ak_auth),
                att_key.out_private,
                att_key.out_public,
            )
            .unwrap();
            let (_, key_name, _) = ctx.read_public(loaded_ak).unwrap();
            Ok((key_name, loaded_ak))
        })
        .unwrap();

    let cred = "42 is a pronic number";
    let cred = cred.as_bytes();

    let expected = Digest::try_from(vec![1, 2, 3, 4, 5]).unwrap();

    let (session_aastributes, session_attributes_mask) = SessionAttributesBuilder::new().build();
    let session_1 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    context
        .tr_sess_set_attributes(
            session_1.unwrap(),
            session_aastributes,
            session_attributes_mask,
        )
        .unwrap();
    let session_2 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    context
        .tr_sess_set_attributes(
            session_2.unwrap(),
            session_aastributes,
            session_attributes_mask,
        )
        .unwrap();

    let (credential_blob, secret) = context
        .execute_without_session(|ctx| {
            ctx.make_credential(ek_rsa, cred.try_into().unwrap(), key_name)
        })
        .unwrap();

    let _ = context
        .execute_with_session(session_1, |ctx| {
            ctx.policy_secret(
                session_2.unwrap(),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    context.set_sessions((session_1, session_2, None));

    println!("credential_blob: {}", hex::encode(credential_blob.value()));
    println!("secret: {}", hex::encode(secret.value()));

    let decrypted = context
        .activate_credential(loaded_ak, ek_rsa, credential_blob, secret)
        .unwrap();

    println!("decrypted = {:?}", decrypted);
}
