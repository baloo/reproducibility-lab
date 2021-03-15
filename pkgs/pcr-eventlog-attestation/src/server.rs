use std::{
    convert::TryFrom,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde_cbor::to_vec;
use tonic::{transport::Server, Request, Response, Status};
use tss_esapi::{
    attributes::SessionAttributesBuilder,
    constants::SessionType,
    handles::{AuthHandle, KeyHandle, ObjectHandle},
    interface_types::algorithm::HashingAlgorithm,
    structures::{EncryptedSecret, IDObject, SymmetricDefinition},
    utils::SignatureData,
    Context, Tcti,
};

use crate::{
    attestor::{get_static_keys, pcr_quote},
    error::Error,
    pea::{
        pea_server::{Pea, PeaServer},
        AuthChallenge, AuthComplete, Quote, QuoteRequest,
    },
    tpm::key::{PublicKey, TpmPublic},
};

struct Service {
    ek_cert: String,
    ek_key_handle: KeyHandle,
    ek_pub_key: PublicKey,
    ak_key_handle: KeyHandle,
    ak_pub_key: TpmPublic,
    image_id: String,
    context: Mutex<Context>,
    eventlog: PathBuf,
}

impl Drop for Service {
    fn drop(&mut self) {
        let mut context = match self.context.lock() {
            Ok(guard) => guard,
            Err(_) => return, // can't do much
        };

        context
            .flush_context(ObjectHandle::from(self.ak_key_handle.value()))
            .expect("unable to release the Attestation Key");
        context
            .flush_context(ObjectHandle::from(self.ek_key_handle.value()))
            .expect("unable to release the Endorsement Key");
    }
}

#[tonic::async_trait]
impl Pea for Service {
    async fn nonce(&self, request: Request<QuoteRequest>) -> Result<Response<Quote>, Status> {
        let mut context = match self.context.lock() {
            Ok(guard) => guard,
            // TODO: we should probably panic, this is pretty much unrecoverable
            Err(_) => return Err(Status::internal("context mutex poisoned")),
        };

        let ref nonce = request.get_ref().nonce;
        let quote = context
            .execute_with_nullauth_session(|ctx| pcr_quote(ctx, nonce, self.ak_key_handle))
            .map_err(Error::from)
            .map_err::<Status, _>(|e| e.into())?;

        // TODO: we need to carry the signature scheme and ... overall get a better serializer here
        let rsa_signature = if let SignatureData::RsaSignature(ref s) = quote.1.signature {
            s.clone()
        } else {
            panic!("ecc not implemented yet");
        };

        let eventlog = fs::read(&self.eventlog)?;

        Ok(Response::new(Quote {
            endorsement_key_cert: self.ek_cert.clone(),
            endorsement_key_pub: to_vec(&self.ek_pub_key)
                .map_err(Error::from)
                .map_err::<Status, _>(|e| e.into())?,
            attestation_key_pub: to_vec(&self.ak_pub_key)
                .map_err(Error::from)
                .map_err::<Status, _>(|e| e.into())?,
            quote: quote.0,
            quote_signature: rsa_signature,
            eventlog,
            image_id: self.image_id.clone(),
        }))
    }

    async fn auth(
        &self,
        request: Request<AuthChallenge>,
    ) -> Result<Response<AuthComplete>, Status> {
        let mut context = match self.context.lock() {
            Ok(guard) => guard,
            // TODO: we should probably panic, this is pretty much unrecoverable
            Err(_) => return Err(Status::internal("context mutex poisoned")),
        };

        let request = request.get_ref();

        let credential_blob = IDObject::try_from({
            let blob: &[u8] = &request.credential_blob;
            blob
        })
        .map_err(Error::from)
        .map_err::<Status, _>(|e| e.into())?;

        let secret = EncryptedSecret::try_from({
            let secret: &[u8] = &request.secret;
            secret
        })
        .map_err(Error::from)
        .map_err::<Status, _>(|e| e.into())?;

        let (session_aastributes, session_attributes_mask) =
            SessionAttributesBuilder::new().build();
        let session_1 = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(Error::from)
            .map_err::<Status, _>(|e| e.into())?;
        context
            .tr_sess_set_attributes(
                session_1.unwrap(),
                session_aastributes,
                session_attributes_mask,
            )
            .map_err(Error::from)
            .map_err::<Status, _>(|e| e.into())?;

        let session_2 = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(Error::from)
            .map_err::<Status, _>(|e| e.into())?;

        context
            .tr_sess_set_attributes(
                session_2.unwrap(),
                session_aastributes,
                session_attributes_mask,
            )
            .map_err(Error::from)
            .map_err::<Status, _>(|e| e.into())?;

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
            .map_err(Error::from)
            .map_err::<Status, _>(|e| e.into())?;

        let decrypted = context
            .execute_with_sessions((session_1, session_2, None), |ctx| {
                ctx.activate_credential(
                    self.ak_key_handle,
                    self.ek_key_handle,
                    credential_blob,
                    secret,
                )
            })
            .map_err(Error::from)
            .map_err::<Status, _>(|e| e.into())?;

        // Ensure we cleanup after ourselves.
        // TODO: can we put a guard on those sessions or something?
        //       guard will need to keep a reference to the context, play with lifetimes? bind it
        //       to mutex' guard lifetime itself?
        if let Some(session_2) = session_2 {
            context
                .flush_context(session_2.handle().into())
                .map_err(Error::from)
                .map_err::<Status, _>(|e| e.into())?;
        }
        if let Some(session_1) = session_1 {
            context
                .flush_context(session_1.handle().into())
                .map_err(Error::from)
                .map_err::<Status, _>(|e| e.into())?;
        }

        Ok(Response::new(AuthComplete {
            proof: decrypted.to_vec(),
        }))
    }
}

pub async fn server<P: AsRef<Path>>(
    listen: &str,
    eventlog: P,
    image_id: &str,
) -> Result<(), Error> {
    let addr = listen.parse().unwrap();
    let tcti = Tcti::from_environment_variable()?;
    let mut context = unsafe { Context::new(tcti) }?;
    let image_id = image_id.to_string();

    let (ek_cert, ek_key_handle, ek_pub_key, ak_pub_key, ak_key_handle) =
        get_static_keys(&mut context)?;

    let service = Service {
        ek_cert,
        ek_key_handle,
        ek_pub_key,
        ak_key_handle,
        ak_pub_key,
        image_id,
        context: Mutex::new(context),
        eventlog: eventlog.as_ref().to_path_buf(),
    };

    Server::builder()
        .add_service(PeaServer::new(service))
        .serve(addr)
        .await
        .map(|e| {
            eprintln!("tonic exit:{:?}", e);
            e
        })
        .map_err(|e| {
            eprintln!("tonic error:{}", e);
            e
        })?;

    Ok(())
}
