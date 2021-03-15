use std::{
    fmt,
    io::{Cursor, Write},
};

use openssl::{
    ec::EcKey,
    encrypt::Encrypter,
    hash::MessageDigest,
    kdf::{derive, Mac, Mode, KBKDF},
    pkey::{PKey, Public},
    rsa::{Padding, Rsa},
    sign::Signer,
    symm::{encrypt,Cipher},
};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    tpm::key::{KeyType, OpensslHash, PublicKey},
};

const INTEGRITY_KEY: &[u8] = b"INTEGRITY\0";
const STORAGE_KEY: &[u8] = b"STORAGE\0";
const IDENTITY_KEY: &[u8]= b"IDENTITY\0";

#[derive(Serialize, Deserialize, Clone)]
pub struct Credential {
    pub secret: Vec<u8>,
    pub credential_blob: Vec<u8>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("secret", &hex::encode(&self.secret))
            .field("credential_blob", &hex::encode(&self.credential_blob))
            .finish()
    }
}

pub trait MakeCredential {
    type Error;

    fn make_credential(&self, ak_name: &[u8], credential: &[u8])
        -> Result<Credential, Self::Error>;
}

impl MakeCredential for PublicKey {
    type Error = Error;

    fn make_credential(
        &self,
        ak_name: &[u8],
        credential: &[u8],
    ) -> Result<Credential, Self::Error> {
        if !self.attributes.restricted() || !self.attributes.decrypt() {
            return Err(Error::PreconditionFailed);
        }

        let digest = self
            .name
            .message_digest()
            .ok_or(Error::PreconditionFailed)?;
        let digest_size = digest.size();

        if credential.len() > digest_size {
            return Err(Error::PreconditionFailed);
        }

        let label = IDENTITY_KEY;

        // 10.2.6.6.3 CryptSecretEncrypt()
        let mut ephemeral_key = Vec::with_capacity(digest_size);
        ephemeral_key.resize(digest_size, 0u8);

        let mut secret = Vec::with_capacity(digest_size);
        secret.resize(digest_size * 8, 0u8);

        // This is a Crypto-safe Rng according to documentation:
        // ThreadRng uses the same PRNG as StdRng for security and performance and is
        // automatically seeded from OsRng.
        // StdRng: The standard RNG. The PRNG algorithm in StdRng is chosen to be efficient on
        // the current platform, to be statistically strong and unpredictable (meaning a
        // cryptographically secure PRNG).
        thread_rng().fill(&mut ephemeral_key[..]);

        match self.key_type {
            KeyType::Rsa => {
                let rsa = Rsa::<Public>::public_key_from_der(&self.pkcs8).map_err(Error::from)?;
                let pkey = PKey::from_rsa(rsa).map_err(Error::from)?;
                let mut encrypter = Encrypter::new(&pkey).map_err(Error::from)?;
                encrypter
                    .set_rsa_padding(Padding::PKCS1_OAEP)
                    .map_err(Error::from)?;
                encrypter
                    .set_rsa_oaep_label(label)
                    .map_err(Error::from)?;
                encrypter.set_rsa_oaep_md(digest).map_err(Error::from)?;
                let size = encrypter
                    .encrypt(&ephemeral_key, &mut secret)
                    .map_err(Error::from)?;
                secret.truncate(size);
            }
            KeyType::Ecc => {
                let _ec = EcKey::public_key_from_der(&self.pkcs8).map_err(Error::from)?;
                unimplemented!("make_credentials ecc");
            }
        };

        let credential_blob = secret_to_credential(
            credential,
            ak_name,
            &ephemeral_key, 
            (digest, self.symmetric.into_cipher())
        )?;

        Ok(Credential {
            secret,
            credential_blob,
        })
    }
}

// 11.4.10.2 KDFa()
// The  Counter  mode  KDF,  from  SP800-108,  uses  HMAC  as  the pseudo-random
// function (PRF). It is referred to in the specification as KDFa().
fn kdfa(digest: MessageDigest, seed: &[u8], label: &[u8], context_u: Option<&[u8]>, context_v: Option<&[u8]>, output_len: usize) ->Result< Vec<u8>, Error> {
    let kdf = KBKDF::new(digest, label.to_vec(), seed.to_vec())
        .set_mac(Mac::Hmac)
        .set_mode(Mode::Counter)
        .set_l(true)
        .set_separator(false);

    let mut context = Vec::with_capacity(context_u.map(|c|c.len()).unwrap_or(0) + context_v.map(|c|c.len()).unwrap_or(0));
    if let Some(context_u) = context_u {
        context.extend_from_slice(context_u);
    }
    if let Some(context_v) = context_v {
        context.extend_from_slice(context_v);
    }

    let kdf = if context.len() > 0 {
        kdf.set_context(context)
    } else {
        kdf
    };

    let mut output = Vec::with_capacity(output_len);
    output.resize(output_len, 0);
    derive(kdf, &mut output)?;

    Ok(output)
}

struct SymKey(Vec<u8>);
struct HmacKey(Vec<u8>);

fn compute_hmac(digest: MessageDigest, key: &HmacKey, input: &[u8], name: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(&key.0).unwrap();

    let mut signer = Signer::new(digest, &pkey).unwrap();
    signer.update(input).unwrap();
    signer.update(name).unwrap();
    let hmac = signer.sign_to_vec().unwrap();
    hmac
}

fn encrypt_secret_to_credential(sym_alg: Cipher, sym_key: &SymKey, secret: &[u8]) -> Result<Vec<u8>, Error> {
    // Default iv is empty
    let iv = sym_alg.iv_len().map(|len| {
        let mut buf = Vec::with_capacity(len);
        buf.resize(len, 0);
        buf
    });

    encrypt(sym_alg, &sym_key.0[..], iv.as_deref(), &secret).map_err(Error::from)
}

/* 7.6.3.15 SecretToCredential() */
fn secret_to_credential(
    secret: &[u8],
    name: &[u8],
    seed: &[u8],
    protector: (MessageDigest, Cipher),
) -> Result<Vec<u8>, Error> {
    let (digest, sym_alg) = protector;
    let digest_size = digest.size();

    // Secret is encoded as:
    //   uint16(len) + secret
    let secret = {
        let out = Vec::with_capacity(secret.len()+2);
        let mut writer = Cursor::new(out);
        writer.write_all(&(secret.len() as u16).to_be_bytes()[..])?;
        writer.write_all(&secret)?;
        writer.into_inner()
    };

    let sym_key = kdfa(digest, seed, STORAGE_KEY, Some(name), None,  sym_alg.key_len()).map(SymKey)?;

    let ciphered = encrypt_secret_to_credential(sym_alg, &sym_key, &secret)?;

    // Calculate outer wrap
    let hmac_key = kdfa(digest, seed, INTEGRITY_KEY, None, None, digest.size()).map(HmacKey)?;
    let hmac = compute_hmac(digest, &hmac_key, &ciphered, name);

    // credentialblob = uint16(len hash) + hmac + cipher
    let credential_blob = Vec::with_capacity(2 + digest_size + ciphered.len());

    let mut writer = Cursor::new(credential_blob);
    writer.write_all(&(digest_size as u16).to_be_bytes()[..])?;
    writer.write_all(&hmac)?;
    writer.write_all(&ciphered)?;

    let credential_blob = writer.into_inner();

    Ok(credential_blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_kdfa() {
        let digest = MessageDigest::sha256();
        let mut seed = Vec::with_capacity(32);
        seed.resize(32, 42);
        let label = CString::new("INTEGRITY").unwrap();
        let out = kdfa(MessageDigest::sha256(), &seed, label.as_bytes_with_nul(), None, None, digest.size()).unwrap();
        assert_eq!(
            hex::encode(out),
            "37138b53de688c51521273053873b3e1008da43cbfcc1d1a88b7be9ba48f55f6"
        );
    }

    #[test]
    fn test_hmac() {
        let key = HmacKey(vec![
            0x37, 0x13, 0x8b, 0x53, 0xde, 0x68, 0x8c, 0x51, 0x52, 0x12, 0x73, 0x5, 0x38, 0x73,
            0xb3, 0xe1, 0x0, 0x8d, 0xa4, 0x3c, 0xbf, 0xcc, 0x1d, 0x1a, 0x88, 0xb7, 0xbe, 0x9b,
            0xa4, 0x8f, 0x55, 0xf6,
        ]);
        let input = vec![42; 128];
        let name = vec![10; 32];
        let out = compute_hmac(MessageDigest::sha256(), &key, &input, &name);

        assert_eq!(
            hex::encode(out),
            "e8e6166c49a445264899c8d483fbedeef26959646523b41f3894ec14a072af16"
        );
    }

    #[test]
    fn test_secret_to_credential() {
        let secret = vec![42; 21];
        let name = vec![10; 16];
        let seed = vec![42; 32];

        let hash = MessageDigest::sha256();
        let cipher = Cipher::aes_128_cfb128();

        let out = secret_to_credential(&secret, &name, &seed, (hash, cipher)).unwrap();

        assert_eq!(
            hex::encode(out), 
            "002004f47cfb6481d980884cb6b54ce9a963c75be97359ea7cdc14c64f99581deaa647a547e1176d1717cbe10d8458dc244e56c51104ab5274"
            );
    }
}
