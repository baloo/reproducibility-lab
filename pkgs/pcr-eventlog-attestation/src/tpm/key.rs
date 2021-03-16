use std::{
    convert::{TryFrom, TryInto},
    fmt,
    io::{Cursor, Write},
};

use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public},
    rsa::Rsa,
    symm,
};
use serde::{
    de::{self, Deserializer, Visitor},
    ser::{Error as SerError, Serializer},
    Deserialize, Serialize,
};
use sha2::{Digest as Sha2Digest, Sha256};
use tss_esapi::{
    attributes::ObjectAttributes,
    constants::tss::{
        TPM2_ALG_ECC, TPM2_ALG_RSA, TPM2_ECC_BN_P256, TPM2_ECC_BN_P638, TPM2_ECC_NIST_P192,
        TPM2_ECC_NIST_P224, TPM2_ECC_NIST_P256, TPM2_ECC_NIST_P384, TPM2_ECC_NIST_P521,
        TPM2_ECC_SM2_P256,
    },
    interface_types::algorithm::HashingAlgorithm,
    tss2_esys::{
        size_t, Tss2_MU_TPM2B_PUBLIC_Marshal, Tss2_MU_TPM2B_PUBLIC_Unmarshal,
        Tss2_MU_TPMT_PUBLIC_Marshal, TPM2B_PUBLIC, TPMA_OBJECT, TPMI_ECC_CURVE,
    },
    Error as TssError, WrapperErrorKind,
};

use crate::error::Error;

fn tpm_ecc_curve_to_openssl(curve: TPMI_ECC_CURVE) -> Result<Nid, Error> {
    match curve {
        c if c == TPM2_ECC_NIST_P192 => Ok(Nid::X9_62_PRIME192V1),
        c if c == TPM2_ECC_NIST_P224 => Ok(Nid::SECP224R1),
        c if c == TPM2_ECC_NIST_P256 => Ok(Nid::X9_62_PRIME256V1),
        c if c == TPM2_ECC_NIST_P384 => Ok(Nid::SECP384R1),
        c if c == TPM2_ECC_NIST_P521 => Ok(Nid::SECP521R1),
        // TODO: find the openssl equivalent of those curve
        c if c == TPM2_ECC_BN_P256 => Err(Error::UnsupportedCurve),
        c if c == TPM2_ECC_BN_P638 => Err(Error::UnsupportedCurve),
        c if c == TPM2_ECC_SM2_P256 => Err(Error::UnsupportedCurve),
        _ => Err(Error::UnsupportedCurve),
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Copy)]
pub enum KeyType {
    Rsa,
    Ecc,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub key_type: KeyType,
    #[serde(with = "HashingAlgorithmDef")]
    pub name: HashingAlgorithm,
    #[serde(with = "ObjectAttributesDef")]
    pub attributes: ObjectAttributes,
    pub symmetric: Cipher,
    pub auth_policy: Vec<u8>,
    // DER-encoded
    pub pkcs8: Vec<u8>,
}

impl PublicKey {
    pub fn to_pkey(&self) -> Result<PKey<Public>, Error> {
        Ok(PKey::public_key_from_der(&self.pkcs8)?)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pem = match self.key_type {
            KeyType::Rsa => {
                let rsa =
                    Rsa::<Public>::public_key_from_der(&self.pkcs8).map_err(|_| fmt::Error)?;
                rsa.public_key_to_pem().map_err(|_| fmt::Error)?
            }
            KeyType::Ecc => {
                let ec = EcKey::public_key_from_der(&self.pkcs8).map_err(|_| fmt::Error)?;
                ec.public_key_to_pem().map_err(|_| fmt::Error)?
            }
        };
        let pem = String::from_utf8_lossy(&pem);
        f.debug_struct("PublicKey")
            .field("key_type", &self.key_type)
            .field("name", &self.name)
            .field("attributes", &self.attributes)
            .field("auth_policy", &hex::encode(&self.auth_policy))
            .field("pkcs8", &hex::encode(&self.pkcs8))
            .field("pem", &pem)
            .finish()
    }
}

impl TryFrom<&TPM2B_PUBLIC> for PublicKey {
    type Error = Error;

    fn try_from(tpm2b_public: &TPM2B_PUBLIC) -> Result<Self, Self::Error> {
        let ref public = tpm2b_public.publicArea;

        let name = HashingAlgorithm::try_from(public.nameAlg)?;
        let attributes = ObjectAttributes(public.objectAttributes);
        let mut auth_policy = Vec::with_capacity(public.authPolicy.size as usize);
        auth_policy.extend_from_slice(&public.authPolicy.buffer[..public.authPolicy.size as usize]);

        let (key_type, pkcs8) = unsafe {
            match public.type_ {
                t if t == TPM2_ALG_RSA => {
                    let exponent = public.parameters.rsaDetail.exponent;
                    // This is the default value, which means 2^16+1
                    let exponent = if exponent == 0 {
                        2_u32.pow(16) + 1
                    } else {
                        exponent
                    };

                    let exponent = BigNum::from_u32(exponent)?;
                    let ref rsa = public.unique.rsa;
                    let n = BigNum::from_slice(&rsa.buffer[..rsa.size as usize])?;

                    let rsa = Rsa::<Public>::from_public_components(n, exponent)?;
                    (KeyType::Rsa, rsa.public_key_to_der()?)
                }
                t if t == TPM2_ALG_ECC => {
                    let ref ecc = public.unique.ecc;
                    let group = public.parameters.eccDetail.curveID;
                    let group = tpm_ecc_curve_to_openssl(group)?;
                    let group = EcGroup::from_curve_name(group)?;
                    let x = BigNum::from_slice(&ecc.x.buffer[..ecc.x.size as usize])?;
                    let y = BigNum::from_slice(&ecc.y.buffer[..ecc.y.size as usize])?;
                    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
                    // TODO: I believe the curve is encoded in the DER. check that.
                    (KeyType::Ecc, key.public_key_to_der()?)
                }
                _ => Err(TssError::WrapperError(WrapperErrorKind::UnsupportedParam))?,
            }
        };

        // Cipher is defined by each member of the TPMT_PUBLIC->parameters union members
        // it is also made available in a "generic" symDetail which is common amongst rsa/ecc
        let symmetric = unsafe {
            let sym_alg = public.parameters.symDetail.sym.algorithm;
            let bits = public.parameters.symDetail.sym.keyBits.sym;
            match sym_alg {
                0x06 => match bits {
                    128 => Ok(symm::Cipher::aes_128_cfb128()),
                    192 => Ok(symm::Cipher::aes_192_cfb128()),
                    256 => Ok(symm::Cipher::aes_256_cfb128()),
                    _ => Err(TssError::WrapperError(WrapperErrorKind::UnsupportedParam)),
                },
                _ => Err(TssError::WrapperError(WrapperErrorKind::UnsupportedParam)),
            }
        }?;
        let symmetric = Cipher(symmetric);

        Ok(Self {
            key_type,
            name,
            attributes,
            auth_policy,
            symmetric,
            pkcs8,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "HashingAlgorithm")]
enum HashingAlgorithmDef {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Null,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ObjectAttributes")]
struct ObjectAttributesDef(TPMA_OBJECT);

#[derive(Clone)]
pub struct Cipher(symm::Cipher);

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Cipher")
            .field(&self.0.nid().as_raw())
            .finish()
    }
}

impl Cipher {
    pub fn into_cipher(&self) -> symm::Cipher {
        self.0.clone()
    }
}

impl Serialize for Cipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i32(self.0.nid().as_raw())
    }
}

impl<'de> Deserialize<'de> for Cipher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CipherVisitor;

        macro_rules! visit_impl {
            ($name:ident, $t:ty) => {
                fn $name<E>(self, value: $t) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    let nid = Nid::from_raw(value as i32);
                    symm::Cipher::from_nid(nid).ok_or_else(|| {
                        E::custom(format!("nid {} is not a valid cipher", nid.as_raw()))
                    })
                }
            };
            ($name:ident, $t:ty, $transform:expr) => {
                fn $name<E>(self, value: $t) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    let nid = $transform(value)
                        .map(Nid::from_raw)
                        .map_err(|_| E::custom(format!("nid {} is not a valid value", value)))?;
                    symm::Cipher::from_nid(nid).ok_or_else(|| {
                        E::custom(format!("nid {} is not a valid cipher", nid.as_raw()))
                    })
                }
            };
        }

        impl<'de> Visitor<'de> for CipherVisitor {
            type Value = symm::Cipher;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an integer between -2^31 and 2^31")
            }

            visit_impl!(visit_i8, i8);
            visit_impl!(visit_i16, i16);
            visit_impl!(visit_i32, i32);
            visit_impl!(visit_i64, i64, |v: i64| v.try_into());
            visit_impl!(visit_u8, u8);
            visit_impl!(visit_u16, u16);
            visit_impl!(visit_u32, u32, |v: u32| v.try_into());
            visit_impl!(visit_u64, u64, |v: u64| v.try_into());
        }
        let cipher = deserializer.deserialize_i32(CipherVisitor)?;
        Ok(Self(cipher))
    }
}

pub trait OpensslHash {
    fn message_digest(&self) -> Option<MessageDigest>;
}

impl OpensslHash for HashingAlgorithm {
    fn message_digest(&self) -> Option<MessageDigest> {
        use HashingAlgorithm::*;
        match self {
            Sha1 => Some(MessageDigest::sha1()),
            Sha256 => Some(MessageDigest::sha256()),
            Sha384 => Some(MessageDigest::sha384()),
            Sha512 => Some(MessageDigest::sha512()),
            Sha3_256 => Some(MessageDigest::sha3_256()),
            Sha3_384 => Some(MessageDigest::sha3_384()),
            Sha3_512 => Some(MessageDigest::sha3_512()),
            Null => Some(MessageDigest::null()),
            Sm3_256 => None,
        }
    }
}

#[allow(missing_debug_implementations, missing_copy_implementations)]
#[derive(Clone)]
pub struct TpmPublic(pub TPM2B_PUBLIC);

impl TpmPublic {
    // Assuming this is a transient object (which in this context it is!)
    // see:
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf
    // 16 Names
    pub fn name(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity((self.0.size) as usize);
        buf.resize((self.0.size) as usize, 0u8);

        let mut written = 0;

        let rc = unsafe {
            Tss2_MU_TPMT_PUBLIC_Marshal(
                &self.0.publicArea,
                buf.as_mut_ptr(),
                buf.len() as size_t,
                &mut written,
            )
        };
        if rc != 0 {
            return Err(Error::PreconditionFailed); // TODO not the best error here
        }

        buf.truncate(written as usize);

        // TODO: read the hash type from the TPM2B_PUBLIC itself
        let mut hasher = Sha256::new();
        hasher.write_all(&buf).expect("unable to write hash");
        let hash = hasher.finalize_reset();

        let out = Vec::with_capacity(2 + hash.len());
        let mut out = Cursor::new(out);

        // name = uint16(hash_alg) + hash
        // TODO: get the proper hash alg, this is the sha256 value hardcoded
        out.write_all(&[0x00, 0x0b])?;
        out.write_all(&hash)?;

        Ok(out.into_inner())
    }

    pub fn pkey(&self) -> Result<PKey<Public>, Error> {
        let ref public = self.0.publicArea;
        let pkey = match public.type_ {
            alg if alg == TPM2_ALG_RSA => unsafe {
                let exponent = public.parameters.rsaDetail.exponent;
                // This is the default value, which means 2^16+1
                let exponent = if exponent == 0 {
                    2_u32.pow(16) + 1
                } else {
                    exponent
                };

                let exponent = BigNum::from_u32(exponent)?;
                let ref rsa = public.unique.rsa;
                let n = BigNum::from_slice(&rsa.buffer[..rsa.size as usize])?;

                let rsa = Rsa::<Public>::from_public_components(n, exponent)?;
                PKey::from_rsa(rsa)?
            },
            _ => unimplemented!("unimplemented key alg"),
        };
        Ok(pkey)
    }
}

impl Default for TpmPublic {
    fn default() -> Self {
        Self(TPM2B_PUBLIC::default())
    }
}

impl From<TPM2B_PUBLIC> for TpmPublic {
    fn from(t: TPM2B_PUBLIC) -> Self {
        Self(t)
    }
}

/// Provide an implementation to convert from a TPM2B_PUBLIC slice to TpmPublic
impl TryFrom<&[u8]> for TpmPublic {
    type Error = Error;
    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let mut out = TpmPublic::default();
        let mut offset = 0;

        let rc = unsafe {
            Tss2_MU_TPM2B_PUBLIC_Unmarshal(s.as_ptr(), s.len() as size_t, &mut offset, &mut out.0)
        };
        if rc != 0 {
            return Err(Error::PreconditionFailed);
        }
        if offset != s.len() as size_t {
            // Extra data in the slice, this is not expected
            return Err(Error::PreconditionFailed);
        }

        Ok(out)
    }
}

impl Serialize for TpmPublic {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut buf = Vec::with_capacity((self.0.size + 2) as usize);
        buf.resize((self.0.size + 2) as usize, 0u8);

        let mut written = 0;
        let rc = unsafe {
            Tss2_MU_TPM2B_PUBLIC_Marshal(
                &self.0,
                buf.as_mut_ptr(),
                buf.len() as size_t,
                &mut written,
            )
        };
        if rc != 0 {
            return Err(S::Error::custom("unable to serialize TPM2B_PUBLIC struct"));
        }

        buf.truncate(written as usize);

        serializer.serialize_bytes(&buf)
    }
}

impl<'de> Deserialize<'de> for TpmPublic {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SliceVisitor;

        impl<'de> Visitor<'de> for SliceVisitor {
            type Value = TpmPublic;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an slice of bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut out = TpmPublic(TPM2B_PUBLIC::default());
                let mut written = 0;

                let rc = unsafe {
                    Tss2_MU_TPM2B_PUBLIC_Unmarshal(
                        value.as_ptr(),
                        value.len() as size_t,
                        &mut written,
                        &mut out.0,
                    )
                };
                if rc != 0 {
                    return Err(E::custom("unable to deserialize TPM2B_PUBLIC struct"));
                }

                Ok(out)
            }
        }

        deserializer.deserialize_bytes(SliceVisitor)
    }
}
