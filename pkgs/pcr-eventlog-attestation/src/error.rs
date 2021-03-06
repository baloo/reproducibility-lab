use std::{
    error::Error as StdError,
    fmt::{self, Display},
    io::Error as IoError,
};

use openssl::{error::ErrorStack, kdf::KDFError};
use tonic::Status;
use tss_esapi::Error as TssError;

#[derive(Debug)]
pub enum Error {
    Tss(TssError),
    Ssl(ErrorStack),
    Kdf(KDFError),
    UnsupportedCurve,
    PreconditionFailed,
    Io(IoError),
    Cbor(serde_cbor::Error),
    Tonic(tonic::transport::Error),
    TonicClient(tonic::Status),
    Utf8(std::string::FromUtf8Error),
    InvalidPath,
    ParseError,
}

macro_rules! error_from {
    ($t:ty, $i:expr) => {
        impl From<$t> for Error {
            fn from(e: $t) -> Self {
                $i(e)
            }
        }
    };
}

error_from!(ErrorStack, Error::Ssl);
error_from!(KDFError, Error::Kdf);
error_from!(TssError, Error::Tss);
error_from!(IoError, Error::Io);
error_from!(serde_cbor::Error, Error::Cbor);
error_from!(tonic::transport::Error, Error::Tonic);
error_from!(tonic::Status, Error::TonicClient);
error_from!(std::string::FromUtf8Error, Error::Utf8);

impl Into<Status> for Error {
    fn into(self) -> Status {
        use Error::*;
        match self {
            Ssl(_) => Status::internal("SSL api failure"),
            Tss(_) => Status::internal("TSS api failure"),
            Kdf(_) => Status::internal("KDF api failure"),
            UnsupportedCurve => Status::failed_precondition("Unsupported ECC Curve"),
            PreconditionFailed => Status::failed_precondition("Precondition failed"),
            Io(_) => Status::internal("Io error"),
            Cbor(_) => Status::internal("cbor error"),
            Tonic(_) => Status::internal("transport error"),
            TonicClient(_) => Status::internal("client error"),
            Utf8(_) => Status::internal("invalid utf8 sequence"),
            InvalidPath => Status::internal("invalid path"),
            ParseError => Status::internal("parse error"),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            Tss(ref e) => write!(f, "Error::Tss({})", e),
            Ssl(ref e) => write!(f, "Error::Ssl({})", e),
            Kdf(ref e) => write!(f, "Error::Kdf({})", e),
            UnsupportedCurve => write!(f, "Error::UnsupportedCurve"),
            PreconditionFailed => write!(f, "Error::PreconditionFailed"),
            Io(ref e) => write!(f, "Error::Io({})", e),
            Cbor(ref e) => write!(f, "Error::Cbor({})", e),
            Tonic(ref e) => write!(f, "Error::Tonic({})", e),
            TonicClient(ref e) => write!(f, "Error::TonicClient({})", e),
            Utf8(ref e) => write!(f, "Error::Utf8({})", e),
            InvalidPath => write!(f, "Error::InvalidPath"),
            ParseError => write!(f, "Error::ParseError"),
        }
    }
}

impl StdError for Error {}

#[derive(Debug)]
pub enum ValidationError {
    NonceMismatch {
        expected: Vec<u8>,
        received: Vec<u8>,
    },
    UnexpectedPCR,
    EndorsementKeyMismatch,
    CertificationChainBroken,
    ProofMismatch,
    ImageChecksumMismatch,
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ValidationError::*;
        match self {
            NonceMismatch { expected, received } => write!(
                f,
                "Validation Error: Nonce mismatch. expected {}, received {}",
                hex::encode(expected),
                hex::encode(received)
            ),
            UnexpectedPCR => write!(f, "Validation Error: PCR in quote does not match eventlog"),
            EndorsementKeyMismatch => write!(
                f,
                "Validation Error: Endorsement key does not match Endorsement certificate"
            ),
            CertificationChainBroken => write!(f, "Validation Error: Could not validate Endorsement certificated against a known root certificate"),
            ProofMismatch => write!(f, "Validation Error: Attestor could not prove possession of the secret"),
            ImageChecksumMismatch => write!(f, "Validation Error: Image checksum mismatch. The image could not be rebuilt from reference repository"),
        }
    }
}
