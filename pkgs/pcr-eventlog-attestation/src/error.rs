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
        }
    }
}

impl StdError for Error {}
