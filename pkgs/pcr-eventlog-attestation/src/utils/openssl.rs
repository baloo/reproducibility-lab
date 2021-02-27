use openssl::{bn::BigNum, pkey::Public, rsa::Rsa, x509::X509};
use tss_esapi::{constants::tss::TPM2_ALG_RSA, tss2_esys::TPM2B_PUBLIC};

pub unsafe fn tpm_public_to_public_rsa(public: &TPM2B_PUBLIC) -> Rsa<Public> {
    assert!(public.publicArea.type_ == TPM2_ALG_RSA);

    let exponent = public.publicArea.parameters.rsaDetail.exponent;
    // This is the default value, which means 2^16+1
    let exponent = if exponent == 0 {
        2_u32.pow(16) + 1
    } else {
        exponent
    };

    let exponent = BigNum::from_u32(exponent).unwrap();
    let ref rsa = public.publicArea.unique.rsa;
    let n = BigNum::from_slice(&rsa.buffer[..rsa.size as usize]).unwrap();

    let rsa = Rsa::<Public>::from_public_components(n, exponent);

    rsa.unwrap()
}

pub fn der_to_x509(input: &[u8]) -> X509 {
    X509::from_der(input).unwrap()
}
