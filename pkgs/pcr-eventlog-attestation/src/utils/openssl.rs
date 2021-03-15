use openssl::x509::X509;

pub fn der_to_x509(input: &[u8]) -> X509 {
    X509::from_der(input).unwrap()
}
