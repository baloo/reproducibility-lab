use openssl::{
    hash::MessageDigest,
    pkey::{PKeyRef, Public},
    rsa::Padding,
    sign::Verifier,
};
use tss_esapi::utils::AsymSchemeUnion;

use crate::error::Error;

pub fn verify_quote(
    ak_pub: &PKeyRef<Public>,
    quote: &[u8],
    // TODO: meh, the AsymSchemeUnion is not great, can we use some standard here?
    quote_signature: (AsymSchemeUnion, &[u8]),
) -> Result<(), Error> {
    // TODO: quite a lot of hard coded schemes here
    let mut v = Verifier::new(MessageDigest::sha256(), ak_pub)?;
    v.set_rsa_padding(Padding::PKCS1_PSS)?;
    v.update(quote)?;
    v.verify(quote_signature.1)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::key::TpmPublic;
    use std::convert::TryFrom;
    use tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256;
    use tss_esapi::utils::AsymSchemeUnion;

    const MANUFACTURER: &str = r#"
-----BEGIN CERTIFICATE-----
MIIFGzCCAwOgAwIBAgIUMYdUtDSM20AcGW+qc0tW1aC+s/QwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSZHVtbXkgbWFudWZhY3R1cmVyMB4XDTIxMDIyMjA0NDMy
OFoXDTMwMTEyMjA0NDMyOFowHTEbMBkGA1UEAwwSZHVtbXkgbWFudWZhY3R1cmVy
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApsq5s6OSRMvixClKxSvj
Vp9lAuWGwUFtpkv+9S1PKLAINKTt5VL0c1A3CvGqDHrDdC/I4h/xQnlWCq3cCAwu
VYOnbZYbTppqJxyrwAogSuQxYptuS8wGyN/pRVll5KZ9MWs8I/Iqk6hTPY9hUhMi
Iqng4ptjI8DPhC8qX9wlhUpPqoRGVN3xPWW4R8eKOJlzcHA7Ag/reUFDXcIa6q5m
+Ht8UJ9R2b5viBoVwVEm413ByCaYY8F9hN7SHWfGo39ZnjIqtvFxZsbje34L/26A
HfdP+AvOq8obbnlcinMH2RMw0aQWY0EQQxEseS4lb5y64o32F4B7n7kjE1hOjJnl
o/MjEYk9idUo7oiqW2qbWuzFXR9JOQhUoG8iDrxkOMMG3sMgHNElSR6rhlwRtRmB
X2MXiF6mkZq9HkuM1iejBFNhmP2Sd+jyT8HIz5c0qqIpGlc9L1R7yG60AH9q4xZN
Sm5jAmi2VnGSrcUSYKu8BQ2JUWk+05SSb5aFhV8WNv3Tf+GQ61HVgY/swtDSbxXk
humbnJxFnC20rM2gXhZNYROAHQZ35ZSnfDi8aBEYPPzRwl5xuBYVzidzcDu4wlNG
VgfMstG4r4OpOAqFwarkT/eN+pICv/N0w4d4ele+ze2s/bTZmwUXOS3PY/3poOgL
16q3Uxki6MXZ9QLl/VuK0x8CAwEAAaNTMFEwHQYDVR0OBBYEFHFPzbR9tlBhiAqn
EhPd6kzDn4JuMB8GA1UdIwQYMBaAFHFPzbR9tlBhiAqnEhPd6kzDn4JuMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAB+WLhxO5xCI2mC8iI69k6+d
H4+kBAVIr1e2vvXCtszVbwd3SaHv4T8kOtgdSr7t/FaplzEIEdyNb36SZ+kCcJ0S
BZALcXUxWfjmBMnqMVFWrZeC5/LuLcfTkSPeESlG1n6ukrxaeGQVCRWeCiIuiaNj
FJjiwjoIH60lkVY0Q/zgUjCkVGhf5ODg+O2wRD3TDmeHO5v2SThYlXK/9/RhXIE2
JECWnYCASirPiLNqMjbRftDWwnzRpTKDEEwzJkURC9AQt+txjtZkTP6rm5aErZqd
IedygT4gAnjg1x/QxBWEf6Y+h57fKS7nRF+7t3Uwj8EEqWdGVHEoAXASTX8PtCqD
5bBfjcp5Q/w3rjYpzZPnBWMiqn4jcHwYOCxO28GNV4+oruWh0me3ob6rWiilQerl
uzUYqW7ncnN3mTva+4rDl1FHealrQUtZGHMoC98s5OBPRLNcl8yg01EY9eTJXSTn
0tHGCqK/nilgLrli2vVF7ryEGAbRoHAUWKPXvPU67YlfCB1RXlvznWDchVXMXFyn
0eb+JvsgkgoABls6WWL/hPGp5uLW9WDIQiEqCNOzU4sLCS9p4YJ0k8VIKB2YvITL
a99yQit1vyEk/bbG2fCL3Dvqt5Yz0tJN043YQXDhHRGuz8YgevwkUt/I+N1MwtfM
XlBI/PDlx6Vv7i5Gac/M
-----END CERTIFICATE-----"#;

    const EK_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIEeDCCAmCgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDDBJkdW1t
eSBtYW51ZmFjdHVyZXIwHhcNMjEwMjI2MTczOTAyWhcNMzEwMjI0MTczOTAyWjAS
MRAwDgYDVQQDEwd1bmtub3duMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAwenpJzgajZlIe7RZNx9t35uhZnqOnQtGmRMGO1GWrNcnzWPKEO540sOQtdgs
sKDzivhXX5uIFWsscIuk2K8sFiVwNfP7QwVs0aisjFz7VkULfiaPvl4zrOWa4JJ7
RGcnY2D6/yMhkUPCy+WkxPJVIe3XCDQxzCDUyyGNpqJ4rOo58CA2CQs+0PSEjlqB
/8tiXZQQYlmQHSIuTHhYUvTsG11JC7iOtug1LbY0a0j5G4AxS9qmV61y4EvNWRxm
8fwpB1DwSMhw9Hov7ni1COqoVaqssQUkuthCX5hCgaZyx+lz9UJXUA5WOgN2YdLv
E4q4m7oOtQsOHBHeVSSYI0G0hwIDAQABo4HNMIHKMBAGA1UdJQQJMAcGBWeBBQgB
MFIGA1UdEQEB/wRIMEakRDBCMRYwFAYFZ4EFAgEMC2lkOjAwMDAxMDE0MRAwDgYF
Z4EFAgIMBXN3dHBtMRYwFAYFZ4EFAgMMC2lkOjIwMTkxMDIzMAwGA1UdEwEB/wQC
MAAwIgYDVR0JBBswGTAXBgVngQUCEDEOMAwMAzIuMAIBAAICAKIwHwYDVR0jBBgw
FoAUcU/NtH22UGGICqcSE93qTMOfgm4wDwYDVR0PAQH/BAUDAwcgADANBgkqhkiG
9w0BAQsFAAOCAgEAJiNpIL0jZZ5Gg3CnXaIzG0ViTEkRNMxY9o+K6Ef+KkAJ/V6r
LSCyH5Xz4Jezg2d3sw2T03iasYKVESK3yqjXOPDtX5sqhnTIWPNsz+HCckAwIkLB
KO8GZUXb//dMu+JsYsSaaDhxzs6bN/phOhunBc72U7AfejoKYQZjPTlPyPS/yTNw
UI5eLAzRgySTrvzMKCiEioW6Y4ra33O8ZFzyOaBncRiwxwHmEs1Px97V5L90i9Qv
RIt6dGnDmniNQ1oKSrrFJ2zL5C/CGgw5oHloLQB1dGE44+ltYExRx9Fn7FmwO+pI
W0i4Jao3GNpHOJR0bo5H4kcVrwTpXzxx7hH7NlAsp7Rb1fQND+uLaQEtfnlOHaJ0
UmgLvWA5wAowHflaj6/vVwWMueBmGAbOi5AGiwBIRtLARzD86iLOPQSEdKSXGeXo
2eFV7KR7CNnjlWkPzrAeYXK/BRxVUdQQLHLZ4sRfYRCA7tX11ABia9agWrEfoyta
IPl2TagiedCfOnJE1RgbotxirxhKyM/7FTUYzLgHYr23dYjkUCB5fIg83Uh5Dm31
1xkt4x65oHiSIHt06MeuU3ifd3YJgDye5W1/0PMhuRRMkHjshKmM9DVxKOdsdF2J
8QHR4//mrebzzYnXJilkGbkloYPAYVRCnDLmXu+D9aIsOpX6WDuO6p8qviU=
-----END CERTIFICATE-----"#;

    const EK_PUB: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArbBTUOX00KTGc2wNoKtX
pc/QE1LU1ZTUsmUQL0EjmyFMYvUnsPxU4F9Y4qsIR/DwFhHaIw+ycxnT3x2a6QRy
1MFkDwQ3SQ4GTNEIIKszfdA4OqrgjWmtEQrjkbqTf0jYV7GQa5BDoUfL1dQbCc8I
D/Ue+7eU6KRkb0Bhxtuo6vIjSs3pf890yKIr0dcrwSM5FqraEECYqtAlRI6Dj0LO
dvMA3aVCf3HwAYfdQFBHO10w7CzTI9ZpZgzl1YrqeOy/hW4sB+iBGv8dzCvm1JqA
sQulcA46NYohakgamn80Pdfif43js80cn6xkNcP9b5uk2n4z2YgpPcgbXCNwLFki
3QIDAQAB
-----END PUBLIC KEY-----"#;

    const AK_PUB: &[u8] = &[]; // TODO

    const QUOTE: &[u8] = &[
        0xff, 0x54, 0x43, 0x47, 0x80, 0x18, 0x0, 0x22, 0x0, 0xb, 0xdc, 0xba, 0x11, 0x90, 0x22,
        0x3b, 0x92, 0x5f, 0xfd, 0xed, 0x18, 0xca, 0xbd, 0xb2, 0x6f, 0xad, 0xb2, 0x60, 0x78, 0xd4,
        0x5b, 0x36, 0x60, 0xaa, 0x17, 0x1e, 0x11, 0xe6, 0x60, 0x4a, 0x79, 0x9b, 0x0, 0x10, 0x0,
        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0, 0x0, 0x0,
        0x0, 0x0, 0xed, 0x87, 0xa4, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x1, 0x20, 0x19, 0x10,
        0x23, 0x0, 0x16, 0x36, 0x36, 0x0, 0x0, 0x0, 0x1, 0x0, 0xb, 0x3, 0x10, 0x0, 0x0, 0x0, 0x20,
        0x36, 0x30, 0x2d, 0xd4, 0x67, 0x7a, 0x8b, 0xe, 0xe7, 0xc0, 0x75, 0xe0, 0x7a, 0xcb, 0xfb,
        0xe, 0x98, 0x3a, 0x2b, 0x90, 0x9c, 0x35, 0x98, 0xc6, 0x3e, 0x8b, 0x5a, 0x14, 0x77, 0x83,
        0x3b, 0x9f,
    ];
    const QUOTE_SIGNATURE: (AsymSchemeUnion, &[u8]) = (
        AsymSchemeUnion::RSAPSS(Sha256),
        &[
            0x2d, 0x97, 0x4c, 0x8a, 0x32, 0xb4, 0xbe, 0x83, 0xa9, 0xb5, 0xf1, 0xe0, 0x5, 0x53,
            0x51, 0x48, 0xde, 0xc6, 0xf1, 0xc, 0x34, 0xc6, 0xfc, 0x14, 0x24, 0xff, 0xe8, 0x8c,
            0x96, 0x29, 0x36, 0x75, 0xad, 0xaa, 0x4b, 0x19, 0xaf, 0x5b, 0x4c, 0x3d, 0xaf, 0xf9,
            0xc3, 0x84, 0x27, 0xb, 0x26, 0xef, 0x3e, 0xe3, 0xe7, 0xa7, 0x4b, 0x49, 0xd1, 0xb8,
            0x47, 0xb5, 0xa3, 0xd0, 0x84, 0x2f, 0xd0, 0xb6, 0x89, 0x4f, 0x56, 0xb8, 0x34, 0xed,
            0xe2, 0x53, 0xdf, 0x49, 0x9a, 0xea, 0xe6, 0x73, 0x52, 0xed, 0x11, 0xd9, 0xf, 0x56,
            0x23, 0x79, 0x94, 0xc1, 0xbd, 0xc, 0xec, 0x5c, 0x13, 0xdb, 0xaf, 0x51, 0x45, 0x7, 0x93,
            0x19, 0x54, 0x5b, 0xa2, 0x35, 0xb8, 0x8a, 0x33, 0xd0, 0x77, 0x6f, 0x59, 0x8e, 0xdb,
            0x85, 0x5b, 0x51, 0x88, 0x80, 0x6e, 0xbe, 0x4f, 0x63, 0x52, 0x2e, 0x3d, 0x5e, 0x99,
            0xd4, 0x26, 0x34, 0x1, 0xe7, 0x79, 0x22, 0x3b, 0x90, 0xf8, 0x9f, 0x35, 0xfa, 0x5d,
            0xdc, 0x70, 0xa9, 0x7c, 0x91, 0xf5, 0x1a, 0xc2, 0x8, 0xfc, 0x24, 0x11, 0xad, 0xb7,
            0x6d, 0x70, 0x93, 0x82, 0xef, 0x23, 0x84, 0xa8, 0x9a, 0x6d, 0x7a, 0x81, 0x2, 0x4, 0x4e,
            0xb6, 0x5a, 0xd0, 0xb4, 0x1d, 0xf3, 0x88, 0xe6, 0xaf, 0xe6, 0x34, 0xdf, 0xfc, 0x7b,
            0x4, 0xf5, 0x44, 0x3b, 0x42, 0x54, 0x6e, 0x1d, 0xa8, 0x9e, 0xb4, 0xf6, 0xf4, 0xd7,
            0xb7, 0xa0, 0x29, 0x2a, 0xa8, 0xff, 0xbc, 0x29, 0xa8, 0x3c, 0xd8, 0xb8, 0x40, 0x27,
            0x67, 0x5d, 0xa1, 0xbd, 0xa0, 0x6c, 0xed, 0xfb, 0xfa, 0x9d, 0x86, 0xd1, 0xaf, 0xa8,
            0x4e, 0x29, 0x43, 0x9d, 0xac, 0x85, 0x42, 0x35, 0xd2, 0x90, 0xcd, 0xea, 0xf, 0xd3,
            0xec, 0xb5, 0x5f, 0x17, 0xf, 0x9e, 0x72, 0x69, 0x8d, 0x23, 0x64, 0x2a, 0x36, 0xfb,
            0xc3, 0xde,
        ],
    );

    #[test]
    fn quote() {
        let ak_pub = TpmPublic::try_from(AK_PUB).expect("parse public attestation key");
        verify_quote(
            ak_pub
                .pkey()
                .expect("create openssl pkey from tpm_public")
                .as_ref(),
            QUOTE,
            QUOTE_SIGNATURE,
        )
        .expect("verify signature");
    }
}
