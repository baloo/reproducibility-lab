// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf

use std::io::Write;

use nom::{
    bytes::complete::{tag, take},
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    IResult,
};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::Error;

const TPM_GENERATED_MAGIC: &[u8] = &[0xff, 0x54, 0x43, 0x47]; // 0xFF TCG
                                                              // 6.9 TPM_ST (Structure Tags)
const TPM_ST_ATTEST_QUOTE: &[u8] = &[0x80, 0x18];

// 10.5.3 TPM2B_NAME
struct Name;

impl Name {
    fn read(input: &[u8]) -> IResult<&[u8], &[u8]> {
        println!("baloo input={:x?}", input);
        let (i, size) = be_u16(input)?;
        println!("baloo size={}", size);
        let (i, name) = take(size as usize)(i)?;

        Ok((i, name))
    }
}

// 10.4.3 TPM2B_DATA
struct Data;

impl Data {
    fn read(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let (i, size) = be_u16(input)?;
        let (i, data) = take(size as usize)(i)?;

        Ok((i, data))
    }
}

// 9.2 TPMI_YES_NO
struct YesNo;
impl YesNo {
    fn read(input: &[u8]) -> IResult<&[u8], bool> {
        let (i, value) = be_u8(input)?;
        match value {
            0 => Ok((i, false)),
            1 => Ok((i, true)),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
        }
    }
}

// 10.11.1 TPMS_CLOCK_INFO
#[derive(Debug)]
pub struct ClockInfo {
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    safe: bool,
}

impl ClockInfo {
    fn read(input: &[u8]) -> IResult<&[u8], ClockInfo> {
        let (i, clock) = be_u64(input)?;
        let (i, reset_count) = be_u32(i)?;
        let (i, restart_count) = be_u32(i)?;
        let (i, safe) = YesNo::read(i)?;

        Ok((
            i,
            ClockInfo {
                clock,
                reset_count,
                restart_count,
                safe,
            },
        ))
    }
}

// 10.6.2 TPMS_PCR_SELECTION
#[derive(Debug)]
struct PCRSelection {
    hash: u16, // 0x0b == sha256 0x04 == sha1
    bitmap: Vec<u8>,
}

impl PCRSelection {
    fn read(input: &[u8]) -> IResult<&[u8], Vec<PCRSelection>> {
        let (i, count) = be_u32(input)?;
        let mut out = Vec::with_capacity(count as usize);
        let mut rest = i;
        for _ in 0..(count as usize) {
            let (i, hash) = be_u16(rest)?;
            let (i, size_of_select) = be_u8(i)?;
            let (i, bitmap) = take(size_of_select as usize)(i)?;
            let bitmap = bitmap.to_vec();

            out.push(PCRSelection { hash, bitmap });

            rest = i;
        }
        Ok((rest, out))
    }
}

// 10.4.2 TPM2B_DIGEST
struct Digest;

impl Digest {
    fn read(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let (i, size) = be_u16(input)?;
        let (i, data) = take(size as usize)(i)?;
        Ok((i, data))
    }
}

// 10.12.4 TPMS_QUOTE_INFO
#[derive(Debug)]
pub struct QuoteInfo {
    select: Vec<PCRSelection>,
    digest: Vec<u8>,
}

impl QuoteInfo {
    fn read(input: &[u8]) -> IResult<&[u8], QuoteInfo> {
        let (i, select) = PCRSelection::read(input)?;
        let (i, digest) = Digest::read(i)?;
        let digest = digest.to_vec();

        Ok((i, QuoteInfo { select, digest }))
    }
}

// 10.12.12 TPMS_ATTEST
#[derive(Debug)]
pub struct Quote {
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock_info: ClockInfo,
    pub firmware_version: u64,
    pub attested: QuoteInfo,
}

impl Quote {
    pub fn read(input: &[u8]) -> Result<Self, Error> {
        fn read_(i: &[u8]) -> IResult<&[u8], Quote> {
            let (i, _) = tag(TPM_GENERATED_MAGIC)(i)?;
            let (i, _type) = tag(TPM_ST_ATTEST_QUOTE)(i)?;
            let (i, qualified_signer) = Name::read(i)?;
            let (i, extra_data) = Data::read(i)?;
            let (i, clock_info) = ClockInfo::read(i)?;
            let (i, firmware_version) = be_u64(i)?;
            let (i, attested) = QuoteInfo::read(i)?;

            let qualified_signer = qualified_signer.to_vec();
            let extra_data = extra_data.to_vec();

            Ok((
                i,
                Quote {
                    qualified_signer,
                    extra_data,
                    clock_info,
                    firmware_version,
                    attested,
                },
            ))
        }

        let (out, quoted) = read_(input).map_err(|_| Error::ParseError)?;
        if out.len() != 0 {
            return Err(Error::ParseError);
        }

        Ok(quoted)
    }

    pub fn compare_sha256(&self, pcr4: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        // For each selected pcr, blablabla
        hasher.write(pcr4).expect("unable to write hash");
        let expected_hash = hasher.finalize_reset();

        &expected_hash[..] == &self.attested.digest[..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as Sha2Digest, Sha256};
    use std::io::Write;

    const quoted: &[u8] = &[
        0xff, 0x54, 0x43, 0x47, 0x80, 0x18, 0x0, 0x22, 0x0, 0xb, 0xd0, 0x10, 0x0, 0x73, 0x21, 0x7f,
        0x91, 0xa7, 0x17, 0x9f, 0x64, 0xd8, 0x2b, 0x8a, 0xa6, 0x2, 0x84, 0xc5, 0xba, 0xa8, 0xd1,
        0x3, 0x47, 0x9e, 0xd9, 0xef, 0xbf, 0x3d, 0xfb, 0x9f, 0x29, 0x6e, 0x0, 0x10, 0x0, 0x1, 0x2,
        0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0, 0x0, 0x0, 0x0, 0x0,
        0xf, 0xf3, 0xc5, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x1, 0x20, 0x17, 0x6, 0x19, 0x0,
        0x16, 0x36, 0x36, 0x0, 0x0, 0x0, 0x1, 0x0, 0xb, 0x3, 0x10, 0x0, 0x0, 0x0, 0x20, 0xd4, 0xb2,
        0xa, 0x36, 0xf0, 0xc2, 0x96, 0x56, 0x42, 0xa1, 0xf2, 0x7a, 0x19, 0xae, 0xcb, 0x72, 0x1d,
        0x80, 0x4c, 0x11, 0x53, 0xd7, 0x4, 0x89, 0xa, 0x68, 0x12, 0x7d, 0xcd, 0xf6, 0x51, 0xa,
    ];

    #[test]
    fn parse_quoted_structure() {
        let parsed = Quote::read(quoted).expect("parse fixed structure");

        let expected_pcr = &[
            0xd2, 0xdb, 0x51, 0x53, 0x9d, 0xa1, 0x04, 0x6b, 0x71, 0x94, 0x2a, 0x47, 0xcc, 0x7d,
            0xe4, 0xce, 0x21, 0x8f, 0x7b, 0x78, 0xa5, 0xd8, 0xec, 0xf6, 0x65, 0x3a, 0x97, 0x20,
            0xc8, 0xda, 0x55, 0xda,
        ];
        assert!(parsed.compare_sha256(expected_pcr));
    }
}
