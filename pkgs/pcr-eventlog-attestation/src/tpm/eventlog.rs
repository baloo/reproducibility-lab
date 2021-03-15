use std::io::Write;

use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{le_u16, le_u32},
    IResult,
};
use sha2::{Digest as Sha2Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
pub enum EventType {
    PrebootCert,
    PostCode,
    Unused,
    NoAction,
    Separator,
    Action,
    EventTag,
    SCrtmContents,
    SCrtmVersion,
    CPUMicrocode,
    PlatformConfigFlags,
    TableOfDevices,
    CompactHash,
    IPL,
    IPLPartitionData,
    NonhostCode,
    NonhostConfig,
    NonhostInfo,
    OmitBootDeviceEvents,

    EFIVariableDriverConfig,
    EFIVariableBoot,
    EFIBootServicesApplication,
    EFIBootServicesDriver,
    EFIRuntimeServicesDriver,
    EFIGPTEvent,
    EFIAction,
    EFIPlatformFirmwareBlob,
    EFIHandoffTables,
    EFIVariableAuthority,

    Unknown(u32),
}

impl EventType {
    fn read(i: &[u8]) -> IResult<&[u8], EventType> {
        use EventType::*;

        let out = match le_u32(i)? {
            (i, 0x0) => (i, PrebootCert),
            (i, 0x1) => (i, PostCode),
            (i, 0x2) => (i, Unused),
            (i, 0x3) => (i, NoAction),
            (i, 0x4) => (i, Separator),
            (i, 0x5) => (i, Action),
            (i, 0x6) => (i, EventTag),
            (i, 0x7) => (i, SCrtmContents),
            (i, 0x8) => (i, SCrtmVersion),
            (i, 0x9) => (i, CPUMicrocode),
            (i, 0xa) => (i, PlatformConfigFlags),
            (i, 0xb) => (i, TableOfDevices),
            (i, 0xc) => (i, CompactHash),
            (i, 0xd) => (i, IPL),
            (i, 0xe) => (i, IPLPartitionData),
            (i, 0xf) => (i, NonhostCode),
            (i, 0x10) => (i, NonhostConfig),
            (i, 0x11) => (i, NonhostInfo),
            (i, 0x12) => (i, OmitBootDeviceEvents),

            (i, 0x80000001) => (i, EFIVariableDriverConfig),
            (i, 0x80000002) => (i, EFIVariableBoot),
            (i, 0x80000003) => (i, EFIBootServicesApplication),
            (i, 0x80000004) => (i, EFIBootServicesDriver),
            (i, 0x80000005) => (i, EFIRuntimeServicesDriver),
            (i, 0x80000006) => (i, EFIGPTEvent),
            (i, 0x80000007) => (i, EFIAction),
            (i, 0x80000008) => (i, EFIPlatformFirmwareBlob),
            (i, 0x80000009) => (i, EFIHandoffTables),
            (i, 0x800000e0) => (i, EFIVariableAuthority),

            (i, e) => (i, Unknown(e)),
        };

        Ok(out)
    }
}

#[derive(Debug)]
pub enum Digest {
    Sha1(Vec<u8>),
    Sha256(Vec<u8>),
}

impl Digest {
    fn read(i: &[u8]) -> IResult<&[u8], Digest> {
        use Digest::*;

        let out = match le_u16(i)? {
            (i, 0x04) => {
                let (i, data) = take(20usize)(i)?;
                (i, Sha1(data.to_vec()))
            }
            (i, 0x0b) => {
                let (i, data) = take(32usize)(i)?;
                (i, Sha256(data.to_vec()))
            }
            _ => return Err(nom::Err::Failure((i, ErrorKind::Tag))),
        };

        Ok(out)
    }
}

#[derive(Debug)]
pub struct Event {
    num: usize,
    pcr_index: u32,
    event_type: EventType,
    digests: Vec<Digest>,
    event_data: Vec<u8>,
}

impl Event {
    fn read(i: &[u8], num: usize) -> IResult<&[u8], Event> {
        let (i, pcr_index) = le_u32(i)?;
        let (i, event_type) = EventType::read(i)?;

        let (mut rest, digest_count) = le_u32(i)?;
        let mut digests = Vec::new();
        for _ in 0..digest_count {
            let (i, digest) = Digest::read(rest)?;
            digests.push(digest);
            rest = i;
        }

        let (i, event_size) = le_u32(rest)?;
        let (i, event_data) = take(event_size as usize)(i)?;

        Ok((
            i,
            Event {
                num,
                pcr_index,
                event_type,
                digests,
                event_data: event_data.to_vec(),
            },
        ))
    }

    fn read_sha1_log(i: &[u8], num: usize) -> IResult<&[u8], Event> {
        let (i, pcr_index) = le_u32(i)?;
        let (i, event_type) = EventType::read(i)?;

        let (i, data) = take(20usize)(i)?;
        let digests = vec![Digest::Sha1(data.to_vec())];

        let (i, event_size) = le_u32(i)?;
        let (i, event_data) = take(event_size as usize)(i)?;

        Ok((
            i,
            Event {
                num,
                pcr_index,
                event_type,
                digests,
                event_data: event_data.to_vec(),
            },
        ))
    }
}

pub fn parse_log(contents: &[u8]) -> Vec<Event> {
    let mut indexes = 0..;

    let mut contents = &contents[..];
    let mut out = Vec::new();
    // Note: the unwrap below can only fail if run out of usize.
    let (rest, first_event) =
        Event::read_sha1_log(contents, indexes.next().unwrap()).expect("parse first element");
    contents = &rest[..];
    let agile_log = first_event.event_type == EventType::NoAction;
    out.push(first_event);

    if agile_log {
        while contents.len() > 0 {
            let (rest, value) = Event::read(contents, indexes.next().unwrap()).expect("parse data");
            out.push(value);
            contents = rest;
        }
    } else {
        while contents.len() > 0 {
            let (rest, value) =
                Event::read_sha1_log(contents, indexes.next().unwrap()).expect("parse data");
            out.push(value);
            contents = rest;
        }
    }
    out
}

pub fn recompute(log: Vec<Event>) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = Sha256::new();
    let mut value = [0u8; 32];
    let mut image_checksum = [0u8; 32];

    for i in log
        .iter()
        .filter(|e| e.pcr_index == 4 && e.event_type != EventType::NoAction)
    {
        if i.event_type == EventType::EFIBootServicesApplication && i.num == 32 {
            for h in i.digests.iter() {
                match h {
                    Digest::Sha256(ref v) => {
                        image_checksum.copy_from_slice(&v[..]);
                    }
                    _ => {}
                }
            }
        }
        hasher.write(&value[..]).expect("unable to write hash");
        for h in i.digests.iter() {
            match h {
                Digest::Sha256(ref v) => {
                    //println!("pcrs = {:#02x?}", v);
                    hasher.write(&v[..]).expect("unable to write hash");
                }
                _ => {}
            }
        }
        let new_pcr = hasher.finalize_reset();
        value.copy_from_slice(&new_pcr[..]);
    }

    (image_checksum[..].to_vec(), value[..].to_vec())
}
