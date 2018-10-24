/*
    An MRT (RFC6396) file parser implemented in Rust, using Nom
    Copyright (C) 2018  Wouter B. de Vries

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#![allow(non_camel_case_types)]
#[macro_use]
extern crate nom;

use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;

use nom::IResult;

#[derive(Debug)]
pub struct MrtHeader {
    timestamp: u32,
    mrt_type: MrtType,
    mrt_subtype: MrtSubType,
    length: u32,
}

#[derive(Debug, PartialEq)]
pub enum MrtType {
    OSPFv2,
    TABLE_DUMP,
    TABLE_DUMP_V2,
    BGP4MP,
    BGP4MP_ET,
    ISIS,
    ISIS_ET,
    OSPFv3,
    OSPFv3_ET,
    UNKNOWN { code: u16 },
}

fn to_mrt_type(i: u16) -> MrtType {
    match i {
        11 => MrtType::OSPFv2,
        12 => MrtType::TABLE_DUMP,
        13 => MrtType::TABLE_DUMP_V2,
        16 => MrtType::BGP4MP,
        17 => MrtType::BGP4MP_ET,
        32 => MrtType::ISIS,
        33 => MrtType::ISIS_ET,
        48 => MrtType::OSPFv3,
        49 => MrtType::OSPFv3_ET,
        _ => MrtType::UNKNOWN { code: i },
    }
}

#[derive(Debug, PartialEq)]
pub enum MrtSubType {
    AFI_IPV4,
    AFI_IPv6,
    PEER_INDEX_TABLE,
    RIB_IPV4_UNICAST,
    RIB_IPV4_MULTICAST,
    RIB_IPV6_UNICAST,
    RIB_IPV6_MULTICAST,
    RIB_GENERIC,
    BGP4MP_STATE_CHANGE,
    BGP4MP_MESSAGE,
    BGP4MP_MESSAGE_AS4,
    BGP4MP_STATE_CHANGE_AS4,
    BGP4MP_MESSAGE_LOCAL,
    BGP4MP_MESSAGE_AS4_LOCAL,
    UNKNOWN,
}

fn to_mrt_sub_type(mrt_type: &MrtType, code: u16) -> MrtSubType {
    match mrt_type {
        MrtType::TABLE_DUMP_V2 => match code {
            1 => MrtSubType::PEER_INDEX_TABLE,
            2 => MrtSubType::RIB_IPV4_UNICAST,
            3 => MrtSubType::RIB_IPV4_MULTICAST,
            4 => MrtSubType::RIB_IPV6_UNICAST,
            5 => MrtSubType::RIB_IPV6_MULTICAST,
            6 => MrtSubType::RIB_GENERIC,
            _ => MrtSubType::UNKNOWN,
        },
        MrtType::BGP4MP => match code {
            0 => MrtSubType::BGP4MP_STATE_CHANGE,
            1 => MrtSubType::BGP4MP_MESSAGE,
            4 => MrtSubType::BGP4MP_MESSAGE_AS4,
            5 => MrtSubType::BGP4MP_STATE_CHANGE_AS4,
            6 => MrtSubType::BGP4MP_MESSAGE_LOCAL,
            7 => MrtSubType::BGP4MP_MESSAGE_AS4_LOCAL,
            _ => MrtSubType::UNKNOWN,
        },
        _ => MrtSubType::UNKNOWN,
    }
}

#[derive(Debug)]
pub struct MrtEntry {
    pub mrt_header: MrtHeader,
    pub message: MrtMessage,
}

#[derive(Debug)]
pub struct PeerEntry {
    peer_type: u8,
    pub peer_bgp_id: u32,
    pub peer_ip_address: IpAddr,
    pub peer_as: u32,
}

#[derive(Debug)]
pub enum MrtMessage {
    PEER_INDEX_TABLE {
        collector_bgp_id: u32,
        view_name: String,
        peers: Vec<PeerEntry>,
    },
    RIB_IPV4_UNICAST {
        header: RibEntryHeader,
        entries: Vec<RibEntry>,
    },
    RIB_IPV6_UNICAST {
        header: RibEntryHeader,
        entries: Vec<RibEntry>,
    },
    BGP4MPMessageAS4 {
        peer_as_number: u32,
        local_as_number: u32,
        interface_index: u16,
        address_family: u16,
        peer_ip_address: IpAddr,
        local_ip_address: IpAddr,
        message: BgpMessage,
    },
    NOT_IMPLEMENTED,
}

#[derive(Debug)]
pub struct RibEntryHeader {
    pub sequence_number: u32,
    pub prefix_length: u8,
    pub prefix: IpAddr,
}
#[derive(Debug)]
pub struct RibEntry {
    pub peer_index: u16,
    pub originated_time: u32,
    length: u16,
    pub bgp_attributes: Vec<BgpAttribute>,
}
#[derive(Debug)]
pub struct BgpAttribute {
    pub optional: bool,
    pub transitive: bool,
    pub partial: bool,
    extended_length: bool,
    length: u16,
    pub value: BgpAttributeValue,
}

#[derive(Debug)]
pub enum Origin {
    IGP,
    EGP,
    INCOMPLETE,
    UNKNOWN,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Origin::IGP => f.write_str("IGP"),
            Origin::EGP => f.write_str("EGP"),
            Origin::INCOMPLETE => f.write_str("INCOMPLETE"),
            Origin::UNKNOWN => f.write_str("UNKNOWN"),
        }
    }
}

#[derive(Debug)]
pub struct AsPathSegment {
    pub segment_type: SegmentType,
    pub asns: Vec<u32>,
}

#[derive(Debug)]
pub struct Community {
    pub asn: u32,
    pub value: u16,
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.asn, self.value)
    }
}

#[derive(Debug)]
pub enum BgpAttributeValue {
    ORIGIN { value: Origin },
    AS_PATH { segments: Vec<AsPathSegment> },
    NEXT_HOP { ipaddress: IpAddr },
    MULTI_EXIT_DISC,
    LOCAL_PREF,
    ATOMIC_AGGREGATE,
    AGGREGATOR,
    COMMUNITY { communities: Vec<Community> },
    NOT_IMPLEMENTED { code: u8 },
}
#[derive(Debug, PartialEq)]
pub enum SegmentType {
    AS_SET,
    AS_SEQUENCE,
    UNKNOWN,
}
#[derive(Debug)]
pub enum BgpMessage {
    OPEN,
    UPDATE {
        withdrawn_routes: Vec<Route>,
        path_attributes: Vec<BgpAttribute>,
        network_layer_reachability_information: Vec<Route>,
    },
    NOTIFICATION,
    KEEPALIVE,
    UNKNOWN,
}
#[derive(Debug)]
pub struct Route {
    prefix_length: u8,
    prefix: IpAddr,
}

named!(bgp4mp_message_as4<&[u8], MrtMessage>,
    do_parse!(
        peer_as_number: u32!(nom::Endianness::Big) >>
        local_as_number: u32!(nom::Endianness::Big) >>
        interface_index: u16!(nom::Endianness::Big) >>
        address_family: u16!(nom::Endianness::Big) >>
        peer_ip_address: switch!(value!(address_family == 2),
            false => map!(take!(4), |x| ip_prefix(x, false)) |
            true => map!(take!(16), |x| ip_prefix(x, true))
        ) >>
        local_ip_address: switch!(value!(address_family == 2),
            false => map!(take!(4), |x| ip_prefix(x, false)) |
            true => map!(take!(16), |x| ip_prefix(x, true))
        ) >>
        take!(16) >>
        u16!(nom::Endianness::Big) >>
        message_type: bits!(take_bits!(u8, 8)) >>
        message: switch!(value!(message_type),
            1 => call!(bgp_message_open) |
            2 => call!(bgp_message_update, address_family == 2) |
            3 => call!(bgp_message_notification) |
            4 => call!(bgp_message_keepalive)
        ) >>
        (MrtMessage::BGP4MPMessageAS4{peer_as_number, local_as_number, interface_index, address_family, peer_ip_address, local_ip_address, message: message})
    )
);

named!(bgp_message_open<&[u8], BgpMessage>,
    do_parse!(
        (BgpMessage::OPEN)
    )
);

named_args!(route(is_ipv6: bool)<&[u8], Route>,
    do_parse!(
        prefix_length: bits!(take_bits!(u8, 8)) >>
        prefix: map!(take!((f64::from(prefix_length)/8.0).ceil()), |x| ip_prefix(x, is_ipv6)) >>
        (Route{prefix_length, prefix})
    )
);

named_args!(bgp_message_update(is_ipv6: bool)<&[u8], BgpMessage>,
    do_parse!(
        withdrawn_routes: length_value!(u16!(nom::Endianness::Big), many0!(complete!(apply!(route, is_ipv6)))) >>
        path_attributes: length_value!(u16!(nom::Endianness::Big), many0!(complete!(apply!(bgp_attribute, is_ipv6)))) >>
        network_layer_reachability_information: many0!(complete!(apply!(route, is_ipv6))) >>
        (BgpMessage::UPDATE{withdrawn_routes, path_attributes, network_layer_reachability_information})
    )
);

named!(bgp_message_notification<&[u8], BgpMessage>,
    do_parse!((BgpMessage::NOTIFICATION))
);

named!(bgp_message_keepalive<&[u8], BgpMessage>,
    do_parse!((BgpMessage::KEEPALIVE))
);

named!(mrt_message_peer_index_table<&[u8], MrtMessage>,
    do_parse!(
        collector_bgp_id: u32!(nom::Endianness::Big) >>
        view_name: map!(length_bytes!(u16!(nom::Endianness::Big)), str::from_utf8) >>
        peers: length_count!(u16!(nom::Endianness::Big), peer_entry) >>
        (MrtMessage::PEER_INDEX_TABLE{
        collector_bgp_id: collector_bgp_id,
        view_name: view_name.unwrap().to_string(),
         peers: peers })
    )
);

named_args!(rib_entry_header(is_ipv6: bool)<&[u8], RibEntryHeader>,
    do_parse!(
        sequence_number: u32!(nom::Endianness::Big) >>
        prefix_length: bits!(take_bits!(u8, 8)) >>
        prefix: take!((f64::from(prefix_length)/8.0).ceil()) >>
        (RibEntryHeader{sequence_number: sequence_number, prefix_length: prefix_length,
        prefix: ip_prefix(prefix, is_ipv6)})
    )
);

named_args!(mrt_rib_message(is_ipv6: bool)<&[u8], MrtMessage>,
    do_parse!(
        header: apply!(rib_entry_header, is_ipv6) >>
        entries: length_count!(u16!(nom::Endianness::Big), apply!(rib_entry, is_ipv6)) >>
        (if is_ipv6 {
            MrtMessage::RIB_IPV6_UNICAST{header: header, entries: entries}
        } else {
            MrtMessage::RIB_IPV4_UNICAST{header: header, entries: entries}
        })
    )
);

named_args!(rib_entry(is_ipv6: bool)<&[u8], RibEntry>,
    do_parse!(
        peer_index: u16!(nom::Endianness::Big) >>
        originated_time: u32!(nom::Endianness::Big) >>
        length: u16!(nom::Endianness::Big) >>
        bgp_attributes: length_value!(value!(length),
        many0!(complete!(apply!(bgp_attribute, is_ipv6)))) >>
        (RibEntry{peer_index: peer_index, originated_time: originated_time, length:length,
        bgp_attributes: bgp_attributes})
    )
);

named!(peer_entry<&[u8], PeerEntry>,
    do_parse!(
        peer_type: take!(1) >>
        peer_bgp_id: u32!(nom::Endianness::Big) >>
        peer_ip_address: switch!(value!((peer_type[0] & 0b1) == 0),
            true => map!(take!(4), |x| ip_prefix(x, false)) |
            false => map!(take!(16), |x| ip_prefix(x, true))
        ) >>
        peer_as: switch!(value!((peer_type[0] & 0b10 != 0)),
            true => u32!(nom::Endianness::Big) |
            false => map!(u16!(nom::Endianness::Big), u32::from)
        ) >>
        (PeerEntry{
        peer_type: peer_type[0],
         peer_bgp_id: peer_bgp_id,
         peer_ip_address: peer_ip_address,
         peer_as: peer_as})
    )
);

named!(mrt_header<&[u8], MrtHeader>,
    do_parse!(
        timestamp: unix_timestamp >>
        mrt_type: mrt_type >>
        mrt_subtype: map!(u16!(nom::Endianness::Big), |x| to_mrt_sub_type(&mrt_type, x)) >>
        length: length >>
      (MrtHeader{timestamp: timestamp, mrt_type: mrt_type, mrt_subtype: mrt_subtype,
      length: length}))
);

named!(mrt_entry<&[u8], MrtEntry>,
    do_parse!(
        mrt_header: mrt_header >>
        message: length_value!(value!(mrt_header.length), apply!(parse_message,
         &mrt_header.mrt_subtype, mrt_header.length)) >>
        (MrtEntry{mrt_header, message})
    )
);

named!(mrt_file<&[u8], Vec<MrtEntry>>,
    many0!(complete!(mrt_entry))
);

// BGP Attributes
named_args!(bgp_attribute(is_ipv6: bool)<&[u8], BgpAttribute>,
    do_parse!(
        flags: bits!(tuple!(take_bits!(u8, 1), take_bits!(u8, 1), take_bits!(u8, 1),
        take_bits!(u8, 1))) >>
        code: bits!(take_bits!(u8, 8)) >>
        length: apply!(parse_varlength, flags.3 > 0) >>
        value: length_value!(value!(length), apply!(parse_bgp_attribute, code, is_ipv6, length)) >>
        (BgpAttribute{optional: flags.0 > 0, transitive: flags.1 > 0, partial: flags.2 > 0,
        extended_length: flags.3 > 0, length: length, value: value})
    )
);

named!(origin<&[u8], BgpAttributeValue>,
    do_parse!(
        value: switch!(bits!(take_bits!(u8, 8)),
            0 => value!(Origin::IGP) |
            1 => value!(Origin::EGP) |
            2 => value!(Origin::INCOMPLETE) |
            _ => value!(Origin::UNKNOWN)
        ) >>
        (BgpAttributeValue::ORIGIN{value: value})
    )
);

named!(as_path<&[u8], BgpAttributeValue>,
    do_parse!(
        segments: many0!(complete!(as_path_segment)) >>
        (BgpAttributeValue::AS_PATH{segments: segments})
    )
);

named!(as_path_segment<&[u8], AsPathSegment>,
    do_parse!(
        segment_type: switch!(bits!(take_bits!(u8, 8)),
            1 => value!(SegmentType::AS_SET) |
            2 => value!(SegmentType::AS_SEQUENCE) |
            _ => value!(SegmentType::UNKNOWN)
        ) >>
        asns: length_count!(bits!(take_bits!(u8, 8)), asn) >>
        (AsPathSegment{segment_type: segment_type, asns: asns})
    )
);

named!(community<&[u8], BgpAttributeValue>,
    do_parse!(
        communities: many0!(complete!(tuple!(u16!(nom::Endianness::Big),
         u16!(nom::Endianness::Big)))) >>
        (BgpAttributeValue::COMMUNITY{communities: communities.iter()
        .map(|x| Community{asn: u32::from(x.0), value: x.1}).collect()})
    )
);

named_args!(next_hop(is_ipv6: bool)<&[u8], BgpAttributeValue>,
    do_parse!(
        ipaddress: switch!(value!(is_ipv6),
            false => map!(take!(4), |x| ip_prefix(x, false)) |
            true => map!(take!(16), |x| ip_prefix(x, true))
        ) >>
        (BgpAttributeValue::NEXT_HOP{ipaddress: ipaddress})
    )
);

named!(take_u8_as_u16<&[u8], u16>, map!(bits!(take_bits!(u8, 8)), u16::from));
named!(take_u16<&[u8], u16>, u16!(nom::Endianness::Big));
named!(length<&[u8], u32>, u32!(nom::Endianness::Big));
named!(unix_timestamp<&[u8], u32>, u32!(nom::Endianness::Big));
named!(mrt_type<&[u8], MrtType>, map!(u16!(nom::Endianness::Big), to_mrt_type));
named!(asn<&[u8], u32>, u32!(nom::Endianness::Big));

fn ip_prefix(value: &[u8], is_ipv6: bool) -> IpAddr {
    if is_ipv6 {
        let mut input: [u8; 16] = [0; 16];

        for (i, val) in value.iter().enumerate() {
            input[i] = *val;
        }

        IpAddr::V6(Ipv6Addr::from(input))
    } else {
        IpAddr::V4(match value.len() {
            0 => Ipv4Addr::new(0, 0, 0, 0),
            1 => Ipv4Addr::new(value[0], 0, 0, 0),
            2 => Ipv4Addr::new(value[0], value[1], 0, 0),
            3 => Ipv4Addr::new(value[0], value[1], value[2], 0),
            4 => Ipv4Addr::new(value[0], value[1], value[2], value[3]),
            _ => Ipv4Addr::new(0, 0, 0, 0),
        })
    }
}

fn parse_message<'a>(
    input: &'a [u8],
    message_type: &MrtSubType,
    length: u32,
) -> IResult<&'a [u8], MrtMessage> {
    match message_type {
        MrtSubType::PEER_INDEX_TABLE => mrt_message_peer_index_table(input),
        MrtSubType::RIB_IPV4_UNICAST => mrt_rib_message(input, false),
        MrtSubType::RIB_IPV6_UNICAST => mrt_rib_message(input, true),
        MrtSubType::BGP4MP_MESSAGE_AS4 => bgp4mp_message_as4(input),
        _ => Ok((&input[(length as usize)..], MrtMessage::NOT_IMPLEMENTED)),
    }
}

fn parse_bgp_attribute(
    input: &[u8],
    code: u8,
    is_ipv6: bool,
    length: u16,
) -> IResult<&[u8], BgpAttributeValue> {
    match code {
        1 => origin(input),
        2 => as_path(input),
        3 => next_hop(input, is_ipv6),
        8 => community(input),
        _ => Ok((
            &input[(length as usize)..],
            BgpAttributeValue::NOT_IMPLEMENTED { code: code },
        )),
    }
}

fn parse_varlength(input: &[u8], extended_length: bool) -> IResult<&[u8], u16> {
    if extended_length {
        take_u16(input)
    } else {
        take_u8_as_u16(input)
    }
}

pub fn read_file_complete(file: File) -> Result<Vec<MrtEntry>, &'static str> {
    let mut buf_reader = BufReader::new(file);
    let mut contents: Vec<u8> = vec![]; // = [0; 630700];
    buf_reader.read_to_end(&mut contents).unwrap();

    let result = mrt_file(contents.as_slice());

    match result {
        Ok(v) => Ok(v.1),
        Err(_) => Err("Something went wrong!"),
    }
}

#[derive(Debug)]
pub struct MrtFile {
    entry_buffer: Vec<u8>,
    reader: BufReader<File>,
}

impl MrtFile {
    pub fn new(file: File) -> MrtFile {
        MrtFile {
            entry_buffer: vec![0; 8 * 1024],
            reader: BufReader::new(file),
        }
    }
}

impl Iterator for MrtFile {
    type Item = MrtEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let mut header: Option<MrtHeader> = None;
        {
            let mut header_buf: [u8; 12] = [0; 12];
            let r = self.reader.read_exact(&mut header_buf);
            if r.is_ok() {
                let tmp = mrt_header(&header_buf);
                if let Ok((_, header2)) = tmp {
                    header = Some(header2);
                }
            } else {
                return None;
            }
        }

        self.entry_buffer.truncate(0);
        if let Some(x) = header {
            let r = self
                .reader
                .by_ref()
                .take(u64::from(x.length))
                .read_to_end(&mut self.entry_buffer);
            if r.is_err() {
                return None;
            }

            let tmp = parse_message(
                &self.entry_buffer[..(x.length as usize)],
                &x.mrt_subtype,
                x.length,
            );
            if let Ok((_, message)) = tmp {
                return Some(MrtEntry {
                    mrt_header: x,
                    message,
                });
            }
        }

        None
    }
}
