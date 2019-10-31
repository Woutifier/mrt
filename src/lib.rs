#![allow(non_camel_case_types)]

/// An MRT (RFC6396) file parser implemented in Rust, using Nom
/// Copyright (C) 2019  Wouter B. de Vries
///
/// This program is free software: you can redistribute it and/or modify
/// it under the terms of the GNU General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// This program is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU General Public License for more details.
///
/// You should have received a copy of the GNU General Public License
/// along with this program.  If not, see <https://www.gnu.org/licenses/>.
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;

use nom::bytes::complete::take;
use nom::combinator::map;
use nom::multi::{count, length_value, many0};
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::sequence::tuple;
use nom::IResult;

#[derive(Debug)]
pub struct MrtHeader {
    pub timestamp: u32,
    pub mrt_type: MrtType,
    pub mrt_subtype: MrtSubType,
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

/// Converts the given u16 to the relevant MrtType
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

/// Converts the given MrtType and u16 to the relevant MrtSubType
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
    peer_type: PeerType,
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
    BGP4MP_MESSAGE_AS4 {
        peer_as_number: u32,
        local_as_number: u32,
        interface_index: u16,
        address_family: IpFamily,
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
    pub bgp_attributes: Vec<BgpAttribute>,
}
#[derive(Debug)]
pub struct BgpAttribute {
    pub optional: bool,
    pub transitive: bool,
    pub partial: bool,
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
    pub asn: u16,
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
    MULTI_EXIT_DISC { value: u32 },
    LOCAL_PREF { value: u32 },
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
        withdrawn_routes: Vec<Subnet>,
        path_attributes: Vec<BgpAttribute>,
        network_layer_reachability_information: Vec<Subnet>,
    },
    NOTIFICATION,
    KEEPALIVE,
    UNKNOWN,
}
#[derive(Debug)]
pub struct Subnet {
    pub prefix_length: u8,
    pub prefix: IpAddr,
}

#[derive(Debug, PartialEq)]
pub struct PeerType {
    pub as_number_size: AsNumberSize,
    pub ip_address_family: IpFamily,
}

#[derive(Debug, PartialEq)]
pub enum AsNumberSize {
    Short,
    Long,
}

#[derive(Debug, PartialEq)]
pub enum IpFamily {
    V4,
    V6,
}

fn bgp4mp_message_as4(input: &[u8]) -> IResult<&[u8], MrtMessage> {
    let (input, peer_as_number) = be_u32(input)?;
    let (input, local_as_number) = be_u32(input)?;
    let (input, interface_index) = be_u16(input)?;
    let (input, address_family) =
        map(be_u16, |x| if x == 1 { IpFamily::V4 } else { IpFamily::V6 })(input)?;

    let take_ip = |input| match address_family {
        IpFamily::V4 => map(take(4usize), |x| ip_prefix(x, false))(input),
        IpFamily::V6 => map(take(16usize), |x| ip_prefix(x, true))(input),
    };

    let (input, peer_ip_address) = take_ip(input)?;
    let (input, local_ip_address) = take_ip(input)?;

    // Skip 16-bytes
    let input = &input[16..];

    let (input, length) = be_u16(input)?;
    let (input, message_type) = be_u8(input)?;

    // Subtract the skipped 16 bytes, the length field (2 bytes) and the messsage type (1 byte)
    // from the length, for the remaining_length
    let remaining_length = length - 19;

    let (input, message) = match message_type {
        1 => Ok((&input[remaining_length as usize..], BgpMessage::OPEN)),
        2 => length_value(
            |x| Ok((x, remaining_length)),
            |x| bgp_message_update(x, address_family == IpFamily::V6),
        )(input),
        3 => Ok((&input[remaining_length as usize..], BgpMessage::NOTIFICATION)),
        4 => Ok((&input[remaining_length as usize..], BgpMessage::KEEPALIVE)),
        _ => Ok((&input[remaining_length as usize..], BgpMessage::NOTIFICATION)),
    }?;

    Ok((
        input,
        MrtMessage::BGP4MP_MESSAGE_AS4 {
            peer_as_number,
            local_as_number,
            interface_index,
            address_family,
            peer_ip_address,
            local_ip_address,
            message,
        },
    ))
}

fn bgp_message_update(input: &[u8], is_ipv6: bool) -> IResult<&[u8], BgpMessage> {
    let (input, withdrawn_routes) =
        length_value(be_u16, many0(|x| parse_subnet(x, is_ipv6)))(input)?;
    let (input, path_attributes) = length_value(be_u16, many0(bgp_attribute))(input)?;
    let (input, network_layer_reachability_information) =
        many0(|x| parse_subnet(x, is_ipv6))(input)?;

    Ok((
        input,
        BgpMessage::UPDATE {
            withdrawn_routes,
            path_attributes,
            network_layer_reachability_information,
        },
    ))
}

fn as_path(input: &[u8]) -> IResult<&[u8], BgpAttributeValue> {
    let (input, segments) = many0(as_path_segment)(input)?;
    Ok((input, BgpAttributeValue::AS_PATH { segments }))
}

fn as_path_segment(input: &[u8]) -> IResult<&[u8], AsPathSegment> {
    let (input, segment_type) = be_u8(input)?;
    let segment_type = match segment_type {
        1 => SegmentType::AS_SET,
        2 => SegmentType::AS_SEQUENCE,
        _ => SegmentType::UNKNOWN,
    };
    let (input, asn_count) = be_u8(input)?;
    let (input, asns) = count(be_u32, asn_count as usize)(input)?;

    Ok((input, AsPathSegment { segment_type, asns }))
}

fn bgp_attribute(input: &[u8]) -> IResult<&[u8], BgpAttribute> {
    let (input, flags) = be_u8(input)?;
    let (input, code) = be_u8(input)?;

    // Check for each of the flags
    let optional = flags & 0b1000_0000 > 0;
    let transitive = flags & 0b0100_0000 > 0;
    let partial = flags & 0b0010_0000 > 0;
    let extended_length = flags & 0b0001_0000 > 0;

    let length_parser = |input| {
        if extended_length {
            be_u16(input)
        } else {
            map(be_u8, u16::from)(input)
        }
    };

    let (input, value) = length_value(length_parser, |x| bgp_attribute_value(x, code))(input)?;

    Ok((
        input,
        BgpAttribute {
            optional,
            transitive,
            partial,
            value,
        },
    ))
}

fn bgp_attribute_value(input: &[u8], code: u8) -> IResult<&[u8], BgpAttributeValue> {
    match code {
        1 => origin(input),
        2 => as_path(input),
        3 => next_hop(input),
        4 => multi_exit_disc(input),
        5 => local_pref(input),
        6 => Ok((&input[..0], BgpAttributeValue::ATOMIC_AGGREGATE)),
        8 => community(input),
        _ => Ok((&input[..0], BgpAttributeValue::NOT_IMPLEMENTED { code })),
    }
}

fn community(input: &[u8]) -> IResult<&[u8], BgpAttributeValue> {
    let (input, communities) = many0(tuple((be_u16, be_u16)))(input)?;

    // Map tuples of two u16s to the community structs
    let communities = communities
        .into_iter()
        .map(|(asn, value)| Community { asn, value })
        .collect();

    Ok((input, BgpAttributeValue::COMMUNITY { communities }))
}

fn multi_exit_disc(input: &[u8]) -> IResult<&[u8], BgpAttributeValue> {
    let (input, value) = be_u32(input)?;
    Ok((input, BgpAttributeValue::MULTI_EXIT_DISC { value }))
}

fn local_pref(input: &[u8]) -> IResult<&[u8], BgpAttributeValue> {
    let (input, value) = be_u32(input)?;
    Ok((input, BgpAttributeValue::LOCAL_PREF { value }))
}

fn next_hop(input: &[u8]) -> IResult<&[u8], BgpAttributeValue> {
    Ok((
        &input[..0],
        BgpAttributeValue::NEXT_HOP {
            ipaddress: ip_prefix(input, input.len() != 4),
        },
    ))
}

fn origin(input: &[u8]) -> IResult<&[u8], BgpAttributeValue> {
    let (input, code) = be_u8(input)?;

    let value = match code {
        0 => Origin::IGP,
        1 => Origin::EGP,
        2 => Origin::INCOMPLETE,
        _ => Origin::UNKNOWN,
    };

    Ok((input, BgpAttributeValue::ORIGIN { value }))
}

fn rib_entry_header(input: &[u8], is_ipv6: bool) -> IResult<&[u8], RibEntryHeader> {
    let (input, sequence_number) = be_u32(input)?;
    let (input, subnet) = parse_subnet(input, is_ipv6)?;

    Ok((
        input,
        RibEntryHeader {
            sequence_number,
            prefix_length: subnet.prefix_length,
            prefix: subnet.prefix,
        },
    ))
}

fn rib_entry(input: &[u8]) -> IResult<&[u8], RibEntry> {
    let (input, peer_index) = be_u16(input)?;
    let (input, originated_time) = unix_timestamp(input)?;

    let (input, bgp_attributes) = length_value(be_u16, many0(bgp_attribute))(input)?;

    Ok((
        input,
        RibEntry {
            peer_index,
            originated_time,
            bgp_attributes,
        },
    ))
}

fn mrt_rib_message(input: &[u8], is_ipv6: bool) -> IResult<&[u8], MrtMessage> {
    let (input, header) = rib_entry_header(input, is_ipv6)?;
    let (input, entry_count) = be_u16(input)?;
    let (input, entries) = count(rib_entry, entry_count as usize)(input)?;

    if is_ipv6 {
        Ok((input, MrtMessage::RIB_IPV6_UNICAST { header, entries }))
    } else {
        Ok((input, MrtMessage::RIB_IPV4_UNICAST { header, entries }))
    }
}

fn unix_timestamp(input: &[u8]) -> IResult<&[u8], u32> {
    be_u32(input)
}

fn mrt_type(input: &[u8]) -> IResult<&[u8], MrtType> {
    map(be_u16, to_mrt_type)(input)
}

fn mrt_sub_type<'a>(input: &'a [u8], mrt_type: &MrtType) -> IResult<&'a [u8], MrtSubType> {
    map(be_u16, |x| to_mrt_sub_type(mrt_type, x))(input)
}

fn mrt_file(input: &[u8]) -> IResult<&[u8], Vec<MrtEntry>> {
    many0(mrt_entry)(input)
}

fn mrt_header(input: &[u8]) -> IResult<&[u8], MrtHeader> {
    let (input, timestamp) = unix_timestamp(input)?;
    let (input, mrt_type) = mrt_type(input)?;
    let (input, mrt_subtype) = mrt_sub_type(input, &mrt_type)?;
    let (input, length) = be_u32(input)?;

    Ok((
        input,
        MrtHeader {
            timestamp,
            mrt_type,
            mrt_subtype,
            length,
        },
    ))
}

fn mrt_entry(input: &[u8]) -> IResult<&[u8], MrtEntry> {
    let (input, mrt_header) = mrt_header(input)?;
    let (input, message) = length_value(
        |x| Ok((x, mrt_header.length)),
        |x| mrt_message(x, &mrt_header.mrt_subtype),
    )(input)?;

    Ok((
        input,
        MrtEntry {
            mrt_header,
            message,
        },
    ))
}

fn parse_subnet(input: &[u8], is_ipv6: bool) -> IResult<&[u8], Subnet> {
    let (input, prefix_length) = be_u8(input)?;
    let prefix_byte_length = (prefix_length as f32 / 8f32).ceil() as usize;

    let (input, prefix) = map(take(prefix_byte_length), |x| ip_prefix(x, is_ipv6))(input)?;

    Ok((
        input,
        Subnet {
            prefix_length,
            prefix,
        },
    ))
}

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

fn parse_str(input: &[u8]) -> IResult<&[u8], &str> {
    Ok((
        &input[..0],
        str::from_utf8(input).expect("Unable to parse string to UTF-8"),
    ))
}

fn peer_index_table(input: &[u8]) -> IResult<&[u8], MrtMessage> {
    let (input, collector_bgp_id) = be_u32(input)?;
    let (input, view_name) = length_value(be_u16, parse_str)(input)?;
    let (input, peer_entry_count) = be_u16(input)?;
    let (input, peers) = count(peer_entry, usize::from(peer_entry_count))(input)?;

    Ok((
        input,
        MrtMessage::PEER_INDEX_TABLE {
            collector_bgp_id,
            view_name: view_name.to_string(),
            peers,
        },
    ))
}

fn peer_type(input: &[u8]) -> IResult<&[u8], PeerType> {
    let (input, peer_type) = be_u8(input)?;
    let mut output = PeerType {
        as_number_size: AsNumberSize::Short,
        ip_address_family: IpFamily::V4,
    };

    // Check for IPv6
    if peer_type & 0b1 > 0 {
        output.ip_address_family = IpFamily::V6;
    }

    // Check for long as number
    if peer_type & 0b10 > 0 {
        output.as_number_size = AsNumberSize::Long
    }

    Ok((input, output))
}

fn peer_entry(input: &[u8]) -> IResult<&[u8], PeerEntry> {
    let (input, peer_type) = peer_type(input)?;
    let (input, peer_bgp_id) = be_u32(input)?;

    // Parse IP address
    let (input, peer_ip_address) = match peer_type.ip_address_family {
        IpFamily::V4 => map(take(4usize), |x| ip_prefix(x, false))(input)?,
        IpFamily::V6 => map(take(16usize), |x| ip_prefix(x, true))(input)?,
    };

    // Parse AS number
    let (input, peer_as) = match peer_type.as_number_size {
        AsNumberSize::Short => map(be_u16, u32::from)(input)?,
        AsNumberSize::Long => be_u32(input)?,
    };

    Ok((
        input,
        PeerEntry {
            peer_type,
            peer_bgp_id,
            peer_ip_address,
            peer_as,
        },
    ))
}

fn mrt_message<'a>(input: &'a [u8], mrt_subtype: &MrtSubType) -> IResult<&'a [u8], MrtMessage> {
    let (input, message) = match mrt_subtype {
        MrtSubType::PEER_INDEX_TABLE => peer_index_table(input)?,
        MrtSubType::RIB_IPV4_UNICAST => mrt_rib_message(input, false)?,
        MrtSubType::RIB_IPV6_UNICAST => mrt_rib_message(input, true)?,
        MrtSubType::BGP4MP_MESSAGE_AS4 => bgp4mp_message_as4(input)?,
        _ => (&input[..0], MrtMessage::NOT_IMPLEMENTED),
    };

    Ok((input, message))
}

/// Reads the given file and returns a vector of all MrtEntry found in that file
///
/// This potentially uses a lot of RAM, and it's likely better to use MrtFile instead
///
///  # Example
/// ```
/// use std::fs::File;
///
/// let f = File::open("example_data/openbgpd_rib_table-v2").unwrap();
/// let entries = mrt::read_file_complete(f).unwrap();
/// for entry in &entries {
///     println!("{:?}", entry);
/// }
/// ```
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

/// This struct makes it possible to read an MRT file iteratively
///
/// Entries can be returned as they are encountered
///
/// # Example
/// ```
/// use std::fs::File;
/// use mrt::MrtMessage;
/// let f = File::open("example_data/openbgpd_rib_table-v2").unwrap();
/// let mrtfile = mrt::MrtFile::new(f);
///
/// for mrt_entry in mrtfile {
///   match mrt_entry.message {
///     MrtMessage::RIB_IPV4_UNICAST {header, entries} => {
///       println!("header: {:?}", header);
///       for entry in entries {
///         println!("entry: {:?}", entry);
///       }
///     },
///     _ => continue,
///   }
/// }
/// ```
//#[derive(Debug)]
pub struct MrtFile {
    entry_buffer: Vec<u8>,
    reader: Box<dyn Read>,
}

impl MrtFile {
    pub fn new<T: Read + 'static>(reader: T) -> MrtFile {
        MrtFile {
            entry_buffer: vec![0; 8 * 1024],
            reader: Box::new(BufReader::new(reader)),
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

            let tmp = mrt_message(&self.entry_buffer[..(x.length as usize)], &x.mrt_subtype);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    //use test::Bencher;

    const EXAMPLE_DATA: &[u8] = include_bytes!("../example_data/openbgpd_rib_table-v2");

    #[test]
    fn parse_example_without_errors() {
        let mut remaining = EXAMPLE_DATA;
        assert_eq!(remaining.len(), 2143);

        let mut remaining_length_previous = remaining.len();

        while remaining.len() > 0 {
            let (remaining2, _) = mrt_entry(remaining).unwrap();
            remaining = remaining2;
            assert!(remaining_length_previous - remaining.len() > 0);
            remaining_length_previous = remaining.len();
        }
    }

    #[test]
    fn correct_mrt_header() {
        let (_, message) = mrt_entry(EXAMPLE_DATA).unwrap();
        assert_eq!(message.mrt_header.timestamp, 1444842656);
        assert_eq!(message.mrt_header.mrt_type, MrtType::TABLE_DUMP_V2);
        assert_eq!(message.mrt_header.mrt_subtype, MrtSubType::PEER_INDEX_TABLE);
    }

    const PEER_VALUES: [(u32, u32, &str, PeerType); 3] = [
        (
            65000,
            3232235530,
            "192.168.1.10",
            PeerType {
                as_number_size: AsNumberSize::Long,
                ip_address_family: IpFamily::V4,
            },
        ),
        (
            65000,
            3232235530,
            "2001:db8:0:1::10",
            PeerType {
                as_number_size: AsNumberSize::Long,
                ip_address_family: IpFamily::V6,
            },
        ),
        (
            65000,
            3232235622,
            "0.0.0.0",
            PeerType {
                as_number_size: AsNumberSize::Short,
                ip_address_family: IpFamily::V4,
            },
        ),
    ];
    #[test]
    fn correct_peer_index_table() {
        let (_, message) = mrt_entry(EXAMPLE_DATA).unwrap();

        if let MrtMessage::PEER_INDEX_TABLE {
            collector_bgp_id,
            view_name,
            peers,
        } = message.message
        {
            assert_eq!(collector_bgp_id, 3232235622);
            assert_eq!(view_name, "");
            for (i, peer) in peers.iter().enumerate() {
                assert_eq!(peer.peer_as, PEER_VALUES[i].0);
                assert_eq!(peer.peer_bgp_id, PEER_VALUES[i].1);
                assert_eq!(
                    peer.peer_ip_address,
                    IpAddr::from_str(PEER_VALUES[i].2).unwrap()
                );
                assert_eq!(peer.peer_type, PEER_VALUES[i].3);
            }
        } else {
            assert!(
                false,
                "First entry in example data has incorrect type (should be PEER_INDEX_TABLE)"
            );
        }
    }

    // Disable benchmarks until bench is stabilized
    /*#[bench]
    fn bench_parse_first_entry(b: &mut Bencher) {
        b.iter(|| mrt_entry(EXAMPLE_DATA))
    }

    #[bench]
    fn bench_parse_file(b: &mut Bencher) {
        b.iter(|| {
            let mut remaining = EXAMPLE_DATA;
            while remaining.len() > 0 {
                let (remaining2, _) = mrt_entry(remaining).unwrap();
                remaining = remaining2;
            }
        })
    }*/
}
