use std::{error::Error, fmt};

use byteorder::{ByteOrder, LittleEndian, NetworkEndian};
use crc32c::crc32c_append;

pub const SCTP_FLAG_END_FRAGMENT: u8 = 0x01;
pub const SCTP_FLAG_BEGIN_FRAGMENT: u8 = 0x02;
pub const SCTP_FLAG_UNRELIABLE: u8 = 0x04;

pub const SCTP_FLAG_COMPLETE_UNRELIABLE: u8 =
    SCTP_FLAG_BEGIN_FRAGMENT | SCTP_FLAG_END_FRAGMENT | SCTP_FLAG_UNRELIABLE;

#[derive(Debug, Copy, Clone)]
pub enum SctpChunk<'a> {
    Data {
        chunk_flags: u8,
        tsn: u32,
        stream_id: u16,
        stream_seq: u16,
        proto_id: u32,
        user_data: &'a [u8],
    },
    Init {
        initiate_tag: u32,
        window_credit: u32,
        num_outbound_streams: u16,
        num_inbound_streams: u16,
        initial_tsn: u32,
    },
    InitAck {
        initiate_tag: u32,
        window_credit: u32,
        num_outbound_streams: u16,
        num_inbound_streams: u16,
        initial_tsn: u32,
        cookie: &'a [u8],
    },
    SAck {
        cumulative_tsn_ack: u32,
        adv_recv_window: u32,
        num_gap_ack_blocks: u16,
        num_dup_tsn: u16,
    },
    Heartbeat {
        heartbeat_info: Option<&'a [u8]>,
    },
    HeartbeatAck {
        heartbeat_info: Option<&'a [u8]>,
    },
    Abort,
    Shutdown {
        cumulative_tsn_ack: u32,
    },
    CookieEcho {
        cookie: &'a [u8],
    },
    CookieAck,
    ForwardTsn {
        new_cumulative_tsn: u32,
    },
}

#[derive(Debug)]
pub struct SctpPacket<'a> {
    source_port: u16,
    dest_port: u16,
    verification_tag: u32,
    chunks: &'a [SctpChunk<'a>],
}

#[derive(Debug)]
pub enum SctpReadError {
    BadPacket,
    BadChecksum,
    TooManyChunks,
}

impl fmt::Display for SctpReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SctpReadError::BadPacket => write!(f, "bad sctp packet"),
            SctpReadError::BadChecksum => write!(f, "bad sctp checksum"),
            SctpReadError::TooManyChunks => write!(f, "too many sctp chunks"),
        }
    }
}

impl Error for SctpReadError {}

pub fn read_sctp_packet<'a>(
    src: &'a [u8],
    chunk_space: &'a mut [SctpChunk<'a>],
) -> Result<SctpPacket<'a>, SctpReadError> {
    if src.len() < 16 {
        return Err(SctpReadError::BadPacket);
    }

    let source_port = NetworkEndian::read_u16(&src[0..2]);
    let dest_port = NetworkEndian::read_u16(&src[2..4]);
    let verification_tag = NetworkEndian::read_u32(&src[4..8]);
    let checksum = LittleEndian::read_u32(&src[8..12]);

    let mut crc = 0;
    crc = crc32c_append(crc, &src[0..8]);
    crc = crc32c_append(crc, &[0, 0, 0, 0]);
    crc = crc32c_append(crc, &src[12..]);
    if crc != checksum {
        return Err(SctpReadError::BadChecksum);
    }

    let mut remaining_chunks = &src[12..];
    let mut chunk_count = 0;
    while remaining_chunks.len() > 4 {
        if chunk_count >= chunk_space.len() {
            return Err(SctpReadError::TooManyChunks);
        }
        let chunk = &mut chunk_space[chunk_count];

        let chunk_type = remaining_chunks[0];
        let chunk_flags = remaining_chunks[1];
        let chunk_length = NetworkEndian::read_u16(&remaining_chunks[2..4]);

        if chunk_length as usize >= remaining_chunks.len() {
            return Err(SctpReadError::BadPacket);
        }

        let chunk_data = &remaining_chunks[4..chunk_length as usize];
        match chunk_type {
            CHUNK_TYPE_DATA => {
                if chunk_data.len() < 12 {
                    return Err(SctpReadError::BadPacket);
                }

                let tsn = NetworkEndian::read_u32(&chunk_data[0..4]);
                let stream_id = NetworkEndian::read_u16(&chunk_data[4..6]);
                let stream_seq = NetworkEndian::read_u16(&chunk_data[6..8]);
                let proto_id = NetworkEndian::read_u32(&chunk_data[8..12]);
                let user_data = &chunk_data[12..];
                *chunk = SctpChunk::Data {
                    chunk_flags,
                    tsn,
                    stream_id,
                    stream_seq,
                    proto_id,
                    user_data,
                };
            }
            CHUNK_TYPE_INIT | CHUNK_TYPE_INIT_ACK => {
                if chunk_data.len() < 16 {
                    return Err(SctpReadError::BadPacket);
                }

                let initiate_tag = NetworkEndian::read_u32(&chunk_data[0..4]);
                let window_credit = NetworkEndian::read_u32(&chunk_data[4..8]);
                let num_outbound_streams = NetworkEndian::read_u16(&chunk_data[8..10]);
                let num_inbound_streams = NetworkEndian::read_u16(&chunk_data[10..12]);
                let initial_tsn = NetworkEndian::read_u32(&chunk_data[12..16]);

                if chunk_type == CHUNK_TYPE_INIT {
                    *chunk = SctpChunk::Init {
                        initiate_tag,
                        window_credit,
                        num_outbound_streams,
                        num_inbound_streams,
                        initial_tsn,
                    };
                } else {
                    if chunk_data.len() < 20 {
                        return Err(SctpReadError::BadPacket);
                    }

                    let param_type = NetworkEndian::read_u16(&chunk_data[16..18]);
                    let param_len = NetworkEndian::read_u16(&chunk_data[18..20]);

                    if param_type != INIT_ACK_PARAM_STATE_COOKIE
                        || 20 + param_len as usize >= chunk_data.len()
                    {
                        return Err(SctpReadError::BadPacket);
                    }

                    *chunk = SctpChunk::InitAck {
                        initiate_tag,
                        window_credit,
                        num_outbound_streams,
                        num_inbound_streams,
                        initial_tsn,
                        cookie: &chunk_data[20..20 + param_len as usize],
                    };
                }
            }
            CHUNK_TYPE_SACK => {
                if chunk_data.len() < 12 {
                    return Err(SctpReadError::BadPacket);
                }

                let cumulative_tsn_ack = NetworkEndian::read_u32(&chunk_data[0..4]);
                let adv_recv_window = NetworkEndian::read_u32(&chunk_data[4..8]);
                let num_gap_ack_blocks = NetworkEndian::read_u16(&chunk_data[8..10]);
                let num_dup_tsn = NetworkEndian::read_u16(&chunk_data[10..12]);

                *chunk = SctpChunk::SAck {
                    cumulative_tsn_ack,
                    adv_recv_window,
                    num_gap_ack_blocks,
                    num_dup_tsn,
                };
            }
            CHUNK_TYPE_HEARTBEAT | CHUNK_TYPE_HEARTBEAT_ACK => {
                let mut heartbeat_info = None;
                if chunk_data.len() > 4 {
                    let param_type = NetworkEndian::read_u16(&chunk_data[0..2]);
                    let param_len = NetworkEndian::read_u16(&chunk_data[2..4]);
                    if param_type == HEARTBEAT_PARAM_INFO
                        && 4 + (param_len as usize) < chunk_data.len()
                    {
                        heartbeat_info = Some(&chunk_data[4..4 + param_len as usize]);
                    }
                }

                if chunk_type == CHUNK_TYPE_HEARTBEAT {
                    *chunk = SctpChunk::Heartbeat { heartbeat_info };
                } else {
                    *chunk = SctpChunk::HeartbeatAck { heartbeat_info };
                }
            }
            CHUNK_TYPE_ABORT => {
                *chunk = SctpChunk::Abort;
            }
            CHUNK_TYPE_SHUTDOWN => {
                if chunk_data.len() < 4 {
                    return Err(SctpReadError::BadPacket);
                }

                let cumulative_tsn_ack = NetworkEndian::read_u32(&chunk_data[0..4]);

                *chunk = SctpChunk::Shutdown { cumulative_tsn_ack };
            }
            CHUNK_TYPE_COOKIE_ECHO => *chunk = SctpChunk::CookieEcho { cookie: chunk_data },
            CHUNK_TYPE_COOKIE_ACK => {
                *chunk = SctpChunk::CookieAck;
            }
            CHUNK_TYPE_FORWARD_TSN => {
                if chunk_data.len() < 4 {
                    return Err(SctpReadError::BadPacket);
                }

                let new_cumulative_tsn = NetworkEndian::read_u32(&chunk_data[0..4]);
                *chunk = SctpChunk::ForwardTsn { new_cumulative_tsn };
            }
            _ => unimplemented!(),
        }

        remaining_chunks = &remaining_chunks[chunk_length as usize..];
        chunk_count += 1;
    }

    Ok(SctpPacket {
        source_port,
        dest_port,
        verification_tag,
        chunks: &chunk_space[0..chunk_count],
    })
}

pub fn write_sctp_packet(dest: &mut [u8], packet: SctpPacket) -> Option<usize> {
    unimplemented!()
}

const CHUNK_TYPE_DATA: u8 = 0x00;
const CHUNK_TYPE_INIT: u8 = 0x01;
const CHUNK_TYPE_INIT_ACK: u8 = 0x02;
const CHUNK_TYPE_SACK: u8 = 0x03;
const CHUNK_TYPE_HEARTBEAT: u8 = 0x04;
const CHUNK_TYPE_HEARTBEAT_ACK: u8 = 0x05;
const CHUNK_TYPE_ABORT: u8 = 0x06;
const CHUNK_TYPE_SHUTDOWN: u8 = 0x07;
const CHUNK_TYPE_COOKIE_ECHO: u8 = 0x0a;
const CHUNK_TYPE_COOKIE_ACK: u8 = 0x0b;
const CHUNK_TYPE_FORWARD_TSN: u8 = 0xc0;

const INIT_ACK_PARAM_STATE_COOKIE: u16 = 0x07;
const HEARTBEAT_PARAM_INFO: u16 = 0x07;
