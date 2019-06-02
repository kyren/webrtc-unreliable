use std::{convert::TryInto, error::Error, fmt};

use byteorder::{ByteOrder, LittleEndian, NetworkEndian};
use crc32c::{crc32c, crc32c_append};

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
        state_cookie: &'a [u8],
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
    ShutdownAck,
    Error,
    CookieEcho {
        state_cookie: &'a [u8],
    },
    CookieAck,
    ShutdownComplete,
    Auth,
    AsConfAck,
    ReConfig,
    Pad,
    IData,
    ForwardTsn {
        new_cumulative_tsn: u32,
    },
    AsConf,
    IForwardTsn,
}

#[derive(Debug)]
pub struct SctpPacket<'a> {
    pub source_port: u16,
    pub dest_port: u16,
    pub verification_tag: u32,
    pub chunks: &'a [SctpChunk<'a>],
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
            SctpReadError::TooManyChunks => write!(f, "too many sctp chunks for provided buffer"),
        }
    }
}

impl Error for SctpReadError {}

pub fn read_sctp_packet<'a>(
    src: &'a [u8],
    check_crc: bool,
    chunk_space: &'a mut [SctpChunk<'a>],
) -> Result<SctpPacket<'a>, SctpReadError> {
    if src.len() < 16 {
        return Err(SctpReadError::BadPacket);
    }

    let source_port = NetworkEndian::read_u16(&src[0..2]);
    let dest_port = NetworkEndian::read_u16(&src[2..4]);
    let verification_tag = NetworkEndian::read_u32(&src[4..8]);
    let checksum = LittleEndian::read_u32(&src[8..12]);

    if check_crc {
        let mut crc = 0;
        crc = crc32c_append(crc, &src[0..8]);
        crc = crc32c_append(crc, &[0, 0, 0, 0]);
        crc = crc32c_append(crc, &src[12..]);
        if crc != checksum {
            return Err(SctpReadError::BadChecksum);
        }
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
        let chunk_len = NetworkEndian::read_u16(&remaining_chunks[2..4]);

        let chunk_next = next_multiple(chunk_len as usize, 4);
        if chunk_next > remaining_chunks.len() || chunk_len < 4 {
            return Err(SctpReadError::BadPacket);
        }

        let chunk_data = &remaining_chunks[4..chunk_len as usize];
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
                        || 16 + param_len as usize > chunk_data.len()
                    {
                        return Err(SctpReadError::BadPacket);
                    }

                    *chunk = SctpChunk::InitAck {
                        initiate_tag,
                        window_credit,
                        num_outbound_streams,
                        num_inbound_streams,
                        initial_tsn,
                        state_cookie: &chunk_data[20..16 + param_len as usize],
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
                    if param_type == HEARTBEAT_PARAM_INFO && (param_len as usize) < chunk_data.len()
                    {
                        heartbeat_info = Some(&chunk_data[4..param_len as usize]);
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
            CHUNK_TYPE_SHUTDOWN_ACK => {
                *chunk = SctpChunk::ShutdownAck;
            }
            CHUNK_TYPE_ERROR => {
                *chunk = SctpChunk::Error;
            }
            CHUNK_TYPE_COOKIE_ECHO => {
                *chunk = SctpChunk::CookieEcho {
                    state_cookie: chunk_data,
                }
            }
            CHUNK_TYPE_COOKIE_ACK => {
                *chunk = SctpChunk::CookieAck;
            }
            CHUNK_TYPE_SHUTDOWN_COMPLETE => {
                *chunk = SctpChunk::ShutdownComplete;
            }
            CHUNK_TYPE_AUTH => {
                *chunk = SctpChunk::Auth;
            }
            CHUNK_TYPE_ASCONF_ACK => {
                *chunk = SctpChunk::AsConfAck;
            }
            CHUNK_TYPE_RE_CONFIG => {
                *chunk = SctpChunk::ReConfig;
            }
            CHUNK_TYPE_PAD => {
                *chunk = SctpChunk::Pad;
            }
            CHUNK_TYPE_IDATA => {
                *chunk = SctpChunk::IData;
            }
            CHUNK_TYPE_FORWARD_TSN => {
                if chunk_data.len() < 4 {
                    return Err(SctpReadError::BadPacket);
                }

                let new_cumulative_tsn = NetworkEndian::read_u32(&chunk_data[0..4]);
                *chunk = SctpChunk::ForwardTsn { new_cumulative_tsn };
            }
            CHUNK_TYPE_ASCONF => {
                *chunk = SctpChunk::AsConf;
            }
            CHUNK_TYPE_I_FORWARD_TSN => {
                *chunk = SctpChunk::IForwardTsn;
            }
            _ => return Err(SctpReadError::BadPacket),
        }

        remaining_chunks = &remaining_chunks[chunk_next..];
        chunk_count += 1;
    }

    Ok(SctpPacket {
        source_port,
        dest_port,
        verification_tag,
        chunks: &chunk_space[0..chunk_count],
    })
}

#[derive(Debug)]
pub enum SctpWriteError {
    BufferSize,
    NoChunks,
    OutOfRange,
}

impl fmt::Display for SctpWriteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SctpWriteError::BufferSize => write!(f, "insufficient output buffer size"),
            SctpWriteError::NoChunks => write!(f, "SCTP packet must have at least one chunk"),
            SctpWriteError::OutOfRange => write!(f, "SCTP packet field is too large"),
        }
    }
}

impl Error for SctpWriteError {}

pub fn write_sctp_packet(dest: &mut [u8], packet: SctpPacket) -> Result<usize, SctpWriteError> {
    if packet.chunks.is_empty() {
        return Err(SctpWriteError::NoChunks);
    }

    if dest.len() < 12 {
        return Err(SctpWriteError::BufferSize);
    }

    NetworkEndian::write_u16(&mut dest[0..2], packet.source_port);
    NetworkEndian::write_u16(&mut dest[2..4], packet.dest_port);
    NetworkEndian::write_u32(&mut dest[4..8], packet.verification_tag);
    dest[8..12].copy_from_slice(&[0, 0, 0, 0]);

    let mut rest = &mut dest[12..];

    for &chunk in packet.chunks {
        if rest.len() < 8 {
            return Err(SctpWriteError::BufferSize);
        }

        let (chunk_header, chunk_data) = rest.split_at_mut(4);
        let (chunk_type, chunk_flags, data_len) = match chunk {
            SctpChunk::Data {
                chunk_flags,
                tsn,
                stream_id,
                stream_seq,
                proto_id,
                user_data,
            } => {
                let data_len = 12 + user_data.len();
                if chunk_data.len() < data_len {
                    return Err(SctpWriteError::BufferSize);
                }

                NetworkEndian::write_u32(&mut chunk_data[0..4], tsn);
                NetworkEndian::write_u16(&mut chunk_data[4..6], stream_id);
                NetworkEndian::write_u16(&mut chunk_data[6..8], stream_seq);
                NetworkEndian::write_u32(&mut chunk_data[8..12], proto_id);
                chunk_data[12..12 + user_data.len()].copy_from_slice(user_data);

                (CHUNK_TYPE_DATA, chunk_flags, data_len)
            }
            SctpChunk::Init {
                initiate_tag,
                window_credit,
                num_outbound_streams,
                num_inbound_streams,
                initial_tsn,
            } => {
                let data_len = 16;
                if chunk_data.len() < data_len {
                    return Err(SctpWriteError::BufferSize);
                }

                NetworkEndian::write_u32(&mut chunk_data[0..4], initiate_tag);
                NetworkEndian::write_u32(&mut chunk_data[4..8], window_credit);
                NetworkEndian::write_u16(&mut chunk_data[8..10], num_outbound_streams);
                NetworkEndian::write_u16(&mut chunk_data[10..12], num_inbound_streams);
                NetworkEndian::write_u32(&mut chunk_data[12..16], initial_tsn);

                (CHUNK_TYPE_INIT, 0, data_len)
            }
            SctpChunk::InitAck {
                initiate_tag,
                window_credit,
                num_outbound_streams,
                num_inbound_streams,
                initial_tsn,
                state_cookie,
            } => {
                let data_len = 20 + state_cookie.len();
                if chunk_data.len() < data_len {
                    return Err(SctpWriteError::BufferSize);
                }

                NetworkEndian::write_u32(&mut chunk_data[0..4], initiate_tag);
                NetworkEndian::write_u32(&mut chunk_data[4..8], window_credit);
                NetworkEndian::write_u16(&mut chunk_data[8..10], num_outbound_streams);
                NetworkEndian::write_u16(&mut chunk_data[10..12], num_inbound_streams);
                NetworkEndian::write_u32(&mut chunk_data[12..16], initial_tsn);
                NetworkEndian::write_u16(&mut chunk_data[16..18], INIT_ACK_PARAM_STATE_COOKIE);
                NetworkEndian::write_u16(
                    &mut chunk_data[18..20],
                    (state_cookie.len() + 4)
                        .try_into()
                        .map_err(|_| SctpWriteError::OutOfRange)?,
                );

                chunk_data[20..data_len].copy_from_slice(state_cookie);

                (CHUNK_TYPE_INIT_ACK, 0, data_len)
            }
            SctpChunk::SAck {
                cumulative_tsn_ack,
                adv_recv_window,
                num_gap_ack_blocks,
                num_dup_tsn,
            } => {
                let data_len = 12;
                if chunk_data.len() < data_len {
                    return Err(SctpWriteError::BufferSize);
                }

                NetworkEndian::write_u32(&mut chunk_data[0..4], cumulative_tsn_ack);
                NetworkEndian::write_u32(&mut chunk_data[4..8], adv_recv_window);
                NetworkEndian::write_u16(&mut chunk_data[8..10], num_gap_ack_blocks);
                NetworkEndian::write_u16(&mut chunk_data[10..12], num_dup_tsn);

                (CHUNK_TYPE_SACK, 0, data_len)
            }
            SctpChunk::Heartbeat { heartbeat_info }
            | SctpChunk::HeartbeatAck { heartbeat_info } => {
                let chunk_type = if let SctpChunk::Heartbeat { .. } = chunk {
                    CHUNK_TYPE_HEARTBEAT
                } else {
                    CHUNK_TYPE_HEARTBEAT_ACK
                };

                let data_len = if let Some(heartbeat_info) = heartbeat_info {
                    let data_len = 4 + heartbeat_info.len();
                    if chunk_data.len() < data_len {
                        return Err(SctpWriteError::BufferSize);
                    }

                    NetworkEndian::write_u16(&mut chunk_data[0..2], HEARTBEAT_PARAM_INFO);
                    NetworkEndian::write_u16(
                        &mut chunk_data[2..4],
                        (heartbeat_info.len() + 4)
                            .try_into()
                            .map_err(|_| SctpWriteError::OutOfRange)?,
                    );
                    chunk_data[4..4 + heartbeat_info.len()].copy_from_slice(heartbeat_info);
                    data_len
                } else {
                    0
                };

                (chunk_type, 0, data_len)
            }
            SctpChunk::Abort => (CHUNK_TYPE_ABORT, 0, 0),
            SctpChunk::Shutdown { cumulative_tsn_ack } => {
                let data_len = 4;
                if chunk_data.len() < 4 {
                    return Err(SctpWriteError::BufferSize);
                }
                NetworkEndian::write_u32(&mut chunk_data[0..4], cumulative_tsn_ack);
                (CHUNK_TYPE_SHUTDOWN, 0, data_len)
            }
            SctpChunk::ShutdownAck => (CHUNK_TYPE_SHUTDOWN_ACK, 0, 0),
            SctpChunk::CookieEcho { state_cookie } => {
                if chunk_data.len() < state_cookie.len() {
                    return Err(SctpWriteError::BufferSize);
                }
                chunk_data[0..state_cookie.len()].copy_from_slice(state_cookie);
                (CHUNK_TYPE_COOKIE_ECHO, 0, state_cookie.len())
            }
            SctpChunk::CookieAck => (CHUNK_TYPE_COOKIE_ACK, 0, 0),
            SctpChunk::ShutdownComplete => (CHUNK_TYPE_SHUTDOWN_COMPLETE, 0, 0),
            SctpChunk::ForwardTsn { new_cumulative_tsn } => {
                let data_len = 4;
                if chunk_data.len() < 4 {
                    return Err(SctpWriteError::BufferSize);
                }
                NetworkEndian::write_u32(&mut chunk_data[0..4], new_cumulative_tsn);
                (CHUNK_TYPE_FORWARD_TSN, 0, data_len)
            }
            chunk => unimplemented!("write for SCTP chunk {:?} not implemented", chunk),
        };

        let data_padded_len = next_multiple(data_len, 4);
        for i in data_len..data_padded_len {
            chunk_data[i] = 0;
        }
        let chunk_len = data_len + 4;
        let chunk_padded_len = data_padded_len + 4;

        chunk_header[0] = chunk_type;
        chunk_header[1] = chunk_flags;
        NetworkEndian::write_u16(
            &mut chunk_header[2..4],
            chunk_len
                .try_into()
                .map_err(|_| SctpWriteError::OutOfRange)?,
        );

        rest = &mut rest[chunk_padded_len..];
    }

    let remainder = rest.len();
    let len = dest.len() - remainder;
    let crc = crc32c(&dest[0..len]);
    LittleEndian::write_u32(&mut dest[8..12], crc);

    Ok(len)
}

const CHUNK_TYPE_DATA: u8 = 0x00;
const CHUNK_TYPE_INIT: u8 = 0x01;
const CHUNK_TYPE_INIT_ACK: u8 = 0x02;
const CHUNK_TYPE_SACK: u8 = 0x03;
const CHUNK_TYPE_HEARTBEAT: u8 = 0x04;
const CHUNK_TYPE_HEARTBEAT_ACK: u8 = 0x05;
const CHUNK_TYPE_ABORT: u8 = 0x06;
const CHUNK_TYPE_SHUTDOWN: u8 = 0x07;
const CHUNK_TYPE_SHUTDOWN_ACK: u8 = 0x08;
const CHUNK_TYPE_ERROR: u8 = 0x09;
const CHUNK_TYPE_COOKIE_ECHO: u8 = 0x0a;
const CHUNK_TYPE_COOKIE_ACK: u8 = 0x0b;
const CHUNK_TYPE_SHUTDOWN_COMPLETE: u8 = 0x0e;
const CHUNK_TYPE_AUTH: u8 = 0x0f;
const CHUNK_TYPE_ASCONF_ACK: u8 = 0x80;
const CHUNK_TYPE_RE_CONFIG: u8 = 0x82;
const CHUNK_TYPE_PAD: u8 = 0x84;
const CHUNK_TYPE_IDATA: u8 = 0x40;
const CHUNK_TYPE_FORWARD_TSN: u8 = 0xc0;
const CHUNK_TYPE_ASCONF: u8 = 0xc1;
const CHUNK_TYPE_I_FORWARD_TSN: u8 = 0xc2;

const INIT_ACK_PARAM_STATE_COOKIE: u16 = 0x07;
const HEARTBEAT_PARAM_INFO: u16 = 0x07;

fn next_multiple(s: usize, m: usize) -> usize {
    if s % m == 0 {
        s
    } else {
        s - s % m + m
    }
}
