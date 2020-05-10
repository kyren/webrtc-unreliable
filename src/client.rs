use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write},
    iter::Iterator,
    mem,
    net::SocketAddr,
    time::{Duration, Instant},
};

use openssl::{
    error::ErrorStack as OpenSslErrorStack,
    ssl::{
        Error as SslError, ErrorCode, HandshakeError, MidHandshakeSslStream, ShutdownResult,
        SslAcceptor, SslStream,
    },
};
use rand::{thread_rng, Rng};

use crate::buffer_pool::{BufferPool, OwnedBuffer};
use crate::sctp::{
    read_sctp_packet, write_sctp_packet, SctpChunk, SctpPacket, SctpWriteError,
    SCTP_FLAG_BEGIN_FRAGMENT, SCTP_FLAG_COMPLETE_UNRELIABLE, SCTP_FLAG_END_FRAGMENT,
};

/// Heartbeat packets will be generated at a maximum of this rate (if the connection is otherwise
/// idle).
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

// Maximum theoretical UDP payload size
pub const MAX_UDP_PAYLOAD_SIZE: usize = 65507;

// Derived through experimentation, any larger and openssl reports 'dtls message too big'.
pub const MAX_DTLS_MESSAGE_SIZE: usize = 16384;

pub const MAX_SCTP_PACKET_SIZE: usize = MAX_DTLS_MESSAGE_SIZE;

// The overhead of sending a single SCTP packet with a single data message.
pub const SCTP_MESSAGE_OVERHEAD: usize = 28;

/// Maximum supported theoretical size of a single WebRTC message, based on DTLS and SCTP packet
/// size limits.
///
/// WebRTC makes no attempt at packet fragmentation and re-assembly or to support fragmented
/// received messages, all sent and received unreliable messages must fit into a single SCTP packet.
/// As such, this maximum size is almost certainly too large for browsers to actually support.
/// Start with a much lower MTU (around 1200) and test it.
pub const MAX_MESSAGE_LEN: usize = MAX_SCTP_PACKET_SIZE - SCTP_MESSAGE_OVERHEAD;

#[derive(Debug)]
pub enum ClientError {
    TlsError(SslError),
    OpenSslError(OpenSslErrorStack),
    NotConnected,
    NotEstablished,
    IncompletePacketRead,
    IncompletePacketWrite,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            ClientError::TlsError(err) => fmt::Display::fmt(err, f),
            ClientError::OpenSslError(err) => fmt::Display::fmt(err, f),
            ClientError::NotConnected => write!(f, "client is not connected"),
            ClientError::NotEstablished => {
                write!(f, "client does not have an established WebRTC data channel")
            }
            ClientError::IncompletePacketRead => {
                write!(f, "WebRTC connection packet not completely read")
            }
            ClientError::IncompletePacketWrite => {
                write!(f, "WebRTC connection packet not completely written")
            }
        }
    }
}

impl Error for ClientError {}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MessageType {
    Text,
    Binary,
}

pub struct Client {
    buffer_pool: BufferPool,
    remote_addr: SocketAddr,
    ssl_state: ClientSslState,
    client_state: ClientState,
}

impl Client {
    pub fn new(
        ssl_acceptor: &SslAcceptor,
        buffer_pool: BufferPool,
        remote_addr: SocketAddr,
    ) -> Result<Client, OpenSslErrorStack> {
        match ssl_acceptor.accept(ClientSslPackets {
            buffer_pool: buffer_pool.clone(),
            incoming_udp: VecDeque::new(),
            outgoing_udp: VecDeque::new(),
        }) {
            Ok(_) => unreachable!("handshake cannot finish with no incoming packets"),
            Err(HandshakeError::SetupFailure(err)) => return Err(err),
            Err(HandshakeError::Failure(_)) => {
                unreachable!("handshake cannot fail before starting")
            }
            Err(HandshakeError::WouldBlock(mid_handshake)) => Ok(Client {
                buffer_pool,
                remote_addr,
                ssl_state: ClientSslState::Handshake(mid_handshake),
                client_state: ClientState {
                    last_activity: Instant::now(),
                    last_sent: Instant::now(),
                    received_messages: Vec::new(),
                    sctp_state: SctpState::Shutdown,
                    sctp_local_port: 0,
                    sctp_remote_port: 0,
                    sctp_local_verification_tag: 0,
                    sctp_remote_verification_tag: 0,
                    sctp_local_tsn: 0,
                    sctp_remote_tsn: 0,
                },
            }),
        }
    }

    /// DTLS and SCTP states are established, and RTC messages may be sent
    pub fn is_established(&self) -> bool {
        match (&self.ssl_state, self.client_state.sctp_state) {
            (ClientSslState::Established(_), SctpState::Established) => true,
            _ => false,
        }
    }

    /// Time of last activity that indicates a working connection
    pub fn last_activity(&self) -> Instant {
        self.client_state.last_activity
    }

    /// Request SCTP and DTLS shutdown, connection immediately becomes un-established
    pub fn start_shutdown(&mut self) -> Result<(), ClientError> {
        self.ssl_state = match mem::replace(&mut self.ssl_state, ClientSslState::Shutdown) {
            ClientSslState::Established(mut ssl_stream) => {
                if self.client_state.sctp_state != SctpState::Shutdown {
                    // TODO: For now, we just do an immediate one-sided SCTP abort
                    send_sctp_packet(
                        &self.buffer_pool,
                        &mut ssl_stream,
                        SctpPacket {
                            source_port: self.client_state.sctp_local_port,
                            dest_port: self.client_state.sctp_remote_port,
                            verification_tag: self.client_state.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::Abort],
                        },
                    )?;
                    self.client_state.last_sent = Instant::now();
                    self.client_state.sctp_state = SctpState::Shutdown;
                }
                match ssl_stream.shutdown().map_err(ssl_err_to_client_err)? {
                    ShutdownResult::Sent => ClientSslState::ShuttingDown(ssl_stream),
                    ShutdownResult::Received => ClientSslState::Shutdown,
                }
            }
            prev_state => prev_state,
        };
        Ok(())
    }

    /// Returns true if the shutdown process has been started or has already finished.
    pub fn shutdown_started(&self) -> bool {
        match &self.ssl_state {
            ClientSslState::ShuttingDown(_) | ClientSslState::Shutdown => true,
            _ => false,
        }
    }

    /// Connection has either timed out or finished shutting down.
    pub fn is_shutdown(&self) -> bool {
        match &self.ssl_state {
            ClientSslState::Shutdown => true,
            _ => false,
        }
    }

    /// Generate any periodic packets, currently only heartbeat packets.
    pub fn generate_periodic(&mut self) -> Result<(), ClientError> {
        // We send heartbeat packets if the last sent packet was more than HEARTBEAT_INTERVAL ago
        if self.client_state.last_sent.elapsed() > HEARTBEAT_INTERVAL {
            match &mut self.ssl_state {
                ClientSslState::Established(ssl_stream) => {
                    if self.client_state.sctp_state == SctpState::Established {
                        send_sctp_packet(
                            &self.buffer_pool,
                            ssl_stream,
                            SctpPacket {
                                source_port: self.client_state.sctp_local_port,
                                dest_port: self.client_state.sctp_remote_port,
                                verification_tag: self.client_state.sctp_remote_verification_tag,
                                chunks: &[SctpChunk::Heartbeat {
                                    heartbeat_info: Some(SCTP_HEARTBEAT),
                                }],
                            },
                        )?;
                        self.client_state.last_sent = Instant::now();
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Pushes an available UDP packet.  Will error if called when the client is currently in the
    /// shutdown state.
    pub fn receive_incoming_packet(&mut self, udp_packet: OwnedBuffer) -> Result<(), ClientError> {
        self.ssl_state = match mem::replace(&mut self.ssl_state, ClientSslState::Shutdown) {
            ClientSslState::Handshake(mut mid_handshake) => {
                mid_handshake.get_mut().incoming_udp.push_back(udp_packet);
                match mid_handshake.handshake() {
                    Ok(ssl_stream) => {
                        log::info!("DTLS handshake finished for remote {}", self.remote_addr);
                        ClientSslState::Established(ssl_stream)
                    }
                    Err(handshake_error) => match handshake_error {
                        HandshakeError::SetupFailure(err) => {
                            return Err(ClientError::OpenSslError(err));
                        }
                        HandshakeError::Failure(mid_handshake) => {
                            log::warn!(
                                "SSL handshake failure with remote {}: {}",
                                self.remote_addr,
                                mid_handshake.error()
                            );
                            ClientSslState::Handshake(mid_handshake)
                        }
                        HandshakeError::WouldBlock(mid_handshake) => {
                            ClientSslState::Handshake(mid_handshake)
                        }
                    },
                }
            }
            ClientSslState::Established(mut ssl_stream) => {
                ssl_stream.get_mut().incoming_udp.push_back(udp_packet);
                ClientSslState::Established(ssl_stream)
            }
            ClientSslState::ShuttingDown(mut ssl_stream) => {
                ssl_stream.get_mut().incoming_udp.push_back(udp_packet);
                match ssl_stream.shutdown() {
                    Err(err) => {
                        if err.code() == ErrorCode::WANT_READ {
                            ClientSslState::ShuttingDown(ssl_stream)
                        } else {
                            return Err(ssl_err_to_client_err(err));
                        }
                    }
                    Ok(ShutdownResult::Sent) => ClientSslState::ShuttingDown(ssl_stream),
                    Ok(ShutdownResult::Received) => ClientSslState::Shutdown,
                }
            }
            ClientSslState::Shutdown => return Err(ClientError::NotConnected),
        };

        while let ClientSslState::Established(ssl_stream) = &mut self.ssl_state {
            let mut ssl_buffer = self.buffer_pool.acquire();
            ssl_buffer.resize(MAX_SCTP_PACKET_SIZE, 0);
            match ssl_stream.ssl_read(&mut ssl_buffer) {
                Ok(size) => {
                    let mut sctp_chunks = [SctpChunk::Abort; SCTP_MAX_CHUNKS];
                    match read_sctp_packet(&ssl_buffer[0..size], false, &mut sctp_chunks) {
                        Ok(sctp_packet) => {
                            if !receive_sctp_packet(
                                &self.buffer_pool,
                                ssl_stream,
                                &mut self.client_state,
                                &sctp_packet,
                            )? {
                                drop(ssl_buffer);
                                self.start_shutdown()?;
                            }
                        }
                        Err(err) => {
                            log::debug!("sctp read error on packet received over DTLS: {}", err);
                        }
                    }
                }
                Err(err) => {
                    if err.code() == ErrorCode::WANT_READ {
                        break;
                    } else if err.code() == ErrorCode::ZERO_RETURN {
                        log::info!("DTLS received close notify");
                        drop(ssl_buffer);
                        self.start_shutdown()?;
                    } else {
                        return Err(ssl_err_to_client_err(err));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn take_outgoing_packets<'a>(&'a mut self) -> impl Iterator<Item = OwnedBuffer> + 'a {
        (match &mut self.ssl_state {
            ClientSslState::Handshake(mid_handshake) => {
                Some(mid_handshake.get_mut().outgoing_udp.drain(..))
            }
            ClientSslState::Established(ssl_stream) | ClientSslState::ShuttingDown(ssl_stream) => {
                Some(ssl_stream.get_mut().outgoing_udp.drain(..))
            }
            ClientSslState::Shutdown => None,
        })
        .into_iter()
        .flatten()
    }

    pub fn send_message(
        &mut self,
        message_type: MessageType,
        message: &[u8],
    ) -> Result<(), ClientError> {
        let ssl_stream = match &mut self.ssl_state {
            ClientSslState::Established(ssl_stream) => ssl_stream,
            _ => {
                return Err(ClientError::NotConnected);
            }
        };

        if self.client_state.sctp_state != SctpState::Established {
            return Err(ClientError::NotEstablished);
        }

        let proto_id = if message_type == MessageType::Text {
            DATA_CHANNEL_PROTO_STRING
        } else {
            DATA_CHANNEL_PROTO_BINARY
        };

        send_sctp_packet(
            &self.buffer_pool,
            ssl_stream,
            SctpPacket {
                source_port: self.client_state.sctp_local_port,
                dest_port: self.client_state.sctp_remote_port,
                verification_tag: self.client_state.sctp_remote_verification_tag,
                chunks: &[SctpChunk::Data {
                    chunk_flags: SCTP_FLAG_COMPLETE_UNRELIABLE,
                    tsn: self.client_state.sctp_local_tsn,
                    stream_id: 0,
                    stream_seq: 0,
                    proto_id,
                    user_data: message,
                }],
            },
        )?;
        self.client_state.sctp_local_tsn = self.client_state.sctp_local_tsn.wrapping_add(1);

        Ok(())
    }

    pub fn receive_messages<'a>(
        &'a mut self,
    ) -> impl Iterator<Item = (MessageType, OwnedBuffer)> + 'a {
        self.client_state.received_messages.drain(..)
    }
}

pub struct ClientState {
    last_activity: Instant,
    last_sent: Instant,

    received_messages: Vec<(MessageType, OwnedBuffer)>,

    sctp_state: SctpState,

    sctp_local_port: u16,
    sctp_remote_port: u16,

    sctp_local_verification_tag: u32,
    sctp_remote_verification_tag: u32,

    sctp_local_tsn: u32,
    sctp_remote_tsn: u32,
}

enum ClientSslState {
    Handshake(MidHandshakeSslStream<ClientSslPackets>),
    Established(SslStream<ClientSslPackets>),
    ShuttingDown(SslStream<ClientSslPackets>),
    Shutdown,
}

#[derive(Debug)]
struct ClientSslPackets {
    buffer_pool: BufferPool,
    incoming_udp: VecDeque<OwnedBuffer>,
    outgoing_udp: VecDeque<OwnedBuffer>,
}

impl Read for ClientSslPackets {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        if let Some(next_packet) = self.incoming_udp.pop_front() {
            let next_packet = self.buffer_pool.adopt(next_packet);
            if next_packet.len() > buf.len() {
                return Err(IoError::new(
                    IoErrorKind::Other,
                    ClientError::IncompletePacketRead,
                ));
            }
            buf[0..next_packet.len()].copy_from_slice(&next_packet);
            Ok(next_packet.len())
        } else {
            Err(IoErrorKind::WouldBlock.into())
        }
    }
}

impl Write for ClientSslPackets {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
        let mut buffer = self.buffer_pool.acquire();
        buffer.extend_from_slice(buf);
        self.outgoing_udp.push_back(buffer.into_owned());
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        Ok(())
    }
}

const SCTP_COOKIE: &[u8] = b"WEBRTC-UNRELIABLE-COOKIE";
const SCTP_HEARTBEAT: &[u8] = b"WEBRTC-UNRELIABLE-HEARTBEAT";
const SCTP_MAX_CHUNKS: usize = 16;
const SCTP_BUFFER_SIZE: u32 = 0x40000;

const DATA_CHANNEL_PROTO_CONTROL: u32 = 50;
const DATA_CHANNEL_PROTO_STRING: u32 = 51;
const DATA_CHANNEL_PROTO_BINARY: u32 = 53;

const DATA_CHANNEL_MESSAGE_ACK: u8 = 2;
const DATA_CHANNEL_MESSAGE_OPEN: u8 = 3;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum SctpState {
    Shutdown,
    InitAck,
    Established,
}

fn ssl_err_to_client_err(err: SslError) -> ClientError {
    if let Some(io_err) = err.io_error() {
        if let Some(inner) = io_err.get_ref() {
            if inner.is::<ClientError>() {
                return *err
                    .into_io_error()
                    .unwrap()
                    .into_inner()
                    .unwrap()
                    .downcast()
                    .unwrap();
            }
        }
    }

    ClientError::TlsError(err)
}

fn max_tsn(a: u32, b: u32) -> u32 {
    if a > b {
        if a - b < (1 << 31) {
            a
        } else {
            b
        }
    } else {
        if b - a < (1 << 31) {
            b
        } else {
            a
        }
    }
}

fn send_sctp_packet(
    buffer_pool: &BufferPool,
    ssl_stream: &mut SslStream<ClientSslPackets>,
    sctp_packet: SctpPacket,
) -> Result<(), ClientError> {
    let mut sctp_buffer = buffer_pool.acquire();
    sctp_buffer.resize(MAX_SCTP_PACKET_SIZE, 0);

    let packet_len = match write_sctp_packet(&mut sctp_buffer, sctp_packet) {
        Ok(len) => len,
        Err(SctpWriteError::BufferSize) => {
            return Err(ClientError::IncompletePacketWrite);
        }
        Err(err) => panic!("error writing SCTP packet: {}", err),
    };

    assert_eq!(
        ssl_stream
            .ssl_write(&sctp_buffer[0..packet_len])
            .map_err(ssl_err_to_client_err)?,
        packet_len
    );

    Ok(())
}

fn receive_sctp_packet(
    buffer_pool: &BufferPool,
    ssl_stream: &mut SslStream<ClientSslPackets>,
    client_state: &mut ClientState,
    sctp_packet: &SctpPacket,
) -> Result<bool, ClientError> {
    for chunk in sctp_packet.chunks {
        match *chunk {
            SctpChunk::Init {
                initiate_tag,
                window_credit: _,
                num_outbound_streams,
                num_inbound_streams,
                initial_tsn,
                support_unreliable,
            } => {
                if !support_unreliable {
                    log::warn!("peer does not support selective unreliability, abort connection");
                    client_state.sctp_state = SctpState::Shutdown;
                    return Ok(false);
                }

                let mut rng = thread_rng();

                client_state.sctp_local_port = sctp_packet.dest_port;
                client_state.sctp_remote_port = sctp_packet.source_port;

                client_state.sctp_local_verification_tag = rng.gen();
                client_state.sctp_remote_verification_tag = initiate_tag;

                client_state.sctp_local_tsn = rng.gen();
                client_state.sctp_remote_tsn = initial_tsn;

                send_sctp_packet(
                    &buffer_pool,
                    ssl_stream,
                    SctpPacket {
                        source_port: client_state.sctp_local_port,
                        dest_port: client_state.sctp_remote_port,
                        verification_tag: client_state.sctp_remote_verification_tag,
                        chunks: &[SctpChunk::InitAck {
                            initiate_tag: client_state.sctp_local_verification_tag,
                            window_credit: SCTP_BUFFER_SIZE,
                            num_outbound_streams: num_outbound_streams,
                            num_inbound_streams: num_inbound_streams,
                            initial_tsn: client_state.sctp_local_tsn,
                            state_cookie: SCTP_COOKIE,
                        }],
                    },
                )?;

                client_state.sctp_state = SctpState::InitAck;
                client_state.last_activity = Instant::now();
                client_state.last_sent = Instant::now();
            }
            SctpChunk::CookieEcho { state_cookie } => {
                if state_cookie == SCTP_COOKIE && client_state.sctp_state != SctpState::Shutdown {
                    send_sctp_packet(
                        &buffer_pool,
                        ssl_stream,
                        SctpPacket {
                            source_port: client_state.sctp_local_port,
                            dest_port: client_state.sctp_remote_port,
                            verification_tag: client_state.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::CookieAck],
                        },
                    )?;
                    client_state.last_sent = Instant::now();

                    if client_state.sctp_state == SctpState::InitAck {
                        client_state.sctp_state = SctpState::Established;
                        client_state.last_activity = Instant::now();
                    }
                }
            }
            SctpChunk::Data {
                chunk_flags,
                tsn,
                stream_id,
                stream_seq: _,
                proto_id,
                user_data,
            } => {
                if chunk_flags & SCTP_FLAG_BEGIN_FRAGMENT == 0
                    || chunk_flags & SCTP_FLAG_END_FRAGMENT == 0
                {
                    log::debug!("received fragmented SCTP packet, dropping");
                } else {
                    client_state.sctp_remote_tsn = max_tsn(client_state.sctp_remote_tsn, tsn);

                    if proto_id == DATA_CHANNEL_PROTO_CONTROL {
                        if !user_data.is_empty() {
                            if user_data[0] == DATA_CHANNEL_MESSAGE_OPEN {
                                send_sctp_packet(
                                    &buffer_pool,
                                    ssl_stream,
                                    SctpPacket {
                                        source_port: client_state.sctp_local_port,
                                        dest_port: client_state.sctp_remote_port,
                                        verification_tag: client_state.sctp_remote_verification_tag,
                                        chunks: &[SctpChunk::Data {
                                            chunk_flags: SCTP_FLAG_COMPLETE_UNRELIABLE,
                                            tsn: client_state.sctp_local_tsn,
                                            stream_id,
                                            stream_seq: 0,
                                            proto_id: DATA_CHANNEL_PROTO_CONTROL,
                                            user_data: &[DATA_CHANNEL_MESSAGE_ACK],
                                        }],
                                    },
                                )?;
                                client_state.sctp_local_tsn =
                                    client_state.sctp_local_tsn.wrapping_add(1);
                            }
                        }
                    } else if proto_id == DATA_CHANNEL_PROTO_STRING {
                        let mut msg_buffer = buffer_pool.acquire();
                        msg_buffer.extend(user_data);
                        client_state
                            .received_messages
                            .push((MessageType::Text, msg_buffer.into_owned()));
                    } else if proto_id == DATA_CHANNEL_PROTO_BINARY {
                        let mut msg_buffer = buffer_pool.acquire();
                        msg_buffer.extend(user_data);
                        client_state
                            .received_messages
                            .push((MessageType::Binary, msg_buffer.into_owned()));
                    }

                    send_sctp_packet(
                        &buffer_pool,
                        ssl_stream,
                        SctpPacket {
                            source_port: client_state.sctp_local_port,
                            dest_port: client_state.sctp_remote_port,
                            verification_tag: client_state.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::SAck {
                                cumulative_tsn_ack: client_state.sctp_remote_tsn,
                                adv_recv_window: SCTP_BUFFER_SIZE,
                                num_gap_ack_blocks: 0,
                                num_dup_tsn: 0,
                            }],
                        },
                    )?;

                    client_state.last_activity = Instant::now();
                    client_state.last_sent = Instant::now();
                }
            }
            SctpChunk::Heartbeat { heartbeat_info } => {
                send_sctp_packet(
                    &buffer_pool,
                    ssl_stream,
                    SctpPacket {
                        source_port: client_state.sctp_local_port,
                        dest_port: client_state.sctp_remote_port,
                        verification_tag: client_state.sctp_remote_verification_tag,
                        chunks: &[SctpChunk::HeartbeatAck { heartbeat_info }],
                    },
                )?;
                client_state.last_activity = Instant::now();
                client_state.last_sent = Instant::now();
            }
            SctpChunk::HeartbeatAck { .. } => {
                client_state.last_activity = Instant::now();
            }
            SctpChunk::SAck {
                cumulative_tsn_ack: _,
                adv_recv_window: _,
                num_gap_ack_blocks,
                num_dup_tsn: _,
            } => {
                if num_gap_ack_blocks > 0 {
                    send_sctp_packet(
                        &buffer_pool,
                        ssl_stream,
                        SctpPacket {
                            source_port: client_state.sctp_local_port,
                            dest_port: client_state.sctp_remote_port,
                            verification_tag: client_state.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::ForwardTsn {
                                new_cumulative_tsn: client_state.sctp_local_tsn,
                            }],
                        },
                    )?;
                    client_state.last_sent = Instant::now();
                }
                client_state.last_activity = Instant::now();
            }
            SctpChunk::Shutdown { .. } => {
                send_sctp_packet(
                    &buffer_pool,
                    ssl_stream,
                    SctpPacket {
                        source_port: client_state.sctp_local_port,
                        dest_port: client_state.sctp_remote_port,
                        verification_tag: client_state.sctp_remote_verification_tag,
                        chunks: &[SctpChunk::ShutdownAck],
                    },
                )?;
            }
            SctpChunk::ShutdownAck { .. } | SctpChunk::Abort => {
                client_state.sctp_state = SctpState::Shutdown;
                return Ok(false);
            }
            SctpChunk::ForwardTsn { new_cumulative_tsn } => {
                client_state.sctp_remote_tsn = new_cumulative_tsn;
            }
            SctpChunk::InitAck { .. } | SctpChunk::CookieAck => {}
            SctpChunk::Error {
                first_param_type,
                first_param_data,
            } => {
                log::warn!(
                    "SCTP error chunk received: {} {:?}",
                    first_param_type,
                    first_param_data
                );
            }
            chunk => log::debug!("unhandled SCTP chunk {:?}", chunk),
        }
    }

    Ok(true)
}
