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

use log::{info, warn};
use openssl::{
    error::ErrorStack as OpenSslErrorStack,
    ssl::{
        Error as SslError, ErrorCode, HandshakeError, MidHandshakeSslStream, ShutdownState,
        SslAcceptor, SslStream,
    },
};
use rand::{thread_rng, Rng};

use crate::buffer_pool::{BufferPool, PooledBuffer};
use crate::sctp::{
    read_sctp_packet, write_sctp_packet, SctpChunk, SctpPacket, SctpWriteError,
    SCTP_FLAG_COMPLETE_UNRELIABLE,
};

/// Heartbeat packets will be generated at a maximum of this rate (if the connection is otherwise
/// idle).
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

// TODO: I'm not sure whether this is correct
pub const MAX_SCTP_PACKET_SIZE: usize = MAX_DTLS_MESSAGE_SIZE;
pub const MAX_DTLS_MESSAGE_SIZE: usize = 16384;
pub const MAX_UDP_PAYLOAD_SIZE: usize = 65507;

#[derive(Debug)]
pub enum RtcClientError {
    TlsError(SslError),
    OpenSslError(OpenSslErrorStack),
    NotConnected,
    NotEstablished,
    IncompletePacketRead,
    IncompletePacketWrite,
}

impl fmt::Display for RtcClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            RtcClientError::TlsError(err) => fmt::Display::fmt(err, f),
            RtcClientError::OpenSslError(err) => fmt::Display::fmt(err, f),
            RtcClientError::NotConnected => write!(f, "client is not connected"),
            RtcClientError::NotEstablished => {
                write!(f, "client does not have an established WebRTC data channel")
            }
            RtcClientError::IncompletePacketRead => {
                write!(f, "WebRTC connection packet not completely read")
            }
            RtcClientError::IncompletePacketWrite => {
                write!(f, "WebRTC connection packet not completely written")
            }
        }
    }
}

impl Error for RtcClientError {}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RtcMessageType {
    Text,
    Binary,
}

pub struct RtcClient {
    remote_addr: SocketAddr,
    ssl_state: ClientSslState,

    last_activity: Instant,
    last_sent: Instant,

    received_messages: Vec<(RtcMessageType, PooledBuffer)>,

    sctp_state: SctpState,

    sctp_local_port: u16,
    sctp_remote_port: u16,

    sctp_local_verification_tag: u32,
    sctp_remote_verification_tag: u32,

    sctp_local_tsn: u32,
    sctp_remote_tsn: u32,
}

impl RtcClient {
    pub fn new(
        ssl_acceptor: &SslAcceptor,
        buffer_pool: BufferPool,
        remote_addr: SocketAddr,
    ) -> Result<RtcClient, OpenSslErrorStack> {
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
            Err(HandshakeError::WouldBlock(mid_handshake)) => Ok(RtcClient {
                remote_addr,
                ssl_state: ClientSslState::Unestablished(Some(mid_handshake)),
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
            }),
        }
    }

    /// DTLS and SCTP states are established, and RTC messages may be sent
    pub fn is_established(&self) -> bool {
        match (&self.ssl_state, self.sctp_state) {
            (ClientSslState::Established(_), SctpState::Established) => true,
            _ => false,
        }
    }

    /// Time of last activity that indicates a working connection
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Request SCTP and DTLS shutdown, connection immediately becomes un-established
    pub fn start_shutdown(&mut self) -> Result<(), RtcClientError> {
        match mem::replace(&mut self.ssl_state, ClientSslState::Unestablished(None)) {
            ClientSslState::Established(mut ssl_stream) => {
                if self.sctp_state != SctpState::Shutdown {
                    // We only send one abort packet because the DTLS connection is closed
                    // immediately after this.
                    send_sctp_packet(
                        &mut ssl_stream,
                        SctpPacket {
                            source_port: self.sctp_local_port,
                            dest_port: self.sctp_remote_port,
                            verification_tag: self.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::Abort],
                        },
                    )?;
                    self.last_sent = Instant::now();
                    self.sctp_state = SctpState::Shutdown;
                }
                ssl_stream.shutdown().map_err(ssl_err_to_client_err)?;
                self.ssl_state = ClientSslState::Shutdown(ssl_stream);
            }
            _ => {}
        }
        Ok(())
    }

    /// Connection has either timed out or finished shutting down
    pub fn is_shutdown(&self) -> bool {
        match &self.ssl_state {
            ClientSslState::Unestablished(None) => true,
            _ => false,
        }
    }

    /// Generate any periodic packets, currently only heartbeat packets.
    pub fn generate_periodic(&mut self) -> Result<(), RtcClientError> {
        // We send heartbeat packets if the last sent packet was more than HEARTBEAT_INTERVAL ago
        if self.last_sent.elapsed() > HEARTBEAT_INTERVAL {
            match &mut self.ssl_state {
                ClientSslState::Established(ssl_stream) => {
                    if self.sctp_state == SctpState::Established {
                        send_sctp_packet(
                            ssl_stream,
                            SctpPacket {
                                source_port: self.sctp_local_port,
                                dest_port: self.sctp_remote_port,
                                verification_tag: self.sctp_remote_verification_tag,
                                chunks: &[SctpChunk::Heartbeat {
                                    heartbeat_info: None,
                                }],
                            },
                        )?;
                        self.last_sent = Instant::now();
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Pushes an available UDP packet.  Will error if called when the client is currently in the
    /// shutdown state.
    pub fn receive_incoming_packet(
        &mut self,
        udp_packet: PooledBuffer,
    ) -> Result<(), RtcClientError> {
        match &mut self.ssl_state {
            ClientSslState::Unestablished(maybe_mid_handshake) => {
                if let Some(mut mid_handshake) = maybe_mid_handshake.take() {
                    mid_handshake.get_mut().incoming_udp.push_back(udp_packet);
                    match mid_handshake.handshake() {
                        Ok(ssl_stream) => {
                            self.ssl_state = ClientSslState::Established(ssl_stream);
                            info!("DTLS handshake finished for remote {:?}", self.remote_addr);
                        }
                        Err(handshake_error) => match handshake_error {
                            HandshakeError::SetupFailure(err) => {
                                return Err(RtcClientError::OpenSslError(err));
                            }
                            HandshakeError::Failure(mid_handshake) => {
                                warn!(
                                    "SSL handshake failure with remote {:?}: {}",
                                    self.remote_addr,
                                    mid_handshake.error()
                                );
                                self.ssl_state = ClientSslState::Unestablished(Some(mid_handshake));
                            }
                            HandshakeError::WouldBlock(mid_handshake) => {
                                self.ssl_state = ClientSslState::Unestablished(Some(mid_handshake));
                            }
                        },
                    }
                } else {
                    return Err(RtcClientError::NotConnected);
                }
            }
            ClientSslState::Established(ssl_stream) => {
                ssl_stream.get_mut().incoming_udp.push_back(udp_packet);
            }
            ClientSslState::Shutdown(ssl_stream) => {
                ssl_stream.get_mut().incoming_udp.push_back(udp_packet);
                if ssl_stream.get_shutdown() == ShutdownState::RECEIVED {
                    self.ssl_state = ClientSslState::Unestablished(None);
                }
            }
        }

        while let ClientSslState::Established(ssl_stream) = &mut self.ssl_state {
            let mut ssl_buffer = ssl_stream.get_ref().buffer_pool.acquire();
            ssl_buffer.resize(MAX_SCTP_PACKET_SIZE, 0);
            match ssl_stream.ssl_read(&mut ssl_buffer) {
                Ok(size) => {
                    let mut sctp_chunks = [SctpChunk::Abort; SCTP_MAX_CHUNKS];
                    match read_sctp_packet(&ssl_buffer[0..size], false, &mut sctp_chunks) {
                        Ok(sctp_packet) => {
                            self.receive_sctp_packet(&sctp_packet)?;
                        }
                        Err(err) => {
                            warn!("sctp read error on packet received over DTLS: {:?}", err);
                        }
                    }
                }
                Err(err) => {
                    if err.code() == ErrorCode::WANT_READ {
                        break;
                    } else {
                        return Err(ssl_err_to_client_err(err));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn take_outgoing_packets<'a>(&'a mut self) -> impl Iterator<Item = PooledBuffer> + 'a {
        (match &mut self.ssl_state {
            ClientSslState::Unestablished(Some(mid_handshake)) => {
                Some(mid_handshake.get_mut().outgoing_udp.drain(..))
            }
            ClientSslState::Unestablished(None) => None,
            ClientSslState::Established(ssl_stream) | ClientSslState::Shutdown(ssl_stream) => {
                Some(ssl_stream.get_mut().outgoing_udp.drain(..))
            }
        })
        .into_iter()
        .flatten()
    }

    pub fn send_message(
        &mut self,
        message_type: RtcMessageType,
        message: &[u8],
    ) -> Result<(), RtcClientError> {
        let ssl_stream = match &mut self.ssl_state {
            ClientSslState::Established(ssl_stream) => ssl_stream,
            _ => {
                return Err(RtcClientError::NotConnected);
            }
        };

        if self.sctp_state != SctpState::Established {
            return Err(RtcClientError::NotEstablished);
        }

        let proto_id = if message_type == RtcMessageType::Text {
            DATA_CHANNEL_PROTO_STRING
        } else {
            DATA_CHANNEL_PROTO_BINARY
        };

        send_sctp_packet(
            ssl_stream,
            SctpPacket {
                source_port: self.sctp_local_port,
                dest_port: self.sctp_remote_port,
                verification_tag: self.sctp_remote_verification_tag,
                chunks: &[SctpChunk::Data {
                    chunk_flags: SCTP_FLAG_COMPLETE_UNRELIABLE,
                    tsn: self.sctp_local_tsn,
                    stream_id: 0,
                    stream_seq: 0,
                    proto_id,
                    user_data: message,
                }],
            },
        )?;
        self.sctp_local_tsn = self.sctp_local_tsn.wrapping_add(1);

        Ok(())
    }

    pub fn receive_messages<'a>(
        &'a mut self,
    ) -> impl Iterator<Item = (RtcMessageType, PooledBuffer)> + 'a {
        self.received_messages.drain(..)
    }

    fn receive_sctp_packet(&mut self, sctp_packet: &SctpPacket) -> Result<(), RtcClientError> {
        let ssl_stream = match &mut self.ssl_state {
            ClientSslState::Established(ssl_stream) => ssl_stream,
            _ => panic!("receive_sctp_packet called in ssl unestablished state"),
        };

        for chunk in sctp_packet.chunks {
            match *chunk {
                SctpChunk::Init {
                    initiate_tag,
                    window_credit: _,
                    num_outbound_streams,
                    num_inbound_streams,
                    initial_tsn,
                } => {
                    let mut rng = thread_rng();

                    self.sctp_local_port = sctp_packet.dest_port;
                    self.sctp_remote_port = sctp_packet.source_port;

                    self.sctp_local_verification_tag = rng.gen();
                    self.sctp_remote_verification_tag = initiate_tag;

                    self.sctp_local_tsn = rng.gen();
                    self.sctp_remote_tsn = initial_tsn;

                    send_sctp_packet(
                        ssl_stream,
                        SctpPacket {
                            source_port: self.sctp_local_port,
                            dest_port: self.sctp_remote_port,
                            verification_tag: self.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::InitAck {
                                initiate_tag: self.sctp_local_verification_tag,
                                window_credit: SCTP_BUFFER_SIZE,
                                num_outbound_streams: num_outbound_streams,
                                num_inbound_streams: num_inbound_streams,
                                initial_tsn: self.sctp_local_tsn,
                                state_cookie: SCTP_COOKIE,
                            }],
                        },
                    )?;

                    self.sctp_state = SctpState::InitAck;
                    self.last_activity = Instant::now();
                    self.last_sent = Instant::now();
                }
                SctpChunk::CookieEcho { state_cookie } => {
                    if state_cookie == SCTP_COOKIE && self.sctp_state != SctpState::Shutdown {
                        send_sctp_packet(
                            ssl_stream,
                            SctpPacket {
                                source_port: self.sctp_local_port,
                                dest_port: self.sctp_remote_port,
                                verification_tag: self.sctp_remote_verification_tag,
                                chunks: &[SctpChunk::CookieAck],
                            },
                        )?;
                        self.last_sent = Instant::now();

                        if self.sctp_state == SctpState::InitAck {
                            self.sctp_state = SctpState::Established;
                            self.last_activity = Instant::now();
                        }
                    }
                }
                SctpChunk::Data {
                    chunk_flags: _,
                    tsn,
                    stream_id,
                    stream_seq: _,
                    proto_id,
                    user_data,
                } => {
                    self.sctp_remote_tsn = max_tsn(self.sctp_remote_tsn, tsn);

                    if proto_id == DATA_CHANNEL_PROTO_CONTROL {
                        if !user_data.is_empty() {
                            if user_data[0] == DATA_CHANNEL_MESSAGE_OPEN {
                                send_sctp_packet(
                                    ssl_stream,
                                    SctpPacket {
                                        source_port: self.sctp_local_port,
                                        dest_port: self.sctp_remote_port,
                                        verification_tag: self.sctp_remote_verification_tag,
                                        chunks: &[SctpChunk::Data {
                                            chunk_flags: SCTP_FLAG_COMPLETE_UNRELIABLE,
                                            tsn: self.sctp_local_tsn,
                                            stream_id,
                                            stream_seq: 0,
                                            proto_id: DATA_CHANNEL_PROTO_CONTROL,
                                            user_data: &[DATA_CHANNEL_MESSAGE_ACK],
                                        }],
                                    },
                                )?;
                                self.sctp_local_tsn = self.sctp_local_tsn.wrapping_add(1);
                            }
                        }
                    } else if proto_id == DATA_CHANNEL_PROTO_STRING {
                        let mut msg_buffer = ssl_stream.get_ref().buffer_pool.acquire();
                        msg_buffer.extend(user_data);
                        self.received_messages
                            .push((RtcMessageType::Text, msg_buffer));
                    } else if proto_id == DATA_CHANNEL_PROTO_BINARY {
                        let mut msg_buffer = ssl_stream.get_ref().buffer_pool.acquire();
                        msg_buffer.extend(user_data);
                        self.received_messages
                            .push((RtcMessageType::Text, msg_buffer));
                    }

                    send_sctp_packet(
                        ssl_stream,
                        SctpPacket {
                            source_port: self.sctp_local_port,
                            dest_port: self.sctp_remote_port,
                            verification_tag: self.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::SAck {
                                cumulative_tsn_ack: self.sctp_remote_tsn,
                                adv_recv_window: SCTP_BUFFER_SIZE,
                                num_gap_ack_blocks: 0,
                                num_dup_tsn: 0,
                            }],
                        },
                    )?;

                    self.last_activity = Instant::now();
                    self.last_sent = Instant::now();
                }
                SctpChunk::Heartbeat { heartbeat_info } => {
                    send_sctp_packet(
                        ssl_stream,
                        SctpPacket {
                            source_port: self.sctp_local_port,
                            dest_port: self.sctp_remote_port,
                            verification_tag: self.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::HeartbeatAck { heartbeat_info }],
                        },
                    )?;
                    self.last_activity = Instant::now();
                    self.last_sent = Instant::now();
                }
                SctpChunk::HeartbeatAck { .. } => {
                    self.last_activity = Instant::now();
                }
                SctpChunk::SAck {
                    cumulative_tsn_ack: _,
                    adv_recv_window: _,
                    num_gap_ack_blocks,
                    num_dup_tsn: _,
                } => {
                    if num_gap_ack_blocks > 0 {
                        send_sctp_packet(
                            ssl_stream,
                            SctpPacket {
                                source_port: self.sctp_local_port,
                                dest_port: self.sctp_remote_port,
                                verification_tag: self.sctp_remote_verification_tag,
                                chunks: &[SctpChunk::ForwardTsn {
                                    new_cumulative_tsn: self.sctp_local_tsn,
                                }],
                            },
                        )?;
                        self.last_sent = Instant::now();
                    }
                    self.last_activity = Instant::now();
                }
                SctpChunk::Shutdown { .. } => {
                    send_sctp_packet(
                        ssl_stream,
                        SctpPacket {
                            source_port: self.sctp_local_port,
                            dest_port: self.sctp_remote_port,
                            verification_tag: self.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::ShutdownAck],
                        },
                    )?;
                }
                SctpChunk::ShutdownAck { .. } | SctpChunk::Abort => {
                    self.sctp_state = SctpState::Shutdown;
                    ssl_stream.shutdown().map_err(ssl_err_to_client_err)?;
                }
                SctpChunk::ForwardTsn { new_cumulative_tsn } => {
                    self.sctp_remote_tsn = new_cumulative_tsn;
                }
                SctpChunk::InitAck { .. } | SctpChunk::CookieAck => {}
            }
        }

        Ok(())
    }
}

enum ClientSslState {
    Unestablished(Option<MidHandshakeSslStream<ClientSslPackets>>),
    Established(SslStream<ClientSslPackets>),
    Shutdown(SslStream<ClientSslPackets>),
}

#[derive(Debug)]
struct ClientSslPackets {
    buffer_pool: BufferPool,
    incoming_udp: VecDeque<PooledBuffer>,
    outgoing_udp: VecDeque<PooledBuffer>,
}

impl Read for ClientSslPackets {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        if let Some(next_packet) = self.incoming_udp.pop_front() {
            if next_packet.len() > buf.len() {
                return Err(IoError::new(
                    IoErrorKind::Other,
                    RtcClientError::IncompletePacketRead,
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
        self.outgoing_udp.push_back(buffer);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        Ok(())
    }
}

const SCTP_COOKIE: &[u8] = b"GAMERALOVESCOOKIES";
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

fn ssl_err_to_client_err(err: SslError) -> RtcClientError {
    match err.into_io_error() {
        Ok(err) => *err
            .into_inner()
            .expect("io error does not have inner error")
            .downcast()
            .expect("inner io error was not RtcClientError"),
        Err(err) => RtcClientError::TlsError(err),
    }
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
    ssl_stream: &mut SslStream<ClientSslPackets>,
    sctp_packet: SctpPacket,
) -> Result<(), RtcClientError> {
    let mut sctp_buffer = ssl_stream.get_ref().buffer_pool.acquire();
    sctp_buffer.resize(MAX_SCTP_PACKET_SIZE, 0);

    let packet_len = match write_sctp_packet(&mut sctp_buffer, sctp_packet) {
        Ok(len) => len,
        Err(SctpWriteError::BufferSize) => {
            return Err(RtcClientError::IncompletePacketWrite);
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
