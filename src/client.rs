use std::{
    collections::VecDeque,
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write},
    iter::Iterator,
    net::SocketAddr,
    time::{Duration, Instant},
};

use log::{info, warn};
use openssl::{
    error::ErrorStack as OpenSslErrorStack,
    ssl::{
        Error as SslError, ErrorCode, HandshakeError, MidHandshakeSslStream, SslAcceptor, SslStream,
    },
};
use rand::{thread_rng, Rng};

use crate::buffer_pool::{BufferPool, PooledBuffer};
use crate::sctp::{read_sctp_packet, write_sctp_packet, SctpChunk, SctpPacket};

/// Maximum time between calls to `Client::update` (for heartbeat packets, shutdown resends, etc)
pub const CLIENT_UPDATE_INTERVAL: Duration = Duration::from_secs(1);

// TODO: I'm not sure whether this is correct
pub const MAX_SCTP_PACKET_SIZE: usize = MAX_DTLS_MESSAGE_SIZE;
pub const MAX_DTLS_MESSAGE_SIZE: usize = 16384;
pub const MAX_UDP_PAYLOAD_SIZE: usize = 65507;

pub struct Client {
    remote_addr: SocketAddr,
    ssl_state: ClientSslState,
    last_activity: Instant,

    sctp_state: SctpState,

    sctp_local_port: u16,
    sctp_remote_port: u16,

    sctp_local_verification_tag: u32,
    sctp_remote_verification_tag: u32,

    sctp_local_tsn: u32,
    sctp_remote_tsn: u32,

    sctp_last_heartbeat: Instant,
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
            Err(HandshakeError::SetupFailure(err)) => Err(err),
            Err(HandshakeError::Failure(_)) => {
                unreachable!("handshake cannot fail before starting")
            }
            Err(HandshakeError::WouldBlock(mid_handshake)) => Ok(Client {
                remote_addr,
                ssl_state: ClientSslState::Unestablished(Some(mid_handshake)),
                last_activity: Instant::now(),
                sctp_state: SctpState::Shutdown,
                sctp_local_port: 0,
                sctp_remote_port: 0,
                sctp_local_verification_tag: 0,
                sctp_remote_verification_tag: 0,
                sctp_local_tsn: 0,
                sctp_remote_tsn: 0,
                sctp_last_heartbeat: Instant::now(),
            }),
        }
    }

    /// DTLS and SCTP states are established, and RTC messages may be sent
    pub fn is_established(&self) -> bool {
        match (&self.ssl_state, &self.sctp_state) {
            (ClientSslState::Established(_), SctpState::Established { .. }) => true,
            _ => false,
        }
    }

    /// Time of last activity that indicates a working connection
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Request SCTP and DTLS shutdown, connection immediately becomes un-established
    pub fn start_shutdown(&mut self) {
        unimplemented!()
    }

    /// Connection has either timed out or finished shutting down
    pub fn is_shutdown(&self) -> bool {
        match &self.ssl_state {
            ClientSslState::Unestablished(None) => true,
            _ => false,
        }
    }

    /// Must be called at `CLIENT_UPDATE_INTERVAL` or faster, may produce heartbeat packets or
    /// perform packet resends
    pub fn update(&mut self) {
        // unimplemented!
    }

    /// Pushes an available UDP packet.  Will error if called when the client is currently in the
    /// shutdown state.
    pub fn receive_incoming_packet(&mut self, udp_packet: PooledBuffer) -> Result<(), IoError> {
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
                                return Err(IoError::new(IoErrorKind::ConnectionRefused, err));
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
                    return Err(IoErrorKind::NotConnected.into());
                }
            }
            ClientSslState::Established(ssl_stream) => {
                ssl_stream.get_mut().incoming_udp.push_back(udp_packet);
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
                            self.receive_sctp_packet(&sctp_packet)
                                .map_err(ssl_err_to_io_err)?;
                        }
                        Err(err) => {
                            warn!("sctp error on packet received over DTLS: {:?}", err);
                        }
                    }
                }
                Err(err) => {
                    if err.code() == ErrorCode::WANT_READ {
                        break;
                    } else {
                        return Err(ssl_err_to_io_err(err));
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
            ClientSslState::Established(ssl_stream) => {
                Some(ssl_stream.get_mut().outgoing_udp.drain(..))
            }
        })
        .into_iter()
        .flatten()
    }

    fn receive_sctp_packet(&mut self, sctp_packet: &SctpPacket) -> Result<(), SslError> {
        let ssl_stream = match &mut self.ssl_state {
            ClientSslState::Established(ssl_stream) => ssl_stream,
            _ => panic!("receive sctp packet called in ssl unestablished state"),
        };

        match self.sctp_state {
            SctpState::Shutdown => match sctp_packet.chunks[0] {
                SctpChunk::Init {
                    initiate_tag,
                    window_credit,
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

                    let init_ack = SctpPacket {
                        source_port: self.sctp_local_port,
                        dest_port: self.sctp_remote_port,
                        verification_tag: self.sctp_remote_verification_tag,
                        chunks: &[SctpChunk::InitAck {
                            initiate_tag: self.sctp_local_verification_tag,
                            window_credit: SCTP_WINDOW_CREDIT,
                            num_outbound_streams: num_outbound_streams,
                            num_inbound_streams: num_inbound_streams,
                            initial_tsn: self.sctp_local_tsn,
                            state_cookie: SCTP_COOKIE,
                        }],
                    };

                    let mut sctp_buffer = ssl_stream.get_ref().buffer_pool.acquire();
                    sctp_buffer.resize(MAX_SCTP_PACKET_SIZE, 0);

                    let packet_len = write_sctp_packet(&mut sctp_buffer, init_ack)
                        .expect("could not write SCTP InitAck packet");

                    assert_eq!(
                        ssl_stream.ssl_write(&sctp_buffer[0..packet_len])?,
                        packet_len
                    );

                    self.sctp_state = SctpState::InitAck;
                }
                _ => {}
            },
            SctpState::InitAck => match sctp_packet.chunks[0] {
                SctpChunk::CookieEcho { state_cookie } => {
                    if state_cookie == SCTP_COOKIE {
                        let cookie_ack = SctpPacket {
                            source_port: self.sctp_local_port,
                            dest_port: self.sctp_remote_port,
                            verification_tag: self.sctp_remote_verification_tag,
                            chunks: &[SctpChunk::CookieAck],
                        };

                        let mut sctp_buffer = ssl_stream.get_ref().buffer_pool.acquire();
                        sctp_buffer.resize(MAX_SCTP_PACKET_SIZE, 0);

                        let packet_len = write_sctp_packet(&mut sctp_buffer, cookie_ack)
                            .expect("could not write SCTP CookieAck packet");

                        assert_eq!(
                            ssl_stream.ssl_write(&sctp_buffer[0..packet_len])?,
                            packet_len
                        );

                        self.sctp_state = SctpState::Established;
                    }
                }
                _ => {}
            },
            SctpState::Established => {
                println!("Established state SCTP packet received: {:#?}", sctp_packet);
            }
            SctpState::ShutdownSent { .. } => {}
        }

        Ok(())
    }
}

enum ClientSslState {
    Unestablished(Option<MidHandshakeSslStream<ClientSslPackets>>),
    Established(SslStream<ClientSslPackets>),
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
                    "failed to read entire datagram in SSL stream",
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
const SHUTDOWN_RESEND: Duration = Duration::from_secs(1);
const MAX_SHUTDOWN_PACKETS: i32 = 5;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
const SCTP_MAX_CHUNKS: usize = 16;
const SCTP_WINDOW_CREDIT: u32 = 0x40000;

enum SctpState {
    Shutdown,
    InitAck,
    Established,
    ShutdownSent { first_sent: Instant, num_sent: i32 },
}

fn ssl_err_to_io_err(err: SslError) -> IoError {
    match err.into_io_error() {
        Ok(err) => err,
        Err(err) => IoError::new(IoErrorKind::Other, err),
    }
}
