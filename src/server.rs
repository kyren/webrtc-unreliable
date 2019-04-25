use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap, VecDeque},
    error::Error,
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write},
    net::SocketAddr,
    time::{Duration, Instant},
};

use futures::{try_ready, Async, Poll, Stream};
use log::{info, warn};
use openssl::ssl::{ErrorCode, HandshakeError, MidHandshakeSslStream, SslAcceptor, SslStream};
use tokio::{net::UdpSocket, timer::Interval};

use crate::buffer_pool::{BufferPool, PooledBuffer};
use crate::crypto::Crypto;
use crate::http::{create_http_server, HttpServer, IncomingSessionStream};
use crate::sctp::{read_sctp_packet, SctpChunk};
use crate::stun::{parse_stun_binding_request, write_stun_success_response};

#[derive(Debug)]
pub enum RtcSendError {
    IoError(IoError),
    DisconnectedClient,
}

impl fmt::Display for RtcSendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            RtcSendError::IoError(err) => fmt::Display::fmt(err, f),
            RtcSendError::DisconnectedClient => write!(f, "RTC Client is no longer connected"),
        }
    }
}

impl Error for RtcSendError {}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RtcMessageType {
    Text,
    Binary,
}

#[derive(Copy, Clone, Debug)]
pub struct RtcMessageResult {
    pub message_len: usize,
    pub message_type: RtcMessageType,
    pub remote_addr: SocketAddr,
}

pub struct RtcServer {
    udp_socket: UdpSocket,
    http_server: HttpServer,
    incoming_session_stream: IncomingSessionStream,
    ssl_acceptor: SslAcceptor,
    outgoing_udp: OutgoingUdp,
    incoming_rtc: IncomingRtc,
    buffer_pool: BufferPool,
    pending_clients: PendingClients,
    connected_clients: ConnectedClients,
    session_timeout: Duration,
    last_timeout_check: Instant,
    timeout_check_timer: Interval,
}

impl RtcServer {
    pub fn new(
        http_listen_addr: SocketAddr,
        udp_listen_addr: SocketAddr,
        public_udp_addr: SocketAddr,
        session_timeout: Duration,
    ) -> Result<RtcServer, IoError> {
        let crypto = Crypto::init().expect("RtcServer: Could not initialize OpenSSL primitives");
        let (http_server, incoming_session_stream) = create_http_server(
            &http_listen_addr,
            public_udp_addr,
            crypto.fingerprint,
            SESSION_BUFFER_SIZE,
        );
        let udp_socket = UdpSocket::bind(&udp_listen_addr)?;

        Ok(RtcServer {
            udp_socket,
            http_server,
            incoming_session_stream,
            ssl_acceptor: crypto.ssl_acceptor,
            outgoing_udp: OutgoingUdp::new(),
            incoming_rtc: IncomingRtc::new(),
            buffer_pool: BufferPool::new(),
            pending_clients: PendingClients::new(),
            connected_clients: ConnectedClients::new(),
            session_timeout,
            last_timeout_check: Instant::now(),
            timeout_check_timer: Interval::new_interval(session_timeout),
        })
    }

    pub fn is_connected(&self, remote_addr: &SocketAddr) -> bool {
        self.connected_clients.contains_key(remote_addr)
    }

    pub fn send(
        &mut self,
        message: &[u8],
        message_type: RtcMessageType,
        remote_addr: &SocketAddr,
    ) -> Poll<(), RtcSendError> {
        try_ready!(self.send_udp().map_err(RtcSendError::IoError));

        let client_state = self
            .connected_clients
            .get_mut(remote_addr)
            .ok_or(RtcSendError::DisconnectedClient)?;

        unimplemented!();

        Ok(Async::Ready(()))
    }

    pub fn receive(&mut self, buf: &mut [u8]) -> Poll<RtcMessageResult, IoError> {
        while self.incoming_rtc.is_empty() {
            try_ready!(self.send_udp());
            try_ready!(self.receive_udp());
        }

        let (message, remote_addr, message_type) = self.incoming_rtc.pop_front().unwrap();
        let message_len = message.len();
        if buf.len() < message_len {
            self.incoming_rtc
                .push_front((message, remote_addr, message_type));
            return Err(IoError::new(
                IoErrorKind::Other,
                "failed to read entire RTC message into buffer",
            ));
        }

        buf[0..message_len].copy_from_slice(&message[..]);

        Ok(Async::Ready(RtcMessageResult {
            message_len,
            message_type,
            remote_addr,
        }))
    }

    pub fn process(&mut self) -> Result<(), IoError> {
        if self
            .http_server
            .poll()
            .map_err(|e| IoError::new(IoErrorKind::Other, e))?
            .is_ready()
        {
            return Err(IoError::new(
                IoErrorKind::Other,
                "http server has unexpectedly died",
            ));
        }

        while let Async::Ready(incoming_session) = self.incoming_session_stream.poll().unwrap() {
            if let Some(incoming_session) = incoming_session {
                self.pending_clients.insert(
                    PendingClientKey {
                        server_user: incoming_session.server_user,
                        remote_user: incoming_session.remote_user,
                    },
                    PendingClient {
                        server_passwd: incoming_session.server_passwd,
                        last_activity: Instant::now(),
                    },
                );
            } else {
                return Err(IoError::new(
                    IoErrorKind::Other,
                    "incoming session channel unexpectedly closed",
                ));
            }
        }

        self.timeout_check_timer.poll().unwrap();
        if self.last_timeout_check.elapsed() >= self.session_timeout {
            let session_timeout = self.session_timeout;
            self.pending_clients.retain(|_, pending_client| {
                pending_client.last_activity.elapsed() < session_timeout
            });
            self.connected_clients.retain(|_, connected_client| {
                connected_client.last_activity.elapsed() < session_timeout
                    || match connected_client.ssl_stream {
                        ClientSslStream::Unestablished(None) => true,
                        _ => false,
                    }
            });
        }

        Ok(())
    }

    fn send_udp(&mut self) -> Poll<(), IoError> {
        while let Some((packet, remote_addr)) = self.outgoing_udp.pop_front() {
            match self.udp_socket.poll_send_to(&packet, &remote_addr)? {
                Async::Ready(len) => {
                    let packet_len = packet.len();
                    if len != packet_len {
                        return Err(IoError::new(
                            IoErrorKind::Other,
                            "failed to write entire datagram to socket",
                        ));
                    }
                }
                Async::NotReady => {
                    self.outgoing_udp.push_front((packet, remote_addr));
                    return Ok(Async::NotReady);
                }
            }
        }

        Ok(Async::Ready(()))
    }

    fn receive_udp(&mut self) -> Poll<(), IoError> {
        let mut packet_buffer = self.buffer_pool.acquire();
        packet_buffer.resize(MAX_DGRAM_SIZE, 0);
        let (len, remote_addr) = try_ready!(self.udp_socket.poll_recv_from(&mut packet_buffer));
        if len > MAX_DGRAM_SIZE {
            return Err(IoError::new(
                IoErrorKind::Other,
                "failed to read entire datagram from socket",
            ));
        }
        packet_buffer.truncate(len);

        match self.connected_clients.entry(remote_addr) {
            HashMapEntry::Occupied(mut occupied) => {
                let connected_client = occupied.get_mut();
                connected_client.last_activity = Instant::now();
                match &mut connected_client.ssl_stream {
                    ClientSslStream::Unestablished(maybe_mid_handshake) => {
                        if let Some(mut mid_handshake) = maybe_mid_handshake.take() {
                            mid_handshake
                                .get_mut()
                                .incoming_udp
                                .push_back(packet_buffer);
                            match mid_handshake.handshake() {
                                Ok(ssl_stream) => {
                                    connected_client.ssl_stream =
                                        ClientSslStream::Established(ssl_stream);
                                    info!("DTLS handshake finished for remote {:?}", remote_addr);
                                }
                                Err(handshake_error) => match handshake_error {
                                    HandshakeError::SetupFailure(err) => {
                                        warn!(
                                            "SSL error during handshake with remote {:?}: {}",
                                            remote_addr, err
                                        );
                                    }
                                    HandshakeError::Failure(mut mid_handshake) => {
                                        warn!(
                                            "SSL handshake failure with remote {:?}: {}",
                                            remote_addr,
                                            mid_handshake.error()
                                        );
                                        self.outgoing_udp.extend(
                                            mid_handshake
                                                .get_mut()
                                                .outgoing_udp
                                                .drain(..)
                                                .map(|p| (p, remote_addr)),
                                        );
                                        connected_client.ssl_stream =
                                            ClientSslStream::Unestablished(Some(mid_handshake));
                                    }
                                    HandshakeError::WouldBlock(mut mid_handshake) => {
                                        self.outgoing_udp.extend(
                                            mid_handshake
                                                .get_mut()
                                                .outgoing_udp
                                                .drain(..)
                                                .map(|p| (p, remote_addr)),
                                        );
                                        connected_client.ssl_stream =
                                            ClientSslStream::Unestablished(Some(mid_handshake));
                                    }
                                },
                            }
                        }
                    }
                    ClientSslStream::Established(ssl_stream) => {
                        ssl_stream.get_mut().incoming_udp.push_back(packet_buffer);
                    }
                }

                if let ClientSslStream::Established(ssl_stream) = &mut connected_client.ssl_stream {
                    loop {
                        let mut ssl_buffer = self.buffer_pool.acquire();
                        ssl_buffer.resize(MAX_DGRAM_SIZE, 0);
                        match ssl_stream.ssl_read(&mut ssl_buffer) {
                            Ok(size) => {
                                ssl_buffer.truncate(size);
                                let mut sctp_chunks = [SctpChunk::Abort; 16];
                                if let Ok(sctp_packet) =
                                    read_sctp_packet(&ssl_buffer, &mut sctp_chunks)
                                {
                                    warn!("unimplemented handling of SCTP {:?}", sctp_packet);
                                } else {
                                    warn!("non-sctp packet received over DTLS");
                                    hexdump::hexdump(&ssl_buffer);
                                }
                            }
                            Err(err) => {
                                if err.code() == ErrorCode::WANT_READ {
                                    break;
                                } else {
                                    return Err(err
                                        .into_io_error()
                                        .map_err(|e| IoError::new(IoErrorKind::Other, e))?);
                                }
                            }
                        }
                    }

                    self.outgoing_udp.extend(
                        ssl_stream
                            .get_mut()
                            .outgoing_udp
                            .drain(..)
                            .map(|p| (p, remote_addr)),
                    );
                }
            }
            HashMapEntry::Vacant(vacant) => {
                if let Some(stun_binding_request) =
                    parse_stun_binding_request(&packet_buffer[0..len])
                {
                    if let Some(pending_client) = self.pending_clients.remove(&PendingClientKey {
                        server_user: stun_binding_request.server_user,
                        remote_user: stun_binding_request.remote_user,
                    }) {
                        let resp_len = write_stun_success_response(
                            stun_binding_request.transaction_id,
                            remote_addr,
                            pending_client.server_passwd.as_bytes(),
                            &mut packet_buffer,
                        )
                        .expect("RtcServer: could not write STUN response packet");

                        packet_buffer.truncate(resp_len);
                        self.outgoing_udp.push_back((packet_buffer, remote_addr));

                        let ssl_stream = match self.ssl_acceptor.accept(ClientSslPackets {
                            buffer_pool: self.buffer_pool.clone(),
                            incoming_udp: VecDeque::new(),
                            outgoing_udp: VecDeque::new(),
                        }) {
                            Ok(_) => {
                                unreachable!("handshake cannot finish with no incoming packets")
                            }
                            Err(HandshakeError::WouldBlock(mut mid_handshake)) => {
                                self.outgoing_udp.extend(
                                    mid_handshake
                                        .get_mut()
                                        .outgoing_udp
                                        .drain(..)
                                        .map(|p| (p, remote_addr)),
                                );
                                ClientSslStream::Unestablished(Some(mid_handshake))
                            }
                            Err(err) => {
                                panic!("RtcServer: could not accept new SSL stream: {:?}", err)
                            }
                        };

                        vacant.insert(ConnectedClient {
                            last_activity: Instant::now(),
                            ssl_stream,
                        });
                    }
                }
            }
        }

        Ok(Async::Ready(()))
    }
}

const MAX_DGRAM_SIZE: usize = 0x10000;
const SESSION_BUFFER_SIZE: usize = 8;

type OutgoingUdp = VecDeque<(PooledBuffer, SocketAddr)>;
type IncomingRtc = VecDeque<(PooledBuffer, SocketAddr, RtcMessageType)>;

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
struct PendingClientKey {
    server_user: String,
    remote_user: String,
}

struct PendingClient {
    server_passwd: String,
    last_activity: Instant,
}

struct ConnectedClient {
    last_activity: Instant,
    ssl_stream: ClientSslStream,
}

type PendingClients = HashMap<PendingClientKey, PendingClient>;
type ConnectedClients = HashMap<SocketAddr, ConnectedClient>;

enum ClientSslStream {
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
        if let Some(next_dgram) = self.incoming_udp.pop_front() {
            if next_dgram.len() > buf.len() {
                return Err(IoError::new(
                    IoErrorKind::Other,
                    "failed to read entire datagram in SSL stream",
                ));
            }
            buf[0..next_dgram.len()].copy_from_slice(&next_dgram);
            Ok(next_dgram.len())
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
