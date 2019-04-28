use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap, VecDeque},
    error::Error,
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    net::SocketAddr,
    time::{Duration, Instant},
};

use futures::{try_ready, Async, Poll, Stream};
use log::{info, warn};
use openssl::ssl::SslAcceptor;
use tokio::{net::UdpSocket, timer::Interval};

use crate::buffer_pool::{BufferPool, PooledBuffer};
use crate::client::{RtcClient, RtcClientError, RtcMessageType, MAX_UDP_PAYLOAD_SIZE};
use crate::crypto::Crypto;
use crate::http::{create_http_server, HttpServer, IncomingSessionStream};
use crate::stun::{parse_stun_binding_request, write_stun_success_response};

#[derive(Debug)]
pub enum RtcError {
    /// Non-fatal error trying to send a message to a disconnected client.
    ClientNotConnected,
    /// Non-fatal error trying to send a message to a client whose WebRTC connection has not been
    /// established yet or is currently shutting down.
    ClientConnectionNotEstablished,
    /// Non-fatal error reading a WebRTC Data Channel message that is too large to fit in the
    /// provided buffer.
    IncompleteMessageRead,
    /// Non-fatal error writing a WebRTC Data Channel message that is too large to fit in the
    /// maximum message size.
    IncompleteMessageWrite,
    /// Other generally fatal internal errors.
    Internal(RtcInternalError),
}

impl fmt::Display for RtcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            RtcError::ClientNotConnected => write!(f, "client is not connected"),
            RtcError::ClientConnectionNotEstablished => {
                write!(f, "client WebRTC connection is not established")
            }
            RtcError::IncompleteMessageRead => {
                write!(f, "incomplete read of WebRTC Data Channel message")
            }
            RtcError::IncompleteMessageWrite => {
                write!(f, "incomplete write of WebRTC Data Channel message")
            }
            RtcError::Internal(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl Error for RtcError {}

#[derive(Debug)]
pub enum RtcInternalError {
    IoError(IoError),
    Other(Box<Error + Sync + Send>),
}

impl fmt::Display for RtcInternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            RtcInternalError::IoError(err) => fmt::Display::fmt(err, f),
            RtcInternalError::Other(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl Error for RtcInternalError {}

impl From<RtcInternalError> for RtcError {
    fn from(err: RtcInternalError) -> RtcError {
        RtcError::Internal(err)
    }
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
    outgoing_udp: VecDeque<(PooledBuffer, SocketAddr)>,
    incoming_rtc: VecDeque<(PooledBuffer, SocketAddr, RtcMessageType)>,
    buffer_pool: BufferPool,
    ice_clients: HashMap<IceClientKey, IceClient>,
    rtc_clients: HashMap<SocketAddr, RtcClient>,
    last_generate_periodic: Instant,
    last_cleanup: Instant,
    periodic_timer: Interval,
}

impl RtcServer {
    pub fn new(
        http_listen_addr: SocketAddr,
        udp_listen_addr: SocketAddr,
        public_udp_addr: SocketAddr,
    ) -> Result<RtcServer, RtcInternalError> {
        const SESSION_BUFFER_SIZE: usize = 8;

        let crypto = Crypto::init().expect("RtcServer: Could not initialize OpenSSL primitives");
        let (http_server, incoming_session_stream) = create_http_server(
            &http_listen_addr,
            public_udp_addr,
            crypto.fingerprint,
            SESSION_BUFFER_SIZE,
        );
        let udp_socket = UdpSocket::bind(&udp_listen_addr).map_err(RtcInternalError::IoError)?;

        Ok(RtcServer {
            udp_socket,
            http_server,
            incoming_session_stream,
            ssl_acceptor: crypto.ssl_acceptor,
            outgoing_udp: VecDeque::new(),
            incoming_rtc: VecDeque::new(),
            buffer_pool: BufferPool::new(),
            ice_clients: HashMap::new(),
            rtc_clients: HashMap::new(),
            last_generate_periodic: Instant::now(),
            last_cleanup: Instant::now(),
            periodic_timer: Interval::new_interval(PERIODIC_TIMER_INTERVAL),
        })
    }

    /// Returns true if the client has a completely established WebRTC data channel connection and
    /// can send messages back and forth.  Returns false for disconnected clients as well as those
    /// that are still starting up or are in the process of shutting down.
    pub fn is_connected(&self, remote_addr: &SocketAddr) -> bool {
        if let Some(client) = self.rtc_clients.get(remote_addr) {
            client.is_established()
        } else {
            false
        }
    }

    /// Disconect the given client, does nothing if the client is not currently connected.
    pub fn disconnect(&mut self, remote_addr: &SocketAddr) {
        if let Some(client) = self.rtc_clients.get_mut(remote_addr) {
            if let Err(err) = client.start_shutdown() {
                warn!(
                    "error starting shutdown for client {:?}: {}",
                    remote_addr, err
                );
            } else {
                info!("starting shutdown for client {:?}", remote_addr);
            }
        }
    }

    /// Send the given message to the given remote client, if they are connected.
    pub fn poll_send(
        &mut self,
        message: &[u8],
        message_type: RtcMessageType,
        remote_addr: &SocketAddr,
    ) -> Poll<(), RtcError> {
        // Send pending UDP messages before potentially buffering new ones
        try_ready!(self.send_udp());

        let client = self
            .rtc_clients
            .get_mut(remote_addr)
            .ok_or(RtcError::ClientNotConnected)?;

        match client.send_message(message_type, message) {
            Err(RtcClientError::NotConnected) => {
                return Err(RtcError::ClientNotConnected);
            }
            Err(RtcClientError::NotEstablished) => {
                return Err(RtcError::ClientConnectionNotEstablished);
            }
            Err(RtcClientError::IncompletePacketWrite) => {
                return Err(RtcError::IncompleteMessageWrite)
            }
            Err(err) => {
                warn!(
                    "message send for client {:?} generated unexpected error, shutting down: {}",
                    remote_addr, err
                );
                let _ = client.start_shutdown();
                return Err(RtcError::ClientNotConnected);
            }
            Ok(()) => {}
        }

        self.outgoing_udp
            .extend(client.take_outgoing_packets().map(|p| (p, *remote_addr)));

        Ok(self.send_udp()?)
    }

    /// Receive a WebRTC data channel message from any connected client.
    ///
    /// `poll_recv` *must* be called until it returns Async::NotReady for proper operation of the
    /// server, as it also handles background tasks such as responding to STUN packets, timing out
    /// existing sessions, and handling HTTP requests.
    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Poll<RtcMessageResult, RtcError> {
        while self.incoming_rtc.is_empty() {
            try_ready!(self.process());
        }

        let (message, remote_addr, message_type) = self.incoming_rtc.pop_front().unwrap();
        let message_len = message.len();
        if buf.len() < message_len {
            self.incoming_rtc
                .push_front((message, remote_addr, message_type));
            return Err(RtcError::IncompleteMessageRead);
        }

        buf[0..message_len].copy_from_slice(&message[..]);

        Ok(Async::Ready(RtcMessageResult {
            message_len,
            message_type,
            remote_addr,
        }))
    }

    // Accepts new incoming WebRTC sessions, times out existing WebRTC sessions, sends outgoing UDP
    // packets, receives incoming UDP packets, and responds to STUN packets.
    fn process(&mut self) -> Poll<(), RtcInternalError> {
        if self
            .http_server
            .poll()
            .map_err(|e| RtcInternalError::Other(e.into()))?
            .is_ready()
        {
            return Err(RtcInternalError::Other(
                "http server has unexpectedly stopped".into(),
            ));
        }

        while let Async::Ready(incoming_session) = self.incoming_session_stream.poll().unwrap() {
            if let Some(incoming_session) = incoming_session {
                info!(
                    "ICE connection initiated with server user: '{}' and remote user: '{}'",
                    incoming_session.server_user, incoming_session.remote_user
                );

                self.ice_clients.insert(
                    IceClientKey {
                        server_user: incoming_session.server_user,
                        remote_user: incoming_session.remote_user,
                    },
                    IceClient {
                        server_passwd: incoming_session.server_passwd,
                        ttl: Instant::now(),
                    },
                );
            } else {
                return Err(RtcInternalError::Other(
                    "incoming session channel unexpectedly closed".into(),
                ));
            }
        }

        if self.last_cleanup.elapsed() >= CLEANUP_INTERVAL {
            self.last_cleanup = Instant::now();
            self.ice_clients.retain(|ice_client_key, ice_client| {
                if ice_client.ttl.elapsed() < ICE_SESSION_TIMEOUT {
                    true
                } else {
                    info!(
                        "ICE session timeout for server user '{}' and remote user '{}'",
                        ice_client_key.server_user, ice_client_key.remote_user
                    );
                    false
                }
            });

            self.rtc_clients.retain(|remote_addr, client| {
                if !client.is_shutdown() && client.last_activity().elapsed() < RTC_SESSION_TIMEOUT {
                    true
                } else {
                    if !client.is_shutdown() {
                        info!("timeout for client {:?}", remote_addr);
                    }
                    info!("client {:?} removed", remote_addr);
                    false
                }
            });
        }

        loop {
            match self.periodic_timer.poll() {
                Ok(Async::Ready(val)) => {
                    val.expect("interval stream should not stop");
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    if err.is_shutdown() {
                        return Err(RtcInternalError::Other(
                            "periodic timer has unexpectedly shutdown".into(),
                        ));
                    }
                }
            }
        }

        try_ready!(self.send_udp());
        Ok(self.receive_udp()?)
    }

    // Send any currently queued UDP packets, or if there are currently none queued generate any
    // required periodic UDP packets and send those.  Returns Async::Ready if all queued UDP packets
    // were sent and the queue is now empty.
    fn send_udp(&mut self) -> Poll<(), RtcInternalError> {
        if self.outgoing_udp.is_empty() {
            self.generate_periodic_packets()?;
        }

        while let Some((packet, remote_addr)) = self.outgoing_udp.pop_front() {
            match self
                .udp_socket
                .poll_send_to(&packet, &remote_addr)
                .map_err(RtcInternalError::IoError)?
            {
                Async::Ready(len) => {
                    let packet_len = packet.len();
                    if len != packet_len {
                        return Err(RtcInternalError::IoError(IoError::new(
                            IoErrorKind::Other,
                            "failed to write entire datagram to socket",
                        )));
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

    // Handle incoming UDP packets, filling the incoming UDP queue and potentially responding to
    // STUN requests.
    fn receive_udp(&mut self) -> Poll<(), RtcInternalError> {
        let mut packet_buffer = self.buffer_pool.acquire();
        packet_buffer.resize(MAX_UDP_PAYLOAD_SIZE, 0);
        let (len, remote_addr) = try_ready!(self
            .udp_socket
            .poll_recv_from(&mut packet_buffer)
            .map_err(RtcInternalError::IoError));
        if len > MAX_UDP_PAYLOAD_SIZE {
            return Err(RtcInternalError::IoError(IoError::new(
                IoErrorKind::Other,
                "failed to read entire datagram from socket",
            )));
        }
        packet_buffer.truncate(len);

        if let Some(stun_binding_request) = parse_stun_binding_request(&packet_buffer[0..len]) {
            if let Some(ice_client) = self.ice_clients.get_mut(&IceClientKey {
                server_user: stun_binding_request.server_user,
                remote_user: stun_binding_request.remote_user,
            }) {
                ice_client.ttl = Instant::now();
                let resp_len = write_stun_success_response(
                    stun_binding_request.transaction_id,
                    remote_addr,
                    ice_client.server_passwd.as_bytes(),
                    &mut packet_buffer,
                )
                .map_err(RtcInternalError::Other)?;

                packet_buffer.truncate(resp_len);
                self.outgoing_udp.push_back((packet_buffer, remote_addr));

                match self.rtc_clients.entry(remote_addr) {
                    HashMapEntry::Vacant(vacant) => {
                        info!(
                            "beginning client WebRTC data channel connection with {:?}",
                            remote_addr,
                        );

                        vacant.insert(
                            RtcClient::new(
                                &self.ssl_acceptor,
                                self.buffer_pool.clone(),
                                remote_addr,
                            )
                            .map_err(|e| RtcInternalError::Other(e.into()))?,
                        );
                    }
                    HashMapEntry::Occupied(_) => {}
                }
            }
        } else {
            if let Some(client) = self.rtc_clients.get_mut(&remote_addr) {
                if let Err(err) = client.receive_incoming_packet(packet_buffer) {
                    warn!(
                        "client {:?} had unexpected error receiving UDP packet, shutting down: {}",
                        remote_addr, err
                    );
                    let _ = client.start_shutdown();
                }
                self.outgoing_udp
                    .extend(client.take_outgoing_packets().map(|p| (p, remote_addr)));
                self.incoming_rtc.extend(
                    client
                        .receive_messages()
                        .map(|(message_type, message)| (message, remote_addr, message_type)),
                );
            }
        }

        Ok(Async::Ready(()))
    }

    // Call `RtcClient::generate_periodic` on all clients, if we are due to do so.
    fn generate_periodic_packets(&mut self) -> Result<(), RtcInternalError> {
        if self.last_generate_periodic.elapsed() >= PERIODIC_PACKET_INTERVAL {
            self.last_generate_periodic = Instant::now();

            for (remote_addr, client) in &mut self.rtc_clients {
                if let Err(err) = client.generate_periodic() {
                    warn!("error for client {:?}, shutting down: {}", remote_addr, err);
                    let _ = client.start_shutdown();
                }
                self.outgoing_udp
                    .extend(client.take_outgoing_packets().map(|p| (p, *remote_addr)));
            }
        }
        Ok(())
    }
}

const RTC_SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const ICE_SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(2);
const PERIODIC_PACKET_INTERVAL: Duration = Duration::from_secs(1);
const PERIODIC_TIMER_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
struct IceClientKey {
    server_user: String,
    remote_user: String,
}

struct IceClient {
    server_passwd: String,
    ttl: Instant,
}
