use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap, VecDeque},
    error::Error,
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::{sync::mpsc, try_ready, Async, Future, Poll, Sink, Stream};
use http::{header, Response};
use log::{info, warn};
use openssl::ssl::SslAcceptor;
use rand::thread_rng;
use tokio::{net::UdpSocket, timer::Interval};

use crate::buffer_pool::{BufferPool, PooledBuffer};
use crate::client::{Client, ClientError, MessageType, MAX_UDP_PAYLOAD_SIZE};
use crate::crypto::Crypto;
use crate::sdp::{gen_sdp_response, parse_sdp_fields, SdpFields};
use crate::stun::{parse_stun_binding_request, write_stun_success_response};
use crate::util::rand_string;

#[derive(Debug)]
pub enum SendError {
    /// Non-fatal error trying to send a message to a disconnected client.
    ClientNotConnected,
    /// Non-fatal error trying to send a message to a client whose WebRTC connection has not been
    /// established yet or is currently shutting down.
    ClientConnectionNotEstablished,
    /// Non-fatal error writing a WebRTC Data Channel message that is too large to fit in the
    /// maximum message size.
    IncompleteMessageWrite,
    /// Other generally fatal internal errors.
    Internal(InternalError),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SendError::ClientNotConnected => write!(f, "client is not connected"),
            SendError::ClientConnectionNotEstablished => {
                write!(f, "client connection is not established")
            }
            SendError::IncompleteMessageWrite => {
                write!(f, "incomplete write of WebRTC Data Channel message")
            }
            SendError::Internal(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl Error for SendError {}

impl From<InternalError> for SendError {
    fn from(err: InternalError) -> SendError {
        SendError::Internal(err)
    }
}

#[derive(Debug)]
pub enum RecvError {
    /// Non-fatal error reading a WebRTC Data Channel message that is too large to fit in the
    /// provided buffer.
    IncompleteMessageRead,
    /// Other generally fatal internal errors.
    Internal(InternalError),
}

impl Error for RecvError {}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            RecvError::IncompleteMessageRead => {
                write!(f, "incomplete read of WebRTC Data Channel message")
            }
            RecvError::Internal(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl From<InternalError> for RecvError {
    fn from(err: InternalError) -> RecvError {
        RecvError::Internal(err)
    }
}

/// Generally fatal internal error in the WebRTC server.
#[derive(Debug)]
pub enum InternalError {
    IoError(IoError),
    Other(BoxError),
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            InternalError::IoError(err) => fmt::Display::fmt(err, f),
            InternalError::Other(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl Error for InternalError {}

#[derive(Copy, Clone, Debug)]
pub struct MessageResult {
    pub message_len: usize,
    pub message_type: MessageType,
    pub remote_addr: SocketAddr,
}

#[derive(Clone)]
pub struct SessionEndpoint {
    public_addr: SocketAddr,
    cert_fingerprint: Arc<String>,
    session_sender: mpsc::Sender<IncomingSession>,
}

impl SessionEndpoint {
    /// Receives an incoming SDP descriptor of an `RTCSessionDescription` from a browser, informs
    /// the corresponding `Server` of the new WebRTC session, and returns a JSON object containing
    /// objects which can construct an `RTCSessionDescription` and an `RTCIceCandidate` in a
    /// browser.
    ///
    /// The returned JSON object contains a digest of the x509 certificate the server will use for
    /// DTLS, and the browser will ensure that this digest matches before starting a WebRTC
    /// connection.
    pub fn session_request<I, E, S>(
        &self,
        sdp_descriptor: S,
    ) -> impl Future<Item = String, Error = BoxError>
    where
        I: AsRef<[u8]>,
        S: Stream<Item = I, Error = E>,
        E: Error + Send + Sync + 'static,
    {
        let this = self.clone();
        parse_sdp_fields(sdp_descriptor)
            .map_err(BoxError::from)
            .and_then(move |SdpFields { ice_ufrag, mid, .. }| {
                const SERVER_USER_LEN: usize = 12;
                const SERVER_PASSWD_LEN: usize = 24;

                let mut rng = thread_rng();
                let server_user = rand_string(&mut rng, SERVER_USER_LEN);
                let server_passwd = rand_string(&mut rng, SERVER_PASSWD_LEN);

                let incoming_session = IncomingSession {
                    server_user: server_user.clone(),
                    server_passwd: server_passwd.clone(),
                    remote_user: ice_ufrag,
                };

                let response = gen_sdp_response(
                    &mut rng,
                    &this.cert_fingerprint,
                    &this.public_addr.ip().to_string(),
                    this.public_addr.ip().is_ipv6(),
                    this.public_addr.port(),
                    &server_user,
                    &server_passwd,
                    &mid,
                );

                this.session_sender
                    .send(incoming_session)
                    .map(|_| response)
                    .map_err(|_| "RtcSessionEndpoint disconnected from RtcServer".into())
            })
    }

    /// Convenience method which returns an `http::Response` rather than a JSON string, with the
    /// correct format headers.
    pub fn http_session_request<I, E, S>(
        &self,
        sdp_descriptor: S,
    ) -> impl Future<Item = Response<String>, Error = BoxError>
    where
        I: AsRef<[u8]>,
        S: Stream<Item = I, Error = E>,
        E: Error + Send + Sync + 'static,
    {
        self.session_request(sdp_descriptor).map(|r| {
            Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(r)
                .expect("could not construct session response")
        })
    }
}

pub struct Server {
    udp_socket: UdpSocket,
    session_endpoint: SessionEndpoint,
    incoming_session_stream: Box<dyn Stream<Item = IncomingSession, Error = ()> + Send>,
    ssl_acceptor: SslAcceptor,
    outgoing_udp: VecDeque<(PooledBuffer, SocketAddr)>,
    incoming_rtc: VecDeque<(PooledBuffer, SocketAddr, MessageType)>,
    buffer_pool: BufferPool,
    sessions: HashMap<SessionKey, Session>,
    clients: HashMap<SocketAddr, Client>,
    last_generate_periodic: Instant,
    last_cleanup: Instant,
    periodic_timer: Interval,
}

impl Server {
    /// Start a new WebRTC data channel server listening on `listen_addr` and advertising its
    /// publicly available address as `public_addr`.
    ///
    /// WebRTC connections must be started via an external communication channel from a browser via
    /// the `SessionEndpoint`, after which a WebRTC data channel can be opened.
    pub fn new(listen_addr: SocketAddr, public_addr: SocketAddr) -> Result<Server, InternalError> {
        const SESSION_BUFFER_SIZE: usize = 8;

        let crypto = Crypto::init().expect("WebRTC server could not initialize OpenSSL primitives");
        let udp_socket = UdpSocket::bind(&listen_addr).map_err(InternalError::IoError)?;

        let (session_sender, session_receiver) = mpsc::channel(SESSION_BUFFER_SIZE);

        info!(
            "new WebRTC data channel server listening on {}, public addr {}",
            listen_addr, public_addr
        );

        let session_endpoint = SessionEndpoint {
            public_addr,
            cert_fingerprint: Arc::new(crypto.fingerprint),
            session_sender,
        };

        Ok(Server {
            udp_socket,
            session_endpoint,
            incoming_session_stream: Box::new(session_receiver),
            ssl_acceptor: crypto.ssl_acceptor,
            outgoing_udp: VecDeque::new(),
            incoming_rtc: VecDeque::new(),
            buffer_pool: BufferPool::new(),
            sessions: HashMap::new(),
            clients: HashMap::new(),
            last_generate_periodic: Instant::now(),
            last_cleanup: Instant::now(),
            periodic_timer: Interval::new_interval(PERIODIC_TIMER_INTERVAL),
        })
    }

    /// Returns a `SessionEndpoint` which can be used to start new WebRTC sessions.
    ///
    /// WebRTC connections must be started via an external communication channel from a browser via
    /// the returned `RtcSessionEndpoint`, and this communication channel will be used to exchange
    /// session descriptions in SDP format.
    ///
    /// The returned `RtcSessionEndpoint` will notify this `RtcServer` of new sessions via a shared
    /// async channel.  This is done so that the `RtcSessionEndpoint` is easy to use in a separate
    /// server task (such as a `hyper` HTTP server).
    pub fn session_endpoint(&self) -> SessionEndpoint {
        self.session_endpoint.clone()
    }

    /// Returns true if the client has a completely established WebRTC data channel connection and
    /// can send messages back and forth.  Returns false for disconnected clients as well as those
    /// that are still starting up or are in the process of shutting down.
    pub fn is_connected(&self, remote_addr: &SocketAddr) -> bool {
        if let Some(client) = self.clients.get(remote_addr) {
            client.is_established()
        } else {
            false
        }
    }

    /// Disconect the given client, does nothing if the client is not currently connected.
    pub fn disconnect(&mut self, remote_addr: &SocketAddr) {
        if let Some(client) = self.clients.get_mut(remote_addr) {
            if let Err(err) = client.start_shutdown() {
                warn!(
                    "error starting shutdown for client {}: {}",
                    remote_addr, err
                );
            } else {
                info!("starting shutdown for client {}", remote_addr);
            }
        }
    }

    /// Send the given message to the given remote client, if they are connected.
    pub fn poll_send(
        &mut self,
        message: &[u8],
        message_type: MessageType,
        remote_addr: &SocketAddr,
    ) -> Poll<(), SendError> {
        // Send pending UDP messages before potentially buffering new ones
        try_ready!(self.send_udp());

        let client = self
            .clients
            .get_mut(remote_addr)
            .ok_or(SendError::ClientNotConnected)?;

        match client.send_message(message_type, message) {
            Err(ClientError::NotConnected) => {
                return Err(SendError::ClientNotConnected);
            }
            Err(ClientError::NotEstablished) => {
                return Err(SendError::ClientConnectionNotEstablished);
            }
            Err(ClientError::IncompletePacketWrite) => {
                return Err(SendError::IncompleteMessageWrite)
            }
            Err(err) => {
                warn!(
                    "message send for client {} generated unexpected error, shutting down: {}",
                    remote_addr, err
                );
                let _ = client.start_shutdown();
                return Err(SendError::ClientNotConnected);
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
    /// server, as it also handles background tasks such as responding to STUN packets and timing
    /// out existing sessions.
    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Poll<MessageResult, RecvError> {
        while self.incoming_rtc.is_empty() {
            try_ready!(self.process());
        }

        let (message, remote_addr, message_type) = self.incoming_rtc.pop_front().unwrap();
        let message_len = message.len();
        if buf.len() < message_len {
            self.incoming_rtc
                .push_front((message, remote_addr, message_type));
            return Err(RecvError::IncompleteMessageRead);
        }

        buf[0..message_len].copy_from_slice(&message[..]);

        Ok(Async::Ready(MessageResult {
            message_len,
            message_type,
            remote_addr,
        }))
    }

    // Accepts new incoming WebRTC sessions, times out existing WebRTC sessions, sends outgoing UDP
    // packets, receives incoming UDP packets, and responds to STUN packets.
    fn process(&mut self) -> Poll<(), InternalError> {
        loop {
            match self.incoming_session_stream.poll() {
                Ok(Async::Ready(Some(incoming_session))) => {
                    info!(
                        "session initiated with server user: '{}' and remote user: '{}'",
                        incoming_session.server_user, incoming_session.remote_user
                    );

                    self.sessions.insert(
                        SessionKey {
                            server_user: incoming_session.server_user,
                            remote_user: incoming_session.remote_user,
                        },
                        Session {
                            server_passwd: incoming_session.server_passwd,
                            ttl: Instant::now(),
                        },
                    );
                }
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) => {
                    return Err(InternalError::Other(
                        "connection to RtcSessionEndpoint has unexpectedly closed".into(),
                    ));
                }
                Err(_) => unreachable!(),
            }
        }

        if self.last_cleanup.elapsed() >= CLEANUP_INTERVAL {
            self.last_cleanup = Instant::now();
            self.sessions.retain(|session_key, session| {
                if session.ttl.elapsed() < RTC_SESSION_TIMEOUT {
                    true
                } else {
                    info!(
                        "session timeout for server user '{}' and remote user '{}'",
                        session_key.server_user, session_key.remote_user
                    );
                    false
                }
            });

            self.clients.retain(|remote_addr, client| {
                if !client.is_shutdown()
                    && client.last_activity().elapsed() < RTC_CONNECTION_TIMEOUT
                {
                    true
                } else {
                    if !client.is_shutdown() {
                        info!("connection timeout for client {}", remote_addr);
                    }
                    info!("client {} removed", remote_addr);
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
                        return Err(InternalError::Other(
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
    fn send_udp(&mut self) -> Poll<(), InternalError> {
        if self.outgoing_udp.is_empty() {
            self.generate_periodic_packets()?;
        }

        while let Some((packet, remote_addr)) = self.outgoing_udp.pop_front() {
            match self
                .udp_socket
                .poll_send_to(&packet, &remote_addr)
                .map_err(InternalError::IoError)?
            {
                Async::Ready(len) => {
                    let packet_len = packet.len();
                    if len != packet_len {
                        return Err(InternalError::IoError(IoError::new(
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
    fn receive_udp(&mut self) -> Poll<(), InternalError> {
        let mut packet_buffer = self.buffer_pool.acquire();
        packet_buffer.resize(MAX_UDP_PAYLOAD_SIZE, 0);
        let (len, remote_addr) = try_ready!(self
            .udp_socket
            .poll_recv_from(&mut packet_buffer)
            .map_err(InternalError::IoError));
        if len > MAX_UDP_PAYLOAD_SIZE {
            return Err(InternalError::IoError(IoError::new(
                IoErrorKind::Other,
                "failed to read entire datagram from socket",
            )));
        }
        packet_buffer.truncate(len);

        if let Some(stun_binding_request) = parse_stun_binding_request(&packet_buffer[0..len]) {
            if let Some(session) = self.sessions.get_mut(&SessionKey {
                server_user: stun_binding_request.server_user,
                remote_user: stun_binding_request.remote_user,
            }) {
                session.ttl = Instant::now();
                let resp_len = write_stun_success_response(
                    stun_binding_request.transaction_id,
                    remote_addr,
                    session.server_passwd.as_bytes(),
                    &mut packet_buffer,
                )
                .map_err(InternalError::Other)?;

                packet_buffer.truncate(resp_len);
                self.outgoing_udp.push_back((packet_buffer, remote_addr));

                match self.clients.entry(remote_addr) {
                    HashMapEntry::Vacant(vacant) => {
                        info!(
                            "beginning client data channel connection with {}",
                            remote_addr,
                        );

                        vacant.insert(
                            Client::new(&self.ssl_acceptor, self.buffer_pool.clone(), remote_addr)
                                .map_err(|e| InternalError::Other(e.into()))?,
                        );
                    }
                    HashMapEntry::Occupied(_) => {}
                }
            }
        } else {
            if let Some(client) = self.clients.get_mut(&remote_addr) {
                if let Err(err) = client.receive_incoming_packet(packet_buffer) {
                    warn!(
                        "client {} had unexpected error receiving UDP packet, shutting down: {}",
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
    fn generate_periodic_packets(&mut self) -> Result<(), InternalError> {
        if self.last_generate_periodic.elapsed() >= PERIODIC_PACKET_INTERVAL {
            self.last_generate_periodic = Instant::now();

            for (remote_addr, client) in &mut self.clients {
                if let Err(err) = client.generate_periodic() {
                    warn!("error for client {}, shutting down: {}", remote_addr, err);
                    let _ = client.start_shutdown();
                }
                self.outgoing_udp
                    .extend(client.take_outgoing_packets().map(|p| (p, *remote_addr)));
            }
        }
        Ok(())
    }
}

const RTC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const RTC_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const PERIODIC_PACKET_INTERVAL: Duration = Duration::from_secs(1);
const PERIODIC_TIMER_INTERVAL: Duration = Duration::from_secs(1);

type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
struct SessionKey {
    server_user: String,
    remote_user: String,
}

struct Session {
    server_passwd: String,
    ttl: Instant,
}

struct IncomingSession {
    pub server_user: String,
    pub server_passwd: String,
    pub remote_user: String,
}
