use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap, VecDeque},
    convert::AsRef,
    error::Error,
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    net::SocketAddr,
    ops::Deref,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_channel::mpsc;
use futures_core::Stream;
use futures_util::{pin_mut, select, FutureExt, SinkExt, StreamExt};
use http::{header, Response};
use openssl::ssl::SslAcceptor;
use rand::thread_rng;
use tokio::net::UdpSocket;
use tokio::time::{self, Interval};

use crate::{
    buffer_pool::{BufferHandle, BufferPool, OwnedBuffer},
    client::{Client, ClientError, MessageType, MAX_UDP_PAYLOAD_SIZE},
    crypto::Crypto,
    sdp::{gen_sdp_response, parse_sdp_fields, SdpFields},
    stun::{parse_stun_binding_request, write_stun_success_response},
    util::rand_string,
};

#[derive(Debug)]
pub enum SendError {
    /// Non-fatal error trying to send a message to an unknown, disconnected, or unestablished
    /// client.
    ClientNotConnected,
    /// Non-fatal error writing a WebRTC Data Channel message that is too large to fit in the
    /// maximum message length.
    IncompleteMessageWrite,
    /// I/O error on the underlying socket.  May or may not be fatal, depending on the specific
    /// error.
    Io(IoError),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SendError::ClientNotConnected => write!(f, "client is not connected"),
            SendError::IncompleteMessageWrite => {
                write!(f, "incomplete write of WebRTC Data Channel message")
            }
            SendError::Io(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl Error for SendError {}

impl From<IoError> for SendError {
    fn from(err: IoError) -> SendError {
        SendError::Io(err)
    }
}

#[derive(Debug)]
pub enum SessionError {
    /// `SessionEndpoint` has beeen disconnected from its `Server` (the `Server` has been dropped).
    Disconnected,
    /// An error streaming the SDP descriptor
    StreamError(Box<dyn Error + Send + Sync + 'static>),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SessionError::Disconnected => write!(f, "`SessionEndpoint` disconnected from `Server`"),
            SessionError::StreamError(e) => {
                write!(f, "error streaming the incoming SDP descriptor: {}", e)
            }
        }
    }
}

impl Error for SessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SessionError::Disconnected => None,
            SessionError::StreamError(e) => Some(e.as_ref()),
        }
    }
}

/// A reference to an internal buffer containing a received message.
pub struct MessageBuffer<'a>(BufferHandle<'a>);

impl<'a> Deref for MessageBuffer<'a> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for MessageBuffer<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct MessageResult<'a> {
    pub message: MessageBuffer<'a>,
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
    pub async fn session_request<I, E, S>(
        &mut self,
        sdp_descriptor: S,
    ) -> Result<String, SessionError>
    where
        I: AsRef<[u8]>,
        E: Error + Send + Sync + 'static,
        S: Stream<Item = Result<I, E>>,
    {
        const SERVER_USER_LEN: usize = 12;
        const SERVER_PASSWD_LEN: usize = 24;

        let SdpFields { ice_ufrag, mid, .. } = parse_sdp_fields(sdp_descriptor)
            .await
            .map_err(|e| SessionError::StreamError(e.into()))?;

        let (incoming_session, response) = {
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
                &self.cert_fingerprint,
                &self.public_addr.ip().to_string(),
                self.public_addr.ip().is_ipv6(),
                self.public_addr.port(),
                &server_user,
                &server_passwd,
                &mid,
            );

            (incoming_session, response)
        };

        self.session_sender
            .send(incoming_session)
            .await
            .map_err(|_| SessionError::Disconnected)?;
        Ok(response)
    }

    /// Convenience method which returns an `http::Response` rather than a JSON string, with the
    /// correct format headers.
    pub async fn http_session_request<I, E, S>(
        &mut self,
        sdp_descriptor: S,
    ) -> Result<Response<String>, SessionError>
    where
        I: AsRef<[u8]>,
        E: Error + Send + Sync + 'static,
        S: Stream<Item = Result<I, E>>,
    {
        let r = self.session_request(sdp_descriptor).await?;
        Ok(Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(r)
            .expect("could not construct session response"))
    }
}

pub struct Server {
    udp_socket: UdpSocket,
    session_endpoint: SessionEndpoint,
    incoming_session_stream: mpsc::Receiver<IncomingSession>,
    ssl_acceptor: SslAcceptor,
    outgoing_udp: VecDeque<(OwnedBuffer, SocketAddr)>,
    incoming_rtc: VecDeque<(OwnedBuffer, SocketAddr, MessageType)>,
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
    pub async fn new(listen_addr: SocketAddr, public_addr: SocketAddr) -> Result<Server, IoError> {
        const SESSION_BUFFER_SIZE: usize = 8;

        let crypto = Crypto::init().expect("WebRTC server could not initialize OpenSSL primitives");
        let udp_socket = UdpSocket::bind(&listen_addr).await?;

        let (session_sender, session_receiver) = mpsc::channel(SESSION_BUFFER_SIZE);

        log::info!(
            "new WebRTC data channel server listening on {}, public addr {}",
            listen_addr,
            public_addr
        );

        let session_endpoint = SessionEndpoint {
            public_addr,
            cert_fingerprint: Arc::new(crypto.fingerprint),
            session_sender,
        };

        Ok(Server {
            udp_socket,
            session_endpoint,
            incoming_session_stream: session_receiver,
            ssl_acceptor: crypto.ssl_acceptor,
            outgoing_udp: VecDeque::new(),
            incoming_rtc: VecDeque::new(),
            buffer_pool: BufferPool::new(),
            sessions: HashMap::new(),
            clients: HashMap::new(),
            last_generate_periodic: Instant::now(),
            last_cleanup: Instant::now(),
            periodic_timer: time::interval(PERIODIC_TIMER_INTERVAL),
        })
    }

    /// Returns a `SessionEndpoint` which can be used to start new WebRTC sessions.
    ///
    /// WebRTC connections must be started via an external communication channel from a browser via
    /// the returned `SessionEndpoint`, and this communication channel will be used to exchange
    /// session descriptions in SDP format.
    ///
    /// The returned `SessionEndpoint` will notify this `Server` of new sessions via a shared async
    /// channel.  This is done so that the `SessionEndpoint` is easy to use in a separate server
    /// task (such as a `hyper` HTTP server).
    pub fn session_endpoint(&self) -> SessionEndpoint {
        self.session_endpoint.clone()
    }

    /// List all the currently established client connections.
    pub fn connected_clients(&self) -> impl Iterator<Item = &SocketAddr> + '_ {
        self.clients.iter().filter_map(|(addr, client)| {
            if client.is_established() {
                Some(addr)
            } else {
                None
            }
        })
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
                log::warn!(
                    "error starting shutdown for client {}: {}",
                    remote_addr,
                    err
                );
            } else {
                log::info!("starting shutdown for client {}", remote_addr);
            }
        }
    }

    /// Send the given message to the given remote client, if they are connected.
    ///
    /// The given message must be less than `MAX_MESSAGE_LEN`.
    pub async fn send(
        &mut self,
        message: &[u8],
        message_type: MessageType,
        remote_addr: &SocketAddr,
    ) -> Result<(), SendError> {
        let client = self
            .clients
            .get_mut(remote_addr)
            .ok_or(SendError::ClientNotConnected)?;

        match client.send_message(message_type, message) {
            Err(ClientError::NotConnected) | Err(ClientError::NotEstablished) => {
                return Err(SendError::ClientNotConnected).into();
            }
            Err(ClientError::IncompletePacketWrite) => {
                return Err(SendError::IncompleteMessageWrite).into();
            }
            Err(err) => {
                log::warn!(
                    "message send for client {} generated unexpected error, shutting down: {}",
                    remote_addr,
                    err
                );
                let _ = client.start_shutdown();
                return Err(SendError::ClientNotConnected).into();
            }
            Ok(()) => {}
        }

        self.outgoing_udp
            .extend(client.take_outgoing_packets().map(|p| (p, *remote_addr)));
        Ok(self.send_outgoing().await?)
    }

    /// Receive a WebRTC data channel message from any connected client.
    ///
    /// `Server::recv` *must* be called for proper operation of the server, as it also handles
    /// background tasks such as responding to STUN packets and timing out existing sessions.
    ///
    /// If the provided buffer is not large enough to hold the received message, the received
    /// message will be truncated, and the original length will be returned as part of
    /// `MessageResult`.
    pub async fn recv(&mut self) -> Result<MessageResult<'_>, IoError> {
        while self.incoming_rtc.is_empty() {
            self.process().await?;
        }

        let (message, remote_addr, message_type) = self.incoming_rtc.pop_front().unwrap();
        let message = MessageBuffer(self.buffer_pool.adopt(message));
        return Ok(MessageResult {
            message,
            message_type,
            remote_addr,
        });
    }

    // Accepts new incoming WebRTC sessions, times out existing WebRTC sessions, sends outgoing UDP
    // packets, receives incoming UDP packets, and responds to STUN packets.
    async fn process(&mut self) -> Result<(), IoError> {
        enum Next {
            IncomingSession(IncomingSession),
            IncomingPacket(usize, SocketAddr),
            PeriodicTimer,
        }

        let mut packet_buffer = self.buffer_pool.acquire();
        packet_buffer.resize(MAX_UDP_PAYLOAD_SIZE, 0);
        let next = {
            let recv_udp = self.udp_socket.recv_from(&mut packet_buffer).fuse();
            pin_mut!(recv_udp);

            let timer_next = self.periodic_timer.tick().fuse();
            pin_mut!(timer_next);

            select! {
                incoming_session = self.incoming_session_stream.next() => {
                    Next::IncomingSession(
                        incoming_session.expect("connection to SessionEndpoint has closed")
                    )
                }
                res = recv_udp => {
                    let (len, remote_addr) = res?;
                    Next::IncomingPacket(len, remote_addr)
                }
                _ = timer_next => {
                    Next::PeriodicTimer
                }
            }
        };

        match next {
            Next::IncomingSession(incoming_session) => {
                drop(packet_buffer);
                self.accept_session(incoming_session)
            }
            Next::IncomingPacket(len, remote_addr) => {
                if len > MAX_UDP_PAYLOAD_SIZE {
                    return Err(IoError::new(
                        IoErrorKind::Other,
                        "failed to read entire datagram from socket",
                    ));
                }
                packet_buffer.truncate(len);
                let packet_buffer = packet_buffer.into_owned();
                self.receive_packet(remote_addr, packet_buffer);
                self.send_outgoing().await?;
            }
            Next::PeriodicTimer => {
                drop(packet_buffer);
                self.timeout_clients();
                self.generate_periodic_packets();
                self.send_outgoing().await?;
            }
        }

        Ok(())
    }

    // Send all pending outgoing UDP packets
    async fn send_outgoing(&mut self) -> Result<(), IoError> {
        while let Some((packet, remote_addr)) = self.outgoing_udp.pop_front() {
            let packet = self.buffer_pool.adopt(packet);
            let len = self.udp_socket.send_to(&packet, &remote_addr).await?;
            let packet_len = packet.len();
            if len != packet_len {
                return Err(IoError::new(
                    IoErrorKind::Other,
                    "failed to write entire datagram to socket",
                ));
            }
        }
        Ok(())
    }

    // Handle a single incoming UDP packet, either by responding to it as a STUN binding request or
    // by handling it as part of an existing WebRTC connection.
    fn receive_packet(&mut self, remote_addr: SocketAddr, packet_buffer: OwnedBuffer) {
        let mut packet_buffer = self.buffer_pool.adopt(packet_buffer);
        if let Some(stun_binding_request) = parse_stun_binding_request(&packet_buffer[..]) {
            if let Some(session) = self.sessions.get_mut(&SessionKey {
                server_user: stun_binding_request.server_user,
                remote_user: stun_binding_request.remote_user,
            }) {
                session.ttl = Instant::now();
                packet_buffer.resize(MAX_UDP_PAYLOAD_SIZE, 0);
                let resp_len = write_stun_success_response(
                    stun_binding_request.transaction_id,
                    remote_addr,
                    session.server_passwd.as_bytes(),
                    &mut packet_buffer,
                )
                .expect("could not write stun response");

                packet_buffer.truncate(resp_len);
                self.outgoing_udp
                    .push_back((packet_buffer.into_owned(), remote_addr));

                match self.clients.entry(remote_addr) {
                    HashMapEntry::Vacant(vacant) => {
                        log::info!(
                            "beginning client data channel connection with {}",
                            remote_addr,
                        );

                        vacant.insert(
                            Client::new(&self.ssl_acceptor, self.buffer_pool.clone(), remote_addr)
                                .expect("could not create new client instance"),
                        );
                    }
                    HashMapEntry::Occupied(_) => {}
                }
            }
        } else {
            if let Some(client) = self.clients.get_mut(&remote_addr) {
                if let Err(err) = client.receive_incoming_packet(packet_buffer.into_owned()) {
                    if !client.shutdown_started() {
                        log::warn!(
                            "client {} had unexpected error receiving UDP packet, shutting down: {}",
                            remote_addr, err
                        );
                        let _ = client.start_shutdown();
                    }
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
    }

    // Call `Client::generate_periodic` on all clients, if we are due to do so.
    fn generate_periodic_packets(&mut self) {
        if self.last_generate_periodic.elapsed() >= PERIODIC_PACKET_INTERVAL {
            self.last_generate_periodic = Instant::now();

            for (remote_addr, client) in &mut self.clients {
                if let Err(err) = client.generate_periodic() {
                    if !client.shutdown_started() {
                        log::warn!("error for client {}, shutting down: {}", remote_addr, err);
                        let _ = client.start_shutdown();
                    }
                }
                self.outgoing_udp
                    .extend(client.take_outgoing_packets().map(|p| (p, *remote_addr)));
            }
        }
    }

    // Clean up all client sessions / connections, if we are due to do so.
    fn timeout_clients(&mut self) {
        if self.last_cleanup.elapsed() >= CLEANUP_INTERVAL {
            self.last_cleanup = Instant::now();
            self.sessions.retain(|session_key, session| {
                if session.ttl.elapsed() < RTC_SESSION_TIMEOUT {
                    true
                } else {
                    log::info!(
                        "session timeout for server user '{}' and remote user '{}'",
                        session_key.server_user,
                        session_key.remote_user
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
                        log::info!("connection timeout for client {}", remote_addr);
                    }
                    log::info!("client {} removed", remote_addr);
                    false
                }
            });
        }
    }

    fn accept_session(&mut self, incoming_session: IncomingSession) {
        log::info!(
            "session initiated with server user: '{}' and remote user: '{}'",
            incoming_session.server_user,
            incoming_session.remote_user
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
}

const RTC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const RTC_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const PERIODIC_PACKET_INTERVAL: Duration = Duration::from_secs(1);
const PERIODIC_TIMER_INTERVAL: Duration = Duration::from_secs(1);

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
