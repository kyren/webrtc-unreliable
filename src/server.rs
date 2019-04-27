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
use crate::client::{
    RtcClient, RtcClientError, RtcMessageType, CLIENT_UPDATE_INTERVAL, MAX_UDP_PAYLOAD_SIZE,
};
use crate::crypto::Crypto;
use crate::http::{create_http_server, HttpServer, IncomingSessionStream};
use crate::stun::{parse_stun_binding_request, write_stun_success_response};

/// After no indication of a working connection for this amount of time, a client will be considered
/// timed out and disconnected.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(8);

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
    /// Other generally fatal internal error
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
    outgoing_udp: OutgoingUdp,
    incoming_rtc: IncomingRtc,
    buffer_pool: BufferPool,
    pending_clients: PendingClients,
    connected_clients: ConnectedClients,
    last_client_update: Instant,
    update_timer: Interval,
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
            outgoing_udp: OutgoingUdp::new(),
            incoming_rtc: IncomingRtc::new(),
            buffer_pool: BufferPool::new(),
            pending_clients: PendingClients::new(),
            connected_clients: ConnectedClients::new(),
            last_client_update: Instant::now(),
            update_timer: Interval::new_interval(CLIENT_UPDATE_INTERVAL),
        })
    }

    /// Returns true if the client has a completely established WebRTC data channel connection and
    /// can send messages back and forth.  Returns false for disconnected clients as well as those
    /// that are still starting up or are in the process of shutting down.
    pub fn is_connected(&self, remote_addr: &SocketAddr) -> bool {
        if let Some(client) = self.connected_clients.get(remote_addr) {
            client.is_established()
        } else {
            false
        }
    }

    /// Disconect the given client, does nothing if the client is not currently connected.
    pub fn disconnect(&mut self, remote_addr: &SocketAddr) {
        if let Some(client) = self.connected_clients.get_mut(remote_addr) {
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

    pub fn send(
        &mut self,
        remote_addr: &SocketAddr,
        message_type: RtcMessageType,
        message: &[u8],
    ) -> Poll<(), RtcError> {
        try_ready!(self.send_udp());

        let client = self
            .connected_clients
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

        Ok(Async::Ready(()))
    }

    pub fn receive(&mut self, buf: &mut [u8]) -> Poll<RtcMessageResult, RtcError> {
        while self.incoming_rtc.is_empty() {
            try_ready!(self.send_udp());
            try_ready!(self.receive_udp());
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

    pub fn process(&mut self) -> Result<(), RtcInternalError> {
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

                self.pending_clients.insert(
                    PendingClientKey {
                        server_user: incoming_session.server_user,
                        remote_user: incoming_session.remote_user,
                    },
                    PendingClient {
                        server_passwd: incoming_session.server_passwd,
                        created: Instant::now(),
                    },
                );
            } else {
                return Err(RtcInternalError::Other(
                    "incoming session channel unexpectedly closed".into(),
                ));
            }
        }

        loop {
            match self.update_timer.poll() {
                Ok(Async::Ready(val)) => {
                    val.expect("interval stream should not stop");
                }
                Ok(Async::NotReady) => break,
                Err(err) => {
                    if err.is_shutdown() {
                        return Err(RtcInternalError::Other(
                            "update timer has unexpectedly shutdown".into(),
                        ));
                    }
                }
            }
        }

        if self.last_client_update.elapsed() >= CLIENT_UPDATE_INTERVAL {
            self.last_client_update = Instant::now();
            self.pending_clients
                .retain(|pending_client_key, pending_client| {
                    if pending_client.created.elapsed() < SESSION_TIMEOUT {
                        true
                    } else {
                        warn!(
                            "ICE session timeout for server user '{}' and remote user '{}'",
                            pending_client_key.server_user, pending_client_key.remote_user
                        );
                        false
                    }
                });

            for (remote_addr, client) in &mut self.connected_clients {
                if let Err(err) = client.update() {
                    warn!("error for client {:?}, shutting down: {}", remote_addr, err);
                    let _ = client.start_shutdown();
                }
            }

            let outgoing_udp = &mut self.outgoing_udp;
            self.connected_clients.retain(|&remote_addr, client| {
                if !client.is_shutdown() && client.last_activity().elapsed() < SESSION_TIMEOUT {
                    outgoing_udp.extend(client.take_outgoing_packets().map(|p| (p, remote_addr)));
                    true
                } else {
                    if !client.is_shutdown() {
                        warn!("timeout for client {:?}", remote_addr);
                    }
                    info!("client {:?} removed", remote_addr);
                    false
                }
            });
        }

        self.send_udp()?;

        Ok(())
    }

    fn send_udp(&mut self) -> Poll<(), RtcInternalError> {
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

        match self.connected_clients.entry(remote_addr) {
            HashMapEntry::Occupied(mut occupied) => {
                let client = occupied.get_mut();
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
                        .map_err(RtcInternalError::Other)?;

                        packet_buffer.truncate(resp_len);
                        self.outgoing_udp.push_back((packet_buffer, remote_addr));

                        vacant.insert(
                            RtcClient::new(
                                &self.ssl_acceptor,
                                self.buffer_pool.clone(),
                                remote_addr,
                            )
                            .map_err(|e| RtcInternalError::Other(e.into()))?,
                        );
                    }
                }
            }
        }

        Ok(Async::Ready(()))
    }
}

type OutgoingUdp = VecDeque<(PooledBuffer, SocketAddr)>;
type IncomingRtc = VecDeque<(PooledBuffer, SocketAddr, RtcMessageType)>;

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
struct PendingClientKey {
    server_user: String,
    remote_user: String,
}

struct PendingClient {
    server_passwd: String,
    created: Instant,
}

type PendingClients = HashMap<PendingClientKey, PendingClient>;
type ConnectedClients = HashMap<SocketAddr, RtcClient>;
