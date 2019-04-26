use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap, VecDeque},
    error::Error,
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write},
    net::SocketAddr,
    time::{Duration, Instant},
};

use futures::{try_ready, Async, Poll, Stream};
use log::warn;
use openssl::ssl::SslAcceptor;
use tokio::{net::UdpSocket, timer::Interval};

use crate::buffer_pool::{BufferPool, PooledBuffer};
use crate::client::{Client, CLIENT_UPDATE_INTERVAL, MAX_UDP_PAYLOAD_SIZE};
use crate::crypto::Crypto;
use crate::http::{create_http_server, HttpServer, IncomingSessionStream};
use crate::stun::{parse_stun_binding_request, write_stun_success_response};

/// After no indication of a working connection for this amount of time, a client will be considered
/// timed out and disconnected.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

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
    last_client_update: Instant,
    update_timer: Interval,
}

impl RtcServer {
    pub fn new(
        http_listen_addr: SocketAddr,
        udp_listen_addr: SocketAddr,
        public_udp_addr: SocketAddr,
    ) -> Result<RtcServer, IoError> {
        const SESSION_BUFFER_SIZE: usize = 8;

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
            last_client_update: Instant::now(),
            update_timer: Interval::new_interval(CLIENT_UPDATE_INTERVAL),
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
                        created: Instant::now(),
                    },
                );
            } else {
                return Err(IoError::new(
                    IoErrorKind::Other,
                    "incoming session channel unexpectedly closed",
                ));
            }
        }

        self.update_timer.poll().unwrap();

        if self.last_client_update.elapsed() >= CLIENT_UPDATE_INTERVAL {
            self.last_client_update = Instant::now();
            self.pending_clients
                .retain(|_, pending_client| pending_client.created.elapsed() < SESSION_TIMEOUT);

            let outgoing_udp = &mut self.outgoing_udp;
            self.connected_clients.retain(|&remote_addr, client| {
                if !client.is_shutdown() && client.last_activity().elapsed() < SESSION_TIMEOUT {
                    outgoing_udp.extend(client.take_outgoing_packets().map(|p| (p, remote_addr)));
                    true
                } else {
                    false
                }
            });

            self.send_udp()?;
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
        packet_buffer.resize(MAX_UDP_PAYLOAD_SIZE, 0);
        let (len, remote_addr) = try_ready!(self.udp_socket.poll_recv_from(&mut packet_buffer));
        if len > MAX_UDP_PAYLOAD_SIZE {
            return Err(IoError::new(
                IoErrorKind::Other,
                "failed to read entire datagram from socket",
            ));
        }
        packet_buffer.truncate(len);

        match self.connected_clients.entry(remote_addr) {
            HashMapEntry::Occupied(mut occupied) => {
                let client = occupied.get_mut();
                if let Err(err) = client.receive_incoming_packet(packet_buffer) {
                    warn!("remote host {:?} error: {}", remote_addr, err);
                }
                self.outgoing_udp
                    .extend(client.take_outgoing_packets().map(|p| (p, remote_addr)));
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

                        vacant.insert(
                            Client::new(&self.ssl_acceptor, self.buffer_pool.clone(), remote_addr)
                                .expect("could not start DTLS handshake"),
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
type ConnectedClients = HashMap<SocketAddr, Client>;
