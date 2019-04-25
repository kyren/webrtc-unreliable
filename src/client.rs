use std::{
    collections::VecDeque,
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write},
    iter::Iterator,
    net::SocketAddr,
};

use log::{info, warn};
use openssl::{
    error::ErrorStack as SslErrorStack,
    ssl::{ErrorCode, HandshakeError, MidHandshakeSslStream, SslAcceptor, SslStream},
};

use crate::buffer_pool::{BufferPool, PooledBuffer};
use crate::sctp::{read_sctp_packet, SctpChunk};
use crate::MAX_UDP_DGRAM_SIZE;

pub struct Client {
    remote_addr: SocketAddr,
    ssl_stream: ClientSslStream,
}

impl Client {
    pub fn new(
        buffer_pool: BufferPool,
        remote_addr: SocketAddr,
        ssl_acceptor: &SslAcceptor,
    ) -> Result<Client, SslErrorStack> {
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
                ssl_stream: ClientSslStream::Unestablished(Some(mid_handshake)),
            }),
        }
    }

    pub fn is_established(&self) -> bool {
        match &self.ssl_stream {
            ClientSslStream::Established(_) => true,
            _ => false,
        }
    }

    pub fn is_shutdown(&self) -> bool {
        match &self.ssl_stream {
            ClientSslStream::Unestablished(None) => true,
            _ => false,
        }
    }

    pub fn start_shutdown(&mut self) {
        unimplemented!()
    }

    pub fn receive_incoming_packet(&mut self, udp_packet: PooledBuffer) -> Result<(), IoError> {
        match &mut self.ssl_stream {
            ClientSslStream::Unestablished(maybe_mid_handshake) => {
                if let Some(mut mid_handshake) = maybe_mid_handshake.take() {
                    mid_handshake.get_mut().incoming_udp.push_back(udp_packet);
                    match mid_handshake.handshake() {
                        Ok(ssl_stream) => {
                            self.ssl_stream = ClientSslStream::Established(ssl_stream);
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
                                self.ssl_stream =
                                    ClientSslStream::Unestablished(Some(mid_handshake));
                            }
                            HandshakeError::WouldBlock(mid_handshake) => {
                                self.ssl_stream =
                                    ClientSslStream::Unestablished(Some(mid_handshake));
                            }
                        },
                    }
                } else {
                    return Err(IoErrorKind::NotConnected.into());
                }
            }
            ClientSslStream::Established(ssl_stream) => {
                ssl_stream.get_mut().incoming_udp.push_back(udp_packet);
            }
        }

        if let ClientSslStream::Established(ssl_stream) = &mut self.ssl_stream {
            loop {
                let mut ssl_buffer = ssl_stream.get_ref().buffer_pool.acquire();
                ssl_buffer.resize(MAX_UDP_DGRAM_SIZE, 0);
                match ssl_stream.ssl_read(&mut ssl_buffer) {
                    Ok(size) => {
                        ssl_buffer.truncate(size);
                        let mut sctp_chunks = [SctpChunk::Abort; 16];
                        match read_sctp_packet(&ssl_buffer, &mut sctp_chunks) {
                            Ok(sctp_packet) => {
                                warn!("unimplemented handling of SCTP {:?}", sctp_packet);
                            }
                            Err(err) => {
                                warn!("sctp error on packet received over DTLS: {:?}", err);
                                hexdump::hexdump(&ssl_buffer);
                            }
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
        }

        Ok(())
    }

    pub fn take_outgoing_packets<'a>(&'a mut self) -> impl Iterator<Item = PooledBuffer> + 'a {
        (match &mut self.ssl_stream {
            ClientSslStream::Unestablished(Some(mid_handshake)) => {
                Some(mid_handshake.get_mut().outgoing_udp.drain(..))
            }
            ClientSslStream::Unestablished(None) => None,
            ClientSslStream::Established(ssl_stream) => {
                Some(ssl_stream.get_mut().outgoing_udp.drain(..))
            }
        })
        .into_iter()
        .flatten()
    }
}

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
