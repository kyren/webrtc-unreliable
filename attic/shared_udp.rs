use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap, HashSet, VecDeque},
    error::Error,
    fmt, mem,
    net::SocketAddr,
};

use bytes::{Bytes, BytesMut};
use futures::{future, sync::mpsc, Async, AsyncSink, Sink, Stream};
use tokio::{
    codec::BytesCodec,
    executor::{Executor, SpawnError},
    net::{UdpFramed, UdpSocket},
};

#[derive(Debug)]
struct UdpConnectionClosed;

impl fmt::Display for UdpConnectionClosed {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "UDP connection has been closed",)
    }
}

impl Error for UdpConnectionClosed {}

type UdpConnectionSink = Box<dyn Sink<SinkItem = Bytes, SinkError = UdpConnectionClosed> + Send>;
type UdpConnectionStream = Box<dyn Stream<Item = BytesMut, Error = ()> + Send>;

type UdpConnection = (UdpConnectionSink, UdpConnectionStream);

fn spawn_udp_listener<E>(
    mut executor: E,
    udp_socket: UdpSocket,
) -> Result<mpsc::Receiver<UdpConnection>, SpawnError>
where
    E: Executor,
{
    const MAX_DGRAM_SIZE: usize = 0x10000;
    const MAX_BUFFERED_PACKETS: usize = 128;
    const MAX_PENDING_CONNECTIONS: usize = 32;
    const OUTGOING_PACKET_BUFFER: usize = 64;
    const INCOMING_PACKET_BUFFER: usize = 8;
    const CONNECTION_BUFFER_SIZE: usize = 8;

    let udp_framed = UdpFramed::new(udp_socket, BytesCodec::new());
    let (mut udp_sink, mut udp_stream) = udp_framed.split();
    let (connection_sender, connection_receiver) = mpsc::channel(CONNECTION_BUFFER_SIZE);
    let (outgoing_packet_sender, mut outgoing_packet_receiver) =
        mpsc::channel(OUTGOING_PACKET_BUFFER);
    let mut connections: HashMap<SocketAddr, mpsc::Sender<BytesMut>> = HashMap::new();
    let mut connection_sender = Some(connection_sender);
    let mut incoming_packets = VecDeque::new();
    let mut outgoing_packets = VecDeque::new();
    let mut waiting_packets = VecDeque::new();
    let mut senders_need_flush = HashSet::new();
    let mut pending_connections: VecDeque<UdpConnection> = VecDeque::new();

    executor.spawn(Box::new(future::poll_fn(move || {
        while incoming_packets.len() < MAX_BUFFERED_PACKETS {
            match udp_stream.poll().expect("udp socket error") {
                Async::Ready(Some((packet, addr))) => {
                    incoming_packets.push_back((packet, addr));
                }
                Async::Ready(None) => unreachable!("UdpFramed Stream should not return None"),
                Async::NotReady => break,
            }
        }

        while let Some((packet, addr)) = incoming_packets.pop_front() {
            match connections.entry(addr) {
                HashMapEntry::Occupied(mut occupied) => {
                    if occupied.get().is_closed() {
                        occupied.remove();
                        incoming_packets.push_front((packet, addr));
                    } else {
                        match occupied.get_mut().start_send(packet) {
                            Ok(AsyncSink::Ready) => {
                                senders_need_flush.insert(addr);
                            }
                            Ok(AsyncSink::NotReady(packet)) => {
                                waiting_packets.push_back((packet, addr));
                            }
                            Err(_) => {
                                occupied.remove();
                            }
                        }
                    }
                }
                HashMapEntry::Vacant(vacant) => {
                    if connection_sender.is_some()
                        && pending_connections.len() < MAX_PENDING_CONNECTIONS
                    {
                        incoming_packets.push_front((packet, addr));

                        let (sender, stream) = mpsc::channel(OUTGOING_PACKET_BUFFER);
                        let sink = outgoing_packet_sender
                            .clone()
                            .sink_map_err(|_| UdpConnectionClosed)
                            .with(move |packet| Ok((packet, addr)));

                        vacant.insert(sender);
                        pending_connections.push_back((Box::new(sink), Box::new(stream)));
                    }
                }
            }
        }
        mem::swap(&mut incoming_packets, &mut waiting_packets);

        senders_need_flush.retain(|addr| {
            if let Some(sender) = connections.get_mut(addr) {
                match sender.poll_complete() {
                    Ok(Async::Ready(_)) => false,
                    Ok(Async::NotReady) => true,
                    Err(_) => {
                        connections.remove(addr);
                        false
                    }
                }
            } else {
                false
            }
        });

        if let Some(mut csender) = connection_sender.take() {
            while let Some((sink, stream)) = pending_connections.pop_front() {
                match csender.start_send((sink, stream)) {
                    Ok(AsyncSink::Ready) => {}
                    Ok(AsyncSink::NotReady((sink, stream))) => {
                        pending_connections.push_front((sink, stream));
                        break;
                    }
                    Err(_) => {
                        pending_connections.clear();
                        break;
                    }
                }
            }
            if csender.poll_complete().is_ok() {
                connection_sender = Some(csender);
            }
        } else {
            pending_connections.clear();
        }

        while outgoing_packets.len() < MAX_BUFFERED_PACKETS {
            match outgoing_packet_receiver.poll().unwrap() {
                Async::Ready(Some((packet, addr))) => {
                    outgoing_packets.push_back((packet, addr));
                }
                Async::Ready(None) => {
                    unreachable!("there is always at least one outgoing packet sender")
                }
                Async::NotReady => break,
            }
        }

        while let Some((packet, addr)) = outgoing_packets.pop_front() {
            match udp_sink
                .start_send((packet, addr))
                .expect("udp socket error")
            {
                AsyncSink::Ready => {}
                AsyncSink::NotReady((sink, stream)) => {
                    outgoing_packets.push_front((sink, stream));
                    break;
                }
            }
        }
        udp_sink.poll_complete().expect("udp socket error");

        Ok(Async::NotReady)
    })))?;

    Ok(connection_receiver)
}
