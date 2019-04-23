use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    sync::Arc,
};

use futures::{
    sync::BiLock,
    task::{self, Task},
    Async, Poll,
};

#[derive(Debug)]
pub enum PacketChannelError {
    TooLarge {
        packet_size: usize,
        buffer_capacity: usize,
    },
    Closed,
}

impl fmt::Display for PacketChannelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            PacketChannelError::TooLarge {
                packet_size,
                buffer_capacity,
            } => write!(
                f,
                "packet size {} too large for max buffer capcity {}",
                packet_size, buffer_capacity
            ),
            PacketChannelError::Closed => write!(f, "packet channel is closed",),
        }
    }
}

impl Error for PacketChannelError {}

impl From<PacketChannelError> for IoError {
    fn from(pce: PacketChannelError) -> Self {
        let kind = match pce {
            PacketChannelError::TooLarge { .. } => IoErrorKind::Other,
            PacketChannelError::Closed => IoErrorKind::ConnectionAborted,
        };
        IoError::new(kind, pce)
    }
}

/// The action to take when a PacketWriter tries to write to a full buffer
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum PacketBufferCapacity {
    /// Packet buffer is unbounded
    Unbounded,
    /// After the given size is reached, writers return NotReady, and become notified when the
    /// PacketReader makes room.
    MaxWait(usize),
    /// After the given size is reached, writers overwrite least recently sent packets until there
    /// is enough room.
    MaxOverwrite(usize),
}

pub struct PacketReader(BiLock<PacketBuffer>, Arc<()>);

pub struct PacketWriter(BiLock<PacketBuffer>, Arc<()>);

struct PacketBuffer {
    data: VecDeque<u8>,
    capacity: PacketBufferCapacity,
    packets: VecDeque<usize>,
    task: Option<Task>,
}

pub fn new_packet_channel(capacity: PacketBufferCapacity) -> (PacketReader, PacketWriter) {
    let packet_buffer = PacketBuffer {
        data: VecDeque::new(),
        capacity,
        packets: VecDeque::new(),
        task: None,
    };
    let reader_link = Arc::new(());
    let writer_link = reader_link.clone();
    let (reader_buffer, writer_buffer) = BiLock::new(packet_buffer);
    (
        PacketReader(reader_buffer, reader_link),
        PacketWriter(writer_buffer, writer_link),
    )
}

impl PacketWriter {
    /// Returns an `Err(PacketChannelError::TooLarge)` if the packet is too large to fit in the
    /// internal buffer capacity (and the packet channel is not allowed to grow the internal
    /// capacity).
    pub fn poll_write_packet(&self, packet: &[u8]) -> Poll<(), PacketChannelError> {
        if let Async::Ready(mut packet_buffer) = self.0.poll_lock() {
            if Arc::strong_count(&self.1) == 1 {
                return Err(PacketChannelError::Closed);
            }

            match packet_buffer.capacity {
                PacketBufferCapacity::Unbounded => {}
                PacketBufferCapacity::MaxWait(max_capacity) => {
                    if packet.len() > max_capacity {
                        return Err(PacketChannelError::TooLarge {
                            packet_size: packet.len(),
                            buffer_capacity: max_capacity,
                        });
                    }
                    if packet_buffer.data.len() + packet.len() > max_capacity {
                        packet_buffer.task = Some(task::current());
                        return Ok(Async::NotReady);
                    }
                }
                PacketBufferCapacity::MaxOverwrite(max_capacity) => {
                    if packet.len() > max_capacity {
                        return Err(PacketChannelError::TooLarge {
                            packet_size: packet.len(),
                            buffer_capacity: max_capacity,
                        });
                    }
                    while packet_buffer.data.len() + packet.len() > packet_buffer.data.capacity() {
                        let next_packet_size = packet_buffer.packets.pop_front().unwrap();
                        packet_buffer.data.drain(0..next_packet_size);
                    }
                }
            }

            packet_buffer.data.extend(packet);
            packet_buffer.packets.push_back(packet.len());
            if let Some(task) = packet_buffer.task.take() {
                task.notify();
            }
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }
}

impl PacketReader {
    /// Returns an `Err(PacketChannelError::TooLarge)` if the next packet does not fit in the given
    /// destination buffer.
    pub fn poll_read_packet(&self, dst: &mut [u8]) -> Poll<usize, PacketChannelError> {
        if let Async::Ready(mut packet_buffer) = self.0.poll_lock() {
            if let Some(next_packet_size) = packet_buffer.packets.pop_front() {
                if next_packet_size > dst.len() {
                    packet_buffer.packets.push_front(next_packet_size);
                    return Err(PacketChannelError::TooLarge {
                        packet_size: next_packet_size,
                        buffer_capacity: dst.len(),
                    });
                }
                for i in 0..next_packet_size.min(dst.len()) {
                    dst[i] = packet_buffer.data[i];
                }
                Ok(Async::Ready(next_packet_size))
            } else {
                if Arc::strong_count(&self.1) == 1 {
                    return Err(PacketChannelError::Closed);
                }

                assert!(packet_buffer.data.len() == 0);
                packet_buffer.task = Some(task::current());
                Ok(Async::NotReady)
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}
