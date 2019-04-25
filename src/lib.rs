mod buffer_pool;
mod client;
mod crypto;
mod http;
mod sctp;
mod sdp;
mod server;
mod stun;
mod util;

const MAX_UDP_DGRAM_SIZE: usize = 0x10000;

pub use server::{RtcMessageResult, RtcMessageType, RtcSendError, RtcServer};
