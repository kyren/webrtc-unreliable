use std::{
    future::Future,
    io,
    net::SocketAddr,
    task::{Context, Poll},
    time::Duration,
};

pub trait UdpSocket {
    fn poll_recv_from(
        &mut self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, SocketAddr), io::Error>>;

    fn poll_send_to(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
        addr: SocketAddr,
    ) -> Poll<Result<usize, io::Error>>;
}

pub trait Runtime {
    type Timer: Future<Output = ()>;
    type UdpSocket: UdpSocket;

    fn bind_udp(&self, listen_addr: SocketAddr) -> Result<Self::UdpSocket, io::Error>;
    fn timer(&self, after: Duration) -> Self::Timer;
}
