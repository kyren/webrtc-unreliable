use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_util::ready;

#[pin_project::pin_project]
pub struct Timer(#[pin] tokio::time::Sleep);

impl Future for Timer {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        self.project().0.poll(cx)
    }
}

pub struct UdpSocket(tokio::net::UdpSocket);

impl crate::runtime::UdpSocket for UdpSocket {
    fn poll_recv_from(
        &mut self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, SocketAddr), io::Error>> {
        let mut buf = tokio::io::ReadBuf::new(buf);
        let socket_addr = ready!(self.0.poll_recv_from(cx, &mut buf))?;
        Poll::Ready(Ok((buf.filled().len(), socket_addr)))
    }

    fn poll_send_to(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
        addr: SocketAddr,
    ) -> Poll<Result<usize, io::Error>> {
        self.0.poll_send_to(cx, buf, addr)
    }
}

pub struct Runtime;

impl crate::runtime::Runtime for Runtime {
    type Timer = Timer;
    type UdpSocket = UdpSocket;

    fn bind_udp(&self, listen_addr: SocketAddr) -> Result<UdpSocket, io::Error> {
        let socket = std::net::UdpSocket::bind(listen_addr)?;
        socket.set_nonblocking(true)?;
        Ok(UdpSocket(tokio::net::UdpSocket::from_std(socket)?))
    }

    fn timer(&self, after: Duration) -> Timer {
        Timer(tokio::time::sleep(after))
    }
}

pub type Server = crate::server::Server<Runtime>;

pub fn new_server(
    listen_addr: SocketAddr,
    public_addr: SocketAddr,
) -> Result<crate::server::Server<Runtime>, io::Error> {
    crate::server::Server::new(Runtime, listen_addr, public_addr)
}
