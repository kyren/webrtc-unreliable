use std::{error, net::SocketAddr};

use futures::{sync::mpsc, Future, Sink, Stream};
use hyper::{header, service::service_fn, Body, Response, Server};
use rand::thread_rng;

use crate::sdp::{gen_sdp_response, parse_sdp_fields, SdpFields};
use crate::util::rand_string;

pub type Error = Box<error::Error + Send + Sync>;
pub type HttpServer = Box<Future<Item = (), Error = Error> + Send>;
pub type IncomingSessionStream = Box<Stream<Item = IncomingSession, Error = ()> + Send>;

pub struct IncomingSession {
    pub server_user: String,
    pub server_passwd: String,
    pub remote_user: String,
}

pub fn create_http_server(
    listen_addr: &SocketAddr,
    udp_addr: SocketAddr,
    cert_fingerprint: String,
    session_buffer: usize,
) -> (HttpServer, IncomingSessionStream) {
    let (session_sender, session_receiver) = mpsc::channel(session_buffer);
    let http_server = Server::bind(&listen_addr)
        .serve(move || {
            let cert_fingerprint = cert_fingerprint.clone();
            let session_sender = session_sender.clone();
            service_fn(move |req| {
                const SERVER_USER_LEN: usize = 8;
                const SERVER_PASSWD_LEN: usize = 24;

                let cert_fingerprint = cert_fingerprint.clone();
                let session_sender = session_sender.clone();
                parse_sdp_fields(req.into_body()).and_then(move |sdp_fields| {
                    let SdpFields { ice_ufrag, mid, .. } = sdp_fields;
                    let mut rng = thread_rng();
                    let server_user = rand_string(&mut rng, SERVER_USER_LEN);
                    let server_passwd = rand_string(&mut rng, SERVER_PASSWD_LEN);
                    session_sender
                        .send(IncomingSession {
                            server_user: server_user.clone(),
                            server_passwd: server_passwd.clone(),
                            remote_user: ice_ufrag,
                        })
                        .map_err(Error::from)
                        .and_then(move |_| {
                            let mut rng = thread_rng();
                            Response::builder()
                                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                .body(Body::from(gen_sdp_response(
                                    &mut rng,
                                    &cert_fingerprint,
                                    &udp_addr.ip().to_string(),
                                    udp_addr.port(),
                                    &server_user,
                                    &server_passwd,
                                    &mid,
                                )))
                                .map_err(Error::from)
                        })
                })
            })
        })
        .map_err(Error::from);

    (Box::new(http_server), Box::new(session_receiver))
}
