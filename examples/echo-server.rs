use std::net::SocketAddr;

use clap::{Arg, Command};
use futures::stream::TryStreamExt;
use http_body_util::BodyStream;
use hyper::{
    header::{self, HeaderValue},
    server::conn::http1,
    service::service_fn,
    Method, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let matches = Command::new("echo-server")
        .arg(
            Arg::new("data")
                .short('d')
                .long("data")
                .takes_value(true)
                .required(true)
                .help("listen on the specified address/port for UDP WebRTC data channels"),
        )
        .arg(
            Arg::new("public")
                .short('p')
                .long("public")
                .takes_value(true)
                .required(true)
                .help("advertise the given address/port as the public WebRTC address/port"),
        )
        .arg(
            Arg::new("http")
                .short('h')
                .long("http")
                .takes_value(true)
                .required(true)
                .help("listen on the specified address/port for incoming HTTP (session reqeusts and test page"),
        )
        .get_matches();

    let webrtc_listen_addr: SocketAddr = matches
        .value_of("data")
        .unwrap()
        .parse()
        .expect("could not parse WebRTC data address/port");

    let public_webrtc_addr: SocketAddr = matches
        .value_of("public")
        .unwrap()
        .parse()
        .expect("could not parse advertised public WebRTC data address/port");

    let session_listen_addr: SocketAddr = matches
        .value_of("http")
        .unwrap()
        .parse()
        .expect("could not parse HTTP address/port");

    let mut rtc_server =
        webrtc_unreliable::tokio::new_server(webrtc_listen_addr, public_webrtc_addr)
            .expect("could not start RTC server");

    let session_endpoint = rtc_server.session_endpoint();

    tokio::spawn(async move {
        let listener = TcpListener::bind(session_listen_addr)
            .await
            .expect("could not listen on HTTP address/port");

        loop {
            match listener.accept().await {
                Err(err) => {
                    log::warn!("error accepting incoming HTTP connection: {:?}", err);
                }
                Ok((stream, remote_addr)) => {
                    let io = TokioIo::new(stream);
                    let session_endpoint = session_endpoint.clone();
                    tokio::spawn(async move {
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(
                                io,
                                service_fn(|req| async {
                                    let mut session_endpoint = session_endpoint.clone();
                                    if req.uri().path() == "/"
                                        || req.uri().path() == "/index.html"
                                            && req.method() == Method::GET
                                    {
                                        log::info!("serving example index HTML to {}", remote_addr);
                                        Response::builder()
                                            .body(include_str!("./echo-server.html").to_owned())
                                    } else if req.uri().path() == "/new_rtc_session"
                                        && req.method() == Method::POST
                                    {
                                        log::info!("WebRTC session request from {}", remote_addr);
                                        match session_endpoint
                                            .http_session_request(
                                                BodyStream::new(req.into_body()).try_filter_map(
                                                    |f| async { Ok(f.into_data().ok()) },
                                                ),
                                            )
                                            .await
                                        {
                                            Ok(mut resp) => {
                                                resp.headers_mut().insert(
                                                    header::ACCESS_CONTROL_ALLOW_ORIGIN,
                                                    HeaderValue::from_static("*"),
                                                );
                                                Ok(resp)
                                            }
                                            Err(err) => {
                                                log::warn!("bad rtc session request: {:?}", err);
                                                Response::builder()
                                                    .status(StatusCode::BAD_REQUEST)
                                                    .body(format!("error: {:?}", err))
                                            }
                                        }
                                    } else {
                                        Response::builder()
                                            .status(StatusCode::NOT_FOUND)
                                            .body("not found".to_owned())
                                    }
                                }),
                            )
                            .await
                        {
                            log::warn!("error serving connection: {:?}", err);
                        }
                    });
                }
            }
        }
    });

    let mut message_buf = Vec::new();
    loop {
        let received = match rtc_server.recv().await {
            Ok(received) => {
                message_buf.clear();
                message_buf.extend(received.message.as_ref());
                Some((received.message_type, received.remote_addr))
            }
            Err(err) => {
                log::warn!("could not receive RTC message: {:?}", err);
                None
            }
        };

        if let Some((message_type, remote_addr)) = received {
            if let Err(err) = rtc_server
                .send(&message_buf, message_type, &remote_addr)
                .await
            {
                log::warn!("could not send message to {}: {:?}", remote_addr, err);
            }
        }
    }
}
