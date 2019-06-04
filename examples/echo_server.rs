use clap::{App, Arg};
use futures::{
    future::{self, Either, IntoFuture},
    Async, Future,
};
use hyper::{
    header::{self, HeaderValue},
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Method, Response, Server, StatusCode,
};
use log::{info, warn};
use tokio::runtime::Runtime;

use webrtc_unreliable::{
    MessageResult as RtcMessageResult, RecvError as RtcRecvError, SendError as RtcSendError,
    Server as RtcServer,
};

fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let matches = App::new("echo_server")
        .arg(
            Arg::with_name("data")
                .short("d")
                .long("data")
                .takes_value(true)
                .required(true)
                .help("listen on the specified address/port for UDP WebRTC data channels"),
        )
        .arg(
            Arg::with_name("public")
                .short("p")
                .long("public")
                .takes_value(true)
                .required(true)
                .help("advertise the given address/port as the public WebRTC address/port"),
        )
        .arg(
            Arg::with_name("http")
                .short("h")
                .long("http")
                .takes_value(true)
                .required(true)
                .help("listen on the specified address/port for incoming HTTP (session reqeusts and test page"),
        )
        .get_matches();

    let mut runtime = Runtime::new().expect("could not build tokio runtime");

    let webrtc_listen_addr = matches
        .value_of("data")
        .unwrap()
        .parse()
        .expect("could not parse WebRTC data address/port");

    let public_webrtc_addr = matches
        .value_of("public")
        .unwrap()
        .parse()
        .expect("could not parse advertised public WebRTC data address/port");

    let session_listen_addr = matches
        .value_of("http")
        .unwrap()
        .parse()
        .expect("could not parse HTTP address/port");

    let mut rtc_server =
        RtcServer::new(webrtc_listen_addr, public_webrtc_addr).expect("could not start RTC server");
    let mut message_buf = vec![0; 0x10000];
    let mut received_message: Option<RtcMessageResult> = None;

    let session_endpoint = rtc_server.session_endpoint();
    runtime.spawn(Box::new(
        Server::bind(&session_listen_addr)
            .serve(make_service_fn(move |addr_stream: &AddrStream| {
                let session_endpoint = session_endpoint.clone();
                let remote_addr = addr_stream.remote_addr();
                service_fn(move |req| {
                    if req.uri().path() == "/"
                        || req.uri().path() == "/index.html" && req.method() == Method::GET
                    {
                        info!("serving example index HTML to {}", remote_addr);
                        Either::A(
                            Response::builder()
                                .body(Body::from(include_str!("./echo_server.html")))
                                .into_future(),
                        )
                    } else if req.uri().path() == "/new_rtc_session" && req.method() == Method::POST
                    {
                        info!("WebRTC session request from {}", remote_addr);
                        Either::B(
                            session_endpoint
                                .http_session_request(req.into_body())
                                .map(|mut resp| {
                                    resp.headers_mut().insert(
                                        header::ACCESS_CONTROL_ALLOW_ORIGIN,
                                        HeaderValue::from_static("*"),
                                    );
                                    resp.map(Body::from)
                                })
                                .then(|resp| match resp {
                                    Ok(resp) => Either::A(future::ok(resp)),
                                    Err(err) => Either::B(
                                        Response::builder()
                                            .status(StatusCode::BAD_REQUEST)
                                            .body(Body::from(format!("error: {}", err)))
                                            .into_future(),
                                    ),
                                }),
                        )
                    } else {
                        Either::A(
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::from("not found"))
                                .into_future(),
                        )
                    }
                })
            }))
            .map_err(|e| panic!("HTTP session server has died! {}", e)),
    ));

    runtime.spawn(Box::new(future::poll_fn(move || loop {
        match received_message.take() {
            Some(received) => {
                match rtc_server.poll_send(
                    &message_buf[0..received.message_len],
                    received.message_type,
                    &received.remote_addr,
                ) {
                    Ok(Async::Ready(())) => {}
                    Ok(Async::NotReady) => {
                        received_message = Some(received);
                        return Ok(Async::NotReady);
                    }
                    Err(RtcSendError::Internal(err)) => {
                        panic!("internal WebRTC server error: {}", err)
                    }
                    Err(err) => warn!(
                        "could not send message to {}: {}",
                        received.remote_addr, err
                    ),
                }
            }
            None => match rtc_server.poll_recv(&mut message_buf) {
                Ok(Async::Ready(incoming_message)) => {
                    received_message = Some(incoming_message);
                }
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(RtcRecvError::Internal(err)) => panic!("internal WebRTC server error: {}", err),
                Err(err) => warn!("could not receive RTC message: {}", err),
            },
        }
    })));

    runtime.shutdown_on_idle().wait().unwrap();
}
