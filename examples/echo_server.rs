use clap::{App, Arg};
use hyper::{
    header::{self, HeaderValue},
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Error, Method, Response, Server, StatusCode,
};

use webrtc_unreliable::Server as RtcServer;

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

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

    let mut rtc_server = RtcServer::new(webrtc_listen_addr, public_webrtc_addr)
        .await
        .expect("could not start RTC server");

    let session_endpoint = rtc_server.session_endpoint();
    let make_svc = make_service_fn(move |addr_stream: &AddrStream| {
        let session_endpoint = session_endpoint.clone();
        let remote_addr = addr_stream.remote_addr();
        async move {
            Ok::<_, Error>(service_fn(move |req| {
                let mut session_endpoint = session_endpoint.clone();
                async move {
                    if req.uri().path() == "/"
                        || req.uri().path() == "/index.html" && req.method() == Method::GET
                    {
                        log::info!("serving example index HTML to {}", remote_addr);
                        Response::builder().body(Body::from(include_str!("./echo_server.html")))
                    } else if req.uri().path() == "/new_rtc_session" && req.method() == Method::POST
                    {
                        log::info!("WebRTC session request from {}", remote_addr);
                        match session_endpoint.http_session_request(req.into_body()).await {
                            Ok(mut resp) => {
                                resp.headers_mut().insert(
                                    header::ACCESS_CONTROL_ALLOW_ORIGIN,
                                    HeaderValue::from_static("*"),
                                );
                                Ok(resp.map(Body::from))
                            }
                            Err(err) => Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("error: {}", err))),
                        }
                    } else {
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Body::from("not found"))
                    }
                }
            }))
        }
    });

    tokio::spawn(async move {
        Server::bind(&session_listen_addr)
            .serve(make_svc)
            .await
            .expect("HTTP session server has died");
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
                log::warn!("could not receive RTC message: {}", err);
                None
            }
        };

        if let Some((message_type, remote_addr)) = received {
            if let Err(err) = rtc_server
                .send(&message_buf, message_type, &remote_addr)
                .await
            {
                log::warn!("could not send message to {}: {}", remote_addr, err);
            }
        }
    }
}
