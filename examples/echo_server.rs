use clap::{App, Arg};
use futures::{future, Async, Future};
use tokio::runtime::Runtime;

use log::warn;
use webrtc_unreliable::{RtcError, RtcMessageResult, RtcServer};

fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let matches = App::new("echo_server")
        .arg(
            Arg::with_name("http")
                .short("h")
                .long("http")
                .takes_value(true)
                .required(true)
                .help("listen on the specified address/port for incoming HTTP connections"),
        )
        .arg(
            Arg::with_name("data")
                .short("d")
                .long("data")
                .takes_value(true)
                .required(true)
                .help("listen on the specified address/port for UDP WebRTC data"),
        )
        .arg(
            Arg::with_name("public")
                .short("p")
                .long("public")
                .takes_value(true)
                .help("advertise a different public WebRTC data port than the one listened on"),
        )
        .get_matches();

    let mut runtime = Runtime::new().expect("could not build runtime");

    let http_listen_addr = matches
        .value_of("http")
        .unwrap()
        .parse()
        .expect("could not parse HTTP address/port");
    let udp_listen_addr = matches
        .value_of("data")
        .unwrap()
        .parse()
        .expect("could not parse WebRTC data address/port");

    let public_udp_addr = if let Some(public) = matches.value_of("public") {
        public
            .parse()
            .expect("could not parse advertised public WebRTC data address/port")
    } else {
        udp_listen_addr
    };

    let mut rtc_server = RtcServer::new(http_listen_addr, udp_listen_addr, public_udp_addr)
        .expect("could not start RTC server");
    let mut message_buf = vec![0; 0x10000];
    let mut received_message: Option<RtcMessageResult> = None;

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
                    Err(RtcError::Internal(err)) => panic!("internal WebRTC server error: {}", err),
                    Err(err) => warn!(
                        "could not send message to {:?}: {}",
                        received.remote_addr, err
                    ),
                }
            }
            None => match rtc_server.poll_recv(&mut message_buf) {
                Ok(Async::Ready(incoming_message)) => {
                    received_message = Some(incoming_message);
                }
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(RtcError::Internal(err)) => panic!("internal WebRTC server error: {}", err),
                Err(err) => warn!("could not receive RTC message: {}", err),
            },
        }
    })));

    runtime.shutdown_on_idle().wait().unwrap();
}
