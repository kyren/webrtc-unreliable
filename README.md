[![Build Status](https://img.shields.io/circleci/project/github/kyren/webrtc-unreliable.svg)](https://circleci.com/gh/kyren/webrtc-unreliable)
[![Latest Version](https://img.shields.io/crates/v/webrtc-unreliable.svg)](https://crates.io/crates/webrtc-unreliable)
[![API Documentation](https://docs.rs/webrtc-unreliable/badge.svg)](https://docs.rs/webrtc-unreliable)

This is a Rust library which allows you to write a game server with browser
based clients and UDP-like networking.

It requires a tokio runtime and provides an async API for accepting WebRTC
connections from browsers and sending and receiving WebRTC unreliable data
channel messages from multiple clients.

The full set of protocols needed to implement WebRTC is daunting.  This crate
does not use an external WebRTC implementation or even a pre-existing SCTP
implementation, currently the only major part of WebRTC that this library
doesn't handle internally is DTLS, which it uses the `openssl` crate for.  As
such, it vastly simpler than using e.g. google's WebRTC implementation to run a
game server, but it only supports many of the necessary protocols in WebRTC to
the *barest minimum*.  You should expect ONLY WebRTC data channels to function,
and only in unreliable, unordered mode.

## Credit

This was originally a sort of Rust / tokio port of the
[WebUDP](https://github.com/seemk/WebUdp) project, so a lot of the credit for
the original design goes there.

## License

This project is licensed under the [MIT license](LICENSE)
