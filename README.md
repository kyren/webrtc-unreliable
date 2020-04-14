## webrtc-unreliable

---

[![Build Status](https://img.shields.io/circleci/project/github/kyren/webrtc-unreliable.svg)](https://circleci.com/gh/kyren/webrtc-unreliable)
[![Latest Version](https://img.shields.io/crates/v/webrtc-unreliable.svg)](https://crates.io/crates/webrtc-unreliable)
[![API Documentation](https://docs.rs/webrtc-unreliable/badge.svg)](https://docs.rs/webrtc-unreliable)

This is a Rust library which allows you to write a game server with browser
based clients and UDP-like networking.

It requires a tokio runtime and provides an async API for accepting WebRTC
connections from browsers and sending and receiving WebRTC unreliable data
channel messages from multiple clients.

The full set of protocols needed to implement WebRTC is daunting.  This crate
implements only the bare minimum subset of WebRTC required to support
unreliable, unordered data channel messages.  Because the WebRTC support is so
minimal, this crate does not need to depend on a pre-existing heavyweight WebRTC
implementation, but as such you should expect *only* WebRTC data channels to
function, and *only* in unreliable, unordered mode.

## Credit

This was originally a sort of Rust / tokio port of the
[WebUDP](https://github.com/seemk/WebUdp) project, so a lot of the credit for
the original design goes there.

## License

This project is licensed under the [MIT license](LICENSE)
