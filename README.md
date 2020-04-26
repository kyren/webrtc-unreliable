## webrtc-unreliable

---

[![Build Status](https://img.shields.io/circleci/project/github/kyren/webrtc-unreliable.svg)](https://circleci.com/gh/kyren/webrtc-unreliable)
[![Latest Version](https://img.shields.io/crates/v/webrtc-unreliable.svg)](https://crates.io/crates/webrtc-unreliable)
[![API Documentation](https://docs.rs/webrtc-unreliable/badge.svg)](https://docs.rs/webrtc-unreliable)

This is a Rust library which allows you to write a game server with browser
based clients and UDP-like networking.

This crate is not meant as a general purpose WebRTC data channel system, it is
instead designed to be used as the bottom level UDP-like transport layer of a
higher level protocol in an environment where UDP is not available.

It requires a tokio runtime and provides an async API for accepting WebRTC
connections from browsers and sending and receiving WebRTC unreliable data
channel messages from multiple clients.

The full set of protocols needed to implement WebRTC is daunting.  This crate
implements only the bare minimum subset of WebRTC required to support
unreliable, unordered data channel messages.  Because the WebRTC support is so
minimal, this crate does not need to depend on a pre-existing heavyweight WebRTC
implementation, but as such the protocol support is extremely limited.

You should expect *only* WebRTC data channels to function, and *only* in
unreliable, unordered mode.  Additionally, there is a stricter limit on WebRTC
message lengths than what would be supported in a full WebRTC implementation.
Only *unfragmented* SCTP packets are handled, so any message large enough to
cause an SCTP packet to need fragmentation causes an error on write and is
simply dropped on read.  The maximum message length depends on the particular
browser you connect with, but in my testing currently it is slightly smaller
than 1200 bytes.

## Credit

This was originally a sort of Rust / tokio port of the
[WebUDP](https://github.com/seemk/WebUdp) project, so a lot of the credit for
the original design goes there.

## License

This project is licensed under the [MIT license](LICENSE)
