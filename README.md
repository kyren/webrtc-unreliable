## webrtc-unreliable

---

[![Build Status](https://img.shields.io/circleci/project/github/triplehex/webrtc-unreliable.svg)](https://circleci.com/gh/triplehex/webrtc-unreliable)
[![Latest Version](https://img.shields.io/crates/v/webrtc-unreliable.svg)](https://crates.io/crates/webrtc-unreliable)
[![API Documentation](https://docs.rs/webrtc-unreliable/badge.svg)](https://docs.rs/webrtc-unreliable)

This is a Rust library which allows you to write a game server with browser
based clients and UDP-like networking.

This crate is not meant as a general purpose WebRTC data channel system, it is
instead designed to be used as the bottom level UDP-like transport layer of a
higher level protocol in an environment where UDP is not available.  It provides
an async API for accepting WebRTC connections from browsers and sending and
receiving WebRTC unreliable data channel messages from multiple clients.

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

This crate is (mostly) async runtime agnostic, it is usable from a rust program
using tokio, async-std, smol, some other runtime, or no runtime at all.  This
crate does not spawn background async tasks at all so it truly does not rely on
an executor, but it does require an async reactor to deliver wake events for its
UDP socket and timers.  It uses [async-io](https://github.com/stjepang/async-io)
for this purpose, which is (arguably) minimal and async runtime agnostic.
However, if `async-io` is not already in use by the rust program using this
crate, it will automatically create a new background reactor thread internally.
It would be better some day for `webrtc-unreliable` to be truly runtime
agnostic, and not (indirectly) spawn a global background reactor thread, but
this is currently waiting on a better async trait story.  If this situation is
problematic for you, please file an issue and I can move faster towards being
truly runtime agnostic.

## Running the example

In a terminal: 

```
$ cargo run --example echo_server -- --data 127.0.0.1:42424 --http 127.0.0.1:8080 --public 127.0.0.1:42424
```

Then, using a web browser, go to 'http://127.0.0.1:8080/index.html'. Open the
debug console, if everything is working correctly you should see messages being
sent and received.

Please note that if you are using Firefox, Firefox does not accept WebRTC
connections to 127.0.0.1, so you may need to use a different IP address.

## Credit

This was originally a Rust / Tokio port of the
[WebUDP](https://github.com/seemk/WebUdp) project, so the credit for the
original design goes there.

## License

This project is licensed under the [MIT license](LICENSE)
