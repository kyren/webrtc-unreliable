## [0.6.0]
- Support a shared `Crypto` instance between servers, useful on Firefox for
  multiple connections per page.
- API incompatible change: Make `Server::new` sync.
- API incompatible change: Add `Runtime` trait to be reactor agnostic, adds an optional `tokio` feature
  to provide the previous tokio implementation.

## [0.5.3]
- Handle FORWARD_TSN support in SCTP when it is specified as an extension

## [0.5.2]
- Fix a bug in STUN parsing that causes failures if the User attribute is the
  last attribute in the packet.
- Update internal crc dependency

## [0.5.1]
- *Attempt* to handle DTLS shutdown correctly at least when there is no packet
  loss.
- Fix some bugs causing at least firefox to complain about ice attributes being
  incorrectly at the media level.
- Don't log "starting shutdown" if the client has already shutdown.
- Update rand dependency.
- Add a method to check whether any clients are not fully shutdown.  This should
  *theoretically* make it possible to implement an *attempt* at clean shutdown
  for all clients.  See issue #15.

## [0.5]
- Change crc32c dependency to crc to unbreak ARM build (thanks @tchamelot!),
- Remove crc32fast in favor of only using crc dependency.
- Handle better clients which have errored and are shutting down without
  spamming log warnings.
- Dont' deliver incoming messages in fragmented SCTP packets as whole messages,
  we do not support fragmented SCTP at all yet.
- API incompatible change: Simplify the API for receiving messages, returning a
  borrowed buffer for incoming messages, eliminating both `RecvError` and a
  needless memcpy.
- API incompatible change: There is no longer a distinction between a client
  that is not fully connected and a client that has been disconnected, both are
  now just `NotConnected`.
- Add a method on the server to list all currently established connections.
- Dependency change from tokio to async-io, no longer requires a tokio runtime.

## [0.4.1]
- Remove crossbeam dependency, use a new buffer pooling strategy that should be
  much faster

## [0.4.0]
- API incompatible change: depend on futures 0.3, tokio 0.2, and refactor API to
  use stable async / await.

## [0.3.0]
- Sign x509 certificates with sha256 instead of sha1
- API changes: don't stutter with `Rtc` prefix, include more precise error types
- Fix message type for received binary messages (thanks @slugalisk!)
- Properly handle SCTP unreliability negotiation in init, better error logging
  to catch protocol errors faster in the future.  Fixes major brokenness with
  firefox (huge thanks @Healthire!)
- Don't generate errors for what is indicative of logic bugs, simplifies error
  API somewhat

## [0.2.1]
- Small doc fixes

## [0.2.0]
- Remove internal hyper server, API now requires external channel for session
  initiation (more flexible, only a small amount of server code required to
  exchange sessions using hyper, see the echo_server.rs example).
- Fix several SCTP handling bugs, marginally more informative SCTP errors
- Easier to run the example (no longer requires nix, uses hyper to serve index page)
- Remove some unnecessary dependencies
- Fix some error handling bugs around SSL errors

## [0.1.1]
- Change SCTP_COOKIE value to a more informative one
- Add IPv6 support to SDP

## [0.1.0]
- Initial release
