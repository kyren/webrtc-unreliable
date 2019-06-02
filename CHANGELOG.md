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
