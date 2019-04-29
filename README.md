[![Build Status](https://img.shields.io/circleci/project/github/kyren/webrtc-unreliable.svg)](https://circleci.com/gh/kyren/webrtc-unreliable)

This is Rust port of the [WebUDP](https://github.com/seemk/WebUdp) project,
which is itself similar to the ideas presented in the article [Simplifying
WebRTC Connections (AKA Hacking the crap out of
WebRTC)](http://www.stormbrewers.com/blog/webrtc-data-channels-without-signaling-aka-hacking-the-crap-out-of-webrtc/)

Allows you to write a game server in rust with browser based clients and
UDP-like networking.  The server requires a tokio runtime and provides a
non-blocking API for accepting WebRTC connections and sending and receiving
WebRTC data channel messages from multiple clients.

This crate supports many of the necessary protocols in WebRTC to the *barest
minimum*.  You should expect ONLY WebRTC data channels to function, and only in
unreliable, unordered mode.
