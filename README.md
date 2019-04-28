This is Rust port of the [WebUDP](https://github.com/seemk/WebUdp) project,
which is in turn based on the ideas presented in the article [Simplifying WebRTC
Connections (AKA Hacking the crap out of
WebRTC)](http://www.stormbrewers.com/blog/webrtc-data-channels-without-signaling-aka-hacking-the-crap-out-of-webrtc/)

Allows you to write a game server in rust with browser based clients and
UDP-like networking.  Uses hyper, tokio, and openssl and provides a futures
polling interface to the server.

This crate supports many of the necessary protocols in WebRTC to the *barest
minimum*.  You should expect ONLY WebRTC data channels to function, and only in
unreliable, unordered mode.
