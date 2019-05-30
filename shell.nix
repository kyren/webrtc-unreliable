let
  moz_overlay = import (
    builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/c8a2ed7e614131ea1ba3d31ef9bcc9890a0df410.tar.gz
  );

  nixpkgs = import (
    builtins.fetchTarball https://github.com/NixOS/nixpkgs-channels/archive/796a8764ab85746f916e2cc8f6a9a5fc6d4d03ac.tar.gz
  ) {
    overlays = [ moz_overlay ];
  };
in with nixpkgs;
let
  rust_channel = rustChannelOf {
    date = "2019-04-11";
    channel = "stable";
  };

  rust = rust_channel.rust.override {
    extensions = [ "rustfmt-preview" ];
  };
in
  mkShell rec {
    buildInputs = [
      pkg-config
      openssl
      rust
    ];
  }
