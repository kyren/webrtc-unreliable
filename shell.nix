let
  moz_overlay = import (
    builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/ac8e9d7bbda8fb5e45cae20c5b7e44c52da3ac0c.tar.gz
  );

  nixpkgs = import (
    builtins.fetchTarball https://github.com/NixOS/nixpkgs-channels/archive/d567c486ca5ac5f0c83bb0264c325204a479a5bb.tar.gz
  ) {
    overlays = [ moz_overlay ];
  };
in with nixpkgs;
let
  rust_channel = rustChannelOf {
    channel = "1.39.0";
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
      cargo-release
      cargo-outdated
    ];
  }
