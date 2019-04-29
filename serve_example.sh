#! /usr/bin/env nix-shell
#! nix-shell -i bash ./shell.nix

set -e
cd "`dirname \"$0\"`"

cargo build --release --examples

pushd examples
hyp 0.0.0.0 8080 &
popd

# Visit http://127.0.0.1/echo_server.html in your web browser
#
# Firefox does not support binding WebRTC to 127.0.0.0/24, replace this with a
# different IP
./target/release/examples/echo_server -d 127.0.0.1:9555 -h 127.0.0.1:9555
