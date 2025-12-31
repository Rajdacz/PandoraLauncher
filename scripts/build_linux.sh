set -e

sudo apt-get update --yes && sudo apt-get install --yes libssl-dev libdbus-1-dev libx11-xcb1 libxkbcommon-x11-dev pkg-config
cargo build --release --target x86_64-unknown-linux-gnu
strip target/x86_64-unknown-linux-gnu/release/pandora_launcher
mv target/x86_64-unknown-linux-gnu/release/pandora_launcher dest/PandoraLauncher-Linux-x86_64
