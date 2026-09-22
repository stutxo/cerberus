#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

# Use the cached flake and Cargo dependencies; never fetch during a benchmark.
if [[ -z "${IN_NIX_SHELL:-}" ]]; then
	exec nix develop --offline --command bash "$PWD/autoresearch.sh"
fi

# Pin the actual compiler paths, not rustup shims: dependency directories can
# carry a different rust-toolchain file. A missing local toolchain is an error.
toolchain_bin="$(dirname -- "$(rustup which --toolchain 1.92.0 rustc)")"
export PATH="$toolchain_bin:$PATH"
export RUSTUP_TOOLCHAIN=1.92.0
export RUSTC="$toolchain_bin/rustc"
export RUSTDOC="$toolchain_bin/rustdoc"
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=8
export CARGO_TARGET_DIR="$PWD/target"
export LC_ALL=C
export TZ=UTC

# Compilation, fixture loading, rejection checks, and warmup are outside the
# measured samples. The binary runs a fixed number of actual crypto operations.
cargo run --frozen --release -p bark-wallet --example btc_ark_swap_bench
