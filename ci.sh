#!/usr/bin/env bash

# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Continuous Integration test script, executed by GitHub Actions on x86 and
# Travis CI on Arm64.

set -euf -o pipefail

# The Parsec operations repository is included as a submodule. It is
# necessary to update it first.
git submodule update --init

################
# Build client #
################
RUST_BACKTRACE=1 cargo build

#################
# Static checks #
#################
# On native target clippy or fmt might not be available.
if cargo fmt -h; then
	cargo fmt --all -- --check
fi
if cargo clippy -h; then
	cargo clippy --all-targets -- -D clippy::all -D clippy::cargo
fi

#############
# Run tests #
#############
RUST_BACKTRACE=1 cargo test -- --test-threads=1

# Remove mbedtls directory if it exists
rm -rf psa-crypto/mbedtls
################################
# Check feature configurations #
################################
# psa-crypto-sys
pushd psa-crypto-sys
cargo build --no-default-features

# psa-crypto
popd
pushd psa-crypto
cargo build --no-default-features
cargo build --no-default-features --features with-mbed-crypto
cargo build --no-default-features --features no-std

# Test dynamic linking
git clone https://github.com/ARMmbed/mbedtls.git
pushd mbedtls
git checkout mbedtls-2.22.0
./scripts/config.py crypto
SHARED=1 make
popd

# Build the driver, clean before to force dynamic linking
cargo clean
MBEDTLS_LIB_DIR=$(pwd)/mbedtls/library MBEDTLS_INCLUDE_DIR=$(pwd)/mbedtls/include cargo build --release

# Build the driver, clean before to force static linking
cargo clean
MBEDTLS_LIB_DIR=$(pwd)/mbedtls/library MBEDTLS_INCLUDE_DIR=$(pwd)/mbedtls/include MBEDCRYPTO_STATIC=1 cargo build --release
