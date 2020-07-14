# PSA Cryptography API Rust Wrapper

This is the higher-level, more Rust-friendly interface.

<p align="center">
  <a href="https://crates.io/crates/psa-crypto"><img alt="Crates.io" src="https://img.shields.io/crates/v/psa-crypto"></a>
  <a href="https://docs.rs/psa-crypto"><img src="https://docs.rs/psa-crypto/badge.svg" alt="Code documentation"/></a>
  <a href="https://github.com/parallaxsecond/rust-psa-crypto/actions?query=workflow%3A%22Continuous+Integration%22"><img src="https://github.com/parallaxsecond/rust-psa-crypto/workflows/Continuous%20Integration/badge.svg" alt="CI tests"/></a>
  <a href="https://travis-ci.com/parallaxsecond/rust-psa-crypto"><img src="https://travis-ci.com/parallaxsecond/rust-psa-crypto.svg?branch=master" alt="Travis CI tests"/></a>
</p>

## Mbed Crypto backing

The features of this crate can modify what is compiled in from the PSA Crypto
specification:
* `operations`: everything is included. The `psa-crypto-sys` crate statically
  links by default Mbed Crypto. See the documentation of [that
crate](https://github.com/parallaxsecond/rust-psa-crypto/tree/master/psa-crypto-sys)
to see how to modify the linking options. This feature is activated by default.
* `interface`: only the abstraction over the PSA Crypto interface (types,
  helper methods) are included. The `MBEDTLS_INCLUDE_DIR` environment variable
is needed to produce Rust shims around PSA Crypto macros.
* without any of the above: only the specification-defined parts are included.
