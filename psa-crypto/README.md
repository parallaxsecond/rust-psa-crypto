# PSA Cryptography API Rust Wrapper

This is the higher-level, more Rust-friendly interface.

<p align="center">
  <a href="https://crates.io/crates/psa-crypto"><img alt="Crates.io" src="https://img.shields.io/crates/v/psa-crypto"></a>
  <a href="https://docs.rs/psa-crypto"><img src="https://docs.rs/psa-crypto/badge.svg" alt="Code documentation"/></a>
  <a href="https://github.com/parallaxsecond/rust-psa-crypto/actions?query=workflow%3A%22Continuous+Integration%22"><img src="https://github.com/parallaxsecond/rust-psa-crypto/workflows/Continuous%20Integration/badge.svg" alt="CI tests"/></a>
  <a href="https://travis-ci.com/parallaxsecond/rust-psa-crypto"><img src="https://travis-ci.com/parallaxsecond/rust-psa-crypto.svg?branch=master" alt="Travis CI tests"/></a>
</p>

## Mbed Crypto backing

The `psa-crypto` comes by default with Mbed Crypto backing for
the interface exposed. If the functionality of the library is
not important/relevant, the interface type system (that offers
functionality for identifying cryptographic algorithms and
modelling key metadata) can be used independently by disabling
the default features of the crate. The feature adding the Mbed
Crypto support is `with-mbed-crypto`.
