<!--
  -- Copyright 2020 Contributors to the Parsec project. 
  -- SPDX-License-Identifier: Apache-2.0
--->
# PSA Cryptography API Rust Wrapper

<p align="center">
  <a href="https://github.com/parallaxsecond/rust-psa-crypto/actions?query=workflow%3A%22Continuous+Integration%22"><img src="https://github.com/parallaxsecond/rust-psa-crypto/workflows/Continuous%20Integration/badge.svg" alt="CI tests"/></a>
</p>

This repository contains a Rust wrapper around the [PSA Cryptography API](https://developer.arm.com/architectures/security-architectures/platform-security-architecture/documentation). There are two layers of wrapping:

* [`psa-crypto-sys`](psa-crypto-sys): a lower-level wrapper that exposes a minimal low-level C interface to Rust

* [`psa-crypto`](psa-crypto): a higher-level, more Rust-friendly interface

In order to cross-build for ARM using the "ci.sh" script, the gcc for arm needs to be installed:

    sudo apt install gcc-12-arm-linux-gnueabihf gcc-arm-linux-gnueabihf \
                     gcc-aarch64-linux-gnu gcc-12-aarch64-linux-gnu


## Notice

The PSA Crypto wrapper is currently work-in-progress. This repository is currently mainly a space for prototyping and design discussion.

If you build the wrapper from source you need to run `git submodule update --init` after cloning the repository.

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

## Contributing

Please check the [**Contribution Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing.html)
to know more about the contribution process.
