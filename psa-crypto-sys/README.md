# PSA Cryptography API Rust Wrapper

This is the lower-level wrapper that exposes a minimal low-level C
interface to Rust.

<p align="center">
  <a href="https://crates.io/crates/psa-crypto-sys"><img alt="Crates.io" src="https://img.shields.io/crates/v/psa-crypto-sys"></a>
  <a href="https://docs.rs/psa-crypto-sys"><img src="https://docs.rs/psa-crypto-sys/badge.svg" alt="Code documentation"/></a>
  <a href="https://github.com/parallaxsecond/rust-psa-crypto/actions?query=workflow%3A%22Continuous+Integration%22"><img src="https://github.com/parallaxsecond/rust-psa-crypto/workflows/Continuous%20Integration/badge.svg" alt="CI tests"/></a>
</p>

## Dependencies

This crate exposes an interface for the PSA Crypto API and thus
links to libraries that expose this interface. The expected name
of the library is derived from the reference implementation of the
API - `mbedcrypto`.

If the library and its headers folder are already installed locally you can
specify their location (the full absolute path) using the `MBEDTLS_LIB_DIR` and
`MBEDTLS_INCLUDE_DIR` environment variables at build time. By default dynamic
linking is attempted - if you wish to link statically you can enable the
`static` feature or pass the `MBEDCRYPTO_STATIC` environment variable, set to
any value.

Alternatively, the crate will attempt to build the library from scratch and
link against it statically. In this use case enabling the `static` feature
makes no difference and there is no way to allow dynamic linking. The
requirements for configuring and building MbedTLS can be found
[on their repository homepage](https://github.com/ARMmbed/mbedtls#tool-versions).

By default, the `mbedcrypto` library itself and the `shim` library (which 
is needed for inline functions) will not have not have any prefixes. If 
the `prefix` feature is enabled, both the libraries are renamed by 
adding a prefix of the form `psa_crypto_X_Y_Z_`. Also every globally 
defined symbol in those libraries has that prefix added. This is to 
avoid link-time collisions with other crates that might use the same 
library, including other versions of this crate. The renaming of 
symbols uses the `nm` and `objcopy` commands.

Linking and generating implementation-specific APIs is controlled by the
`operations` feature that is enabled by default. Therefore, if you
require only the specification-defined bits of the API (namely the constants and types)
you can simply disable default features.

You might want to only use the interface part (including the
implementation-defined bits) of this crate to build for example a PSA Secure
Element Driver. With the feature `interface`, this crate will only produce the
implementation-defined types and their helpers/accessors using the
`MBEDTLS_INCLUDE_DIR` variable that you need to pass.

## Cross-compilation

The `interface` and `operations` features need a C toolchain. When cross-compiling, the
appropriate C toolchain will automatically be selected. Compilation will fail if it is
not available on your system.

The CI currently tests cross-compilation for the following targets:

- `aarch64-unknown-linux-gnu`
- `armv7-unknown-linux-gnueabihf`
