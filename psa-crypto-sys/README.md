# PSA Cryptography API Rust Wrapper

This is the lower-level wrapper that exposes a minimal low-level C
interface to Rust.

## Dependencies

This crate exposes an interface for the PSA Crypto API and thus
links to libraries that expose this interface. The expected name
of the library is derived from the reference implementation of the
API - `mbedcrypto`.

If the library and its headers folder are already installed locally you can
specify their location (the full absolute path) using the `MBEDTLS_LIB_DIR` and
`MBEDTLS_INCLUDE_DIR` environment variables at build time. By default dynamic
linking is attempted - if you wish to link statically you can enable the
`static` feature.

Alternatively, the crate will attempt to build the library from scratch and
link against it statically. In this use case enabling the `static` feature
makes no difference and there is no way to allow dynamic linking. The
requirements for configuring and building MbedTLS can be found
[on their repository homepage](https://github.com/ARMmbed/mbedtls#tool-versions).

Linking and generating implementation-specific APIs is controlled by the
`implementation-defined` feature that is enabled by default. Therefore, if you
require only the spec-defined bits of the API (namely the constants and types)
you can simply disable default features.

Currently the version of MbedTLS built is 2.22.0
