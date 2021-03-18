# Changelog

## [psa-crypto-0.8.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-0.8.0) (2021-03-17)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-sys-0.8.0...psa-crypto-0.8.0)

## [psa-crypto-sys-0.8.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-sys-0.8.0) (2021-03-17)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-0.7.0...psa-crypto-sys-0.8.0)

**Implemented enhancements:**

- Handling key handle closing is noisy and error prone [\#34](https://github.com/parallaxsecond/rust-psa-crypto/issues/34)
- Add method to retrieve hash from AsymSign [\#73](https://github.com/parallaxsecond/rust-psa-crypto/pull/73) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- Update the Mbed TLS submodule to 2.25.0 [\#76](https://github.com/parallaxsecond/rust-psa-crypto/issues/76)

**Merged pull requests:**

- Bump version and minor changes [\#80](https://github.com/parallaxsecond/rust-psa-crypto/pull/80) ([ionut-arm](https://github.com/ionut-arm))
- Add cross-compilation tests [\#79](https://github.com/parallaxsecond/rust-psa-crypto/pull/79) ([hug-dev](https://github.com/hug-dev))
- Update to version 2.25.0 of Mbed TLS [\#77](https://github.com/parallaxsecond/rust-psa-crypto/pull/77) ([hug-dev](https://github.com/hug-dev))
- Implement Display on Algorithm [\#75](https://github.com/parallaxsecond/rust-psa-crypto/pull/75) ([hug-dev](https://github.com/hug-dev))

## [psa-crypto-0.7.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-0.7.0) (2021-01-18)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-sys-0.7.0...psa-crypto-0.7.0)

## [psa-crypto-sys-0.7.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-sys-0.7.0) (2021-01-18)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-0.6.1...psa-crypto-sys-0.7.0)

**Merged pull requests:**

- Bump bindgen and crate versions [\#71](https://github.com/parallaxsecond/rust-psa-crypto/pull/71) ([ionut-arm](https://github.com/ionut-arm))
- Fix clippy lint and disable Travis [\#70](https://github.com/parallaxsecond/rust-psa-crypto/pull/70) ([ionut-arm](https://github.com/ionut-arm))

## [psa-crypto-0.6.1](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-0.6.1) (2020-12-18)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-sys-0.6.1...psa-crypto-0.6.1)

## [psa-crypto-sys-0.6.1](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-sys-0.6.1) (2020-12-18)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-0.6.0...psa-crypto-sys-0.6.1)

**Fixed bugs:**

- Conversion to `Status` seems wrong [\#24](https://github.com/parallaxsecond/rust-psa-crypto/issues/24)

**Merged pull requests:**

- Bump both crates to 0.6.1 [\#69](https://github.com/parallaxsecond/rust-psa-crypto/pull/69) ([paulhowardarm](https://github.com/paulhowardarm))
- Remove the bindgen dependency if not needed [\#68](https://github.com/parallaxsecond/rust-psa-crypto/pull/68) ([hug-dev](https://github.com/hug-dev))

## [psa-crypto-0.6.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-0.6.0) (2020-10-20)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-sys-0.6.0...psa-crypto-0.6.0)

## [psa-crypto-sys-0.6.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-sys-0.6.0) (2020-10-20)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-0.5.1...psa-crypto-sys-0.6.0)

**Fixed bugs:**

- Remove shim\_PSA\_ALG\_IS\_FULL\_LENGTH\_MAC [\#63](https://github.com/parallaxsecond/rust-psa-crypto/pull/63) ([hug-dev](https://github.com/hug-dev))
- Fix nightly CI [\#62](https://github.com/parallaxsecond/rust-psa-crypto/pull/62) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- What's the purpose of the "interface" feature? [\#66](https://github.com/parallaxsecond/rust-psa-crypto/issues/66)

**Merged pull requests:**

- Lower the version of bindgen to avoid conflict [\#67](https://github.com/parallaxsecond/rust-psa-crypto/pull/67) ([hug-dev](https://github.com/hug-dev))
- Remove const for backwards compatibility [\#65](https://github.com/parallaxsecond/rust-psa-crypto/pull/65) ([hug-dev](https://github.com/hug-dev))

## [psa-crypto-0.5.1](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-0.5.1) (2020-09-04)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-sys-0.5.1...psa-crypto-0.5.1)

## [psa-crypto-sys-0.5.1](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-sys-0.5.1) (2020-09-04)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-0.5.0...psa-crypto-sys-0.5.1)

**Implemented enhancements:**

- Upgrade dependencies [\#60](https://github.com/parallaxsecond/rust-psa-crypto/pull/60) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- Exposing native types for key encodings [\#53](https://github.com/parallaxsecond/rust-psa-crypto/issues/53)

**Merged pull requests:**

- Fix the interface feature [\#61](https://github.com/parallaxsecond/rust-psa-crypto/pull/61) ([hug-dev](https://github.com/hug-dev))
- Fix indentation of the workflow [\#59](https://github.com/parallaxsecond/rust-psa-crypto/pull/59) ([hug-dev](https://github.com/hug-dev))
- Changed key derivation convertor to const function [\#58](https://github.com/parallaxsecond/rust-psa-crypto/pull/58) ([sbailey-arm](https://github.com/sbailey-arm))

## [psa-crypto-0.5.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-0.5.0) (2020-08-20)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-sys-0.5.0...psa-crypto-0.5.0)

## [psa-crypto-sys-0.5.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-sys-0.5.0) (2020-08-20)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-0.4.0...psa-crypto-sys-0.5.0)

**Implemented enhancements:**

- Added helper methods and changed safety of size macros [\#55](https://github.com/parallaxsecond/rust-psa-crypto/pull/55) ([sbailey-arm](https://github.com/sbailey-arm))

**Fixed bugs:**

- Added missing AEAD conversion and tag length method [\#57](https://github.com/parallaxsecond/rust-psa-crypto/pull/57) ([sbailey-arm](https://github.com/sbailey-arm))

## [psa-crypto-0.4.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-0.4.0) (2020-08-13)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-sys-0.4.0...psa-crypto-0.4.0)

## [psa-crypto-sys-0.4.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-sys-0.4.0) (2020-08-13)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-0.3.0...psa-crypto-sys-0.4.0)

**Implemented enhancements:**

- Added conversion helper methods [\#51](https://github.com/parallaxsecond/rust-psa-crypto/pull/51) ([sbailey-arm](https://github.com/sbailey-arm))
- Added tests for all operations that were added that are supported by Mbed Crypto [\#50](https://github.com/parallaxsecond/rust-psa-crypto/pull/50) ([sbailey-arm](https://github.com/sbailey-arm))

**Fixed bugs:**

- 'export\_key\_pair\_test' panicked at 'called `Result::unwrap\(\)` on an `Err` value: StorageFailure' [\#46](https://github.com/parallaxsecond/rust-psa-crypto/issues/46)
- psa-crypto-sys test fail on i686 [\#41](https://github.com/parallaxsecond/rust-psa-crypto/issues/41)
- Changes to the C library do not trigger a rebuild [\#35](https://github.com/parallaxsecond/rust-psa-crypto/issues/35)
- Add license file to crates [\#45](https://github.com/parallaxsecond/rust-psa-crypto/pull/45) ([ionut-arm](https://github.com/ionut-arm))
- Re-run build if any file under psa-crypto-sys/vendor has changed [\#43](https://github.com/parallaxsecond/rust-psa-crypto/pull/43) ([joechrisellis](https://github.com/joechrisellis))
- Blocklist `max\_align\_t` in bindgen [\#42](https://github.com/parallaxsecond/rust-psa-crypto/pull/42) ([joechrisellis](https://github.com/joechrisellis))

**Closed issues:**

- Include the LICENSE file in the crate [\#44](https://github.com/parallaxsecond/rust-psa-crypto/issues/44)

**Merged pull requests:**

- Added helper methods for checking derivation policy flag [\#54](https://github.com/parallaxsecond/rust-psa-crypto/pull/54) ([sbailey-arm](https://github.com/sbailey-arm))
- Refactor of key\_derivation [\#52](https://github.com/parallaxsecond/rust-psa-crypto/pull/52) ([sbailey-arm](https://github.com/sbailey-arm))
- Add key derivation [\#49](https://github.com/parallaxsecond/rust-psa-crypto/pull/49) ([sbailey-arm](https://github.com/sbailey-arm))
- Added all missing ops listed in Service API that Mbed Crypto support … [\#48](https://github.com/parallaxsecond/rust-psa-crypto/pull/48) ([sbailey-arm](https://github.com/sbailey-arm))
- Add support for `psa\_generate\_random` [\#47](https://github.com/parallaxsecond/rust-psa-crypto/pull/47) ([joechrisellis](https://github.com/joechrisellis))

## [psa-crypto-0.3.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-0.3.0) (2020-07-14)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-sys-0.3.0...psa-crypto-0.3.0)

## [psa-crypto-sys-0.3.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-sys-0.3.0) (2020-07-14)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-0.2.2...psa-crypto-sys-0.3.0)

**Implemented enhancements:**

- Have a feature only using the PSA interface [\#38](https://github.com/parallaxsecond/rust-psa-crypto/issues/38)
- Add an interface feature only using include files [\#39](https://github.com/parallaxsecond/rust-psa-crypto/pull/39) ([hug-dev](https://github.com/hug-dev))

**Merged pull requests:**

- Added export\_key [\#40](https://github.com/parallaxsecond/rust-psa-crypto/pull/40) ([sbailey-arm](https://github.com/sbailey-arm))

## [psa-crypto-0.2.2](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-0.2.2) (2020-07-06)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/psa-crypto-sys-0.2.3...psa-crypto-0.2.2)

## [psa-crypto-sys-0.2.3](https://github.com/parallaxsecond/rust-psa-crypto/tree/psa-crypto-sys-0.2.3) (2020-07-06)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/0.2.1...psa-crypto-sys-0.2.3)

**Implemented enhancements:**

- Added asymmetric encrypt and decrypt to psa-crypto and psa-crypto-sys [\#37](https://github.com/parallaxsecond/rust-psa-crypto/pull/37) ([sbailey-arm](https://github.com/sbailey-arm))
- Add an env var for static linking to Mbed Crypto [\#36](https://github.com/parallaxsecond/rust-psa-crypto/pull/36) ([hug-dev](https://github.com/hug-dev))
- Derive Zeroize for all types [\#33](https://github.com/parallaxsecond/rust-psa-crypto/pull/33) ([ionut-arm](https://github.com/ionut-arm))

## [0.2.1](https://github.com/parallaxsecond/rust-psa-crypto/tree/0.2.1) (2020-06-23)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/0.2.0...0.2.1)

**Implemented enhancements:**

- Implement macros to have size of output buffers [\#30](https://github.com/parallaxsecond/rust-psa-crypto/issues/30)
- Always close key handle if key is persistent [\#26](https://github.com/parallaxsecond/rust-psa-crypto/issues/26)
- Add a test on the CI compiling Mbed TLS and linking dynamically the crate to Mbed Crypto [\#25](https://github.com/parallaxsecond/rust-psa-crypto/issues/25)

**Merged pull requests:**

- Added macro calls for sign output size and export key buffer size [\#31](https://github.com/parallaxsecond/rust-psa-crypto/pull/31) ([sbailey-arm](https://github.com/sbailey-arm))

## [0.2.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/0.2.0) (2020-06-16)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/0.1.0...0.2.0)

**Implemented enhancements:**

- Part of moving Parsec to use psa-crypto [\#28](https://github.com/parallaxsecond/rust-psa-crypto/pull/28) ([sbailey-arm](https://github.com/sbailey-arm))
- Modify Mbed TLS version to most recent realease [\#27](https://github.com/parallaxsecond/rust-psa-crypto/pull/27) ([hug-dev](https://github.com/hug-dev))
- Add various improvements [\#20](https://github.com/parallaxsecond/rust-psa-crypto/pull/20) ([hug-dev](https://github.com/hug-dev))

**Fixed bugs:**

- Pass parsec CI tests [\#29](https://github.com/parallaxsecond/rust-psa-crypto/pull/29) ([sbailey-arm](https://github.com/sbailey-arm))

**Closed issues:**

- Design a good abstraction for key IDs [\#4](https://github.com/parallaxsecond/rust-psa-crypto/issues/4)
- Create the Rust representation of PSA Crypto operations [\#3](https://github.com/parallaxsecond/rust-psa-crypto/issues/3)
- Create abstractions of key attributes and algorithms [\#2](https://github.com/parallaxsecond/rust-psa-crypto/issues/2)

## [0.1.0](https://github.com/parallaxsecond/rust-psa-crypto/tree/0.1.0) (2020-06-03)

[Full Changelog](https://github.com/parallaxsecond/rust-psa-crypto/compare/1a05271fd6d2140063a10764f0e8028d8fde1b40...0.1.0)

**Implemented enhancements:**

- Update Mbed TLS version and add new types [\#22](https://github.com/parallaxsecond/rust-psa-crypto/pull/22) ([hug-dev](https://github.com/hug-dev))
- Separate implementation-defined feature in -sys [\#21](https://github.com/parallaxsecond/rust-psa-crypto/pull/21) ([ionut-arm](https://github.com/ionut-arm))
- Add no-std feature; impl Display on Error [\#19](https://github.com/parallaxsecond/rust-psa-crypto/pull/19) ([ionut-arm](https://github.com/ionut-arm))
- Add Secure Element types definition [\#18](https://github.com/parallaxsecond/rust-psa-crypto/pull/18) ([hug-dev](https://github.com/hug-dev))
- Add documentation, examples and tests [\#16](https://github.com/parallaxsecond/rust-psa-crypto/pull/16) ([hug-dev](https://github.com/hug-dev))
- Improve build of psa-crypto-sys crate [\#15](https://github.com/parallaxsecond/rust-psa-crypto/pull/15) ([ionut-arm](https://github.com/ionut-arm))
- Improve interface of both crates [\#14](https://github.com/parallaxsecond/rust-psa-crypto/pull/14) ([ionut-arm](https://github.com/ionut-arm))
- Add Rust-FFI conversions for Attributes [\#13](https://github.com/parallaxsecond/rust-psa-crypto/pull/13) ([hug-dev](https://github.com/hug-dev))
- Change dependency to MbedTLS and update build [\#12](https://github.com/parallaxsecond/rust-psa-crypto/pull/12) ([ionut-arm](https://github.com/ionut-arm))
- Add Rust-FFI conversions for Algorithms [\#11](https://github.com/parallaxsecond/rust-psa-crypto/pull/11) ([hug-dev](https://github.com/hug-dev))
- Split between Status and Error [\#10](https://github.com/parallaxsecond/rust-psa-crypto/pull/10) ([hug-dev](https://github.com/hug-dev))
- Implement design [\#9](https://github.com/parallaxsecond/rust-psa-crypto/pull/9) ([hug-dev](https://github.com/hug-dev))
- Split into two crates: psa-crypto-sys and psa-crypto. [\#6](https://github.com/parallaxsecond/rust-psa-crypto/pull/6) ([egrimley-arm](https://github.com/egrimley-arm))
- First draft of rust-psa-crypto, Rust wrapper for \(some of\) mbed-crypto. [\#5](https://github.com/parallaxsecond/rust-psa-crypto/pull/5) ([egrimley-arm](https://github.com/egrimley-arm))

**Closed issues:**

- Be able to dynamically link with any PSA Crypto C shared library [\#1](https://github.com/parallaxsecond/rust-psa-crypto/issues/1)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
