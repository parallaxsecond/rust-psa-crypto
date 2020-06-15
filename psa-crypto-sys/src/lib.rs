// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Cryptography API Wrapper
//!
//! This crate provides abstraction over an implementation of the PSA Cryptography API.
//! You can find the API
//! [here](https://developer.arm.com/architectures/security-architectures/platform-security-architecture/documentation).

// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::missing_safety_doc)]
// Respect the C API case
#![allow(non_snake_case)]

#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    trivial_casts
)]
#[allow(clippy::all)]
#[cfg(feature = "implementation-defined")]
mod psa_crypto_binding {
    include!(concat!(env!("OUT_DIR"), "/shim_bindings.rs"));
}

#[allow(dead_code)]
mod constants;
#[allow(dead_code)]
#[cfg(feature = "implementation-defined")]
mod shim_methods;
#[allow(dead_code)]
mod types;

pub use constants::*;
pub use types::*;

#[cfg(feature = "implementation-defined")]
pub use psa_crypto_binding::{
    mbedtls_psa_crypto_free, psa_close_key, psa_crypto_init, psa_destroy_key,
    psa_export_public_key, psa_generate_key, psa_get_key_attributes, psa_import_key,
    psa_key_attributes_t, psa_open_key, psa_reset_key_attributes, psa_sign_hash, psa_verify_hash,
};

// Secure Element Driver definitions
#[cfg(feature = "implementation-defined")]
pub use psa_crypto_binding::{
    psa_drv_se_asymmetric_t, psa_drv_se_context_t, psa_drv_se_key_management_t, psa_drv_se_t,
    psa_key_creation_method_t, psa_key_slot_number_t,
};

#[cfg(feature = "implementation-defined")]
pub use shim_methods::*;
