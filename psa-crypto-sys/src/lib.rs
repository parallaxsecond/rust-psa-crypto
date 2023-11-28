// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Cryptography API Wrapper
//!
//! This crate provides abstraction over an implementation of the PSA Cryptography API.
//! You can find the API
//! [here](https://developer.arm.com/architectures/security-architectures/platform-security-architecture/documentation).

#![cfg_attr(feature = "no-std", no_std)]
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
#[cfg(feature = "interface")]
mod psa_crypto_binding {
    include!(concat!(env!("OUT_DIR"), "/shim_bindings.rs"));
}

mod constants;
#[cfg(feature = "interface")]
mod extras;
#[cfg(feature = "interface")]
mod shim;
mod types;

pub use constants::*;
pub use types::*;

#[cfg(feature = "operations")]
pub use psa_crypto_binding::{
    psa_aead_decrypt, psa_aead_encrypt, psa_asymmetric_decrypt, psa_asymmetric_encrypt,
    psa_cipher_abort, psa_cipher_decrypt_setup, psa_cipher_encrypt_setup, psa_cipher_finish,
    psa_cipher_set_iv, psa_cipher_update, psa_close_key, psa_copy_key, psa_crypto_init,
    psa_destroy_key, psa_export_key, psa_export_public_key, psa_generate_key, psa_generate_random,
    psa_get_key_attributes, psa_hash_compare, psa_hash_compute, psa_import_key,
    psa_key_derivation_abort, psa_key_derivation_input_bytes, psa_key_derivation_input_key,
    psa_key_derivation_key_agreement, psa_key_derivation_output_key,
    psa_key_derivation_set_capacity, psa_key_derivation_setup, psa_mac_compute, psa_mac_verify,
    psa_open_key, psa_raw_key_agreement, psa_reset_key_attributes, psa_sign_hash, psa_verify_hash,
};

#[cfg(feature = "interface")]
pub use psa_crypto_binding::{
    psa_cipher_operation_t, psa_key_attributes_t, psa_key_derivation_operation_t,
};

// Secure Element Driver definitions
#[cfg(feature = "interface")]
pub use psa_crypto_binding::{
    psa_drv_se_asymmetric_t, psa_drv_se_context_t, psa_drv_se_key_management_t, psa_drv_se_t,
    psa_key_creation_method_t, psa_key_slot_number_t,
};

#[cfg(feature = "interface")]
pub use extras::*;
#[cfg(feature = "interface")]
pub use shim::*;
