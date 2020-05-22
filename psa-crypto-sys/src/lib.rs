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
mod psa_crypto_binding {
    include!(concat!(env!("OUT_DIR"), "/shim_bindings.rs"));
}

#[allow(dead_code)]
mod constants;

pub use constants::*;
pub use psa_crypto_binding::psa_algorithm_t;
pub use psa_crypto_binding::psa_close_key;
pub use psa_crypto_binding::psa_crypto_init;
pub use psa_crypto_binding::psa_destroy_key;
pub use psa_crypto_binding::psa_dh_group_t;
pub use psa_crypto_binding::psa_ecc_curve_t;
pub use psa_crypto_binding::psa_export_public_key;
pub use psa_crypto_binding::psa_generate_key;
pub use psa_crypto_binding::psa_import_key;
pub use psa_crypto_binding::psa_key_attributes_t;
pub use psa_crypto_binding::psa_key_handle_t;
pub use psa_crypto_binding::psa_key_id_t;
pub use psa_crypto_binding::psa_key_lifetime_t;
pub use psa_crypto_binding::psa_key_type_t;
pub use psa_crypto_binding::psa_key_usage_t;
pub use psa_crypto_binding::psa_open_key;
pub use psa_crypto_binding::psa_reset_key_attributes;
pub use psa_crypto_binding::psa_sign_hash;
pub use psa_crypto_binding::psa_status_t;
pub use psa_crypto_binding::psa_verify_hash;

pub unsafe fn psa_get_key_bits(attributes: *const psa_key_attributes_t) -> usize {
    psa_crypto_binding::shim_get_key_bits(attributes)
}

pub unsafe fn psa_get_key_type(attributes: *const psa_key_attributes_t) -> psa_key_type_t {
    psa_crypto_binding::shim_get_key_type(attributes)
}

pub unsafe fn psa_get_key_lifetime(attributes: *const psa_key_attributes_t) -> psa_key_lifetime_t {
    psa_crypto_binding::shim_get_key_lifetime(attributes)
}

pub unsafe fn psa_get_key_algorithm(attributes: *const psa_key_attributes_t) -> psa_algorithm_t {
    psa_crypto_binding::shim_get_key_algorithm(attributes)
}

pub unsafe fn psa_get_key_usage_flags(attributes: *const psa_key_attributes_t) -> psa_key_usage_t {
    psa_crypto_binding::shim_get_key_usage_flags(attributes)
}

pub unsafe fn psa_key_attributes_init() -> psa_key_attributes_t {
    psa_crypto_binding::shim_key_attributes_init()
}

pub unsafe fn psa_set_key_algorithm(attributes: *mut psa_key_attributes_t, alg: psa_algorithm_t) {
    psa_crypto_binding::shim_set_key_algorithm(attributes, alg);
}

pub unsafe fn psa_set_key_bits(attributes: *mut psa_key_attributes_t, bits: usize) {
    psa_crypto_binding::shim_set_key_bits(attributes, bits);
}

pub unsafe fn psa_set_key_id(attributes: *mut psa_key_attributes_t, id: psa_key_id_t) {
    psa_crypto_binding::shim_set_key_id(attributes, id);
}

pub unsafe fn psa_set_key_lifetime(
    attributes: *mut psa_key_attributes_t,
    lifetime: psa_key_lifetime_t,
) {
    psa_crypto_binding::shim_set_key_lifetime(attributes, lifetime);
}

pub unsafe fn psa_set_key_type(attributes: *mut psa_key_attributes_t, type_: psa_key_type_t) {
    psa_crypto_binding::shim_set_key_type(attributes, type_);
}

pub unsafe fn psa_set_key_usage_flags(
    attributes: *mut psa_key_attributes_t,
    usage_flags: psa_key_usage_t,
) {
    psa_crypto_binding::shim_set_key_usage_flags(attributes, usage_flags);
}

pub fn PSA_ALG_IS_HASH(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_HASH(alg) == 1 }
}

pub fn PSA_ALG_IS_MAC(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_MAC(alg) == 1 }
}

pub fn PSA_ALG_IS_CIPHER(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_CIPHER(alg) == 1 }
}

pub fn PSA_ALG_IS_AEAD(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_AEAD(alg) == 1 }
}

pub fn PSA_ALG_IS_SIGN(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_SIGN(alg) == 1 }
}

pub fn PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg) == 1 }
}

pub fn PSA_ALG_IS_KEY_AGREEMENT(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_KEY_AGREEMENT(alg) == 1 }
}

pub fn PSA_ALG_IS_KEY_DERIVATION(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_KEY_DERIVATION(alg) == 1 }
}

pub fn PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) == 1 }
}

pub fn PSA_ALG_IS_RSA_PSS(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_RSA_PSS(alg) == 1 }
}

pub fn PSA_ALG_IS_ECDSA(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_ECDSA(alg) == 1 }
}

pub fn PSA_ALG_IS_DETERMINISTIC_ECDSA(alg: psa_algorithm_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_ALG_IS_DETERMINISTIC_ECDSA(alg) == 1 }
}

pub fn PSA_ALG_SIGN_GET_HASH(alg: psa_algorithm_t) -> psa_algorithm_t {
    unsafe { psa_crypto_binding::shim_PSA_ALG_SIGN_GET_HASH(alg) }
}

pub fn PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg: psa_algorithm_t) -> psa_algorithm_t {
    unsafe { psa_crypto_binding::shim_PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg) }
}

pub fn PSA_ALG_RSA_PSS(hash_alg: psa_algorithm_t) -> psa_algorithm_t {
    unsafe { psa_crypto_binding::shim_PSA_ALG_RSA_PSS(hash_alg) }
}

pub fn PSA_ALG_ECDSA(hash_alg: psa_algorithm_t) -> psa_algorithm_t {
    unsafe { psa_crypto_binding::shim_PSA_ALG_ECDSA(hash_alg) }
}

pub fn PSA_ALG_DETERMINISTIC_ECDSA(hash_alg: psa_algorithm_t) -> psa_algorithm_t {
    unsafe { psa_crypto_binding::shim_PSA_ALG_DETERMINISTIC_ECDSA(hash_alg) }
}

pub fn PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type: psa_key_type_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) == 1 }
}

pub fn PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type: psa_key_type_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type) == 1 }
}

pub fn PSA_KEY_TYPE_IS_DH_KEY_PAIR(key_type: psa_key_type_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_IS_DH_KEY_PAIR(key_type) == 1 }
}

pub fn PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(key_type: psa_key_type_t) -> bool {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(key_type) == 1 }
}

pub fn PSA_KEY_TYPE_GET_CURVE(key_type: psa_key_type_t) -> psa_ecc_curve_t {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_GET_CURVE(key_type) }
}

pub fn PSA_KEY_TYPE_GET_GROUP(key_type: psa_key_type_t) -> psa_dh_group_t {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_GET_GROUP(key_type) }
}

pub fn PSA_KEY_TYPE_ECC_KEY_PAIR(curve: psa_ecc_curve_t) -> psa_key_type_t {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_ECC_KEY_PAIR(curve) }
}

pub fn PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve: psa_ecc_curve_t) -> psa_key_type_t {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve) }
}

pub fn PSA_KEY_TYPE_DH_KEY_PAIR(group: psa_dh_group_t) -> psa_key_type_t {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_DH_KEY_PAIR(group) }
}

pub fn PSA_KEY_TYPE_DH_PUBLIC_KEY(group: psa_dh_group_t) -> psa_key_type_t {
    unsafe { psa_crypto_binding::shim_PSA_KEY_TYPE_DH_PUBLIC_KEY(group) }
}
