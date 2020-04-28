// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Cryptography API Wrapper
//!
//! This crate provides abstraction over an implementation of the PSA Cryptography API.
//! You can find the API
//! [here](https://developer.arm.com/architectures/security-architectures/platform-security-architecture/documentation).

#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]
// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]
//xx For now:
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(missing_debug_implementations)]
#![allow(missing_docs)]

use lazy_static::lazy_static;
use std::sync::Mutex;

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

struct Global {
    init_succeeded: bool,
    // Calls to psa_open_key, psa_generate_key and psa_destroy_key
    // are not thread safe. We work around this bug with the key_mutex.
    // Mbed issue: https://github.com/ARMmbed/mbed-crypto/issues/266
    key_mutex: Mutex<()>,
}

impl Global {
    fn new() -> Global {
        Global {
            init_succeeded: false,
            key_mutex: Mutex::new(()),
        }
    }
}

lazy_static! {
    static ref GLOBAL: Mutex<Global> = Mutex::new(Global::new());
}

fn init() -> bool {
    if GLOBAL.lock().unwrap().init_succeeded {
        return true;
    }
    let status = unsafe { psa_crypto_binding::psa_crypto_init() };
    if status != PSA_SUCCESS {
        return false;
    }
    GLOBAL.lock().unwrap().init_succeeded = true;
    true
}

macro_rules! wrap_any {
    ($x:expr) => {
        if !init() {
            panic!("Error when initialising PSA Crypto")
        } else {
            #[allow(unused_unsafe)]
            unsafe {
                $x
            }
        }
    };
}

macro_rules! wrap_status {
    ($x:expr) => {
        if !init() {
            PSA_ERROR_BAD_STATE
        } else {
            unsafe { $x }
        }
    };
}

macro_rules! key_lock {
    ($x:expr) => {{
        let mutex = &GLOBAL.lock().unwrap().key_mutex;
        let _guard = mutex.lock().unwrap();
        $x
    }};
}

// Reexported types:

pub use psa_crypto_binding::psa_algorithm_t;
pub use psa_crypto_binding::psa_key_handle_t;
pub use psa_crypto_binding::psa_key_id_t;
pub use psa_crypto_binding::psa_key_lifetime_t;
pub use psa_crypto_binding::psa_key_type_t;
pub use psa_crypto_binding::psa_key_usage_t;
pub use psa_crypto_binding::psa_status_t;

// Wrapped types:

#[allow(non_camel_case_types)]
pub struct psa_key_attributes_t {
    x: psa_crypto_binding::psa_key_attributes_t,
}

impl Drop for psa_key_attributes_t {
    fn drop(&mut self) {
        wrap_any!(psa_crypto_binding::psa_reset_key_attributes(&mut self.x));
    }
}

// Wrapped linkable functions:

pub fn psa_asymmetric_sign(
    handle: psa_key_handle_t,
    alg: psa_algorithm_t,
    hash: *const u8,
    hash_length: usize,
    signature: *mut u8,
    signature_size: usize,
    signature_length: *mut usize,
) -> psa_status_t {
    wrap_status!(psa_crypto_binding::psa_asymmetric_sign(
        handle,
        alg,
        hash,
        hash_length,
        signature,
        signature_size,
        signature_length
    ))
}

pub fn psa_asymmetric_verify(
    handle: psa_key_handle_t,
    alg: psa_algorithm_t,
    hash: *const u8,
    hash_length: usize,
    signature: *const u8,
    signature_length: usize,
) -> psa_status_t {
    wrap_status!(psa_crypto_binding::psa_asymmetric_verify(
        handle,
        alg,
        hash,
        hash_length,
        signature,
        signature_length
    ))
}

pub fn psa_close_key(handle: psa_key_handle_t) -> psa_status_t {
    wrap_status!(psa_crypto_binding::psa_close_key(handle))
}

pub fn psa_destroy_key(handle: psa_key_handle_t) -> psa_status_t {
    wrap_status!(key_lock!(psa_crypto_binding::psa_destroy_key(handle)))
}

pub fn psa_export_public_key(
    handle: psa_key_handle_t,
    data: *mut u8,
    data_size: usize,
    data_length: *mut usize,
) -> psa_status_t {
    wrap_status!(psa_crypto_binding::psa_export_public_key(
        handle,
        data,
        data_size,
        data_length
    ))
}

pub fn psa_generate_key(
    attributes: *const psa_key_attributes_t,
    handle: *mut psa_key_handle_t,
) -> psa_status_t {
    wrap_status!(key_lock!(psa_crypto_binding::psa_generate_key(
        &(*attributes).x,
        handle
    )))
}

pub fn psa_get_key_attributes(
    handle: psa_key_handle_t,
    attributes: *mut psa_key_attributes_t,
) -> psa_status_t {
    wrap_status!(psa_crypto_binding::psa_get_key_attributes(
        handle,
        &mut (*attributes).x
    ))
}

pub fn psa_get_key_bits(attributes: &psa_key_attributes_t) -> usize {
    wrap_any!((*attributes).x.core.bits as usize)
}

pub fn psa_get_key_type(attributes: &psa_key_attributes_t) -> psa_key_type_t {
    wrap_any!((*attributes).x.core.type_)
}

pub fn psa_import_key(
    attributes: *const psa_key_attributes_t,
    data: *const u8,
    data_length: usize,
    handle: *mut psa_key_handle_t,
) -> psa_status_t {
    wrap_status!(psa_crypto_binding::psa_import_key(
        &(*attributes).x,
        data,
        data_length,
        handle
    ))
}

pub fn psa_open_key(id: psa_key_id_t, handle: *mut psa_key_handle_t) -> psa_status_t {
    wrap_status!(key_lock!(psa_crypto_binding::psa_open_key(id, handle)))
}

pub fn psa_reset_key_attributes(attributes: *mut psa_key_attributes_t) {
    wrap_any!(psa_crypto_binding::psa_reset_key_attributes(
        &mut (*attributes).x
    ))
}

// Wrapped shims:

pub fn psa_key_attributes_init() -> psa_key_attributes_t {
    let attr = wrap_any!(psa_crypto_binding::shim_key_attributes_init());
    psa_key_attributes_t { x: attr }
}

pub fn psa_set_key_algorithm(attributes: &mut psa_key_attributes_t, alg: psa_algorithm_t) {
    wrap_any!(psa_crypto_binding::shim_set_key_algorithm(
        &mut attributes.x,
        alg
    ));
}

pub fn psa_set_key_bits(attributes: &mut psa_key_attributes_t, bits: usize) {
    wrap_any!(psa_crypto_binding::shim_set_key_bits(
        &mut attributes.x,
        bits
    ));
}

pub fn psa_set_key_id(attributes: &mut psa_key_attributes_t, id: psa_key_id_t) {
    wrap_any!(psa_crypto_binding::shim_set_key_id(&mut attributes.x, id));
}

pub fn psa_set_key_lifetime(attributes: &mut psa_key_attributes_t, lifetime: psa_key_lifetime_t) {
    wrap_any!(psa_crypto_binding::shim_set_key_lifetime(
        &mut attributes.x,
        lifetime
    ));
}

pub fn psa_set_key_type(attributes: &mut psa_key_attributes_t, type_: psa_key_type_t) {
    wrap_any!(psa_crypto_binding::shim_set_key_type(
        &mut attributes.x,
        type_
    ));
}

pub fn psa_set_key_usage_flags(
    attributes: &mut psa_key_attributes_t,
    usage_flags: psa_key_usage_t,
) {
    wrap_any!(psa_crypto_binding::shim_set_key_usage_flags(
        &mut attributes.x,
        usage_flags
    ));
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
