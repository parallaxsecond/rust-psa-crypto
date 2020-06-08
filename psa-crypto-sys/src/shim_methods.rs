// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use super::psa_crypto_binding::{
    self, psa_algorithm_t, psa_dh_group_t, psa_ecc_curve_t, psa_key_attributes_t, psa_key_id_t,
    psa_key_lifetime_t, psa_key_type_t, psa_key_usage_t, psa_status_t, psa_key_handle_t
};

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

pub unsafe fn psa_get_key_attributes(key_handle: psa_key_handle_t, attributes: *mut psa_key_attributes_t) -> psa_status_t {
    psa_crypto_binding::shim_get_key_attributes(key_handle, attributes)
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

pub unsafe fn psa_get_key_id(attributes: *const psa_key_attributes_t) -> psa_key_id_t {
    psa_crypto_binding::shim_get_key_id(attributes)
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
