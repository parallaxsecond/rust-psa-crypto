// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

// This file is needed to provide linkable versions of certain
// PSA Crypto functions that may be declared static inline.
// See: https://github.com/ARMmbed/mbedtls/issues/3230

#include "shim.h"

size_t
shim_get_key_bits(const psa_key_attributes_t *attributes)
{
    return psa_get_key_bits(attributes);
}

psa_key_type_t
shim_get_key_type(const psa_key_attributes_t *attributes)
{
    return psa_get_key_type(attributes);
}

psa_key_attributes_t
shim_key_attributes_init(void)
{
    return psa_key_attributes_init();
}

void
shim_set_key_algorithm(psa_key_attributes_t *attributes,
                       psa_algorithm_t alg)
{
    psa_set_key_algorithm(attributes, alg);
}

void
shim_set_key_bits(psa_key_attributes_t *attributes,
                  size_t bits)
{
    psa_set_key_bits(attributes, bits);
}

void
shim_set_key_id(psa_key_attributes_t *attributes,
                psa_key_id_t id)
{
    psa_set_key_id(attributes, id);
}

void
shim_set_key_lifetime(psa_key_attributes_t *attributes,
                      psa_key_lifetime_t lifetime)
{
    psa_set_key_lifetime(attributes, lifetime);
}

void
shim_set_key_type(psa_key_attributes_t *attributes,
                  psa_key_type_t type_)
{
    psa_set_key_type(attributes, type_);
}

void
shim_set_key_usage_flags(psa_key_attributes_t *attributes,
                         psa_key_usage_t usage_flags)
{
    psa_set_key_usage_flags(attributes, usage_flags);
}

int
shim_PSA_ALG_IS_HASH(psa_algorithm_t alg)
{
    return PSA_ALG_IS_HASH(alg);
}

int
shim_PSA_ALG_IS_MAC(psa_algorithm_t alg) {
    return PSA_ALG_IS_MAC(alg);
}

int
shim_PSA_ALG_IS_CIPHER(psa_algorithm_t alg) {
    return PSA_ALG_IS_CIPHER(alg);
}

int
shim_PSA_ALG_IS_AEAD(psa_algorithm_t alg) {
    return PSA_ALG_IS_AEAD(alg);
}

int
shim_PSA_ALG_IS_SIGN(psa_algorithm_t alg) {
    return PSA_ALG_IS_SIGN(alg);
}

int
shim_PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(psa_algorithm_t alg) {
    return PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg);
}

int
shim_PSA_ALG_IS_KEY_AGREEMENT(psa_algorithm_t alg) {
    return PSA_ALG_IS_KEY_AGREEMENT(alg);
}

int
shim_PSA_ALG_IS_KEY_DERIVATION(psa_algorithm_t alg) {
    return PSA_ALG_IS_KEY_DERIVATION(alg);
}

int
shim_PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm_t alg) {
    return PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg);
}

int
shim_PSA_ALG_IS_RSA_PSS(psa_algorithm_t alg) {
    return PSA_ALG_IS_RSA_PSS(alg);
}

int
shim_PSA_ALG_IS_ECDSA(psa_algorithm_t alg) {
    return PSA_ALG_IS_ECDSA(alg);
}

int
shim_PSA_ALG_IS_DETERMINISTIC_ECDSA(psa_algorithm_t alg) {
    return PSA_ALG_IS_DETERMINISTIC_ECDSA(alg);
}

psa_algorithm_t
shim_PSA_ALG_SIGN_GET_HASH(psa_algorithm_t alg) {
    return PSA_ALG_SIGN_GET_HASH(alg);
}

psa_algorithm_t
shim_PSA_ALG_RSA_PKCS1V15_SIGN(psa_algorithm_t hash_alg) {
	return PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg);
}

psa_algorithm_t
shim_PSA_ALG_RSA_PSS(psa_algorithm_t hash_alg) {
	return PSA_ALG_RSA_PSS(hash_alg);
}

psa_algorithm_t
shim_PSA_ALG_ECDSA(psa_algorithm_t hash_alg) {
	return PSA_ALG_ECDSA(hash_alg);
}

psa_algorithm_t
shim_PSA_ALG_DETERMINISTIC_ECDSA(psa_algorithm_t hash_alg) {
	return PSA_ALG_DETERMINISTIC_ECDSA(hash_alg);
}
