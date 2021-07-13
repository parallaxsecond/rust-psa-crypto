// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

// This file is needed to provide linkable versions of certain
// PSA Crypto functions that may be declared static inline.
// See: https://github.com/ARMmbed/mbedtls/issues/3230

#include "shim.h"

psa_key_id_t
shim_get_key_id(const psa_key_attributes_t *attributes)
{
    return psa_get_key_id(attributes);
}

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

psa_key_lifetime_t
shim_get_key_lifetime(const psa_key_attributes_t *attributes)
{
    return psa_get_key_lifetime(attributes);
}

psa_algorithm_t
shim_get_key_algorithm(const psa_key_attributes_t *attributes)
{
    return psa_get_key_algorithm(attributes);
}

psa_key_usage_t
shim_get_key_usage_flags(const psa_key_attributes_t *attributes)
{
    return psa_get_key_usage_flags(attributes);
}

psa_key_attributes_t
shim_key_attributes_init(void)
{
    return psa_key_attributes_init();
}

psa_key_derivation_operation_t
shim_key_derivation_operation_init(void)
{
    return psa_key_derivation_operation_init();
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
shim_PSA_ALG_IS_HMAC(psa_algorithm_t alg) {
    return PSA_ALG_IS_HMAC(alg);
}

int
shim_PSA_ALG_IS_BLOCK_CIPHER_MAC (psa_algorithm_t alg) {
    return PSA_ALG_IS_BLOCK_CIPHER_MAC (alg);
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
shim_PSA_ALG_IS_RSA_OAEP(psa_algorithm_t alg) {
    return PSA_ALG_IS_RSA_OAEP(alg);
}

int
shim_PSA_ALG_IS_KEY_AGREEMENT(psa_algorithm_t alg) {
    return PSA_ALG_IS_KEY_AGREEMENT(alg);
}

int
shim_PSA_ALG_IS_RAW_KEY_AGREEMENT (psa_algorithm_t alg) {
    return PSA_ALG_IS_RAW_KEY_AGREEMENT(alg);
}

int
shim_PSA_ALG_IS_FFDH(psa_algorithm_t alg) {
    return PSA_ALG_IS_FFDH(alg);
}

int
shim_PSA_ALG_IS_ECDH(psa_algorithm_t alg) {
    return PSA_ALG_IS_ECDH(alg);
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

int
shim_PSA_ALG_IS_HKDF(psa_algorithm_t alg) {
    return PSA_ALG_IS_HKDF(alg);
}

int
shim_PSA_ALG_IS_TLS12_PRF(psa_algorithm_t alg) {
    return PSA_ALG_IS_TLS12_PRF(alg);
}

int
shim_PSA_ALG_IS_TLS12_PSK_TO_MS(psa_algorithm_t alg) {
    return PSA_ALG_IS_TLS12_PSK_TO_MS(alg);
}

psa_algorithm_t
shim_PSA_ALG_SIGN_GET_HASH(psa_algorithm_t sign_alg) {
    return PSA_ALG_SIGN_GET_HASH(sign_alg);
}

psa_algorithm_t
shim_PSA_ALG_RSA_OAEP_GET_HASH(psa_algorithm_t rsa_oaep_alg) {
    return PSA_ALG_RSA_OAEP_GET_HASH(rsa_oaep_alg);
}

psa_algorithm_t
shim_PSA_ALG_HMAC_GET_HASH(psa_algorithm_t hmac_alg) {
    return PSA_ALG_HMAC_GET_HASH(hmac_alg);
}

psa_algorithm_t
shim_PSA_ALG_HKDF_GET_HASH(psa_algorithm_t hkdf_alg) {
    return PSA_ALG_HKDF_GET_HASH(hkdf_alg);
}

psa_algorithm_t
shim_PSA_ALG_TLS12_PRF_GET_HASH(psa_algorithm_t tls12_prf_alg) {
    return PSA_ALG_TLS12_PRF_GET_HASH(tls12_prf_alg);
}

psa_algorithm_t
shim_PSA_ALG_TLS12_PSK_TO_MS_GET_HASH(psa_algorithm_t tls12_psk_to_ms_alg) {
    return PSA_ALG_TLS12_PSK_TO_MS_GET_HASH(tls12_psk_to_ms_alg);
}

psa_algorithm_t
shim_PSA_ALG_KEY_AGREEMENT_GET_BASE(psa_algorithm_t alg) {
    return PSA_ALG_KEY_AGREEMENT_GET_BASE(alg);
}

psa_algorithm_t
shim_PSA_ALG_KEY_AGREEMENT_GET_KDF(psa_algorithm_t alg) {
    return PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
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

psa_algorithm_t
shim_PSA_ALG_HMAC(psa_algorithm_t hash_alg) {
    return PSA_ALG_HMAC(hash_alg);
}

psa_algorithm_t
shim_PSA_ALG_TRUNCATED_MAC(psa_algorithm_t mac_alg, size_t mac_length) {
    return PSA_ALG_TRUNCATED_MAC(mac_alg, mac_length);
}

psa_algorithm_t
shim_PSA_ALG_FULL_LENGTH_MAC(psa_algorithm_t mac_alg) {
    return PSA_ALG_FULL_LENGTH_MAC(mac_alg);
}

psa_algorithm_t
shim_PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(psa_algorithm_t aead_alg) {
    return PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(aead_alg);
}

psa_algorithm_t
shim_PSA_ALG_AEAD_WITH_SHORTENED_TAG(psa_algorithm_t aead_alg, size_t tag_length) {
    return PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, tag_length);
}

psa_algorithm_t
shim_PSA_ALG_HKDF(psa_algorithm_t hash_alg) {
    return PSA_ALG_HKDF(hash_alg);
}

psa_algorithm_t
shim_PSA_ALG_TLS12_PRF(psa_algorithm_t hash_alg) {
    return PSA_ALG_TLS12_PRF(hash_alg);
}

psa_algorithm_t
shim_PSA_ALG_TLS12_PSK_TO_MS(psa_algorithm_t hash_alg) {
    return PSA_ALG_TLS12_PSK_TO_MS(hash_alg);
}

psa_algorithm_t
shim_PSA_ALG_KEY_AGREEMENT(psa_algorithm_t raw_key_agreement, psa_algorithm_t key_derivation) {
    return PSA_ALG_KEY_AGREEMENT(raw_key_agreement, key_derivation);
}

int
shim_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(psa_key_type_t key_type)
{
	return PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type);
}

int
shim_PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(psa_key_type_t key_type)
{
	return PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type);
}

int
shim_PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(psa_key_type_t key_type)
{
	return PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(key_type);
}

int
shim_PSA_KEY_TYPE_IS_DH_KEY_PAIR(psa_key_type_t key_type)
{
	return PSA_KEY_TYPE_IS_DH_KEY_PAIR(key_type);
}

psa_algorithm_t
shim_PSA_ALG_RSA_OAEP(psa_algorithm_t hash_alg)
{
	return PSA_ALG_RSA_OAEP(hash_alg);
}

psa_ecc_family_t
shim_PSA_KEY_TYPE_ECC_GET_FAMILY(psa_key_type_t key_type)
{
	return PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
}

psa_dh_family_t
shim_PSA_KEY_TYPE_DH_GET_FAMILY(psa_key_type_t key_type)
{
	return PSA_KEY_TYPE_DH_GET_FAMILY(key_type);
}

psa_key_type_t
shim_PSA_KEY_TYPE_ECC_KEY_PAIR(psa_ecc_family_t curve)
{
	return PSA_KEY_TYPE_ECC_KEY_PAIR(curve);
}

psa_key_type_t
shim_PSA_KEY_TYPE_ECC_PUBLIC_KEY(psa_ecc_family_t curve)
{
	return PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve);
}

psa_key_type_t
shim_PSA_KEY_TYPE_DH_KEY_PAIR(psa_dh_family_t group)
{
	return PSA_KEY_TYPE_DH_KEY_PAIR(group);
}

psa_key_type_t
shim_PSA_KEY_TYPE_DH_PUBLIC_KEY(psa_dh_family_t group)
{
	return PSA_KEY_TYPE_DH_PUBLIC_KEY(group);
}

psa_key_type_t
shim_PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(psa_key_type_t key_type)
{
    return PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(key_type);
}

size_t
shim_PSA_SIGN_OUTPUT_SIZE(psa_key_type_t key_type, size_t key_bits, psa_algorithm_t alg)
{
    return PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg);
}

size_t
shim_PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(psa_key_type_t key_type, size_t key_bits, psa_algorithm_t alg)
{
    return PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg);
}

size_t
shim_PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(psa_key_type_t key_type, size_t key_bits, psa_algorithm_t alg)
{
    return PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg);
}

size_t
shim_PSA_EXPORT_KEY_OUTPUT_SIZE(psa_key_type_t key_type, size_t key_bits)
{
    return PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits);
}

size_t
shim_PSA_HASH_LENGTH(psa_algorithm_t alg)
{
    return PSA_HASH_LENGTH(alg);
}

size_t
shim_PSA_MAC_LENGTH(psa_key_type_t key_type, size_t key_bits, psa_algorithm_t alg)
{
    return PSA_MAC_LENGTH(key_type, key_bits, alg);
}

size_t
shim_PSA_MAC_TRUNCATED_LENGTH(psa_algorithm_t alg)
{
    return PSA_MAC_TRUNCATED_LENGTH(alg);
}

size_t
shim_PSA_AEAD_TAG_LENGTH(psa_key_type_t key_type, size_t key_bits, psa_algorithm_t alg)
{
    return PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg);
}

size_t
shim_PSA_AEAD_ENCRYPT_OUTPUT_SIZE(psa_key_type_t key_type, psa_algorithm_t aead_alg, size_t plaintext_length)
{
    return PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, aead_alg, plaintext_length);
}

size_t
shim_PSA_AEAD_DECRYPT_OUTPUT_SIZE(psa_key_type_t key_type, psa_algorithm_t aead_alg, size_t ciphertext_length)
{
    return PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, aead_alg, ciphertext_length);
}
