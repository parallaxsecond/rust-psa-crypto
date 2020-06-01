// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#include <psa/crypto.h>
#include <psa/crypto_se_driver.h>

const psa_status_t shim_PSA_SUCCESS = PSA_SUCCESS;
const psa_status_t shim_PSA_ERROR_GENERIC_ERROR = PSA_ERROR_GENERIC_ERROR;
const psa_status_t shim_PSA_ERROR_NOT_SUPPORTED = PSA_ERROR_NOT_SUPPORTED;
const psa_status_t shim_PSA_ERROR_NOT_PERMITTED = PSA_ERROR_NOT_PERMITTED;
const psa_status_t shim_PSA_ERROR_BUFFER_TOO_SMALL = PSA_ERROR_BUFFER_TOO_SMALL;
const psa_status_t shim_PSA_ERROR_ALREADY_EXISTS = PSA_ERROR_ALREADY_EXISTS;
const psa_status_t shim_PSA_ERROR_DOES_NOT_EXIST = PSA_ERROR_DOES_NOT_EXIST;
const psa_status_t shim_PSA_ERROR_BAD_STATE = PSA_ERROR_BAD_STATE;
const psa_status_t shim_PSA_ERROR_INVALID_ARGUMENT = PSA_ERROR_INVALID_ARGUMENT;
const psa_status_t shim_PSA_ERROR_INSUFFICIENT_MEMORY = PSA_ERROR_INSUFFICIENT_MEMORY;
const psa_status_t shim_PSA_ERROR_INSUFFICIENT_STORAGE = PSA_ERROR_INSUFFICIENT_STORAGE;
const psa_status_t shim_PSA_ERROR_COMMUNICATION_FAILURE = PSA_ERROR_COMMUNICATION_FAILURE;
const psa_status_t shim_PSA_ERROR_STORAGE_FAILURE = PSA_ERROR_STORAGE_FAILURE;
const psa_status_t shim_PSA_ERROR_HARDWARE_FAILURE = PSA_ERROR_HARDWARE_FAILURE;
const psa_status_t shim_PSA_ERROR_INSUFFICIENT_ENTROPY = PSA_ERROR_INSUFFICIENT_ENTROPY;
const psa_status_t shim_PSA_ERROR_INVALID_SIGNATURE = PSA_ERROR_INVALID_SIGNATURE;
const psa_status_t shim_PSA_ERROR_INVALID_PADDING = PSA_ERROR_INVALID_PADDING;
const psa_status_t shim_PSA_ERROR_INSUFFICIENT_DATA = PSA_ERROR_INSUFFICIENT_DATA;
const psa_status_t shim_PSA_ERROR_INVALID_HANDLE = PSA_ERROR_INVALID_HANDLE;

const size_t shim_PSA_MAX_KEY_BITS = PSA_MAX_KEY_BITS;
const psa_key_bits_t shim_PSA_KEY_BITS_TOO_LARGE = PSA_KEY_BITS_TOO_LARGE;
const psa_key_type_t shim_PSA_KEY_TYPE_NONE = PSA_KEY_TYPE_NONE;
const psa_key_type_t shim_PSA_KEY_TYPE_VENDOR_FLAG = PSA_KEY_TYPE_VENDOR_FLAG;
const psa_key_type_t shim_PSA_KEY_TYPE_CATEGORY_MASK = PSA_KEY_TYPE_CATEGORY_MASK;
const psa_key_type_t shim_PSA_KEY_TYPE_CATEGORY_SYMMETRIC = PSA_KEY_TYPE_CATEGORY_SYMMETRIC;
const psa_key_type_t shim_PSA_KEY_TYPE_CATEGORY_RAW = PSA_KEY_TYPE_CATEGORY_RAW;
const psa_key_type_t shim_PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY = PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY;
const psa_key_type_t shim_PSA_KEY_TYPE_CATEGORY_KEY_PAIR = PSA_KEY_TYPE_CATEGORY_KEY_PAIR;
const psa_key_type_t shim_PSA_KEY_TYPE_CATEGORY_FLAG_PAIR = PSA_KEY_TYPE_CATEGORY_FLAG_PAIR;
const psa_key_type_t shim_PSA_KEY_TYPE_RAW_DATA = PSA_KEY_TYPE_RAW_DATA;
const psa_key_type_t shim_PSA_KEY_TYPE_HMAC = PSA_KEY_TYPE_HMAC;
const psa_key_type_t shim_PSA_KEY_TYPE_DERIVE = PSA_KEY_TYPE_DERIVE;
const psa_key_type_t shim_PSA_KEY_TYPE_AES = PSA_KEY_TYPE_AES;
const psa_key_type_t shim_PSA_KEY_TYPE_DES = PSA_KEY_TYPE_DES;
const psa_key_type_t shim_PSA_KEY_TYPE_CAMELLIA = PSA_KEY_TYPE_CAMELLIA;
const psa_key_type_t shim_PSA_KEY_TYPE_ARC4 = PSA_KEY_TYPE_ARC4;
const psa_key_type_t shim_PSA_KEY_TYPE_CHACHA20 = PSA_KEY_TYPE_CHACHA20;
const psa_key_type_t shim_PSA_KEY_TYPE_RSA_PUBLIC_KEY = PSA_KEY_TYPE_RSA_PUBLIC_KEY;
const psa_key_type_t shim_PSA_KEY_TYPE_RSA_KEY_PAIR = PSA_KEY_TYPE_RSA_KEY_PAIR;
const psa_key_type_t shim_PSA_KEY_TYPE_DSA_PUBLIC_KEY = PSA_KEY_TYPE_DSA_PUBLIC_KEY;
const psa_key_type_t shim_PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE = PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE;
const psa_key_type_t shim_PSA_KEY_TYPE_ECC_KEY_PAIR_BASE = PSA_KEY_TYPE_ECC_KEY_PAIR_BASE;
const psa_key_type_t shim_PSA_KEY_TYPE_ECC_CURVE_MASK = PSA_KEY_TYPE_ECC_CURVE_MASK;
const psa_ecc_curve_t shim_PSA_ECC_CURVE_SECP_K1 = PSA_ECC_CURVE_SECP_K1;
const psa_ecc_curve_t shim_PSA_ECC_CURVE_SECP_R1 = PSA_ECC_CURVE_SECP_R1;
const psa_ecc_curve_t shim_PSA_ECC_CURVE_SECP_R2 = PSA_ECC_CURVE_SECP_R2;
const psa_ecc_curve_t shim_PSA_ECC_CURVE_SECT_K1 = PSA_ECC_CURVE_SECT_K1;
const psa_ecc_curve_t shim_PSA_ECC_CURVE_SECT_R1 = PSA_ECC_CURVE_SECT_R1;
const psa_ecc_curve_t shim_PSA_ECC_CURVE_SECT_R2 = PSA_ECC_CURVE_SECT_R2;
const psa_ecc_curve_t shim_PSA_ECC_CURVE_BRAINPOOL_P_R1 = PSA_ECC_CURVE_BRAINPOOL_P_R1;
const psa_ecc_curve_t shim_PSA_ECC_CURVE_MONTGOMERY = PSA_ECC_CURVE_MONTGOMERY;
const psa_dh_group_t shim_PSA_DH_GROUP_RFC7919 = PSA_DH_GROUP_RFC7919;
const psa_algorithm_t shim_PSA_ALG_VENDOR_FLAG = PSA_ALG_VENDOR_FLAG;
const psa_algorithm_t shim_PSA_ALG_CATEGORY_MASK = PSA_ALG_CATEGORY_MASK;
const psa_algorithm_t shim_PSA_ALG_CATEGORY_HASH = PSA_ALG_CATEGORY_HASH;
const psa_algorithm_t shim_PSA_ALG_CATEGORY_MAC = PSA_ALG_CATEGORY_MAC;
const psa_algorithm_t shim_PSA_ALG_CATEGORY_CIPHER = PSA_ALG_CATEGORY_CIPHER;
const psa_algorithm_t shim_PSA_ALG_CATEGORY_AEAD = PSA_ALG_CATEGORY_AEAD;
const psa_algorithm_t shim_PSA_ALG_CATEGORY_SIGN = PSA_ALG_CATEGORY_SIGN;
const psa_algorithm_t shim_PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION = PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION;
const psa_algorithm_t shim_PSA_ALG_CATEGORY_KEY_AGREEMENT = PSA_ALG_CATEGORY_KEY_AGREEMENT;
const psa_algorithm_t shim_PSA_ALG_CATEGORY_KEY_DERIVATION = PSA_ALG_CATEGORY_KEY_DERIVATION;
const psa_algorithm_t shim_PSA_ALG_HASH_MASK = PSA_ALG_HASH_MASK;
const psa_algorithm_t shim_PSA_ALG_MD2 = PSA_ALG_MD2;
const psa_algorithm_t shim_PSA_ALG_MD4 = PSA_ALG_MD4;
const psa_algorithm_t shim_PSA_ALG_MD5 = PSA_ALG_MD5;
const psa_algorithm_t shim_PSA_ALG_RIPEMD160 = PSA_ALG_RIPEMD160;
const psa_algorithm_t shim_PSA_ALG_SHA_1 = PSA_ALG_SHA_1;
const psa_algorithm_t shim_PSA_ALG_SHA_224 = PSA_ALG_SHA_224;
const psa_algorithm_t shim_PSA_ALG_SHA_256 = PSA_ALG_SHA_256;
const psa_algorithm_t shim_PSA_ALG_SHA_384 = PSA_ALG_SHA_384;
const psa_algorithm_t shim_PSA_ALG_SHA_512 = PSA_ALG_SHA_512;
const psa_algorithm_t shim_PSA_ALG_SHA_512_224 = PSA_ALG_SHA_512_224;
const psa_algorithm_t shim_PSA_ALG_SHA_512_256 = PSA_ALG_SHA_512_256;
const psa_algorithm_t shim_PSA_ALG_SHA3_224 = PSA_ALG_SHA3_224;
const psa_algorithm_t shim_PSA_ALG_SHA3_256 = PSA_ALG_SHA3_256;
const psa_algorithm_t shim_PSA_ALG_SHA3_384 = PSA_ALG_SHA3_384;
const psa_algorithm_t shim_PSA_ALG_SHA3_512 = PSA_ALG_SHA3_512;
const psa_algorithm_t shim_PSA_ALG_ANY_HASH = PSA_ALG_ANY_HASH;
const psa_algorithm_t shim_PSA_ALG_MAC_SUBCATEGORY_MASK = PSA_ALG_MAC_SUBCATEGORY_MASK;
const psa_algorithm_t shim_PSA_ALG_HMAC_BASE = PSA_ALG_HMAC_BASE;
const psa_algorithm_t shim_PSA_ALG_MAC_TRUNCATION_MASK = PSA_ALG_MAC_TRUNCATION_MASK;
const psa_algorithm_t shim_PSA_ALG_CIPHER_MAC_BASE = PSA_ALG_CIPHER_MAC_BASE;
const psa_algorithm_t shim_PSA_ALG_CBC_MAC = PSA_ALG_CBC_MAC;
const psa_algorithm_t shim_PSA_ALG_CMAC = PSA_ALG_CMAC;
const psa_algorithm_t shim_PSA_ALG_CIPHER_STREAM_FLAG = PSA_ALG_CIPHER_STREAM_FLAG;
const psa_algorithm_t shim_PSA_ALG_CIPHER_FROM_BLOCK_FLAG = PSA_ALG_CIPHER_FROM_BLOCK_FLAG;
const psa_algorithm_t shim_PSA_ALG_ARC4 = PSA_ALG_ARC4;
const psa_algorithm_t shim_PSA_ALG_CTR = PSA_ALG_CTR;
const psa_algorithm_t shim_PSA_ALG_CFB = PSA_ALG_CFB;
const psa_algorithm_t shim_PSA_ALG_OFB = PSA_ALG_OFB;
const psa_algorithm_t shim_PSA_ALG_XTS = PSA_ALG_XTS;
const psa_algorithm_t shim_PSA_ALG_CBC_NO_PADDING = PSA_ALG_CBC_NO_PADDING;
const psa_algorithm_t shim_PSA_ALG_CBC_PKCS7 = PSA_ALG_CBC_PKCS7;
const psa_algorithm_t shim_PSA_ALG_CCM = PSA_ALG_CCM;
const psa_algorithm_t shim_PSA_ALG_GCM = PSA_ALG_GCM;
const psa_algorithm_t shim_PSA_ALG_AEAD_TAG_LENGTH_MASK = PSA_ALG_AEAD_TAG_LENGTH_MASK;
const psa_algorithm_t shim_PSA_ALG_RSA_PKCS1V15_SIGN_BASE = PSA_ALG_RSA_PKCS1V15_SIGN_BASE;
const psa_algorithm_t shim_PSA_ALG_RSA_PKCS1V15_SIGN_RAW = PSA_ALG_RSA_PKCS1V15_SIGN_RAW;
const psa_algorithm_t shim_PSA_ALG_RSA_PSS_BASE = PSA_ALG_RSA_PSS_BASE;
const psa_algorithm_t shim_PSA_ALG_DSA_BASE = PSA_ALG_DSA_BASE;
const psa_algorithm_t shim_PSA_ALG_DETERMINISTIC_DSA_BASE = PSA_ALG_DETERMINISTIC_DSA_BASE;
const psa_algorithm_t shim_PSA_ALG_DSA_DETERMINISTIC_FLAG = PSA_ALG_DSA_DETERMINISTIC_FLAG;
const psa_algorithm_t shim_PSA_ALG_ECDSA_BASE = PSA_ALG_ECDSA_BASE;
const psa_algorithm_t shim_PSA_ALG_ECDSA_ANY = PSA_ALG_ECDSA_ANY;
const psa_algorithm_t shim_PSA_ALG_DETERMINISTIC_ECDSA_BASE = PSA_ALG_DETERMINISTIC_ECDSA_BASE;
const psa_algorithm_t shim_PSA_ALG_RSA_PKCS1V15_CRYPT = PSA_ALG_RSA_PKCS1V15_CRYPT;
const psa_algorithm_t shim_PSA_ALG_RSA_OAEP_BASE = PSA_ALG_RSA_OAEP_BASE;
const psa_algorithm_t shim_PSA_ALG_HKDF_BASE = PSA_ALG_HKDF_BASE;
const psa_algorithm_t shim_PSA_ALG_TLS12_PRF_BASE = PSA_ALG_TLS12_PRF_BASE;
const psa_algorithm_t shim_PSA_ALG_TLS12_PSK_TO_MS_BASE = PSA_ALG_TLS12_PSK_TO_MS_BASE;
const psa_algorithm_t shim_PSA_ALG_KEY_DERIVATION_MASK = PSA_ALG_KEY_DERIVATION_MASK;
const psa_key_lifetime_t shim_PSA_KEY_LIFETIME_VOLATILE = PSA_KEY_LIFETIME_VOLATILE;
const psa_key_lifetime_t shim_PSA_KEY_LIFETIME_PERSISTENT = PSA_KEY_LIFETIME_PERSISTENT;
const psa_key_usage_t shim_PSA_KEY_USAGE_EXPORT = PSA_KEY_USAGE_EXPORT;
const psa_key_usage_t shim_PSA_KEY_USAGE_ENCRYPT = PSA_KEY_USAGE_ENCRYPT;
const psa_key_usage_t shim_PSA_KEY_USAGE_DECRYPT = PSA_KEY_USAGE_DECRYPT;
const psa_key_usage_t shim_PSA_KEY_USAGE_SIGN = PSA_KEY_USAGE_SIGN;
const psa_key_usage_t shim_PSA_KEY_USAGE_VERIFY = PSA_KEY_USAGE_VERIFY;
const psa_key_usage_t shim_PSA_KEY_USAGE_DERIVE = PSA_KEY_USAGE_DERIVE;

psa_key_id_t
shim_get_key_id(const psa_key_attributes_t *attributes);

size_t
shim_get_key_bits(const psa_key_attributes_t *attributes);

psa_key_type_t
shim_get_key_type(const psa_key_attributes_t *attributes);
psa_key_lifetime_t
shim_get_key_lifetime(const psa_key_attributes_t *attributes);
psa_algorithm_t
shim_get_key_algorithm(const psa_key_attributes_t *attributes);
psa_key_usage_t
shim_get_key_usage_flags(const psa_key_attributes_t *attributes);
psa_key_attributes_t
shim_key_attributes_init(void);

void
shim_set_key_algorithm(psa_key_attributes_t *attributes,
                       psa_algorithm_t alg);

void
shim_set_key_bits(psa_key_attributes_t *attributes,
                  size_t bits);

void
shim_set_key_id(psa_key_attributes_t *attributes,
                psa_key_id_t id);

void
shim_set_key_lifetime(psa_key_attributes_t *attributes,
                      psa_key_lifetime_t lifetime);

void
shim_set_key_type(psa_key_attributes_t *attributes,
                  psa_key_type_t type_);

void
shim_set_key_usage_flags(psa_key_attributes_t *attributes,
                         psa_key_usage_t usage_flags);

int
shim_PSA_ALG_IS_HASH(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_MAC(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_CIPHER(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_AEAD(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_SIGN(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_KEY_AGREEMENT(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_KEY_DERIVATION(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_RSA_PSS(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_ECDSA(psa_algorithm_t alg);
int
shim_PSA_ALG_IS_DETERMINISTIC_ECDSA(psa_algorithm_t alg);
psa_algorithm_t
shim_PSA_ALG_RSA_PKCS1V15_SIGN(psa_algorithm_t hash_alg);
psa_algorithm_t
shim_PSA_ALG_RSA_PSS(psa_algorithm_t hash_alg);
psa_algorithm_t
shim_PSA_ALG_ECDSA(psa_algorithm_t hash_alg);
psa_algorithm_t
shim_PSA_ALG_DETERMINISTIC_ECDSA(psa_algorithm_t hash_alg);
psa_algorithm_t
shim_PSA_ALG_SIGN_GET_HASH(psa_algorithm_t alg);
int
shim_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(psa_key_type_t key_type);
int
shim_PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(psa_key_type_t key_type);
int
shim_PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(psa_key_type_t key_type);
int
shim_PSA_KEY_TYPE_IS_DH_KEY_PAIR(psa_key_type_t key_type);
psa_ecc_curve_t
shim_PSA_KEY_TYPE_GET_CURVE(psa_key_type_t key_type);
psa_dh_group_t
shim_PSA_KEY_TYPE_GET_GROUP(psa_key_type_t key_type);
psa_key_type_t
shim_PSA_KEY_TYPE_ECC_KEY_PAIR(psa_ecc_curve_t curve);
psa_key_type_t
shim_PSA_KEY_TYPE_ECC_PUBLIC_KEY(psa_ecc_curve_t curve);
psa_key_type_t
shim_PSA_KEY_TYPE_DH_KEY_PAIR(psa_dh_group_t group);
psa_key_type_t
shim_PSA_KEY_TYPE_DH_PUBLIC_KEY(psa_dh_group_t group);
