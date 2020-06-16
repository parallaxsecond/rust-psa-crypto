// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Constants used by the Mbed Provider for interaction with the Mbed Crypto C library.

#![allow(missing_docs)]

use super::types::*;

// PSA error codes
pub const PSA_SUCCESS: psa_status_t = 0;
pub const PSA_ERROR_GENERIC_ERROR: psa_status_t = -132;
pub const PSA_ERROR_NOT_PERMITTED: psa_status_t = -133;
pub const PSA_ERROR_NOT_SUPPORTED: psa_status_t = -134;
pub const PSA_ERROR_INVALID_ARGUMENT: psa_status_t = -135;
pub const PSA_ERROR_INVALID_HANDLE: psa_status_t = -136;
pub const PSA_ERROR_BAD_STATE: psa_status_t = -137;
pub const PSA_ERROR_BUFFER_TOO_SMALL: psa_status_t = -138;
pub const PSA_ERROR_ALREADY_EXISTS: psa_status_t = -139;
pub const PSA_ERROR_DOES_NOT_EXIST: psa_status_t = -140;
pub const PSA_ERROR_INSUFFICIENT_MEMORY: psa_status_t = -141;
pub const PSA_ERROR_INSUFFICIENT_STORAGE: psa_status_t = -142;
pub const PSA_ERROR_INSUFFICIENT_DATA: psa_status_t = -143;
pub const PSA_ERROR_COMMUNICATION_FAILURE: psa_status_t = -145;
pub const PSA_ERROR_STORAGE_FAILURE: psa_status_t = -146;
pub const PSA_ERROR_HARDWARE_FAILURE: psa_status_t = -147;
pub const PSA_ERROR_INSUFFICIENT_ENTROPY: psa_status_t = -148;
pub const PSA_ERROR_INVALID_SIGNATURE: psa_status_t = -149;
pub const PSA_ERROR_INVALID_PADDING: psa_status_t = -150;
pub const PSA_ERROR_CORRUPTION_DETECTED: psa_status_t = -151;
pub const PSA_ERROR_DATA_CORRUPT: psa_status_t = -152;
pub const PSA_ERROR_DATA_INVALID: psa_status_t = -153;

pub const PSA_MAX_KEY_BITS: usize = 65528;
pub const PSA_KEY_TYPE_NONE: psa_key_type_t = 0;
pub const PSA_KEY_TYPE_RAW_DATA: psa_key_type_t = 4097;
pub const PSA_KEY_TYPE_HMAC: psa_key_type_t = 4352;
pub const PSA_KEY_TYPE_DERIVE: psa_key_type_t = 4608;
pub const PSA_KEY_TYPE_AES: psa_key_type_t = 9216;
pub const PSA_KEY_TYPE_DES: psa_key_type_t = 8961;
pub const PSA_KEY_TYPE_CAMELLIA: psa_key_type_t = 9219;
pub const PSA_KEY_TYPE_ARC4: psa_key_type_t = 8194;
pub const PSA_KEY_TYPE_CHACHA20: psa_key_type_t = 8196;
pub const PSA_KEY_TYPE_RSA_PUBLIC_KEY: psa_key_type_t = 16385;
pub const PSA_KEY_TYPE_RSA_KEY_PAIR: psa_key_type_t = 28673;
pub const PSA_ECC_FAMILY_SECP_K1: psa_ecc_curve_t = 23;
pub const PSA_ECC_FAMILY_SECP_R1: psa_ecc_curve_t = 18;
pub const PSA_ECC_FAMILY_SECP_R2: psa_ecc_curve_t = 27;
pub const PSA_ECC_FAMILY_SECT_K1: psa_ecc_curve_t = 39;
pub const PSA_ECC_FAMILY_SECT_R1: psa_ecc_curve_t = 34;
pub const PSA_ECC_FAMILY_SECT_R2: psa_ecc_curve_t = 43;
pub const PSA_ECC_FAMILY_BRAINPOOL_P_R1: psa_ecc_curve_t = 48;
pub const PSA_ECC_FAMILY_MONTGOMERY: psa_ecc_curve_t = 65;
pub const PSA_DH_FAMILY_RFC7919: psa_dh_group_t = 3;
pub const PSA_ALG_MD2: psa_algorithm_t = 16_777_217;
pub const PSA_ALG_MD4: psa_algorithm_t = 16_777_218;
pub const PSA_ALG_MD5: psa_algorithm_t = 16_777_219;
pub const PSA_ALG_RIPEMD160: psa_algorithm_t = 16_777_220;
pub const PSA_ALG_SHA_1: psa_algorithm_t = 16_777_221;
pub const PSA_ALG_SHA_224: psa_algorithm_t = 16_777_224;
pub const PSA_ALG_SHA_256: psa_algorithm_t = 16_777_225;
pub const PSA_ALG_SHA_384: psa_algorithm_t = 16_777_226;
pub const PSA_ALG_SHA_512: psa_algorithm_t = 16_777_227;
pub const PSA_ALG_SHA_512_224: psa_algorithm_t = 16_777_228;
pub const PSA_ALG_SHA_512_256: psa_algorithm_t = 16_777_229;
pub const PSA_ALG_SHA3_224: psa_algorithm_t = 16_777_232;
pub const PSA_ALG_SHA3_256: psa_algorithm_t = 16_777_233;
pub const PSA_ALG_SHA3_384: psa_algorithm_t = 16_777_234;
pub const PSA_ALG_SHA3_512: psa_algorithm_t = 16_777_235;
pub const PSA_ALG_ANY_HASH: psa_algorithm_t = 16_777_471;
pub const PSA_ALG_CBC_MAC: psa_algorithm_t = 46_137_345;
pub const PSA_ALG_CMAC: psa_algorithm_t = 46_137_346;
pub const PSA_ALG_ARC4: psa_algorithm_t = 75_497_473;
pub const PSA_ALG_CTR: psa_algorithm_t = 79_691_777;
pub const PSA_ALG_CFB: psa_algorithm_t = 79_691_778;
pub const PSA_ALG_OFB: psa_algorithm_t = 79_691_779;
pub const PSA_ALG_XTS: psa_algorithm_t = 71_303_423;
pub const PSA_ALG_CBC_NO_PADDING: psa_algorithm_t = 73_400_576;
pub const PSA_ALG_CBC_PKCS7: psa_algorithm_t = 73_400_577;
pub const PSA_ALG_CCM: psa_algorithm_t = 104_861_697;
pub const PSA_ALG_GCM: psa_algorithm_t = 104_861_698;
pub const PSA_ALG_RSA_PKCS1V15_SIGN_RAW: psa_algorithm_t = 268_566_528;
pub const PSA_ALG_ECDSA_ANY: psa_algorithm_t = 268_828_672;
pub const PSA_ALG_RSA_PKCS1V15_CRYPT: psa_algorithm_t = 302_120_960;
pub const PSA_KEY_LIFETIME_VOLATILE: psa_key_lifetime_t = 0;
pub const PSA_KEY_LIFETIME_PERSISTENT: psa_key_lifetime_t = 1;
pub const PSA_KEY_USAGE_EXPORT: psa_key_usage_t = 1;
pub const PSA_KEY_USAGE_ENCRYPT: psa_key_usage_t = 256;
pub const PSA_KEY_USAGE_DECRYPT: psa_key_usage_t = 512;
pub const PSA_KEY_USAGE_SIGN: psa_key_usage_t = 1024;
pub const PSA_KEY_USAGE_VERIFY: psa_key_usage_t = 2048;
pub const PSA_KEY_USAGE_DERIVE: psa_key_usage_t = 4096;
pub const PSA_KEY_ID_USER_MIN: psa_key_id_t = 0x0000_0001;
pub const PSA_KEY_ID_USER_MAX: psa_key_id_t = 0x3fff_ffff;

#[cfg(feature = "implementation-defined")]
pub const PSA_DRV_SE_HAL_VERSION: u32 = 5;
