// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]
/// Additional functionality required that PSA Crypto does not provide
use crate::types::{psa_algorithm_t, psa_key_type_t};

/// Retrieves the tag length from an aead_alg.
/// Note: `aead_alg` is an AEAD algorithm, such that `PSA_ALG_IS_AEAD(aead_alg)` is `true`.
pub fn PSA_ALG_AEAD_TAG_TRUNCATED_LENGTH(aead_alg: psa_algorithm_t) -> usize {
    const TAG_LENGTH_MASK: u32 = 0b111111; // tag lengths are 6 bits in length
    const PSA_V1_0_0_TAG_LENGTH_START_BIT: u32 = 16; // tag length at bit position [21:16]

    let pre_mask_tag_length = aead_alg >> PSA_V1_0_0_TAG_LENGTH_START_BIT;

    (pre_mask_tag_length & TAG_LENGTH_MASK) as usize
}

/// Retrieves the output size of an ECDH raw key agreement operation shared secret.
/// Caller must ensure key type is compatible.
/// Returns 0 if key size is too large.
/// This does not match any PSA macro, it will be replaces by PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE once
/// mbedTLS adds support for it.
pub unsafe fn PSA_RAW_ECDH_KEY_AGREEMENT_OUTPUT_SIZE(
    _key_type: psa_key_type_t,
    key_bits: usize,
) -> usize {
    /*
    The size of the shared secret is always `ceiling(m/8)` bytes long where `m` is the bit size associated with the curve,
    i.e. the bit size of the order of the curve's coordinate field. When m is not a multiple of 8, the byte containing the most
    significant bit of the shared secret is padded with zero bits.
    */
    if let Some(numerator) = key_bits.checked_add(7) {
        numerator / 8
    } else {
        0
    }
}

#[test]
fn truncated_aead_length_1() {
    let test_aead_alg = 0b11001110010010110001110011010011; // 21:16 is 001011
    assert_eq!(11, PSA_ALG_AEAD_TAG_TRUNCATED_LENGTH(test_aead_alg));
}

#[test]
fn truncated_aead_length_2() {
    let test_aead_alg = 0b11001110010000000001110011010011; // 21:16 is 000000
    assert_eq!(0, PSA_ALG_AEAD_TAG_TRUNCATED_LENGTH(test_aead_alg));
}

#[test]
fn truncated_aead_length_3() {
    let test_aead_alg = 0b11001110011111110001110011010011; // 21:16 is 111111
    assert_eq!(63, PSA_ALG_AEAD_TAG_TRUNCATED_LENGTH(test_aead_alg));
}

#[test]
fn truncated_aead_length_full_range() {
    // Test from 0 to 63
    let base_mask = 0b11001110010000000001110011010011;
    for test_val in 0..63 {
        let test_mask = test_val << 16;
        let test_aead_alg = base_mask | test_mask;
        assert_eq!(
            test_val as usize,
            PSA_ALG_AEAD_TAG_TRUNCATED_LENGTH(test_aead_alg)
        );
    }
}
