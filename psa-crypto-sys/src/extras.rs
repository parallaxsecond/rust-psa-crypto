// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]
/// Additional functionality required that PSA Crypto does not provide
use crate::types::psa_algorithm_t;

/// Retrieves the tag length from an aead_alg.
/// Note: `aead_alg` is an AEAD algorithm, such that `PSA_ALG_IS_AEAD(aead_alg)` is `true`.
pub fn PSA_ALG_AEAD_TAG_TRUNCATED_LENGTH(aead_alg: psa_algorithm_t) -> usize {
    const TAG_LENGTH_MASK: u32 = 0b111111; // tag lengths are 6 bits in length
    const PSA_V1_0_0_TAG_LENGTH_START_BIT: u32 = 16; // tag length at bit position [21:16]

    let pre_mask_tag_length = aead_alg >> PSA_V1_0_0_TAG_LENGTH_START_BIT;

    (pre_mask_tag_length & TAG_LENGTH_MASK) as usize
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
