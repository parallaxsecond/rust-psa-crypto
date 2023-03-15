// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Hash operations
//!
//! See the PSA Crypto API for the format of the different parameters used in this module.

use crate::initialized;
use crate::types::algorithm::Hash;
use crate::types::status::{Result, Status};
use crate::LOCK;

/// Calculate hash of a message
///
/// # Example
///
/// ```
/// use psa_crypto::operations::hash::hash_compute;
/// use psa_crypto::types::algorithm::Hash;
/// # const MESSAGE: [u8; 32] = [
/// #     0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
/// #     0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
/// # ];
///
/// psa_crypto::init().unwrap();
/// let hash_alg = Hash::Sha256;
/// let mut hash = vec![0; hash_alg.hash_length()];
/// let size = hash_compute(hash_alg,
///                      &MESSAGE,
///                      &mut hash).unwrap();
/// ```
pub fn hash_compute(hash_alg: Hash, input: &[u8], hash: &mut [u8]) -> Result<usize> {
    initialized()?;
    let _lock = LOCK.read();

    let mut output_length = 0;

    Status::from(unsafe {
        psa_crypto_sys::psa_hash_compute(
            hash_alg.into(),
            input.as_ptr(),
            input.len(),
            hash.as_mut_ptr(),
            hash.len(),
            &mut output_length,
        )
    })
    .to_result()?;
    Ok(output_length)
}

/// Calculate the hash of a message and compare it with a reference value
///
/// # Example
///
/// ```
/// use psa_crypto::operations::hash::{hash_compute, hash_compare};
/// use psa_crypto::types::algorithm::Hash;
/// # const MESSAGE: [u8; 3] = [0xb0, 0xbd, 0x69];
/// # const HASH: [u8; 32] = [0x40, 0x96, 0x80, 0x42, 0x21, 0x09, 0x3d, 0xdc, 0xcf, 0xbf, 0x46, 0x83, 0x14, 0x90, 0xea, 0x63, 0xe9, 0xe9, 0x94, 0x14, 0x85, 0x8f, 0x8d, 0x75, 0xff, 0x7f, 0x64, 0x2c, 0x7c, 0xa6, 0x18, 0x03];
/// psa_crypto::init().unwrap();
/// let hash_alg = Hash::Sha256;
/// hash_compare(hash_alg,
///                      &MESSAGE,
///                      &HASH).unwrap();
/// ```
pub fn hash_compare(hash_alg: Hash, input: &[u8], hash_to_compare: &[u8]) -> Result<()> {
    initialized()?;
    let _lock = LOCK.read();

    Status::from(unsafe {
        psa_crypto_sys::psa_hash_compare(
            hash_alg.into(),
            input.as_ptr(),
            input.len(),
            hash_to_compare.as_ptr(),
            hash_to_compare.len(),
        )
    })
    .to_result()
}
