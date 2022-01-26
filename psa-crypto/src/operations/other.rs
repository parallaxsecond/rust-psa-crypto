// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Other cryptographic services
//!
//! See the PSA Crypto API for the format of the different parameters used in this module.

use crate::initialized;
use crate::types::status::{Result, Status};
use crate::LOCK;

/// Generate a buffer of random bytes.
///
/// The random bytes are written into `output`. The function returns a result based on whether the
/// operation succeeded or failed.
///
/// Example:
///
/// ```
/// use psa_crypto::operations::other::generate_random;
///
/// psa_crypto::init().unwrap();
/// const BUFFER_SIZE: usize = 16;
/// let mut buffer = vec![0u8; BUFFER_SIZE];
/// let result = generate_random(&mut buffer);
/// ```
pub fn generate_random(output: &mut [u8]) -> Result<()> {
    initialized()?;
    let _lock = LOCK.read();

    Status::from(unsafe { psa_crypto_sys::psa_generate_random(output.as_mut_ptr(), output.len()) })
        .to_result()?;

    Ok(())
}
