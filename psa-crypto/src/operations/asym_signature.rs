// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Asymmetric Signature operations

use crate::initialized;
use crate::types::algorithm::AsymmetricSignature;
use crate::types::key::Id;
use crate::types::status::{Result, Status};

/// Sign a hash
pub fn sign_hash(
    key: Id,
    alg: AsymmetricSignature,
    hash: &[u8],
    signature: &mut [u8],
) -> Result<usize> {
    initialized()?;

    let mut signature_length = 0;
    let handle = key.handle()?;

    Status::from(unsafe {
        psa_crypto_sys::psa_sign_hash(
            handle,
            alg.into(),
            hash.as_ptr(),
            hash.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_length,
        )
    })
    .to_result()?;

    key.close_handle(handle)?;

    Ok(signature_length)
}

/// Verify a hash
pub fn verify_hash(key: Id, alg: AsymmetricSignature, hash: &[u8], signature: &[u8]) -> Result<()> {
    initialized()?;

    let handle = key.handle()?;

    Status::from(unsafe {
        psa_crypto_sys::psa_verify_hash(
            handle,
            alg.into(),
            hash.as_ptr(),
            hash.len(),
            signature.as_ptr(),
            signature.len(),
        )
    })
    .to_result()?;

    key.close_handle(handle)
}
