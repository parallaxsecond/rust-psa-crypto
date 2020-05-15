// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Asymmetric Signature operations

use crate::initialized;
use crate::types::algorithm::{Algorithm, AsymmetricSignature};
use crate::types::key::Id;
use crate::types::status::{status_to_result, Result};

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

    status_to_result(unsafe {
        psa_crypto_sys::psa_asymmetric_sign(
            handle,
            Algorithm::from(alg).into(),
            hash.as_ptr(),
            hash.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_length,
        )
    })?;

    key.close_handle(handle)?;

    Ok(signature_length)
}

/// Verify a hash
pub fn verify_hash(key: Id, alg: AsymmetricSignature, hash: &[u8], signature: &[u8]) -> Result<()> {
    initialized()?;

    let handle = key.handle()?;

    status_to_result(unsafe {
        psa_crypto_sys::psa_asymmetric_verify(
            handle,
            Algorithm::from(alg).into(),
            hash.as_ptr(),
            hash.len(),
            signature.as_ptr(),
            signature.len(),
        )
    })?;

    key.close_handle(handle)
}
