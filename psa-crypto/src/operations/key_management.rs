// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Key Management operations

use crate::initialized;
use crate::types::key::{Attributes, Id};
use crate::types::status::{status_to_result, Result};

/// Generate a key
pub fn generate_key(attributes: Attributes, id: Option<u32>) -> Result<Id> {
    initialized()?;

    let mut attributes = psa_crypto_sys::psa_key_attributes_t::from(attributes);
    let id = if let Some(id) = id {
        unsafe { psa_crypto_sys::psa_set_key_id(&mut attributes, id) };
        id
    } else {
        0
    };
    let mut handle = 0;

    status_to_result(unsafe { psa_crypto_sys::psa_generate_key(&attributes, &mut handle) })?;

    unsafe { psa_crypto_sys::psa_reset_key_attributes(&mut attributes) };

    Ok(Id {
        id,
        handle: Some(handle),
    })
}

/// Destroy a key
///
/// # Safety
///
/// blablabla
pub unsafe fn destroy_key(key: Id) -> Result<()> {
    initialized()?;
    let handle = key.handle()?;
    status_to_result(psa_crypto_sys::psa_destroy_key(handle))?;
    key.close_handle(handle)
}

/// Import a key
pub fn import_key(attributes: Attributes, id: Option<u32>, data: &[u8]) -> Result<Id> {
    initialized()?;

    let mut attributes = psa_crypto_sys::psa_key_attributes_t::from(attributes);
    let id = if let Some(id) = id {
        unsafe { psa_crypto_sys::psa_set_key_id(&mut attributes, id) };
        id
    } else {
        0
    };
    let mut handle = 0;

    status_to_result(unsafe {
        psa_crypto_sys::psa_import_key(&attributes, data.as_ptr(), data.len(), &mut handle)
    })?;

    unsafe { psa_crypto_sys::psa_reset_key_attributes(&mut attributes) };

    Ok(Id {
        id,
        handle: Some(handle),
    })
}

/// Export a public key
pub fn export_public_key(key: Id, data: &mut [u8]) -> Result<usize> {
    initialized()?;
    let handle = key.handle()?;
    let mut data_length = 0;

    status_to_result(unsafe {
        psa_crypto_sys::psa_export_public_key(
            handle,
            data.as_mut_ptr(),
            data.len(),
            &mut data_length,
        )
    })?;

    key.close_handle(handle)?;

    Ok(data_length)
}
