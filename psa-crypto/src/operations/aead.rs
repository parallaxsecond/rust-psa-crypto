// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Authenticated Encryption with Associated Data (AEAD) operations
//!
//! See the PSA Crypto API for the format of the different parameters used in this module.

use crate::initialized;
use crate::types::algorithm::Aead;
use crate::types::key::Id;
use crate::types::status::{Result, Status};

/// Process an authenticated encryption operation.
/// # Example
///
/// ```
/// use psa_crypto::types::algorithm::{Aead, AeadWithDefaultLengthTag};
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::operations::{key_management, aead};
/// # const KEY_DATA: [u8; 16] = [0x41, 0x89, 0x35, 0x1B, 0x5C, 0xAE, 0xA3, 0x75, 0xA0, 0x29, 0x9E, 0x81, 0xC6, 0x21, 0xBF, 0x43];
/// # const NONCE: [u8; 13] = [0x48, 0xc0, 0x90, 0x69, 0x30, 0x56, 0x1e, 0x0a, 0xb0, 0xef, 0x4c, 0xd9, 0x72];
/// # const ADDITIONAL_DATA: [u8; 32] = [0x40, 0xa2, 0x7c, 0x1d, 0x1e, 0x23, 0xea, 0x3d, 0xbe, 0x80, 0x56, 0xb2,
/// # 0x77, 0x48, 0x61, 0xa4, 0xa2, 0x01, 0xcc, 0xe4, 0x9f, 0x19, 0x99, 0x7d, 0x19, 0x20, 0x6d, 0x8c, 0x8a, 0x34, 0x39, 0x51];
/// # const INPUT_DATA: [u8; 24] = [0x45, 0x35, 0xd1, 0x2b, 0x43, 0x77, 0x92, 0x8a, 0x7c, 0x0a, 0x61, 0xc9, 0xf8, 0x25, 0xa4, 0x86,
/// # 0x71, 0xea, 0x05, 0x91, 0x07, 0x48, 0xc8, 0xef];
/// let alg = Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm);
/// let attributes = Attributes {
/// key_type: Type::Aes,
///      bits: 0,
///      lifetime: Lifetime::Volatile,
///      policy: Policy {
///          usage_flags: UsageFlags {
///              encrypt: true,
///              ..Default::default()
///          },
///          permitted_algorithms: alg.into(),
///      },
/// };
/// psa_crypto::init().unwrap();
/// let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
/// let output_buffer_size = attributes.aead_encrypt_output_size(alg.into(), INPUT_DATA.len()).unwrap();
/// let mut output_buffer = vec![0; output_buffer_size];
/// let length = aead::encrypt(my_key, alg, &NONCE, &ADDITIONAL_DATA, &INPUT_DATA, &mut output_buffer).unwrap();
/// output_buffer.resize(length, 0);
/// ```
pub fn encrypt(
    key_id: Id,
    aead_alg: Aead,
    nonce: &[u8],
    additional_data: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<usize> {
    initialized()?;

    let mut ciphertext_size = 0;
    Status::from(unsafe {
        psa_crypto_sys::psa_aead_encrypt(
            key_id.0,
            aead_alg.into(),
            nonce.as_ptr(),
            nonce.len(),
            additional_data.as_ptr(),
            additional_data.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &mut ciphertext_size,
        )
    })
    .to_result()?;
    Ok(ciphertext_size)
}

/// Process an authenticated decryption operation.
/// # Example
///
/// ```
/// use psa_crypto::types::algorithm::{Aead, AeadWithDefaultLengthTag};
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::operations::{key_management, aead};
/// # const KEY_DATA: [u8; 16] = [0x41, 0x89, 0x35, 0x1B, 0x5C, 0xAE, 0xA3, 0x75, 0xA0, 0x29, 0x9E, 0x81, 0xC6, 0x21, 0xBF, 0x43];
/// # const NONCE: [u8; 13] = [0x48, 0xc0, 0x90, 0x69, 0x30, 0x56, 0x1e, 0x0a, 0xb0, 0xef, 0x4c, 0xd9, 0x72];
/// # const ADDITIONAL_DATA: [u8; 32] = [0x40, 0xa2, 0x7c, 0x1d, 0x1e, 0x23, 0xea, 0x3d, 0xbe, 0x80, 0x56, 0xb2,
/// # 0x77, 0x48, 0x61, 0xa4, 0xa2, 0x01, 0xcc, 0xe4, 0x9f, 0x19, 0x99, 0x7d, 0x19, 0x20, 0x6d, 0x8c, 0x8a, 0x34, 0x39, 0x51];
/// # const INPUT_DATA: [u8; 40] = [0x26, 0xc5, 0x69, 0x61, 0xc0, 0x35, 0xa7, 0xe4, 0x52, 0xcc, 0xe6, 0x1b, 0xc6, 0xee, 0x22, 0x0d,
/// # 0x77, 0xb3, 0xf9, 0x4d, 0x18, 0xfd, 0x10, 0xb6, 0xd8, 0x0e, 0x8b, 0xf8, 0x0f, 0x4a, 0x46, 0xca, 0xb0, 0x6d, 0x43, 0x13, 0xf0, 0xdb, 0x9b, 0xe9];
/// let alg = Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm);
/// let attributes = Attributes {
/// key_type: Type::Aes,
///      bits: 0,
///      lifetime: Lifetime::Volatile,
///      policy: Policy {
///          usage_flags: UsageFlags {
///              decrypt: true,
///              ..Default::default()
///          },
///          permitted_algorithms: alg.into(),
///      },
/// };
/// psa_crypto::init().unwrap();
/// let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
/// let output_buffer_size = attributes.aead_decrypt_output_size(alg.into(), INPUT_DATA.len()).unwrap();
/// let mut output_buffer = vec![0; output_buffer_size];
/// let length = aead::decrypt(my_key, alg, &NONCE, &ADDITIONAL_DATA, &INPUT_DATA, &mut output_buffer).unwrap();
/// output_buffer.resize(length, 0);
/// ```
pub fn decrypt(
    key_id: Id,
    aead_alg: Aead,
    nonce: &[u8],
    additional_data: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<usize> {
    initialized()?;

    let mut plaintext_size = 0;

    Status::from(unsafe {
        psa_crypto_sys::psa_aead_decrypt(
            key_id.0,
            aead_alg.into(),
            nonce.as_ptr(),
            nonce.len(),
            additional_data.as_ptr(),
            additional_data.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
            &mut plaintext_size,
        )
    })
    .to_result()?;
    Ok(plaintext_size)
}
