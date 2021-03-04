// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Asymmetric Encryption operations
//!
//! See the PSA Crypto API for the format of the different parameters used in this module.

use crate::initialized;
use crate::types::algorithm::AsymmetricEncryption;
use crate::types::key::Id;
use crate::types::status::{Result, Status};

/// Encrypt a short message with a key pair or public key
///
/// The encrypted message is written in `ciphertext`. The function returns the number of bytes written.
///
/// # Example
///
/// ```
/// # use psa_crypto::operations::key_management::generate;
/// # use psa_crypto::operations::asym_encryption::encrypt;
/// # use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// # use psa_crypto::types::algorithm::{AsymmetricEncryption, Hash};
/// #
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaKeyPair,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags: UsageFlags {
/// #             encrypt: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: AsymmetricEncryption::RsaPkcs1v15Crypt.into(),
/// #     },
/// # };
/// # const MESSAGE: [u8; 32] = [
/// #     0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
/// #     0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
/// # ];
/// psa_crypto::init().unwrap();
/// let my_key = generate(attributes, None).unwrap();
/// let alg = AsymmetricEncryption::RsaPkcs1v15Crypt;
/// let buffer_size = attributes.asymmetric_encrypt_output_size(alg).unwrap();
/// let mut encrypted_message = vec![0; buffer_size];
///
/// let size = encrypt(my_key,
///                      alg,
///                      &MESSAGE,
///                      None,
///                      &mut encrypted_message).unwrap();
/// encrypted_message.resize(size, 0);
/// ```
pub fn encrypt(
    key_id: Id,
    alg: AsymmetricEncryption,
    plaintext: &[u8],
    salt: Option<&[u8]>,
    ciphertext: &mut [u8],
) -> Result<usize> {
    initialized()?;

    let mut output_length = 0;
    let (salt_ptr, salt_len) = match salt {
        Some(salt) => (salt.as_ptr(), salt.len()),
        None => (core::ptr::null(), 0),
    };

    Status::from(unsafe {
        psa_crypto_sys::psa_asymmetric_encrypt(
            key_id.0,
            alg.into(),
            plaintext.as_ptr(),
            plaintext.len(),
            salt_ptr,
            salt_len,
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &mut output_length,
        )
    })
    .to_result()?;
    Ok(output_length)
}

/// Decrypt a short message with a key pair or private key
///
/// The decrypted message is written in `plaintext`. The function returns the number of bytes written.
///
/// # Example
///
/// ```
/// # use psa_crypto::operations::key_management::{generate, export_public};
/// # use psa_crypto::operations::asym_encryption::decrypt;
/// # use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// # use psa_crypto::types::algorithm::{AsymmetricEncryption, Hash};
/// # use rsa::{RSAPublicKey, PaddingScheme, PublicKey};
/// # use rand::rngs::OsRng;
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaKeyPair,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags: UsageFlags {
/// #             decrypt: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: AsymmetricEncryption::RsaPkcs1v15Crypt.into()
/// #     },
/// # };
/// # const MESSAGE: [u8; 64] = [ 0x4e, 0x31, 0x74, 0x96, 0x8f, 0xe4, 0xba, 0xb3, 0xaf, 0x77, 0x75,
/// # 0x76, 0x61, 0xde, 0xe5, 0xb8, 0x2c, 0x4f, 0x2a, 0x77, 0x6f, 0x2a, 0x86, 0x36, 0x13, 0xc3, 0xd1,
/// # 0x26, 0x77, 0x30, 0x64, 0x9c, 0xb9, 0x95, 0x84, 0x73, 0x54, 0xfd, 0x6d, 0x2f, 0xba, 0x7e, 0x6c,
/// # 0xb5, 0x0a, 0xe1, 0x09, 0x4e, 0x57, 0x3e, 0xeb, 0x7c, 0x64, 0xcc, 0x9d, 0xf2, 0xf2, 0x37, 0x2e,
/// # 0xb1, 0xe9, 0x92, 0xb7, 0x7b];
/// psa_crypto::init().unwrap();
///
/// let key_id = generate(attributes, None).unwrap();
/// let mut pub_key = vec![0; attributes.export_public_key_output_size().unwrap()];
/// let _pub_key_length = export_public(key_id.clone(), &mut pub_key);
/// let rsa_pub_key = RSAPublicKey::from_pkcs1(&pub_key).unwrap();
/// let ciphertext = rsa_pub_key.encrypt(&mut OsRng, PaddingScheme::new_pkcs1v15_encrypt(), &MESSAGE).unwrap();
///
/// let alg = AsymmetricEncryption::RsaPkcs1v15Crypt;
/// let buffer_size = attributes.asymmetric_decrypt_output_size(alg).unwrap();
/// let mut decrypted_message = vec![0; buffer_size];
/// let size = decrypt(key_id,
///                      alg,
///                      &ciphertext,
///                      None,
///                      &mut decrypted_message).unwrap();
/// decrypted_message.resize(size, 0);
/// ```
pub fn decrypt(
    key_id: Id,
    alg: AsymmetricEncryption,
    encrypted_message: &[u8],
    salt: Option<&[u8]>,
    plaintext: &mut [u8],
) -> Result<usize> {
    initialized()?;

    let mut output_length = 0;
    let (salt_ptr, salt_len) = match salt {
        Some(salt) => (salt.as_ptr(), salt.len()),
        None => (core::ptr::null(), 0),
    };

    Status::from(unsafe {
        psa_crypto_sys::psa_asymmetric_decrypt(
            key_id.0,
            alg.into(),
            encrypted_message.as_ptr(),
            encrypted_message.len(),
            salt_ptr,
            salt_len,
            plaintext.as_mut_ptr(),
            plaintext.len(),
            &mut output_length,
        )
    })
    .to_result()?;
    Ok(output_length)
}
