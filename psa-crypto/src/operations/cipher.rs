// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Unauthenticated Ciphers operations

use crate::initialized;
use crate::types::algorithm::Cipher;
use crate::types::key::Id;
use crate::types::status::{Result, Status};

fn crypt(
    encrypt: bool,
    key_id: Id,
    alg: Cipher,
    plaintext: &[u8],
    iv: &[u8],
    ciphertext: &mut [u8],
) -> Result<usize> {
    initialized()?;

    let mut operation: psa_crypto_sys::psa_cipher_operation_t =
        unsafe { psa_crypto_sys::psa_cipher_operation_init() };

    Status::from(unsafe {
        (if encrypt {
            psa_crypto_sys::psa_cipher_encrypt_setup
        } else {
            psa_crypto_sys::psa_cipher_decrypt_setup
        })(&mut operation, key_id.0, alg.into())
    })
    .to_result()?;

    let mut output_length = 0;
    let mut output_length_finish = 0;
    let mut inner_crypt = || {
        Status::from(unsafe {
            psa_crypto_sys::psa_cipher_set_iv(&mut operation, iv.as_ptr(), iv.len())
        })
        .to_result()?;

        Status::from(unsafe {
            psa_crypto_sys::psa_cipher_update(
                &mut operation,
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
                &mut output_length,
            )
        })
        .to_result()?;

        Status::from(unsafe {
            psa_crypto_sys::psa_cipher_finish(
                &mut operation,
                ciphertext.as_mut_ptr().add(output_length),
                ciphertext.len() - output_length,
                &mut output_length_finish,
            )
        })
        .to_result()?;

        Ok(())
    };
    match inner_crypt() {
        Ok(()) => (),
        Err(x) => {
            Status::from(unsafe { psa_crypto_sys::psa_cipher_abort(&mut operation) })
                .to_result()?;
            return Err(x);
        }
    }

    Ok(output_length + output_length_finish)
}

/// Encrypt a short message with a key
///
/// The encrypted message is written in `ciphertext`. The function returns the number of bytes written.
///
/// # Example
///
/// ```
/// # use psa_crypto::operations::cipher::encrypt;
/// # use psa_crypto::operations::key_management::generate;
/// # use psa_crypto::types::algorithm::Cipher;
/// # use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// #
/// # let mut usage_flags: UsageFlags = Default::default();
/// # usage_flags.set_encrypt();
/// # let mut attributes = Attributes {
/// #     key_type: Type::Aes,
/// #     bits: 128,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags,
/// #         permitted_algorithms: Cipher::CbcNoPadding.into(),
/// #     },
/// # };
/// # const MESSAGE: [u8; 16] = [0; 16];
/// psa_crypto::init().unwrap();
/// let my_key = generate(attributes, None).unwrap();
/// let alg = Cipher::CbcNoPadding;
/// let iv = vec![0; 16];
/// let mut encrypted_message = vec![0; MESSAGE.len()];
///
/// let size = encrypt(my_key, alg, &MESSAGE, &iv, &mut encrypted_message).unwrap();
/// ```
pub fn encrypt(
    key_id: Id,
    alg: Cipher,
    plaintext: &[u8],
    iv: &[u8],
    ciphertext: &mut [u8],
) -> Result<usize> {
    crypt(true, key_id, alg, plaintext, iv, ciphertext)
}

/// Decrypt a short message with a key
///
/// The decrypted message is written in `plaintext`. The function returns the number of bytes written.
///
/// # Example
///
/// ```
/// # use psa_crypto::operations::cipher::decrypt;
/// # use psa_crypto::operations::key_management::generate;
/// # use psa_crypto::types::algorithm::Cipher;
/// # use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// #
/// # let mut usage_flags: UsageFlags = Default::default();
/// # usage_flags.set_decrypt();
/// # let mut attributes = Attributes {
/// #     key_type: Type::Aes,
/// #     bits: 128,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags,
/// #         permitted_algorithms: Cipher::Ctr.into(),
/// #     },
/// # };
/// # const MESSAGE: [u8; 13] = [0; 13];
/// psa_crypto::init().unwrap();
/// let my_key = generate(attributes, None).unwrap();
/// let alg = Cipher::Ctr;
/// let iv = vec![0; 16];
/// let mut decrypted_message = vec![0; MESSAGE.len()];
///
/// let size = decrypt(my_key, alg, &MESSAGE, &iv, &mut decrypted_message).unwrap();
/// ```
pub fn decrypt(
    key_id: Id,
    alg: Cipher,
    ciphertext: &[u8],
    iv: &[u8],
    plaintext: &mut [u8],
) -> Result<usize> {
    crypt(false, key_id, alg, ciphertext, iv, plaintext)
}
