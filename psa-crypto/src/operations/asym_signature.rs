// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Asymmetric Signature operations
//!
//! See the PSA Crypto API for the format of the different parameters used in this module.

use crate::initialized;
use crate::types::algorithm::AsymmetricSignature;
use crate::types::key::Id;
use crate::types::status::{Result, Status};

/// Sign an already-calculated hash with a private key
///
/// The signature is written in `signature`. The function returns the number of bytes written.
///
/// # Example
///
/// ```
/// # use psa_crypto::operations::key_management::generate;
/// # use psa_crypto::operations::asym_signature::sign_hash;
/// # use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// # use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaKeyPair,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags: UsageFlags {
/// #             sign_hash: true,
/// #             sign_message: true,
/// #             verify_hash: true,
/// #             verify_message: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
/// #             hash_alg: Hash::Sha256.into(),
/// #         }.into(),
/// #     },
/// # };
/// # const HASH: [u8; 32] = [
/// #     0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
/// #     0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
/// # ];
/// psa_crypto::init().unwrap();
/// let mut signature = vec![0; 256];
/// let my_key = generate(attributes, None).unwrap();
/// let size = sign_hash(my_key,
///                      AsymmetricSignature::RsaPkcs1v15Sign {
///                          hash_alg: Hash::Sha256.into(),
///                      },
///                      &HASH,
///                      &mut signature).unwrap();
/// signature.resize(size, 0);
/// ```
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

/// Verify the signature of a hash or short message using a public key
///
/// # Example
///
/// ```
/// # use psa_crypto::operations::key_management::generate;
/// # use psa_crypto::operations::asym_signature::{sign_hash, verify_hash};
/// # use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// # use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaKeyPair,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags: UsageFlags {
/// #             sign_hash: true,
/// #             sign_message: true,
/// #             verify_hash: true,
/// #             verify_message: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
/// #             hash_alg: Hash::Sha256.into(),
/// #         }.into(),
/// #     },
/// # };
/// # const HASH: [u8; 32] = [
/// #     0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
/// #     0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
/// # ];
/// psa_crypto::init().unwrap();
/// let mut signature = vec![0; 256];
/// let alg = AsymmetricSignature::RsaPkcs1v15Sign {
///     hash_alg: Hash::Sha256.into(),
/// };
/// let my_key = generate(attributes, None).unwrap();
/// let size = sign_hash(my_key,
///                      alg,
///                      &HASH,
///                      &mut signature).unwrap();
/// signature.resize(size, 0);
/// verify_hash(my_key, alg, &HASH, &signature).unwrap();
/// ```
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
