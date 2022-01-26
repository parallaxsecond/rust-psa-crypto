// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Asymmetric Signature operations
//!
//! See the PSA Crypto API for the format of the different parameters used in this module.

use crate::initialized;
use crate::types::algorithm::AsymmetricSignature;
use crate::types::key::Id;
use crate::types::status::{Result, Status};
use crate::LOCK;

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
/// # let mut usage_flags: UsageFlags = Default::default();
/// # usage_flags.set_sign_hash().set_verify_hash();
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaKeyPair,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags,
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
/// let my_key = generate(attributes, None).unwrap();
/// let alg = AsymmetricSignature::RsaPkcs1v15Sign {
///                          hash_alg: Hash::Sha256.into(),
///                      };
/// let buffer_size = attributes.sign_output_size(alg).unwrap();
/// let mut signature = vec![0; buffer_size];
///
/// let size = sign_hash(my_key,
///                      alg,
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
    let _lock = LOCK.read();

    let mut signature_length = 0;

    Status::from(unsafe {
        psa_crypto_sys::psa_sign_hash(
            key.0,
            alg.into(),
            hash.as_ptr(),
            hash.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_length,
        )
    })
    .to_result()?;
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
/// # let mut usage_flags: UsageFlags = Default::default();
/// # usage_flags.set_sign_hash().set_verify_hash();
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaKeyPair,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags,
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
/// let alg = AsymmetricSignature::RsaPkcs1v15Sign {
///     hash_alg: Hash::Sha256.into(),
/// };
/// let buffer_size = attributes.sign_output_size(alg).unwrap();
/// let mut signature = vec![0; buffer_size];
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
    let _lock = LOCK.read();

    Status::from(unsafe {
        psa_crypto_sys::psa_verify_hash(
            key.0,
            alg.into(),
            hash.as_ptr(),
            hash.len(),
            signature.as_ptr(),
            signature.len(),
        )
    })
    .to_result()
}
