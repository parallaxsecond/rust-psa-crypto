// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Key Management operations

use crate::initialized;
use crate::types::key::{Attributes, Id, Lifetime};
use crate::types::status::{Result, Status};
use core::convert::TryFrom;
use psa_crypto_sys::{psa_key_handle_t, psa_key_id_t};

/// Generate a key or a key pair
///
/// `id` can be set to `None` when creating a volatile key. Setting the `id` to something will
/// override the `lifetime` field of the attributes to `Lifetime::Persistent`.
/// When generating a persistent key with a
/// specific ID, the `Id` structure can be created after reset with the `from_persistent_key_id`
/// constructor on `Id`.
/// The `Id` structure returned can be used for cryptographic operations using that key.
///
/// # Example
///
/// ```
/// use psa_crypto::operations::key_management;
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
///
/// let mut attributes = Attributes {
///     key_type: Type::RsaKeyPair,
///     bits: 1024,
///     lifetime: Lifetime::Volatile,
///     policy: Policy {
///         usage_flags: UsageFlags {
///             sign_hash: true,
///             sign_message: true,
///             verify_hash: true,
///             verify_message: true,
///             ..Default::default()
///         },
///         permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
///             hash_alg: Hash::Sha256.into(),
///         }.into(),
///     },
/// };
///
/// psa_crypto::init().unwrap();
/// let _my_key = key_management::generate(attributes, None).unwrap();
/// ```
pub fn generate(attributes: Attributes, id: Option<u32>) -> Result<Id> {
    initialized()?;
    let mut key_attributes = psa_crypto_sys::psa_key_attributes_t::try_from(attributes)?;
    let id = if let Some(id) = id {
        unsafe { psa_crypto_sys::psa_set_key_id(&mut key_attributes, id) };
        id
    } else {
        0
    };
    let mut handle = 0;
    Status::from(unsafe { psa_crypto_sys::psa_generate_key(&key_attributes, &mut handle) })
        .to_result()?;
    Attributes::reset(&mut key_attributes);

    complete_new_key_operation(attributes.lifetime, id, handle)
}

/// Destroy a key
///
/// # Safety
///
/// It is unsafe to destroy a key that is concurrently used for any cryptographic operation. This
/// crate does not currently provide a mechanism to ensure thread safety of `destroy_key` but might
/// do in the future.
/// It is undefined behaviour to concurrently destroy and use a key.
///
/// This function can be safely called if the caller ensures that no other threads are concurrently
/// using copies of the same `Id` (that includes different `Id` instances that were created using
/// the same `id` parameter with the `from_persistent_key_id` function).
///
/// # Example
///
/// ```
/// # use psa_crypto::operations::key_management;
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
///
/// psa_crypto::init().unwrap();
/// let my_key = key_management::generate(attributes, None).unwrap();
/// // Safe because no other threads is using this ID.
/// unsafe {key_management::destroy(my_key).unwrap() };
/// ```
pub unsafe fn destroy(key: Id) -> Result<()> {
    initialized()?;
    let handle = key.handle()?;
    Status::from(psa_crypto_sys::psa_destroy_key(handle)).to_result()
}

/// Import a key in binary format
///
/// `id` can be set to `None` when creating a volatile key. Setting the `id` to something will
/// override the `lifetime` field of the attributes to `Lifetime::Persistent`.
/// When generating a persistent key with a specific ID, the `Id` structure can be created after
/// reset with the `from_persistent_key_id` constructor on `Id`.  Please check the PSA Crypto API
/// for a more complete description on the format expected in `data`.  The `Id` structure returned
/// can be used for cryptographic operations using that key.
///
/// # Example
///
/// ```
/// # const KEY_DATA: [u8; 140] = [
/// #     48, 129, 137, 2, 129, 129, 0, 153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247, 20, 102,
/// #     253, 217, 247, 246, 142, 107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109, 16, 81, 135, 72,
/// #     112, 132, 150, 175, 128, 173, 182, 122, 227, 214, 196, 130, 54, 239, 93, 5, 203, 185, 233, 61,
/// #     159, 156, 7, 161, 87, 48, 234, 105, 161, 108, 215, 211, 150, 168, 156, 212, 6, 63, 81, 24, 101,
/// #     72, 160, 97, 243, 142, 86, 10, 160, 122, 8, 228, 178, 252, 35, 209, 222, 228, 16, 143, 99, 143,
/// #     146, 241, 186, 187, 22, 209, 86, 141, 24, 159, 12, 146, 44, 111, 254, 183, 54, 229, 109, 28,
/// #     39, 22, 141, 173, 85, 26, 58, 9, 128, 27, 57, 131, 2, 3, 1, 0, 1,
/// # ];
/// use psa_crypto::operations::key_management;
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
///
/// let mut attributes = Attributes {
///     key_type: Type::RsaPublicKey,
///     bits: 1024,
///     lifetime: Lifetime::Volatile,
///     policy: Policy {
///         usage_flags: UsageFlags {
///             sign_hash: true,
///             sign_message: true,
///             verify_hash: true,
///             verify_message: true,
///             ..Default::default()
///         },
///         permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
///             hash_alg: Hash::Sha256.into(),
///         }.into(),
///     },
/// };
///
/// psa_crypto::init().unwrap();
/// let _my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
/// ```
pub fn import(attributes: Attributes, id: Option<u32>, data: &[u8]) -> Result<Id> {
    initialized()?;

    let mut key_attributes = psa_crypto_sys::psa_key_attributes_t::try_from(attributes)?;
    let id = if let Some(id) = id {
        unsafe { psa_crypto_sys::psa_set_key_id(&mut key_attributes, id) };
        id
    } else {
        0
    };
    let mut handle = 0;

    Status::from(unsafe {
        psa_crypto_sys::psa_import_key(&key_attributes, data.as_ptr(), data.len(), &mut handle)
    })
    .to_result()?;

    Attributes::reset(&mut key_attributes);

    complete_new_key_operation(attributes.lifetime, id, handle)
}

/// Export a public key or the public part of a key pair in binary format
///
/// The key is written in `data`. The functions returns the number of bytes written.
/// Please check the PSA Crypto API for a more complete description on the format of `data`.
///
/// # Example
///
/// ```
/// # use psa_crypto::operations::key_management;
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
/// psa_crypto::init().unwrap();
/// let buffer_size = attributes.export_public_key_output_size().unwrap();
/// let mut data = vec![0; buffer_size];
/// let my_key = key_management::generate(attributes, None).unwrap();
/// let size = key_management::export_public(my_key, &mut data).unwrap();
/// data.resize(size, 0);
/// ```
pub fn export_public(key: Id, data: &mut [u8]) -> Result<usize> {
    initialized()?;
    let handle = key.handle()?;
    let mut data_length = 0;

    let export_res = Status::from(unsafe {
        psa_crypto_sys::psa_export_public_key(
            handle,
            data.as_mut_ptr(),
            data.len(),
            &mut data_length,
        )
    })
    .to_result();
    let handle_close_res = key.close_handle(handle);
    export_res?;
    handle_close_res?;
    Ok(data_length)
}

/// Export a key pair in binary format
///
/// The key is written in `data`. The functions returns the number of bytes written.
/// Please check the PSA Crypto API for a more complete description on the format of `data`.
///
/// # Example
///
/// ```
/// # use psa_crypto::operations::key_management;
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
/// #             export: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
/// #             hash_alg: Hash::Sha256.into(),
/// #         }.into(),
/// #     },
/// # };
/// psa_crypto::init().unwrap();
/// let buffer_size = attributes.export_key_output_size().unwrap();
/// let mut data = vec![0; buffer_size];
/// let my_key = key_management::generate(attributes, None).unwrap();
/// let size = key_management::export_key(my_key, &mut data).unwrap();
/// data.resize(size, 0);
/// ```
pub fn export_key(key: Id, data: &mut [u8]) -> Result<usize> {
    initialized()?;
    let handle = key.handle()?;
    let mut data_length = 0;

    let export_res = Status::from(unsafe {
        psa_crypto_sys::psa_export_key(handle, data.as_mut_ptr(), data.len(), &mut data_length)
    })
    .to_result();
    let handle_close_res = key.close_handle(handle);
    export_res?;
    handle_close_res?;
    Ok(data_length)
}

/// Completes a new key operation (either generate or import)
///
/// If key is not `Volatile` (`Persistent` or `Custom(u32)`), handle is closed.
///
/// If a key is `Volatile`, `Id` returned contains the key `handle`. Otherwise, it does not.
fn complete_new_key_operation(
    key_lifetime: Lifetime,
    id: psa_key_id_t,
    handle: psa_key_handle_t,
) -> Result<Id> {
    if key_lifetime != Lifetime::Volatile {
        Status::from(unsafe { psa_crypto_sys::psa_close_key(handle) }).to_result()?;
    }
    Ok(Id {
        id,
        handle: if key_lifetime == Lifetime::Volatile {
            Some(handle)
        } else {
            None
        },
    })
}
