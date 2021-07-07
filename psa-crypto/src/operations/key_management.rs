// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Key Management operations

use crate::initialized;
use crate::types::key::{Attributes, Id};
use crate::types::status::{Result, Status};
use core::convert::TryFrom;
#[cfg(feature = "interface")]
use log::error;

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
///
/// psa_crypto::init().unwrap();
/// let _my_key = key_management::generate(attributes, None).unwrap();
/// ```
pub fn generate(attributes: Attributes, id: Option<u32>) -> Result<Id> {
    initialized()?;
    let mut key_attributes = psa_crypto_sys::psa_key_attributes_t::try_from(attributes)?;
    if let Some(id) = id {
        unsafe { psa_crypto_sys::psa_set_key_id(&mut key_attributes, id) };
    }
    let mut id = 0;
    Status::from(unsafe { psa_crypto_sys::psa_generate_key(&key_attributes, &mut id) })
        .to_result()?;
    Attributes::reset(&mut key_attributes);

    Ok(Id(id))
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
/// use psa_crypto::operations::key_management;
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
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
///
/// psa_crypto::init().unwrap();
/// let my_key = key_management::generate(attributes, None).unwrap();
/// // Safe because no other threads is using this ID.
/// unsafe {key_management::destroy(my_key).unwrap() };
/// ```
pub unsafe fn destroy(key: Id) -> Result<()> {
    initialized()?;
    Status::from(psa_crypto_sys::psa_destroy_key(key.0)).to_result()
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
/// # let mut usage_flags: UsageFlags = Default::default();
/// # usage_flags.set_sign_hash().set_verify_hash();
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaPublicKey,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags,
/// #         permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
/// #             hash_alg: Hash::Sha256.into(),
/// #         }.into(),
/// #     },
/// # };
///
/// psa_crypto::init().unwrap();
/// let _my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
/// ```
pub fn import(attributes: Attributes, id: Option<u32>, data: &[u8]) -> Result<Id> {
    initialized()?;

    let mut key_attributes = psa_crypto_sys::psa_key_attributes_t::try_from(attributes)?;
    if let Some(id) = id {
        unsafe { psa_crypto_sys::psa_set_key_id(&mut key_attributes, id) };
    }
    let mut id = 0;

    Status::from(unsafe {
        psa_crypto_sys::psa_import_key(&key_attributes, data.as_ptr(), data.len(), &mut id)
    })
    .to_result()?;

    Attributes::reset(&mut key_attributes);

    Ok(Id(id))
}

/// Export a public key or the public part of a key pair in binary format
///
/// The key is written in `data`. The functions returns the number of bytes written.
/// Please check the PSA Crypto API for a more complete description on the format of `data`.
///
/// # Example
///
/// ```
/// use psa_crypto::operations::key_management;
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
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
/// psa_crypto::init().unwrap();
/// let buffer_size = attributes.export_public_key_output_size().unwrap();
/// let mut data = vec![0; buffer_size];
/// let my_key = key_management::generate(attributes, None).unwrap();
/// let size = key_management::export_public(my_key, &mut data).unwrap();
/// data.resize(size, 0);
/// ```
pub fn export_public(key: Id, data: &mut [u8]) -> Result<usize> {
    initialized()?;
    let mut data_length = 0;

    Status::from(unsafe {
        psa_crypto_sys::psa_export_public_key(
            key.0,
            data.as_mut_ptr(),
            data.len(),
            &mut data_length,
        )
    })
    .to_result()?;
    Ok(data_length)
}

/// Export a key pair in binary format
///
/// The key is written in `data`. The function returns the number of bytes written.
/// Please check the PSA Crypto API for a more complete description on the format of `data`.
///
/// # Example
///
/// ```
/// use psa_crypto::operations::key_management;
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
/// # let mut usage_flags: UsageFlags = Default::default();
/// # usage_flags.set_sign_hash().set_verify_hash().set_export();
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
/// psa_crypto::init().unwrap();
/// let buffer_size = attributes.export_key_output_size().unwrap();
/// let mut data = vec![0; buffer_size];
/// let my_key = key_management::generate(attributes, None).unwrap();
/// let size = key_management::export(my_key, &mut data).unwrap();
/// data.resize(size, 0);
/// ```
pub fn export(key: Id, data: &mut [u8]) -> Result<usize> {
    initialized()?;
    let mut data_length = 0;

    Status::from(unsafe {
        psa_crypto_sys::psa_export_key(key.0, data.as_mut_ptr(), data.len(), &mut data_length)
    })
    .to_result()?;
    Ok(data_length)
}

/// Copy key material from one location to another
/// The function returns the key ID of the newly created key `Id` can be set to `None` when creating a volatile key.
/// When generating a persistent key with a specific ID, the `Id` structure can be created after
/// reset with the `from_persistent_key_id` constructor on `Id`.
///
/// The originating key must have the usage flag `copy` set.
///
/// # Example
///
/// ```
/// use psa_crypto::operations::key_management;
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::types::algorithm::{AsymmetricSignature, Hash, Algorithm};
/// # let key_data = [0x30, 0x82, 0x02, 0x5e, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xaf, 0x05, 0x7d, 0x39, 0x6e, 0xe8, 0x4f, 0xb7, 0x5f, 0xdb, 0xb5, 0xc2, 0xb1, 0x3c, 0x7f, 0xe5, 0xa6, 0x54, 0xaa, 0x8a, 0xa2, 0x47, 0x0b, 0x54, 0x1e, 0xe1, 0xfe, 0xb0, 0xb1, 0x2d, 0x25, 0xc7, 0x97, 0x11, 0x53, 0x12, 0x49, 0xe1, 0x12, 0x96, 0x28, 0x04, 0x2d, 0xbb, 0xb6, 0xc1, 0x20, 0xd1, 0x44, 0x35, 0x24, 0xef, 0x4c, 0x0e, 0x6e, 0x1d, 0x89, 0x56, 0xee, 0xb2, 0x07, 0x7a, 0xf1, 0x23, 0x49, 0xdd, 0xee, 0xe5, 0x44, 0x83, 0xbc, 0x06, 0xc2, 0xc6, 0x19, 0x48, 0xcd, 0x02, 0xb2, 0x02, 0xe7, 0x96, 0xae, 0xbd, 0x94, 0xd3, 0xa7, 0xcb, 0xf8, 0x59, 0xc2, 0xc1, 0x81, 0x9c, 0x32, 0x4c, 0xb8, 0x2b, 0x9c, 0xd3, 0x4e, 0xde, 0x26, 0x3a, 0x2a, 0xbf, 0xfe, 0x47, 0x33, 0xf0, 0x77, 0x86, 0x9e, 0x86, 0x60, 0xf7, 0xd6, 0x83, 0x4d, 0xa5, 0x3d, 0x69, 0x0e, 0xf7, 0x98, 0x5f, 0x6b, 0xc3, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x81, 0x81, 0x00, 0x87, 0x4b, 0xf0, 0xff, 0xc2, 0xf2, 0xa7, 0x1d, 0x14, 0x67, 0x1d, 0xdd, 0x01, 0x71, 0xc9, 0x54, 0xd7, 0xfd, 0xbf, 0x50, 0x28, 0x1e, 0x4f, 0x6d, 0x99, 0xea, 0x0e, 0x1e, 0xbc, 0xf8, 0x2f, 0xaa, 0x58, 0xe7, 0xb5, 0x95, 0xff, 0xb2, 0x93, 0xd1, 0xab, 0xe1, 0x7f, 0x11, 0x0b, 0x37, 0xc4, 0x8c, 0xc0, 0xf3, 0x6c, 0x37, 0xe8, 0x4d, 0x87, 0x66, 0x21, 0xd3, 0x27, 0xf6, 0x4b, 0xbe, 0x08, 0x45, 0x7d, 0x3e, 0xc4, 0x09, 0x8b, 0xa2, 0xfa, 0x0a, 0x31, 0x9f, 0xba, 0x41, 0x1c, 0x28, 0x41, 0xed, 0x7b, 0xe8, 0x31, 0x96, 0xa8, 0xcd, 0xf9, 0xda, 0xa5, 0xd0, 0x06, 0x94, 0xbc, 0x33, 0x5f, 0xc4, 0xc3, 0x22, 0x17, 0xfe, 0x04, 0x88, 0xbc, 0xe9, 0xcb, 0x72, 0x02, 0xe5, 0x94, 0x68, 0xb1, 0xea, 0xd1, 0x19, 0x00, 0x04, 0x77, 0xdb, 0x2c, 0xa7, 0x97, 0xfa, 0xc1, 0x9e, 0xda, 0x3f, 0x58, 0xc1, 0x02, 0x41, 0x00, 0xe2, 0xab, 0x76, 0x08, 0x41, 0xbb, 0x9d, 0x30, 0xa8, 0x1d, 0x22, 0x2d, 0xe1, 0xeb, 0x73, 0x81, 0xd8, 0x22, 0x14, 0x40, 0x7f, 0x1b, 0x97, 0x5c, 0xbb, 0xfe, 0x4e, 0x1a, 0x94, 0x67, 0xfd, 0x98, 0xad, 0xbd, 0x78, 0xf6, 0x07, 0x83, 0x6c, 0xa5, 0xbe, 0x19, 0x28, 0xb9, 0xd1, 0x60, 0xd9, 0x7f, 0xd4, 0x5c, 0x12, 0xd6, 0xb5, 0x2e, 0x2c, 0x98, 0x71, 0xa1, 0x74, 0xc6, 0x6b, 0x48, 0x81, 0x13, 0x02, 0x41, 0x00, 0xc5, 0xab, 0x27, 0x60, 0x21, 0x59, 0xae, 0x7d, 0x6f, 0x20, 0xc3, 0xc2, 0xee, 0x85, 0x1e, 0x46, 0xdc, 0x11, 0x2e, 0x68, 0x9e, 0x28, 0xd5, 0xfc, 0xbb, 0xf9, 0x90, 0xa9, 0x9e, 0xf8, 0xa9, 0x0b, 0x8b, 0xb4, 0x4f, 0xd3, 0x64, 0x67, 0xe7, 0xfc, 0x17, 0x89, 0xce, 0xb6, 0x63, 0xab, 0xda, 0x33, 0x86, 0x52, 0xc3, 0xc7, 0x3f, 0x11, 0x17, 0x74, 0x90, 0x2e, 0x84, 0x05, 0x65, 0x92, 0x70, 0x91, 0x02, 0x41, 0x00, 0xb6, 0xcd, 0xbd, 0x35, 0x4f, 0x7d, 0xf5, 0x79, 0xa6, 0x3b, 0x48, 0xb3, 0x64, 0x3e, 0x35, 0x3b, 0x84, 0x89, 0x87, 0x77, 0xb4, 0x8b, 0x15, 0xf9, 0x4e, 0x0b, 0xfc, 0x05, 0x67, 0xa6, 0xae, 0x59, 0x11, 0xd5, 0x7a, 0xd6, 0x40, 0x9c, 0xf7, 0x64, 0x7b, 0xf9, 0x62, 0x64, 0xe9, 0xbd, 0x87, 0xeb, 0x95, 0xe2, 0x63, 0xb7, 0x11, 0x0b, 0x9a, 0x1f, 0x9f, 0x94, 0xac, 0xce, 0xd0, 0xfa, 0xfa, 0x4d, 0x02, 0x40, 0x71, 0x19, 0x5e, 0xec, 0x37, 0xe8, 0xd2, 0x57, 0xde, 0xcf, 0xc6, 0x72, 0xb0, 0x7a, 0xe6, 0x39, 0xf1, 0x0c, 0xbb, 0x9b, 0x0c, 0x73, 0x9d, 0x0c, 0x80, 0x99, 0x68, 0xd6, 0x44, 0xa9, 0x4e, 0x3f, 0xd6, 0xed, 0x92, 0x87, 0x07, 0x7a, 0x14, 0x58, 0x3f, 0x37, 0x90, 0x58, 0xf7, 0x6a, 0x8a, 0xec, 0xd4, 0x3c, 0x62, 0xdc, 0x8c, 0x0f, 0x41, 0x76, 0x66, 0x50, 0xd7, 0x25, 0x27, 0x5a, 0xc4, 0xa1, 0x02, 0x41, 0x00, 0xbb, 0x32, 0xd1, 0x33, 0xed, 0xc2, 0xe0, 0x48, 0xd4, 0x63, 0x38, 0x8b, 0x7b, 0xe9, 0xcb, 0x4b, 0xe2, 0x9f, 0x4b, 0x62, 0x50, 0xbe, 0x60, 0x3e, 0x70, 0xe3, 0x64, 0x75, 0x01, 0xc9, 0x7d, 0xdd, 0xe2, 0x0a, 0x4e, 0x71, 0xbe, 0x95, 0xfd, 0x5e, 0x71, 0x78, 0x4e, 0x25, 0xac, 0xa4, 0xba, 0xf2, 0x5b, 0xe5, 0x73, 0x8a, 0xae, 0x59, 0xbb, 0xfe, 0x1c, 0x99, 0x77, 0x81, 0x44, 0x7a, 0x2b, 0x24];
/// # let mut usage_flags: UsageFlags = Default::default();
/// # usage_flags.set_copy().set_export();
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaKeyPair,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags,
/// #         permitted_algorithms: Algorithm::None,
/// #     },
/// # };
/// psa_crypto::init().unwrap();
/// let my_key = key_management::import(attributes, None, &key_data).unwrap();
/// let my_key_copy = key_management::copy(my_key, attributes, None).unwrap();
/// ```
pub fn copy(key_id_to_copy: Id, attributes: Attributes, id: Option<u32>) -> Result<Id> {
    initialized()?;
    let mut key_attributes = psa_crypto_sys::psa_key_attributes_t::try_from(attributes)?;
    if let Some(id) = id {
        unsafe { psa_crypto_sys::psa_set_key_id(&mut key_attributes, id) };
    }

    let mut new_id = 0;
    let copy_res = Status::from(unsafe {
        psa_crypto_sys::psa_copy_key(key_id_to_copy.0, &key_attributes, &mut new_id)
    })
    .to_result();
    Attributes::reset(&mut key_attributes);
    copy_res?;

    Ok(Id(new_id))
}

/// Remove non-essential copies of key material from memory
///
/// This function will remove these extra copies of the key material from memory.
///
/// This function is not required to remove key material from memory in any of the following situations:
///     The key is currently in use in a cryptographic operation.
///     The key is volatile.
///
/// # Example
///
/// ```
/// use psa_crypto::operations::key_management;
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
/// # let mut usage_flags: UsageFlags = Default::default();
/// # usage_flags.set_cache();
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
/// psa_crypto::init().unwrap();
/// //let my_key = key_management::generate(attributes, None).unwrap();
/// //let size = key_management::purge(my_key).unwrap();
/// ```
pub fn purge(/*key_id: Id*/) /*-> Result<()>*/
{
    error!("This operation is not yet supported by Mbed Crypto. Once it is supported, uncomment and remove this notice");
    // Also uncomment the example
    /*initialized()?;
    let handle = key_id.handle()?;
    let purge_res = Status::from(psa_crypto_sys::psa_purge_key(handle)).to_result()
    let close_handle_res = key_id.close_handle(handle);
    purge_res?;
    close_handle_res*/
}
