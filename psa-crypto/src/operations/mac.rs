// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Message Authentication Code (MAC) operations

use crate::initialized;
use crate::types::key::Id;
use crate::types::algorithm::Mac;
use crate::types::status::{Result, Status, Error};


/// Calculate the message authentication code (MAC) of a message
/// The key must allow `sign_message`
///
/// # Example
///
/// ```
/// use psa_crypto::operations::{mac::compute_mac, key_management::generate};
/// use psa_crypto::types::algorithm::{Hash, Mac, FullLengthMac};
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// # const MESSAGE: [u8; 32] = [
/// #     0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
/// #     0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
/// # ];
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaKeyPair,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags: UsageFlags {
/// #             sign_message: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: FullLengthMac::Hmac{hash_alg: Hash::Sha256}.into(),
/// #     },
/// # };
/// #
/// psa_crypto::init().unwrap();
/// let my_key = generate(attributes, None).unwrap();
/// let mac_alg = Mac::FullLength(FullLengthMac::Hmac{hash_alg: Hash::Sha256});
/// let buffer_size = attributes.mac_length(mac_alg).unwrap();
/// let mut mac = vec![0; buffer_size];
///
/// let size = compute_mac(my_key,
///                     mac_alg,
///                      &MESSAGE,
///                      &mut mac).unwrap();
/// mac.resize(size, 0);
/// ```
pub fn compute_mac(key_id: Id, mac_alg: Mac, input_message: &[u8], mac: &mut [u8]) -> Result<usize> {
    initialized()?;

    let mut output_length = 0;
    let key_handle = key_id.handle()?;

    let mac_compute_res = Status::from(unsafe {
        psa_crypto_sys::psa_mac_compute(
            key_handle,
            mac_alg.into(),
            input_message.as_ptr(),
            input_message.len(),
            mac.as_mut_ptr(),
            mac.len(),
            &mut output_length,
        )}
    ).to_result();
    let close_handle_res = key_id.close_handle(key_handle);
    mac_compute_res?;
    close_handle_res?;
    Ok(output_length)
}

/// Calculate the message authentication code (MAC) of a message and compare it with a reference value
/// The key must allow `sign_message`
///
/// # Example
///
/// ```
/// use psa_crypto::operations::{mac::{compute_mac, verify_mac}, key_management::generate};
/// use psa_crypto::types::algorithm::{Hash, Mac, FullLengthMac};
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// # const MESSAGE: [u8; 32] = [
/// #     0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
/// #     0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
/// # ];
/// # let mut attributes = Attributes {
/// #     key_type: Type::RsaKeyPair,
/// #     bits: 1024,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags: UsageFlags {
/// #             sign_message: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: Mac::FullLength(FullLengthMac::Hmac{hash_alg: Hash::Sha256}).into(),
/// #     },
/// # };
/// #
/// psa_crypto::init().unwrap();
/// let my_key = generate(attributes, None).unwrap();
/// let mac_alg = Mac::FullLength(FullLengthMac::Hmac{hash_alg: Hash::Sha256});
/// let buffer_size = attributes.mac_length(mac_alg).unwrap();
/// let mut mac = vec![0; buffer_size];
///
/// let size = compute_mac(my_key,
///                     mac_alg,
///                      &MESSAGE,
///                      &mut mac).unwrap();
/// mac.resize(size, 0);
/// assert!(verify_mac(my_key, mac_alg, &MESSAGE, &mac));
/// ```
pub fn verify_mac(key_id: Id, mac_alg: Mac, input_message: &[u8], expected_mac: &[u8]) -> Result<()> {
    initialized()?;

    let key_handle = key_id.handle()?;

    let mac_verify_res = Status::from(unsafe {
        psa_crypto_sys::psa_mac_verify(
            key_handle,
            mac_alg.into(),
            input_message.as_ptr(),
            input_message.len(),
            expected_mac.as_ptr(),
            expected_mac.len(),
        )}
    ).to_result();
    let close_handle_res = key_id.close_handle(key_handle);
    mac_verify_res?;
    close_handle_res
}