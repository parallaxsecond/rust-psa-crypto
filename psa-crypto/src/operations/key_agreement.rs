// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Key Agreement operations
use crate::initialized;
use crate::types::algorithm::RawKeyAgreement;
use crate::types::key::Id;
use crate::types::status::{Result, Status};

/// Perform a key agreement and return the raw shared secret.
/// # Example
///
/// ```
/// use psa_crypto::operations::{key_agreement, key_management};
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags, EccFamily};
/// use psa_crypto::types::algorithm::{KeyAgreement, RawKeyAgreement};
///
/// # const PEER_PUBLIC_KEY: [u8; 65] = [0x04, 0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7, 0x02,
/// # 0x70, 0x39, 0x8c, 0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf, 0x63,
/// # 0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c, 0x13, 0xc5, 0x8d, 0x6a, 0xac, 0x23, 0xf0, 0x46,
/// # 0xad, 0xa3, 0x0f, 0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72, 0xab];
///
///
/// # const OUR_KEY_DATA: [u8; 32] = [0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92, 0xda, 0xa2,
/// # 0x31, 0x6d, 0xe5, 0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8, 0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57, 0x86, 0x2d, 0x14, 0x33];
/// let alg = RawKeyAgreement::Ecdh;
/// # let attributes = Attributes {
/// #     key_type: Type::EccKeyPair {curve_family: EccFamily::SecpR1 },
/// #     bits: 256,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags: UsageFlags {
/// #         derive: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: KeyAgreement::Raw(alg).into(),
/// #     },
/// # };
///
/// psa_crypto::init().unwrap();
/// let my_key = key_management::import(attributes, None, &OUR_KEY_DATA).unwrap();
/// let mut output = vec![0; attributes.raw_key_agreement_output_size(alg).unwrap()];
/// let size = key_agreement::raw_key_agreement(alg, my_key, &PEER_PUBLIC_KEY, &mut output).unwrap();
/// output.resize(size, 0);
/// ```
pub fn raw_key_agreement(
    alg: RawKeyAgreement,
    key_id: Id,
    peer_key: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    initialized()?;
    let mut output_size = 0;
    Status::from(unsafe {
        psa_crypto_sys::psa_raw_key_agreement(
            alg.into(),
            key_id.0,
            peer_key.as_ptr(),
            peer_key.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut output_size,
        )
    })
    .to_result()?;

    Ok(output_size)
}
