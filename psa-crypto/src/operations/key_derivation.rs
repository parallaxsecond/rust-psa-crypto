// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # Key Derivation operations

use crate::initialized;
use crate::types::key::Attributes;
use crate::types::key::Id;
use crate::types::key_derivation::Operation;
use crate::types::status::{Error, Result, Status};
use core::convert::{TryFrom, TryInto};

/// This function calculates output bytes from a key derivation algorithm and uses those bytes to generate a key deterministically.
/// The key's location, usage policy, type and size are taken from attributes.
/// # Example
///
/// ```
/// use psa_crypto::operations::{key_derivation, key_management};
/// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
/// use psa_crypto::types::algorithm::{Hash, KeyDerivation};
/// use psa_crypto::types::key_derivation::{Operation, Inputs, Input, InputSecret};
///
/// # const KEY_DATA: [u8; 23] = [0; 23];
/// # let mut attributes = Attributes {
/// #     key_type: Type::Derive,
/// #     bits: 0,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags: UsageFlags {
/// #             derive: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: KeyDerivation::Hkdf {
/// #            hash_alg: Hash::Sha256,
/// #         }.into()
/// #     }
/// # };
///
/// # let mut derived_key_attributes = Attributes {
/// # key_type: Type::RawData,
/// #     bits: 8,
/// #     lifetime: Lifetime::Volatile,
/// #     policy: Policy {
/// #         usage_flags: UsageFlags {
/// #             derive: true,
/// #             ..Default::default()
/// #         },
/// #         permitted_algorithms: KeyDerivation::Hkdf {
/// #            hash_alg: Hash::Sha256,
/// #         }.into()
/// #     }
/// # };
///
/// psa_crypto::init().unwrap();
/// let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
/// let info = vec![20; 0x3f];
/// let mut operation = Operation {
///     inputs: Inputs::Hkdf {
///         hash_alg: Hash::Sha256,
///         salt: None,
///         secret: InputSecret::Input(Input::Key(my_key)),
///         info: Input::Bytes(&info),
/// },
///     capacity: None,
/// };
/// let _new_key = key_derivation::output_key(operation, derived_key_attributes, None).unwrap();
/// ```
pub fn output_key(operation: Operation, attributes: Attributes, id: Option<u32>) -> Result<Id> {
    initialized()?;

    let mut key_attributes = psa_crypto_sys::psa_key_attributes_t::try_from(attributes)?;
    if let Some(id) = id {
        unsafe { psa_crypto_sys::psa_set_key_id(&mut key_attributes, id) };
    }
    let mut id_for_new_key = 0;

    let mut op: psa_crypto_sys::psa_key_derivation_operation_t = operation.try_into()?;
    let key_deriv_res = Status::from(unsafe {
        psa_crypto_sys::psa_key_derivation_output_key(&key_attributes, &mut op, &mut id_for_new_key)
    })
    .to_result();
    if key_deriv_res == Err(Error::InsufficientData) {
        key_deriv_res?;
    } // InsufficientData is only error that does not require abort
    Operation::abort(op)?;
    key_deriv_res?; // All other error can now return after abort
    Ok(Id(id_for_new_key))
}
