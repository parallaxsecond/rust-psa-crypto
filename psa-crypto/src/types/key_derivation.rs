// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Key Derivation Operation types

use super::algorithm::{Hash, KeyDerivation, RawKeyAgreement};
use super::key::Id;
#[cfg(feature = "operations")]
use super::status::{Error, Result, Status};
#[cfg(feature = "operations")]
use core::convert::{From, TryFrom};

/// Key derivation operation for deriving keys from existing sources
#[derive(Debug, Clone, Copy)]
pub struct Operation<'a> {
    /// Key derivation algorithm and inputs
    pub inputs: Inputs<'a>,
    /// Maximum capacity of a key derivation operation
    pub capacity: Option<usize>,
}

/// Wrapper around KeyDerivation to enforce correct `Input`s
#[derive(Debug, Clone, Copy)]
pub enum Inputs<'a> {
    /// HKDF algorithm.
    Hkdf {
        /// A hash algorithm to use
        hash_alg: Hash,
        /// Salt, used in the "extract" step. It is optional; if omitted, the derivation uses an empty salt.
        /// Typically a direct input, can also be a key of type `RawData`.
        salt: Option<Input<'a>>,
        /// Secret, used in the "extract" step. This is typically a key of type `Derive` , or the shared secret
        /// resulting from a key agreement, using `Input::KeyAgreement`.
        /// Must be a key or key agreement input if used with `psa_key_derivation_output_key`.
        secret: InputSecret<'a>,
        /// Info, used in the "expand" step. Typically a direct input, can also be a key of type `RawData`.
        info: Input<'a>,
    },
    /// TLS-1.2 PRF algorithm.
    Tls12Prf {
        /// A hash algorithm to use.
        hash_alg: Hash,
        /// Seed, typically a direct input, can also be a key of type `RawData`.
        seed: Input<'a>,
        /// Secret, used in the "extract" step. This is typically a key of type `Derive` , or the shared secret
        /// resulting from a key agreement, using `Input::KeyAgreement`.
        /// Must be a key or key agreement input if used with `psa_key_derivation_output_key`.
        secret: InputSecret<'a>,
        /// Label. Typically a direct input, can also be a key of type `RawData`.
        label: Input<'a>,
    },
    /// TLS-1.2 PSK-to-MasterSecret algorithm.
    Tls12PskToMs {
        /// A hash algorithm to use.
        hash_alg: Hash,
        /// Seed, typically a direct input, can also be a key of type `RawData`.
        seed: Input<'a>,
        /// Secret, used in the "extract" step. This is typically a key of type `Derive` , or the shared secret
        /// resulting from a key agreement, using `Input::KeyAgreement`.
        /// Must be a key or key agreement input if used with `psa_key_derivation_output_key`.
        /// Must not be larger than `PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE`.
        secret: InputSecret<'a>,
        /// Label. Typically a direct input, can also be a key of type `RawData`.
        label: Input<'a>,
    },
}

/// Enumeration of the step of a key derivation.
#[cfg(feature = "operations")]
#[derive(Debug, Clone, Copy)]
enum DerivationStep {
    /// A secret input for key derivation.
    Secret,
    /// A label for key derivation.
    Label,
    /// A context for key derivation.
    //Context, In PSA spec but not in Mbed Crypto
    /// A salt for key derivation.
    Salt,
    /// An information string for key derivation.
    Info,
    /// A seed for key derivation.
    Seed,
}

#[cfg(feature = "operations")]
impl From<DerivationStep> for psa_crypto_sys::psa_key_derivation_step_t {
    fn from(derivation_step: DerivationStep) -> Self {
        match derivation_step {
            DerivationStep::Secret => psa_crypto_sys::PSA_KEY_DERIVATION_INPUT_SECRET,
            DerivationStep::Label => psa_crypto_sys::PSA_KEY_DERIVATION_INPUT_LABEL,
            DerivationStep::Salt => psa_crypto_sys::PSA_KEY_DERIVATION_INPUT_SALT,
            //DerivationStep::Context => psa_crypto_sys::PSA_KEY_DERIVATION_INPUT_CONTEXT, In PSA spec but not in Mbed Crypto
            DerivationStep::Info => psa_crypto_sys::PSA_KEY_DERIVATION_INPUT_INFO,
            DerivationStep::Seed => psa_crypto_sys::PSA_KEY_DERIVATION_INPUT_SEED,
        }
    }
}

#[cfg(feature = "interface")]
impl From<Inputs<'_>> for psa_crypto_sys::psa_algorithm_t {
    fn from(key_derivation_with_inputs: Inputs) -> Self {
        key_derivation_with_inputs.key_derivation().into()
    }
}

impl Inputs<'_> {
    /// Retrieve key derivation algorithm without inputs
    pub fn key_derivation(&self) -> KeyDerivation {
        match self {
            Inputs::Hkdf { hash_alg, .. } => KeyDerivation::Hkdf {
                hash_alg: *hash_alg,
            },
            Inputs::Tls12Prf { hash_alg, .. } => KeyDerivation::Tls12Prf {
                hash_alg: *hash_alg,
            },
            Inputs::Tls12PskToMs { hash_alg, .. } => KeyDerivation::Tls12PskToMs {
                hash_alg: *hash_alg,
            },
        }
    }

    #[cfg(feature = "operations")]
    pub(crate) fn apply_inputs_to_op(
        &self,
        op: &mut psa_crypto_sys::psa_key_derivation_operation_t,
    ) -> Result<()> {
        match self {
            Inputs::Hkdf {
                salt, secret, info, ..
            } => {
                if let Some(salt) = salt {
                    Inputs::apply_input_step_to_op(op, DerivationStep::Salt, salt)?;
                }
                Inputs::apply_input_secret_step_to_op(op, secret)?;
                Inputs::apply_input_step_to_op(op, DerivationStep::Info, info)
            }
            Inputs::Tls12Prf {
                seed,
                secret,
                label,
                ..
            }
            | Inputs::Tls12PskToMs {
                seed,
                secret,
                label,
                ..
            } => {
                Inputs::apply_input_step_to_op(op, DerivationStep::Seed, seed)?;
                Inputs::apply_input_secret_step_to_op(op, secret)?;
                Inputs::apply_input_step_to_op(op, DerivationStep::Label, label)
            }
        }
    }

    #[cfg(feature = "operations")]
    fn apply_input_step_to_op(
        op: &mut psa_crypto_sys::psa_key_derivation_operation_t,
        step: DerivationStep,
        input: &Input,
    ) -> Result<()> {
        match input {
            Input::Bytes(bytes) => Status::from(unsafe {
                psa_crypto_sys::psa_key_derivation_input_bytes(
                    op,
                    step.into(),
                    bytes.as_ptr(),
                    bytes.len(),
                )
            })
            .to_result(),
            Input::Key(key_id) => Status::from(unsafe {
                psa_crypto_sys::psa_key_derivation_input_key(op, step.into(), key_id.0)
            })
            .to_result(),
        }
    }

    #[cfg(feature = "operations")]
    fn apply_input_secret_step_to_op(
        op: &mut psa_crypto_sys::psa_key_derivation_operation_t,
        secret: &InputSecret,
    ) -> Result<()> {
        match secret {
            InputSecret::Input(input) => {
                Inputs::apply_input_step_to_op(op, DerivationStep::Secret, input)
            }
            InputSecret::KeyAgreement {
                private_key,
                peer_key,
                ..
            } => Status::from(unsafe {
                psa_crypto_sys::psa_key_derivation_key_agreement(
                    op,
                    DerivationStep::Secret.into(),
                    private_key.0,
                    (**peer_key).as_ptr(),
                    peer_key.len(),
                )
            })
            .to_result(),
        }
    }
}

/// Enumeration of supported input data for different input steps
#[derive(Debug, Clone, Copy)]
pub enum Input<'a> {
    /// Byte input for key derivation
    Bytes(&'a [u8]),
    /// Key input for key derivation
    Key(Id),
}

/// Enumeration of supported input data for different input steps
#[derive(Debug, Clone, Copy)]
pub enum InputSecret<'a> {
    /// Regular input of bytes or a key ID
    Input(Input<'a>),
    /// Output of a key agreement
    KeyAgreement {
        /// Key agreement algorithm to use
        alg: RawKeyAgreement,
        /// Private key to use in key agreement
        private_key: Id,
        /// Public key data of peer key to use. Must be in the same format that `key_management::import` accepts for the public key
        /// corresponding to the type of private key.
        peer_key: &'a [u8],
    },
}

impl<'a> From<Input<'a>> for InputSecret<'a> {
    fn from(input: Input<'a>) -> Self {
        InputSecret::<'a>::Input(input)
    }
}

#[cfg(feature = "operations")]
impl TryFrom<Operation<'_>> for psa_crypto_sys::psa_key_derivation_operation_t {
    type Error = Error;

    fn try_from(operation: Operation) -> Result<Self> {
        let mut op = psa_crypto_sys::psa_key_derivation_operation_init();
        let mut setup_deriv_op = || -> Result<()> {
            let mut key_derivation_alg: psa_crypto_sys::psa_algorithm_t =
                operation.inputs.key_derivation().into();

            // If key agreement is used as the input for secret step, extract key agreement alg and combine it with key derivation alg
            let secret = match operation.inputs {
                Inputs::Hkdf { secret, .. }
                | Inputs::Tls12Prf { secret, .. }
                | Inputs::Tls12PskToMs { secret, .. } => secret,
            };
            if let InputSecret::KeyAgreement { alg, .. } = secret {
                key_derivation_alg = unsafe {
                    psa_crypto_sys::PSA_ALG_KEY_AGREEMENT(alg.into(), key_derivation_alg)
                };
            }

            Status::from(unsafe {
                psa_crypto_sys::psa_key_derivation_setup(&mut op, key_derivation_alg)
            })
            .to_result()?;
            operation.inputs.apply_inputs_to_op(&mut op)
        };
        if let Err(error) = setup_deriv_op() {
            Operation::abort(op)?;
            return Err(error);
        }

        if let Some(capacity) = operation.capacity {
            // Maybe best to add capacity to the algorithms for static check as some don't support it
            Status::from(unsafe {
                psa_crypto_sys::psa_key_derivation_set_capacity(&mut op, capacity)
            })
            .to_result()?;
        }
        Ok(op)
    }
}

impl Operation<'_> {
    /// Clears operation C struct and consumes KeyDerivationOperation struct
    #[cfg(feature = "operations")]
    pub(crate) fn abort(mut op: psa_crypto_sys::psa_key_derivation_operation_t) -> Result<()> {
        Status::from(unsafe { psa_crypto_sys::psa_key_derivation_abort(&mut op) }).to_result()
    }
}
