// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Status Codes
//!
//! This module defines success and error codes returned by any PSA function.

use log::error;

/// Result type returned by any PSA operation
pub type Result<T> = core::result::Result<T, Error>;

/// Definition of a PSA status code
#[derive(Clone, Copy, Debug)]
pub enum Status {
    /// Status code for success
    Success,
    /// Status codes for errors
    Error(Error),
}

/// Definition of a PSA status code
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// An error occurred that does not correspond to any defined failure cause
    GenericError,
    /// The requested operation or a parameter is not supported by this implementation
    NotSupported,
    /// The requested action is denied by a policy
    NotPermitted,
    /// An output buffer is too small
    BufferTooSmall,
    /// Asking for an item that already exists
    AlreadyExists,
    /// Asking for an item that doesn't exist
    DoesNotExist,
    /// The requested action cannot be performed in the current state
    BadState,
    /// The parameters passed to the function are invalid
    InvalidArgument,
    /// There is not enough runtime memory
    InsufficientMemory,
    /// There is not enough persistent storage
    InsufficientStorage,
    /// There was a communication failure inside the implementation
    CommunicationFailure,
    /// There was a storage failure that may have led to data loss
    StorageFailure,
    /// Stored data has been corrupted
    DataCorrupt,
    /// Data read from storage is not valid for the implementation
    DataInvalid,
    /// A hardware failure was detected
    HardwareFailure,
    /// A tampering attempt was detected
    CorruptionDetected,
    /// There is not enough entropy to generate random data needed for the requested action
    InsufficientEntropy,
    /// The signature, MAC or hash is incorrect
    InvalidSignature,
    /// The decrypted padding is incorrect
    InvalidPadding,
    /// Insufficient data when attempting to read from a resource
    InssuficientData,
    /// The key handle is not valid
    InvalidHandle,
}

impl From<Error> for Status {
    fn from(error: Error) -> Self {
        Status::Error(error)
    }
}

impl From<psa_crypto_sys::psa_status_t> for Status {
    fn from(status: psa_crypto_sys::psa_status_t) -> Self {
        match status {
            psa_crypto_sys::PSA_SUCCESS => Status::Success,
            s => {
                error!("{} not recognised as a valid PSA status.", s);
                Status::Error(Error::GenericError)
            }
        }
    }
}

pub(crate) fn status_to_result(status: psa_crypto_sys::psa_status_t) -> Result<()> {
    match status.into() {
        Status::Success => Ok(()),
        Status::Error(error) => Err(error),
    }
}
