// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Status Codes
//!
//! This module defines success and error codes returned by any PSA function.

use log::error;

#[cfg(not(feature = "no-std"))]
use std::fmt;

/// Result type returned by any PSA operation
pub type Result<T> = core::result::Result<T, Error>;

/// Definition of a PSA status code
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Status {
    /// Status code for success
    Success,
    /// Status codes for errors
    Error(Error),
}

impl Status {
    /// Convert the Status into a Result returning the empty tuple
    ///
    /// # Example
    ///
    /// ```
    /// use psa_crypto::types::status::{Status, Error};
    ///
    /// let status_err = Status::Error(Error::GenericError);
    /// assert!(status_err.to_result().is_err());
    ///
    /// let status_ok = Status::Success;
    /// assert!(status_ok.to_result().is_ok());
    /// ```
    pub fn to_result(self) -> Result<()> {
        match self {
            Status::Success => Ok(()),
            Status::Error(error) => Err(error),
        }
    }
}

/// Definition of a PSA status code
#[derive(Clone, Copy, Debug, PartialEq)]
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
    InsufficientData,
    /// The key handle is not valid
    InvalidHandle,
}

#[cfg(not(feature = "no-std"))]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::GenericError => write!(
                f,
                "An error occurred that does not correspond to any defined failure cause"
            ),
            Error::NotSupported => write!(
                f,
                "The requested operation or a parameter is not supported by this implementation"
            ),
            Error::NotPermitted => write!(f, "The requested action is denied by a policy"),
            Error::BufferTooSmall => write!(f, "An output buffer is too small"),
            Error::AlreadyExists => write!(f, "Asking for an item that already exists"),
            Error::DoesNotExist => write!(f, "Asking for an item that doesn't exist"),
            Error::BadState => write!(
                f,
                "The requested action cannot be performed in the current state"
            ),
            Error::InvalidArgument => {
                write!(f, "The parameters passed to the function are invalid")
            }
            Error::InsufficientMemory => write!(f, "There is not enough runtime memory"),
            Error::InsufficientStorage => write!(f, "There is not enough persistent storage"),
            Error::CommunicationFailure => write!(
                f,
                "There was a communication failure inside the implementation"
            ),
            Error::StorageFailure => write!(
                f,
                "There was a storage failure that may have led to data loss"
            ),
            Error::DataCorrupt => write!(f, "Stored data has been corrupted"),
            Error::DataInvalid => write!(
                f,
                "Data read from storage is not valid for the implementation"
            ),
            Error::HardwareFailure => write!(f, "A hardware failure was detected"),
            Error::CorruptionDetected => write!(f, "A tampering attempt was detected"),
            Error::InsufficientEntropy => write!(
                f,
                "There is not enough entropy to generate random data needed for the requested action"
            ),
            Error::InvalidSignature => write!(
                f,
                "The signature, MAC or hash is incorrect"
            ),
            Error::InvalidPadding => write!(
                f,
                "The decrypted padding is incorrect"
            ),
            Error::InsufficientData => write!(
                f,
                "Insufficient data when attempting to read from a resource"
            ),
            Error::InvalidHandle => write!(
                f,
                "The key handle is not valid"
            ),
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for Error {}

impl From<Error> for Status {
    fn from(error: Error) -> Self {
        Status::Error(error)
    }
}

impl From<psa_crypto_sys::psa_status_t> for Error {
    fn from(status: psa_crypto_sys::psa_status_t) -> Self {
        match status {
            psa_crypto_sys::PSA_ERROR_GENERIC_ERROR => Error::GenericError,
            psa_crypto_sys::PSA_ERROR_NOT_SUPPORTED => Error::NotSupported,
            psa_crypto_sys::PSA_ERROR_NOT_PERMITTED => Error::NotPermitted,
            psa_crypto_sys::PSA_ERROR_BUFFER_TOO_SMALL => Error::BufferTooSmall,
            psa_crypto_sys::PSA_ERROR_ALREADY_EXISTS => Error::AlreadyExists,
            psa_crypto_sys::PSA_ERROR_DOES_NOT_EXIST => Error::DoesNotExist,
            psa_crypto_sys::PSA_ERROR_BAD_STATE => Error::BadState,
            psa_crypto_sys::PSA_ERROR_INVALID_ARGUMENT => Error::InvalidArgument,
            psa_crypto_sys::PSA_ERROR_INSUFFICIENT_MEMORY => Error::InsufficientMemory,
            psa_crypto_sys::PSA_ERROR_INSUFFICIENT_STORAGE => Error::InsufficientStorage,
            psa_crypto_sys::PSA_ERROR_COMMUNICATION_FAILURE => Error::CommunicationFailure,
            psa_crypto_sys::PSA_ERROR_STORAGE_FAILURE => Error::StorageFailure,
            psa_crypto_sys::PSA_ERROR_HARDWARE_FAILURE => Error::HardwareFailure,
            psa_crypto_sys::PSA_ERROR_INSUFFICIENT_ENTROPY => Error::InsufficientEntropy,
            psa_crypto_sys::PSA_ERROR_INVALID_SIGNATURE => Error::InvalidSignature,
            psa_crypto_sys::PSA_ERROR_INVALID_PADDING => Error::InvalidPadding,
            psa_crypto_sys::PSA_ERROR_INSUFFICIENT_DATA => Error::InsufficientData,
            psa_crypto_sys::PSA_ERROR_INVALID_HANDLE => Error::InvalidHandle,
            s => {
                error!("{} not recognised as a valid PSA status.", s);
                Error::GenericError
            }
        }
    }
}

impl From<psa_crypto_sys::psa_status_t> for Status {
    fn from(status: psa_crypto_sys::psa_status_t) -> Self {
        match status {
            psa_crypto_sys::PSA_SUCCESS => Status::Success,
            x => Status::Error(x.into()),
        }
    }
}

impl From<Status> for psa_crypto_sys::psa_status_t {
    fn from(status: Status) -> psa_crypto_sys::psa_status_t {
        match status {
            Status::Success => psa_crypto_sys::PSA_SUCCESS,
            Status::Error(error) => error.into(),
        }
    }
}

impl From<Error> for psa_crypto_sys::psa_status_t {
    fn from(error: Error) -> psa_crypto_sys::psa_status_t {
        match error {
            Error::GenericError => psa_crypto_sys::PSA_ERROR_GENERIC_ERROR,
            Error::NotSupported => psa_crypto_sys::PSA_ERROR_NOT_SUPPORTED,
            Error::NotPermitted => psa_crypto_sys::PSA_ERROR_NOT_PERMITTED,
            Error::BufferTooSmall => psa_crypto_sys::PSA_ERROR_BUFFER_TOO_SMALL,
            Error::AlreadyExists => psa_crypto_sys::PSA_ERROR_ALREADY_EXISTS,
            Error::DoesNotExist => psa_crypto_sys::PSA_ERROR_DOES_NOT_EXIST,
            Error::BadState => psa_crypto_sys::PSA_ERROR_BAD_STATE,
            Error::InvalidArgument => psa_crypto_sys::PSA_ERROR_INVALID_ARGUMENT,
            Error::InsufficientMemory => psa_crypto_sys::PSA_ERROR_INSUFFICIENT_MEMORY,
            Error::InsufficientStorage => psa_crypto_sys::PSA_ERROR_INSUFFICIENT_STORAGE,
            Error::CommunicationFailure => psa_crypto_sys::PSA_ERROR_COMMUNICATION_FAILURE,
            Error::StorageFailure => psa_crypto_sys::PSA_ERROR_STORAGE_FAILURE,
            //Error::DataCorrupt => psa_crypto_sys::PSA_ERROR_DATA_CORRUPT,
            //Error::DataInvalid => psa_crypto_sys::PSA_ERROR_DATA_INVALID,
            Error::HardwareFailure => psa_crypto_sys::PSA_ERROR_HARDWARE_FAILURE,
            //Error::CorruptionDetected => psa_crypto_sys::PSA_ERROR_CORRUPTION_DETECTED,
            Error::InsufficientEntropy => psa_crypto_sys::PSA_ERROR_INSUFFICIENT_ENTROPY,
            Error::InvalidSignature => psa_crypto_sys::PSA_ERROR_INVALID_SIGNATURE,
            Error::InvalidPadding => psa_crypto_sys::PSA_ERROR_INVALID_PADDING,
            Error::InsufficientData => psa_crypto_sys::PSA_ERROR_INSUFFICIENT_DATA,
            Error::InvalidHandle => psa_crypto_sys::PSA_ERROR_INVALID_HANDLE,
            e => {
                error!("No equivalent of {:?} to a psa_status_t.", e);
                psa_crypto_sys::PSA_ERROR_GENERIC_ERROR
            }
        }
    }
}

impl From<Status> for Result<()> {
    fn from(status: Status) -> Self {
        status.to_result()
    }
}

#[cfg(test)]
mod test {
    use crate::types::status::{Error, Status};

    #[test]
    fn conversion() {
        assert_eq!(psa_crypto_sys::PSA_SUCCESS, Status::Success.into());
        assert_eq!(
            psa_crypto_sys::PSA_ERROR_HARDWARE_FAILURE,
            Status::Error(Error::HardwareFailure).into()
        );
        assert_eq!(
            Status::Error(Error::HardwareFailure),
            psa_crypto_sys::PSA_ERROR_HARDWARE_FAILURE.into()
        );
        assert_ne!(
            Status::Error(Error::InsufficientEntropy),
            psa_crypto_sys::PSA_ERROR_HARDWARE_FAILURE.into()
        );
        assert_eq!(Status::Error(Error::GenericError), 0x0EAD_BEEF.into());
    }
}
