// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA key material types

use picky_asn1::wrapper::IntegerAsn1;
use serde::{Deserialize, Serialize};

/// Native definition of the information required to describe an RSA public key. See the PSA spec
/// for more details on this struct definition.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RsaPublicKey {
    /// The modulus of this key material.
    modulus: IntegerAsn1, // n
    /// The public exponent of this key material.
    public_exponent: IntegerAsn1, // e
}

/// Native definition of the information required to describe an RSA private key. See the PSA spec
/// for more details on this struct definition.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RsaPrivateKey {
    /// The version of this key material.
    version: IntegerAsn1, // must be 0

    /// The modulus of this key material.
    modulus: IntegerAsn1, // n

    /// The public exponenent of this key material.
    public_exponent: IntegerAsn1, // e

    /// The private exponenent of this key material.
    private_exponent: IntegerAsn1, // d

    /// The first prime for this key material.
    prime_1: IntegerAsn1, // p

    /// The second prime for this key material.
    prime_2: IntegerAsn1, // q

    /// The first exponent for this key material.
    exponent_1: IntegerAsn1, // d mod (p - 1)

    /// The second exponent for this key material.
    exponent_2: IntegerAsn1, // d mod (q - 1)

    /// The coefficient for this key material.
    coefficient: IntegerAsn1, // (inverse of q) mod p
}
