// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Algorithms

#![allow(deprecated)]

#[cfg(feature = "interface")]
use crate::types::status::{Error, Result};
#[cfg(feature = "interface")]
use core::convert::{TryFrom, TryInto};
#[cfg(feature = "interface")]
use log::error;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Enumeration of possible algorithm definitions.
/// Each variant of the enum contains a main algorithm type (which is required for
/// that variant).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum Algorithm {
    /// An invalid algorithm identifier value.
    /// `None` does not allow any cryptographic operation with the key. The key can still be
    /// used for non-cryptographic actions such as exporting, if permitted by the usage flags.
    None,
    /// Hash algorithm.
    Hash(Hash),
    /// MAC algorithm.
    Mac(Mac),
    /// Symmetric Cipher algorithm.
    Cipher(Cipher),
    /// Authenticated Encryption with Associated Data (AEAD) algorithm.
    Aead(Aead),
    /// Public-key signature algorithm.
    AsymmetricSignature(AsymmetricSignature),
    /// Public-key encryption algorithm.
    AsymmetricEncryption(AsymmetricEncryption),
    /// Key agreement algorithm.
    KeyAgreement(KeyAgreement),
    /// Key derivation algorithm.
    KeyDerivation(KeyDerivation),
}

impl Algorithm {
    /// Check if the algorithm is a HMAC algorithm, truncated or not
    ///
    /// # Example
    ///
    /// ```
    /// use psa_crypto::types::algorithm::{Algorithm, Mac, FullLengthMac, Hash};
    /// let hmac = Algorithm::Mac(Mac::Truncated {
    ///     mac_alg: FullLengthMac::Hmac { hash_alg: Hash::Sha256 },
    ///     mac_length: 30,
    /// });
    /// assert!(hmac.is_hmac());
    /// ```
    pub fn is_hmac(self) -> bool {
        match self {
            Algorithm::Mac(mac_alg) => mac_alg.is_hmac(),
            _ => false,
        }
    }
}

/// Enumeration of hash algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
#[allow(deprecated)]
pub enum Hash {
    /// MD2
    #[deprecated = "The MD2 hash is weak and deprecated and is only recommended for use in legacy protocols."]
    Md2,
    /// MD4
    #[deprecated = "The MD4 hash is weak and deprecated and is only recommended for use in legacy protocols."]
    Md4,
    /// MD5
    #[deprecated = "The MD5 hash is weak and deprecated and is only recommended for use in legacy protocols."]
    Md5,
    /// RIPEMD-160
    Ripemd160,
    /// SHA-1
    #[deprecated = "The SHA-1 hash is weak and deprecated and is only recommended for use in legacy protocols."]
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
    /// SHA-512/224
    Sha512_224,
    /// SHA-512/256
    Sha512_256,
    /// SHA3-224
    Sha3_224,
    /// SHA3-256
    Sha3_256,
    /// SHA3-384
    Sha3_384,
    /// SHA3-512
    Sha3_512,
}

impl Hash {
    /// Get the digest size output by the hash algorithm in bytes
    ///
    /// # Example
    ///
    /// ```
    /// use psa_crypto::types::algorithm::Hash;
    /// assert_eq!(Hash::Sha256.hash_length(), 32);
    /// assert_eq!(Hash::Sha512.hash_length(), 64);
    /// ```
    pub fn hash_length(self) -> usize {
        match self {
            Hash::Md2 | Hash::Md4 | Hash::Md5 => 16,
            Hash::Ripemd160 | Hash::Sha1 => 20,
            Hash::Sha224 | Hash::Sha512_224 | Hash::Sha3_224 => 28,
            Hash::Sha256 | Hash::Sha512_256 | Hash::Sha3_256 => 32,
            Hash::Sha384 | Hash::Sha3_384 => 48,
            Hash::Sha3_512 | Hash::Sha512 => 64,
        }
    }
}

/// Enumeration of untruncated MAC algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum FullLengthMac {
    /// HMAC algorithm
    Hmac {
        /// Hash algorithm to use.
        hash_alg: Hash,
    },
    /// The CBC-MAC construction over a block cipher.
    CbcMac,
    /// The CMAC construction over a block cipher.
    Cmac,
}

/// Enumeration of message authentication code algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum Mac {
    /// Untruncated MAC algorithm
    FullLength(FullLengthMac),
    /// Truncated MAC algorithm
    Truncated {
        /// The MAC algorithm to truncate.
        mac_alg: FullLengthMac,
        /// Desired length of the truncated MAC in bytes.
        mac_length: usize,
    },
}

impl Mac {
    /// Check if the MAC algorithm is a HMAC algorithm, truncated or not
    pub fn is_hmac(self) -> bool {
        matches!(
            self,
            Mac::FullLength(FullLengthMac::Hmac { .. })
                | Mac::Truncated {
                    mac_alg: FullLengthMac::Hmac { .. },
                    ..
                }
        )
    }

    /// Check if the MAC algorithm is a construction over a block cipher
    pub fn is_block_cipher_needed(self) -> bool {
        matches!(
            self,
            Mac::FullLength(FullLengthMac::CbcMac)
                | Mac::FullLength(FullLengthMac::Cmac)
                | Mac::Truncated {
                    mac_alg: FullLengthMac::CbcMac,
                    ..
                }
                | Mac::Truncated {
                    mac_alg: FullLengthMac::Cmac,
                    ..
                }
        )
    }
}

/// Enumeration of symmetric encryption algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
// StreamCipher contains "Cipher" to differentiate with the other ones that are block cipher modes.
#[allow(clippy::pub_enum_variant_names)]
pub enum Cipher {
    /// The stream cipher mode of a stream cipher algorithm.
    StreamCipher,
    /// A stream cipher built using the Counter (CTR) mode of a block cipher.
    Ctr,
    /// A stream cipher built using the Cipher Feedback (CFB) mode of a block cipher.
    Cfb,
    /// A stream cipher built using the Output Feedback (OFB) mode of a block cipher.
    Ofb,
    /// The XTS cipher mode of a block cipher.
    Xts,
    /// The Electronic Code Book (ECB) mode of a block cipher, with no padding.
    EcbNoPadding,
    /// The Cipher Block Chaining (CBC) mode of a block cipher, with no padding.
    CbcNoPadding,
    /// The Cipher Block Chaining (CBC) mode of a block cipher, with PKCS#7 padding.
    CbcPkcs7,
}

impl Cipher {
    /// Check is the cipher algorithm is a mode of a block cipher.
    pub fn is_block_cipher_mode(self) -> bool {
        matches!(
            self,
            Cipher::Ctr
                | Cipher::Cfb
                | Cipher::Ofb
                | Cipher::Xts
                | Cipher::EcbNoPadding
                | Cipher::CbcNoPadding
                | Cipher::CbcPkcs7
        )
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
/// AEAD algorithm with default length tag enumeration
pub enum AeadWithDefaultLengthTag {
    /// The CCM authenticated encryption algorithm.
    Ccm,
    /// The GCM authenticated encryption algorithm.
    Gcm,
    /// The Chacha20-Poly1305 AEAD algorithm.
    Chacha20Poly1305,
}

/// Enumeration of authenticated encryption with additional data algorithms
/// supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum Aead {
    /// AEAD algorithm with a default length tag
    AeadWithDefaultLengthTag(AeadWithDefaultLengthTag),
    /// AEAD algorithm with a shortened tag.
    AeadWithShortenedTag {
        /// An AEAD algorithm.
        aead_alg: AeadWithDefaultLengthTag,
        /// Desired length of the authentication tag in bytes.
        tag_length: usize,
    },
}

impl Aead {
    /// Check if the Aead algorithm needs a block cipher
    pub fn is_aead_on_block_cipher(self) -> bool {
        matches!(
            self,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm)
                | Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm)
                | Aead::AeadWithShortenedTag {
                    aead_alg: AeadWithDefaultLengthTag::Ccm,
                    ..
                }
                | Aead::AeadWithShortenedTag {
                    aead_alg: AeadWithDefaultLengthTag::Gcm,
                    ..
                }
        )
    }

    /// Check if this AEAD algorithm is the (truncated or not) Chacha20-Poly1305 AEAD algorithm.
    pub fn is_chacha20_poly1305_alg(self) -> bool {
        matches!(
            self,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Chacha20Poly1305)
                | Aead::AeadWithShortenedTag {
                    aead_alg: AeadWithDefaultLengthTag::Chacha20Poly1305,
                    ..
                }
        )
    }
}

/// Enumeration of hash algorithms used in "hash-and-sign" algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum SignHash {
    /// A specific hash algorithm to choose.
    Specific(Hash),
    /// In a hash-and-sign algorithm policy, allow any hash algorithm. This value must not be used
    /// to build an algorithm specification to perform an operation. It is only valid to build
    /// policies, for signature algorithms.
    Any,
}

impl SignHash {
    /// Check if the alg given for a cryptographic operation is permitted to be used with this
    /// algorithm as a policy
    pub fn is_alg_permitted(self, alg: SignHash) -> bool {
        if let SignHash::Specific(_) = alg {
            if self == SignHash::Any {
                true
            } else {
                self == alg
            }
        } else {
            // Any is not permitted for a cryptographic operation
            false
        }
    }
}

impl From<Hash> for SignHash {
    fn from(hash: Hash) -> Self {
        SignHash::Specific(hash)
    }
}

/// Enumeration of asymmetric signing algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum AsymmetricSignature {
    /// RSA PKCS#1 v1.5 signature with hashing.
    RsaPkcs1v15Sign {
        /// A hash algorithm to use.
        hash_alg: SignHash,
    },
    /// Raw PKCS#1 v1.5 signature.
    RsaPkcs1v15SignRaw,
    /// RSA PSS signature with hashing.
    RsaPss {
        /// A hash algorithm to use.
        hash_alg: SignHash,
    },
    /// ECDSA signature with hashing.
    Ecdsa {
        /// A hash algorithm to use.
        hash_alg: SignHash,
    },
    /// ECDSA signature without hashing.
    EcdsaAny,
    /// Deterministic ECDSA signature with hashing.
    DeterministicEcdsa {
        /// A hash algorithm to use.
        hash_alg: SignHash,
    },
}

impl AsymmetricSignature {
    /// Check if the alg given for a cryptographic operation is permitted to be used with this
    /// algorithm as a policy
    ///
    /// # Example
    ///
    /// ```
    /// use psa_crypto::types::algorithm::{AsymmetricSignature, SignHash, Hash};
    /// assert!(AsymmetricSignature::RsaPkcs1v15Sign { hash_alg: SignHash::Any }
    ///         .is_alg_permitted(AsymmetricSignature::RsaPkcs1v15Sign {
    ///             hash_alg:  SignHash::Specific(Hash::Sha1)
    ///         })
    ///        );
    /// assert!(!AsymmetricSignature::RsaPkcs1v15Sign { hash_alg: SignHash::Specific(Hash::Sha256) }
    ///         .is_alg_permitted(AsymmetricSignature::RsaPkcs1v15Sign {
    ///             hash_alg:  SignHash::Specific(Hash::Sha1)
    ///         })
    ///        );
    /// ```
    pub fn is_alg_permitted(self, alg: AsymmetricSignature) -> bool {
        match self {
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: hash_policy,
            } => {
                if let AsymmetricSignature::RsaPkcs1v15Sign { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            AsymmetricSignature::RsaPss {
                hash_alg: hash_policy,
            } => {
                if let AsymmetricSignature::RsaPss { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            AsymmetricSignature::Ecdsa {
                hash_alg: hash_policy,
            } => {
                if let AsymmetricSignature::Ecdsa { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            AsymmetricSignature::DeterministicEcdsa {
                hash_alg: hash_policy,
            } => {
                if let AsymmetricSignature::DeterministicEcdsa { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            // These ones can not be wildcard algorithms
            asymmetric_signature_alg => asymmetric_signature_alg == alg,
        }
    }

    /// Check if this is a RSA algorithm
    pub fn is_rsa_alg(self) -> bool {
        matches!(
            self,
            AsymmetricSignature::RsaPkcs1v15Sign { .. }
                | AsymmetricSignature::RsaPkcs1v15SignRaw
                | AsymmetricSignature::RsaPss { .. }
        )
    }

    /// Check if this is an ECC algorithm
    pub fn is_ecc_alg(self) -> bool {
        matches!(
            self,
            AsymmetricSignature::Ecdsa { .. }
                | AsymmetricSignature::EcdsaAny
                | AsymmetricSignature::DeterministicEcdsa { .. }
        )
    }

    /// Determines if the given hash length is compatible with the asymmetric signature scheme
    pub fn is_hash_len_permitted(self, hash_len: usize) -> bool {
        match self {
            AsymmetricSignature::EcdsaAny | AsymmetricSignature::RsaPkcs1v15SignRaw => true,
            AsymmetricSignature::DeterministicEcdsa { hash_alg }
            | AsymmetricSignature::RsaPkcs1v15Sign { hash_alg }
            | AsymmetricSignature::Ecdsa { hash_alg }
            | AsymmetricSignature::RsaPss { hash_alg } => {
                if let SignHash::Specific(hash_alg) = hash_alg {
                    hash_alg.hash_length() == hash_len
                } else {
                    false
                }
            }
        }
    }

    /// Retrieves the specific hash that the `AsymmetricSignature` algorithm is restricted to.
    ///
    /// For algorithms that do not specify a hash, `None` is returned.
    pub fn hash(self) -> Option<SignHash> {
        match self {
            AsymmetricSignature::EcdsaAny | AsymmetricSignature::RsaPkcs1v15SignRaw => None,
            AsymmetricSignature::DeterministicEcdsa { hash_alg }
            | AsymmetricSignature::RsaPkcs1v15Sign { hash_alg }
            | AsymmetricSignature::Ecdsa { hash_alg }
            | AsymmetricSignature::RsaPss { hash_alg } => Some(hash_alg),
        }
    }
}

/// Enumeration of asymmetric encryption algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum AsymmetricEncryption {
    /// RSA PKCS#1 v1.5 encryption.
    RsaPkcs1v15Crypt,
    /// RSA OAEP encryption.
    RsaOaep {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
}

/// Key agreement algorithm enumeration.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum RawKeyAgreement {
    /// The finite-field Diffie-Hellman (DH) key agreement algorithm.
    Ffdh,
    /// The elliptic curve Diffie-Hellman (ECDH) key agreement algorithm.
    Ecdh,
}

/// Enumeration of key agreement algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum KeyAgreement {
    /// Key agreement only algorithm.
    Raw(RawKeyAgreement),
    /// Build a combined algorithm that chains a key agreement with a key derivation.
    WithKeyDerivation {
        /// A key agreement algorithm.
        ka_alg: RawKeyAgreement,
        /// A key derivation algorithm.
        kdf_alg: KeyDerivation,
    },
}

/// Enumeration of key derivation functions supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub enum KeyDerivation {
    /// HKDF algorithm.
    Hkdf {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
    /// TLS-1.2 PRF algorithm.
    Tls12Prf {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
    /// TLS-1.2 PSK-to-MasterSecret algorithm.
    Tls12PskToMs {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
}

impl From<Hash> for Algorithm {
    fn from(alg: Hash) -> Self {
        Algorithm::Hash(alg)
    }
}
impl From<Mac> for Algorithm {
    fn from(alg: Mac) -> Self {
        Algorithm::Mac(alg)
    }
}
impl From<Cipher> for Algorithm {
    fn from(alg: Cipher) -> Self {
        Algorithm::Cipher(alg)
    }
}
impl From<Aead> for Algorithm {
    fn from(alg: Aead) -> Self {
        Algorithm::Aead(alg)
    }
}
impl From<AsymmetricSignature> for Algorithm {
    fn from(alg: AsymmetricSignature) -> Self {
        Algorithm::AsymmetricSignature(alg)
    }
}
impl From<AsymmetricEncryption> for Algorithm {
    fn from(alg: AsymmetricEncryption) -> Self {
        Algorithm::AsymmetricEncryption(alg)
    }
}
impl From<KeyAgreement> for Algorithm {
    fn from(alg: KeyAgreement) -> Self {
        Algorithm::KeyAgreement(alg)
    }
}
impl From<KeyDerivation> for Algorithm {
    fn from(alg: KeyDerivation) -> Self {
        Algorithm::KeyDerivation(alg)
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for Algorithm {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if alg == 0 {
            Ok(Algorithm::None)
        } else if psa_crypto_sys::PSA_ALG_IS_HASH(alg) {
            let hash: Hash = alg.try_into()?;
            Ok(hash.into())
        } else if psa_crypto_sys::PSA_ALG_IS_MAC(alg) {
            let mac: Mac = alg.try_into()?;
            Ok(mac.into())
        } else if psa_crypto_sys::PSA_ALG_IS_CIPHER(alg) {
            error!("Cipher algorithms are not supported.");
            Err(Error::NotSupported)
        } else if psa_crypto_sys::PSA_ALG_IS_AEAD(alg) {
            let aead: Aead = alg.try_into()?;
            Ok(aead.into())
        } else if psa_crypto_sys::PSA_ALG_IS_SIGN(alg) {
            let asym_sign: AsymmetricSignature = alg.try_into()?;
            Ok(asym_sign.into())
        } else if psa_crypto_sys::PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg) {
            let asym_encryption: AsymmetricEncryption = alg.try_into()?;
            Ok(asym_encryption.into())
        } else if psa_crypto_sys::PSA_ALG_IS_KEY_AGREEMENT(alg) {
            let key_agreement: KeyAgreement = alg.try_into()?;
            Ok(key_agreement.into())
        } else if psa_crypto_sys::PSA_ALG_IS_KEY_DERIVATION(alg) {
            let key_derivation: KeyDerivation = alg.try_into()?;
            Ok(key_derivation.into())
        } else {
            error!("Can not find a valid Algorithm for {}.", alg);
            Err(Error::NotSupported)
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<Algorithm> for psa_crypto_sys::psa_algorithm_t {
    type Error = Error;
    fn try_from(alg: Algorithm) -> Result<Self> {
        match alg {
            Algorithm::None => Ok(0),
            Algorithm::Hash(hash) => Ok(hash.into()),
            Algorithm::AsymmetricSignature(asym_sign) => Ok(asym_sign.into()),
            Algorithm::AsymmetricEncryption(asym_encrypt) => Ok(asym_encrypt.into()),
            Algorithm::Mac(mac) => Ok(mac.into()),
            Algorithm::KeyAgreement(key_agreement) => Ok(key_agreement.into()),
            Algorithm::KeyDerivation(key_derivation) => Ok(key_derivation.into()),
            Algorithm::Aead(aead) => Ok(aead.into()),
            _ => {
                error!("Algorithm not supported: {:?}.", alg);
                Err(Error::NotSupported)
            }
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for Hash {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        match alg {
            psa_crypto_sys::PSA_ALG_MD2 => Ok(Hash::Md2),
            psa_crypto_sys::PSA_ALG_MD4 => Ok(Hash::Md4),
            psa_crypto_sys::PSA_ALG_MD5 => Ok(Hash::Md5),
            psa_crypto_sys::PSA_ALG_RIPEMD160 => Ok(Hash::Ripemd160),
            psa_crypto_sys::PSA_ALG_SHA_1 => Ok(Hash::Sha1),
            psa_crypto_sys::PSA_ALG_SHA_224 => Ok(Hash::Sha224),
            psa_crypto_sys::PSA_ALG_SHA_256 => Ok(Hash::Sha256),
            psa_crypto_sys::PSA_ALG_SHA_384 => Ok(Hash::Sha384),
            psa_crypto_sys::PSA_ALG_SHA_512 => Ok(Hash::Sha512),
            psa_crypto_sys::PSA_ALG_SHA_512_224 => Ok(Hash::Sha512_224),
            psa_crypto_sys::PSA_ALG_SHA_512_256 => Ok(Hash::Sha512_256),
            psa_crypto_sys::PSA_ALG_SHA3_224 => Ok(Hash::Sha3_224),
            psa_crypto_sys::PSA_ALG_SHA3_256 => Ok(Hash::Sha3_256),
            psa_crypto_sys::PSA_ALG_SHA3_384 => Ok(Hash::Sha3_384),
            psa_crypto_sys::PSA_ALG_SHA3_512 => Ok(Hash::Sha3_512),
            a => {
                error!("Can not find a valid Hash algorithm for {}.", a);
                Err(Error::InvalidArgument)
            }
        }
    }
}

#[cfg(feature = "interface")]
impl From<Hash> for psa_crypto_sys::psa_algorithm_t {
    fn from(hash: Hash) -> Self {
        match hash {
            Hash::Md2 => psa_crypto_sys::PSA_ALG_MD2,
            Hash::Md4 => psa_crypto_sys::PSA_ALG_MD4,
            Hash::Md5 => psa_crypto_sys::PSA_ALG_MD5,
            Hash::Ripemd160 => psa_crypto_sys::PSA_ALG_RIPEMD160,
            Hash::Sha1 => psa_crypto_sys::PSA_ALG_SHA_1,
            Hash::Sha224 => psa_crypto_sys::PSA_ALG_SHA_224,
            Hash::Sha256 => psa_crypto_sys::PSA_ALG_SHA_256,
            Hash::Sha384 => psa_crypto_sys::PSA_ALG_SHA_384,
            Hash::Sha512 => psa_crypto_sys::PSA_ALG_SHA_512,
            Hash::Sha512_224 => psa_crypto_sys::PSA_ALG_SHA_512_224,
            Hash::Sha512_256 => psa_crypto_sys::PSA_ALG_SHA_512_256,
            Hash::Sha3_224 => psa_crypto_sys::PSA_ALG_SHA3_224,
            Hash::Sha3_256 => psa_crypto_sys::PSA_ALG_SHA3_256,
            Hash::Sha3_384 => psa_crypto_sys::PSA_ALG_SHA3_384,
            Hash::Sha3_512 => psa_crypto_sys::PSA_ALG_SHA3_512,
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for SignHash {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if alg == psa_crypto_sys::PSA_ALG_ANY_HASH {
            Ok(SignHash::Any)
        } else {
            Ok(SignHash::Specific(alg.try_into()?))
        }
    }
}

#[cfg(feature = "interface")]
impl From<SignHash> for psa_crypto_sys::psa_algorithm_t {
    fn from(sign_hash: SignHash) -> Self {
        match sign_hash {
            SignHash::Specific(hash) => hash.into(),
            SignHash::Any => psa_crypto_sys::PSA_ALG_ANY_HASH,
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for AsymmetricSignature {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if alg == psa_crypto_sys::PSA_ALG_RSA_PKCS1V15_SIGN_RAW {
            Ok(AsymmetricSignature::RsaPkcs1v15SignRaw)
        } else if alg == psa_crypto_sys::PSA_ALG_ECDSA_ANY {
            Ok(AsymmetricSignature::EcdsaAny)
        } else if psa_crypto_sys::PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) {
            Ok(AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: psa_crypto_sys::PSA_ALG_SIGN_GET_HASH(alg).try_into()?,
            })
        } else if psa_crypto_sys::PSA_ALG_IS_RSA_PSS(alg) {
            Ok(AsymmetricSignature::RsaPss {
                hash_alg: psa_crypto_sys::PSA_ALG_SIGN_GET_HASH(alg).try_into()?,
            })
        } else if psa_crypto_sys::PSA_ALG_IS_ECDSA(alg) {
            Ok(AsymmetricSignature::Ecdsa {
                hash_alg: psa_crypto_sys::PSA_ALG_SIGN_GET_HASH(alg).try_into()?,
            })
        } else if psa_crypto_sys::PSA_ALG_IS_DETERMINISTIC_ECDSA(alg) {
            Ok(AsymmetricSignature::DeterministicEcdsa {
                hash_alg: psa_crypto_sys::PSA_ALG_SIGN_GET_HASH(alg).try_into()?,
            })
        } else {
            error!(
                "Can not find a valid AsymmetricSignature algorithm for {}.",
                alg
            );
            Err(Error::InvalidArgument)
        }
    }
}

#[cfg(feature = "interface")]
impl From<AsymmetricSignature> for psa_crypto_sys::psa_algorithm_t {
    fn from(asym_sign: AsymmetricSignature) -> Self {
        match asym_sign {
            AsymmetricSignature::RsaPkcs1v15Sign { hash_alg } => {
                psa_crypto_sys::PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg.into())
            }
            AsymmetricSignature::RsaPkcs1v15SignRaw => {
                psa_crypto_sys::PSA_ALG_RSA_PKCS1V15_SIGN_RAW
            }
            AsymmetricSignature::RsaPss { hash_alg } => {
                psa_crypto_sys::PSA_ALG_RSA_PSS(hash_alg.into())
            }
            AsymmetricSignature::Ecdsa { hash_alg } => {
                psa_crypto_sys::PSA_ALG_ECDSA(hash_alg.into())
            }
            AsymmetricSignature::EcdsaAny => psa_crypto_sys::PSA_ALG_ECDSA_ANY,
            AsymmetricSignature::DeterministicEcdsa { hash_alg } => {
                psa_crypto_sys::PSA_ALG_DETERMINISTIC_ECDSA(hash_alg.into())
            }
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for AsymmetricEncryption {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if alg == psa_crypto_sys::PSA_ALG_RSA_PKCS1V15_CRYPT {
            Ok(AsymmetricEncryption::RsaPkcs1v15Crypt)
        } else if unsafe { psa_crypto_sys::PSA_ALG_IS_RSA_OAEP(alg) } {
            Ok(AsymmetricEncryption::RsaOaep {
                hash_alg: psa_crypto_sys::PSA_ALG_RSA_OAEP_GET_HASH(alg).try_into()?,
            })
        } else {
            error!(
                "Can not find a valid AsymmetricEncryption algorithm for {}.",
                alg
            );
            Err(Error::InvalidArgument)
        }
    }
}

#[cfg(feature = "interface")]
impl From<AsymmetricEncryption> for psa_crypto_sys::psa_algorithm_t {
    fn from(asym_encrypt: AsymmetricEncryption) -> Self {
        match asym_encrypt {
            AsymmetricEncryption::RsaPkcs1v15Crypt => psa_crypto_sys::PSA_ALG_RSA_PKCS1V15_CRYPT,
            AsymmetricEncryption::RsaOaep { hash_alg } => unsafe {
                psa_crypto_sys::PSA_ALG_RSA_OAEP(hash_alg.into())
            },
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for Mac {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if psa_crypto_sys::PSA_ALG_IS_MAC(alg) {
            if unsafe { psa_crypto_sys::PSA_ALG_FULL_LENGTH_MAC(alg) } == alg {
                Ok(Mac::FullLength(alg.try_into()?))
            } else {
                let mac_length = unsafe { psa_crypto_sys::PSA_MAC_TRUNCATED_LENGTH(alg) };
                let mac_alg: FullLengthMac =
                    unsafe { psa_crypto_sys::PSA_ALG_FULL_LENGTH_MAC(alg) }.try_into()?;
                Ok(Mac::Truncated {
                    mac_alg,
                    mac_length,
                })
            }
        } else {
            error!("Can not find a valid MAC algorithm for {}.", alg);
            Err(Error::InvalidArgument)
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for FullLengthMac {
    type Error = Error;

    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if psa_crypto_sys::PSA_ALG_IS_HMAC(alg) {
            Ok(FullLengthMac::Hmac {
                hash_alg: psa_crypto_sys::PSA_ALG_HMAC_GET_HASH(alg).try_into()?,
            })
        } else if alg == psa_crypto_sys::PSA_ALG_CBC_MAC {
            Ok(FullLengthMac::CbcMac)
        } else if alg == psa_crypto_sys::PSA_ALG_CMAC {
            Ok(FullLengthMac::Cmac)
        } else {
            error!("Can not find a valid MAC algorithm for {}.", alg);
            Err(Error::InvalidArgument)
        }
    }
}

#[cfg(feature = "interface")]
impl From<Mac> for psa_crypto_sys::psa_algorithm_t {
    fn from(mac: Mac) -> Self {
        match mac {
            Mac::FullLength(full_length_mac) => full_length_mac.into(),
            Mac::Truncated {
                mac_alg: alg,
                mac_length: length,
                // The following call is NOT currently checked. If length is invalid, the return of this call is unspecified
            } => unsafe { psa_crypto_sys::PSA_ALG_TRUNCATED_MAC(alg.into(), length) },
        }
    }
}

impl From<FullLengthMac> for Mac {
    fn from(full_length_mac: FullLengthMac) -> Self {
        Mac::FullLength(full_length_mac)
    }
}

#[cfg(feature = "interface")]
impl From<FullLengthMac> for psa_crypto_sys::psa_algorithm_t {
    fn from(full_length_mac: FullLengthMac) -> Self {
        match full_length_mac {
            FullLengthMac::CbcMac => psa_crypto_sys::PSA_ALG_CBC_MAC,
            FullLengthMac::Cmac => psa_crypto_sys::PSA_ALG_CMAC,
            FullLengthMac::Hmac { hash_alg } => unsafe {
                psa_crypto_sys::PSA_ALG_HMAC(hash_alg.into())
            },
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for Aead {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if let Ok(aead_with_default_length_tag) = AeadWithDefaultLengthTag::try_from(alg) {
            Ok(Aead::AeadWithDefaultLengthTag(aead_with_default_length_tag))
        } else {
            // Must be shortened tag
            let aead_alg = AeadWithDefaultLengthTag::try_from(unsafe {
                psa_crypto_sys::PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg)
            })?;
            let tag_length = psa_crypto_sys::PSA_ALG_AEAD_TAG_TRUNCATED_LENGTH(alg);
            Ok(Aead::AeadWithShortenedTag {
                aead_alg,
                tag_length,
            })
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for AeadWithDefaultLengthTag {
    type Error = Error;

    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if alg
            == unsafe {
                psa_crypto_sys::PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(psa_crypto_sys::PSA_ALG_CCM)
            }
        {
            Ok(AeadWithDefaultLengthTag::Ccm)
        } else if alg
            == unsafe {
                psa_crypto_sys::PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(psa_crypto_sys::PSA_ALG_GCM)
            }
        {
            Ok(AeadWithDefaultLengthTag::Gcm)
        } else if alg
            == unsafe {
                psa_crypto_sys::PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(
                    psa_crypto_sys::PSA_ALG_CHACHA20_POLY1305,
                )
            }
        {
            Ok(AeadWithDefaultLengthTag::Chacha20Poly1305)
        } else {
            error!("Can not find a valid Aead algorithm for {}.", alg);
            Err(Error::InvalidArgument)
        }
    }
}

#[cfg(feature = "interface")]
impl From<Aead> for psa_crypto_sys::psa_algorithm_t {
    fn from(aead: Aead) -> Self {
        match aead {
            Aead::AeadWithDefaultLengthTag(aead_with_default_length_mac) => {
                aead_with_default_length_mac.into()
            }
            // The following call is NOT currently checked. If length is invalid, the return of this call is unspecified
            Aead::AeadWithShortenedTag {
                aead_alg,
                tag_length,
            } => unsafe {
                psa_crypto_sys::PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg.into(), tag_length)
            },
        }
    }
}

#[cfg(feature = "interface")]
impl From<AeadWithDefaultLengthTag> for psa_crypto_sys::psa_algorithm_t {
    fn from(aead_with_default_length_tag: AeadWithDefaultLengthTag) -> Self {
        match aead_with_default_length_tag {
            AeadWithDefaultLengthTag::Ccm => unsafe {
                psa_crypto_sys::PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(psa_crypto_sys::PSA_ALG_CCM)
            },
            AeadWithDefaultLengthTag::Gcm => unsafe {
                psa_crypto_sys::PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(psa_crypto_sys::PSA_ALG_GCM)
            },
            AeadWithDefaultLengthTag::Chacha20Poly1305 => unsafe {
                psa_crypto_sys::PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(
                    psa_crypto_sys::PSA_ALG_CHACHA20_POLY1305,
                )
            },
        }
    }
}

impl From<AeadWithDefaultLengthTag> for Aead {
    fn from(aead_with_default_tag_length: AeadWithDefaultLengthTag) -> Self {
        Aead::AeadWithDefaultLengthTag(aead_with_default_tag_length)
    }
}

#[cfg(feature = "interface")]
impl From<KeyAgreement> for psa_crypto_sys::psa_algorithm_t {
    fn from(key_agreement: KeyAgreement) -> Self {
        match key_agreement {
            KeyAgreement::Raw(raw_key_agreement) => raw_key_agreement.into(),
            KeyAgreement::WithKeyDerivation { ka_alg, kdf_alg } => unsafe {
                psa_crypto_sys::PSA_ALG_KEY_AGREEMENT(ka_alg.into(), kdf_alg.into())
            },
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for KeyAgreement {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if psa_crypto_sys::PSA_ALG_IS_KEY_AGREEMENT(alg) {
            if psa_crypto_sys::PSA_ALG_IS_RAW_KEY_AGREEMENT(alg) {
                Ok(KeyAgreement::Raw(alg.try_into()?))
            } else {
                Ok(KeyAgreement::WithKeyDerivation {
                    ka_alg: unsafe { psa_crypto_sys::PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) }
                        .try_into()?,
                    kdf_alg: unsafe { psa_crypto_sys::PSA_ALG_KEY_AGREEMENT_GET_KDF(alg) }
                        .try_into()?,
                })
            }
        } else {
            error!("Can not find a valid KeyAgreement algorithm for {}.", alg);
            Err(Error::InvalidArgument)
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for RawKeyAgreement {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if psa_crypto_sys::PSA_ALG_IS_FFDH(alg) {
            Ok(RawKeyAgreement::Ffdh)
        } else if psa_crypto_sys::PSA_ALG_IS_ECDH(alg) {
            Ok(RawKeyAgreement::Ecdh)
        } else {
            error!(
                "Can not find a valid RawKeyAgreement algorithm for {}.",
                alg
            );
            Err(Error::InvalidArgument)
        }
    }
}

#[cfg(feature = "interface")]
impl From<RawKeyAgreement> for psa_crypto_sys::psa_algorithm_t {
    fn from(raw_key_agreement: RawKeyAgreement) -> Self {
        match raw_key_agreement {
            RawKeyAgreement::Ecdh => psa_crypto_sys::PSA_ALG_ECDH,
            RawKeyAgreement::Ffdh => psa_crypto_sys::PSA_ALG_FFDH,
        }
    }
}

impl From<RawKeyAgreement> for KeyAgreement {
    fn from(raw_key_agreement: RawKeyAgreement) -> Self {
        KeyAgreement::Raw(raw_key_agreement)
    }
}

#[cfg(feature = "interface")]
impl From<KeyDerivation> for psa_crypto_sys::psa_algorithm_t {
    fn from(key_derivation: KeyDerivation) -> Self {
        match key_derivation {
            KeyDerivation::Hkdf { hash_alg, .. } => unsafe {
                psa_crypto_sys::PSA_ALG_HKDF(hash_alg.into())
            },
            KeyDerivation::Tls12Prf { hash_alg, .. } => unsafe {
                psa_crypto_sys::PSA_ALG_TLS12_PRF(hash_alg.into())
            },
            KeyDerivation::Tls12PskToMs { hash_alg, .. } => unsafe {
                psa_crypto_sys::PSA_ALG_TLS12_PSK_TO_MS(hash_alg.into())
            },
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_algorithm_t> for KeyDerivation {
    type Error = Error;
    fn try_from(alg: psa_crypto_sys::psa_algorithm_t) -> Result<Self> {
        if psa_crypto_sys::PSA_ALG_IS_HKDF(alg) {
            Ok(KeyDerivation::Hkdf {
                hash_alg: psa_crypto_sys::PSA_ALG_HKDF_GET_HASH(alg).try_into()?,
            })
        } else if psa_crypto_sys::PSA_ALG_IS_TLS12_PRF(alg) {
            Ok(KeyDerivation::Tls12Prf {
                hash_alg: psa_crypto_sys::PSA_ALG_TLS12_PRF_GET_HASH(alg).try_into()?,
            })
        } else if psa_crypto_sys::PSA_ALG_IS_TLS12_PSK_TO_MS(alg) {
            Ok(KeyDerivation::Tls12PskToMs {
                hash_alg: psa_crypto_sys::PSA_ALG_TLS12_PSK_TO_MS_GET_HASH(alg).try_into()?,
            })
        } else {
            error!("Can not find a valid KeyDerivation algorithm for {}.", alg);
            Err(Error::InvalidArgument)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::types::algorithm::{Algorithm, AsymmetricSignature, Hash, SignHash};
    use core::convert::{TryFrom, TryInto};

    #[test]
    fn conversion() {
        assert_eq!(
            Hash::Sha256,
            psa_crypto_sys::PSA_ALG_SHA_256.try_into().unwrap()
        );
        assert_eq!(psa_crypto_sys::PSA_ALG_SHA_256, Hash::Sha256.into());
        assert_eq!(
            SignHash::Any,
            psa_crypto_sys::PSA_ALG_ANY_HASH.try_into().unwrap()
        );
        assert_eq!(
            SignHash::Specific(Hash::Sha256),
            psa_crypto_sys::PSA_ALG_SHA_256.try_into().unwrap()
        );
        assert_eq!(
            Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha3_512),
            }),
            psa_crypto_sys::PSA_ALG_ECDSA(psa_crypto_sys::PSA_ALG_SHA3_512)
                .try_into()
                .unwrap()
        );
        assert_eq!(
            psa_crypto_sys::PSA_ALG_ECDSA(psa_crypto_sys::PSA_ALG_SHA3_512),
            Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha3_512),
            })
            .try_into()
            .unwrap()
        );
    }

    #[test]
    fn convert_fail() {
        let _ = AsymmetricSignature::try_from(0xDEAD_BEEF).unwrap_err();
        let _ = AsymmetricSignature::try_from(psa_crypto_sys::PSA_ALG_ANY_HASH).unwrap_err();
        let _ = Hash::try_from(psa_crypto_sys::PSA_ALG_ANY_HASH).unwrap_err();
        let _ = Hash::try_from(psa_crypto_sys::PSA_ALG_RSA_PKCS1V15_SIGN_RAW).unwrap_err();
    }
}
