// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Key types

#![allow(deprecated)]

use crate::types::algorithm::{Algorithm, Cipher};
use crate::types::status::{status_to_result, Error, Result};
use log::error;
use serde::{Deserialize, Serialize};

/// Native definition of the attributes needed to fully describe
/// a cryptographic key.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Attributes {
    /// Lifetime of the key
    pub lifetime: Lifetime,
    /// Intrinsic category and type of the key
    pub key_type: Type,
    /// Size of the key in bits
    pub bits: usize,
    /// Policy restricting the permitted usage of the key
    pub policy: Policy,
}

impl Attributes {
    /// Check if a key has permission to be exported
    pub fn is_exportable(self) -> bool {
        self.policy.usage_flags.export
    }

    /// Check export in a faillible way
    pub fn can_export(self) -> Result<()> {
        if self.is_exportable() {
            Ok(())
        } else {
            error!("Key attributes do not permit exporting key.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if a key has permission to sign a message hash
    pub fn is_hash_signable(self) -> bool {
        self.policy.usage_flags.sign_hash
    }

    /// Check hash signing permission in a faillible way
    pub fn can_sign_hash(self) -> Result<()> {
        if self.is_hash_signable() {
            Ok(())
        } else {
            error!("Key attributes do not permit signing hashes.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if a key has permission to verify a message hash
    pub fn is_hash_verifiable(self) -> bool {
        self.policy.usage_flags.verify_hash
    }

    /// Check hash signing permission in a faillible way
    pub fn can_verify_hash(self) -> Result<()> {
        if self.is_hash_verifiable() {
            Ok(())
        } else {
            error!("Key attributes do not permit verifying hashes.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if the alg given for a cryptographic operation is permitted to be used with the key
    pub fn is_alg_permitted(self, alg: Algorithm) -> bool {
        match self.policy.permitted_algorithms {
            Algorithm::None => false,
            Algorithm::AsymmetricSignature(asymmetric_signature_alg_policy) => {
                if let Algorithm::AsymmetricSignature(asymmetric_signature_alg) = alg {
                    asymmetric_signature_alg_policy.is_alg_permitted(asymmetric_signature_alg)
                } else {
                    false
                }
            }
            // These ones can not be wildcard algorithms: it is sufficient to just check for
            // equality.
            permitted_alg => permitted_alg == alg,
        }
    }

    /// Check if alg is permitted in a faillible way
    pub fn permits_alg(self, alg: Algorithm) -> Result<()> {
        if self.is_alg_permitted(alg) {
            Ok(())
        } else {
            error!("Key attributes do not permit specified algorithm.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if the alg given for a cryptographic operation is compatible with the type of the
    /// key
    pub fn is_compatible_with_alg(self, alg: Algorithm) -> bool {
        match self.key_type {
            Type::RawData => false,
            Type::Hmac => alg.is_hmac(),
            Type::Derive => {
                if let Algorithm::KeyDerivation(_) = alg {
                    true
                } else {
                    false
                }
            }
            Type::Aes | Type::Camellia => {
                if let Algorithm::Mac(mac_alg) = alg {
                    mac_alg.is_block_cipher_needed()
                } else if let Algorithm::Cipher(cipher_alg) = alg {
                    cipher_alg.is_block_cipher_mode()
                } else if let Algorithm::Aead(aead_alg) = alg {
                    aead_alg.is_aead_on_block_cipher()
                } else {
                    false
                }
            }
            Type::Des => {
                if let Algorithm::Mac(mac_alg) = alg {
                    mac_alg.is_block_cipher_needed()
                } else if let Algorithm::Cipher(cipher_alg) = alg {
                    cipher_alg.is_block_cipher_mode()
                } else {
                    false
                }
            }
            Type::Arc4 => alg == Algorithm::Cipher(Cipher::StreamCipher),
            Type::Chacha20 => {
                if alg == Algorithm::Cipher(Cipher::StreamCipher) {
                    true
                } else if let Algorithm::Aead(aead_alg) = alg {
                    aead_alg.is_chacha20_poly1305_alg()
                } else {
                    false
                }
            }
            Type::RsaPublicKey | Type::RsaKeyPair => {
                if let Algorithm::AsymmetricSignature(sign_alg) = alg {
                    sign_alg.is_rsa_alg()
                } else if let Algorithm::AsymmetricEncryption(_) = alg {
                    true
                } else {
                    false
                }
            }
            Type::EccKeyPair { .. } | Type::EccPublicKey { .. } => {
                if let Algorithm::AsymmetricSignature(sign_alg) = alg {
                    sign_alg.is_ecc_alg()
                } else {
                    false
                }
            }
            Type::DhKeyPair { .. } | Type::DhPublicKey { .. } => {
                if let Algorithm::KeyAgreement(_) = alg {
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Check if alg is compatible in a faillible way
    pub fn compatible_with_alg(self, alg: Algorithm) -> Result<()> {
        if self.is_compatible_with_alg(alg) {
            Ok(())
        } else {
            error!("Key attributes are not compatible with specified algorithm.");
            Err(Error::NotPermitted)
        }
    }
}

/// The lifetime of a key indicates where it is stored and which application and system actions
/// will create and destroy it.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Lifetime {
    /// A volatile key only exists as long as the identifier to it is not destroyed.
    Volatile,
    /// A persistent key remains in storage until it is explicitly destroyed or until the
    /// corresponding storage area is wiped.
    Persistent,
    /// Implementations can offer other storage areas designated by other lifetime values as
    /// implementation-specific extensions.
    Custom(u32),
}

/// Enumeration of key types supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Type {
    /// Not a valid key type for any cryptographic operation but can be used to store arbitrary
    /// data in the key store.
    RawData,
    /// HMAC key.
    Hmac,
    /// A secret key for derivation.
    Derive,
    /// Key for a cipher, AEAD or MAC algorithm based on the AES block cipher.
    Aes,
    /// Key for a cipher or MAC algorithm based on DES or 3DES (Triple-DES).
    Des,
    /// Key for a cipher, AEAD or MAC algorithm based on the Camellia block cipher.
    Camellia,
    /// Key for the RC4 stream cipher.
    Arc4,
    /// Key for the ChaCha20 stream cipher or the Chacha20-Poly1305 AEAD algorithm.
    Chacha20,
    /// RSA public key.
    RsaPublicKey,
    /// RSA key pair: both the private and public key.
    RsaKeyPair,
    /// Elliptic curve key pair: both the private and public key.
    EccKeyPair {
        /// ECC curve family to use.
        curve_family: EccFamily,
    },
    /// Elliptic curve public key.
    EccPublicKey {
        /// ECC curve family to use.
        curve_family: EccFamily,
    },
    /// Diffie-Hellman key pair: both the private key and public key.
    DhKeyPair {
        /// Diffie-Hellman group family to use.
        group_family: DhFamily,
    },
    /// Diffie-Hellman public key.
    DhPublicKey {
        /// Diffie-Hellman group family to use.
        group_family: DhFamily,
    },
}

impl Type {
    /// Checks if a key type is ECC key pair with any curve family inside.
    pub fn is_ecc_key_pair(self) -> bool {
        match self {
            Type::EccKeyPair { .. } => true,
            _ => false,
        }
    }

    /// Checks if a key type is ECC public key with any curve family inside.
    pub fn is_ecc_public_key(self) -> bool {
        match self {
            Type::EccPublicKey { .. } => true,
            _ => false,
        }
    }

    /// Checks if a key type is DH public key with any group family inside.
    pub fn is_dh_public_key(self) -> bool {
        match self {
            Type::DhPublicKey { .. } => true,
            _ => false,
        }
    }

    /// Checks if a key type is DH key pair with any group family inside.
    pub fn is_dh_key_pair(self) -> bool {
        match self {
            Type::DhKeyPair { .. } => true,
            _ => false,
        }
    }
}

/// Enumeration of elliptic curve families supported. They are needed to create an ECC key.
/// The specific curve used for each family is given by the `bits` field of the key attributes.
/// See the book for more details.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum EccFamily {
    /// SEC Koblitz curves over prime fields.
    /// This family comprises the following curves:
    ///   * secp192k1: `bits` = 192
    ///   * secp224k1: `bits` = 225
    ///   * secp256k1: `bits` = 256
    SecpK1,
    /// SEC random curves over prime fields.
    /// This family comprises the following curves:
    ///   * secp192r1: `bits` = 192
    ///   * secp224r1: `bits` = 224
    ///   * secp256r1: `bits` = 256
    ///   * secp384r1: `bits` = 384
    ///   * secp521r1: `bits` = 512
    SecpR1,
    /// SEC additional random curves over prime fields.
    /// This family comprises the following curves:
    ///   * secp160r2: `bits` = 160 (Deprecated)
    #[deprecated = "This family of curve is weak and deprecated."]
    SecpR2,
    /// SEC Koblitz curves over binary fields.
    /// This family comprises the following curves:
    ///   * sect163k1: `bits` = 163 (DEPRECATED)
    ///   * sect233k1: `bits` = 233
    ///   * sect239k1: `bits` = 239
    ///   * sect283k1: `bits` = 283
    ///   * sect409k1: `bits` = 409
    ///   * sect571k1: `bits` = 571
    SectK1,
    /// SEC random curves over binary fields.
    /// This family comprises the following curves:
    ///   * sect163r1: `bits` = 163 (DEPRECATED)
    ///   * sect233r1: `bits` = 233
    ///   * sect283r1: `bits` = 283
    ///   * sect409r1: `bits` = 409
    ///   * sect571r1: `bits` = 571
    SectR1,
    /// SEC additional random curves over binary fields.
    /// This family comprises the following curves:
    ///   * sect163r2 : bits = 163 (DEPRECATED)
    #[deprecated = "This family of curve is weak and deprecated."]
    SectR2,
    /// Brainpool P random curves.
    /// This family comprises the following curves:
    ///   * brainpoolP160r1: `bits` = 160 (DEPRECATED)
    ///   * brainpoolP192r1: `bits` = 192
    ///   * brainpoolP224r1: `bits` = 224
    ///   * brainpoolP256r1: `bits` = 256
    ///   * brainpoolP320r1: `bits` = 320
    ///   * brainpoolP384r1: `bits` = 384
    ///   * brainpoolP512r1: `bits` = 512
    BrainpoolPR1,
    /// Curve used primarily in France and elsewhere in Europe.
    /// This family comprises one 256-bit curve:
    ///   * FRP256v1: `bits` = 256
    Frp,
    /// Montgomery curves.
    /// This family comprises the following Montgomery curves:
    ///   * Curve25519: `bits` = 255
    ///   * Curve448: `bits` = 448
    Montgomery,
}

/// Enumeration of Diffie Hellman group families supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DhFamily {
    /// Diffie-Hellman groups defined in RFC 7919 Appendix A.
    /// This family includes groups with the following `bits`: 2048, 3072, 4096, 6144, 8192.
    /// An implementation can support all of these sizes or only a subset.
    Rfc7919,
}

/// Definition of the key policy, what is permitted to do with the key.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Usage flags for the key.
    pub usage_flags: UsageFlags,
    /// Permitted algorithms to be used with the key.
    pub permitted_algorithms: Algorithm,
}

/// Definition of the usage flags. They encode what kind of operations are permitted on the key.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UsageFlags {
    /// Permission to export the key.
    pub export: bool,
    /// Permission to copy the key.
    pub copy: bool,
    /// Permission for the implementation to cache the key.
    pub cache: bool,
    /// Permission to encrypt a message with the key.
    pub encrypt: bool,
    /// Permission to decrypt a message with the key.
    pub decrypt: bool,
    /// Permission to sign a message with the key.
    pub sign_message: bool,
    /// Permission to verify a message signature with the key.
    pub verify_message: bool,
    /// Permission to sign a message hash with the key.
    pub sign_hash: bool,
    /// Permission to verify a message hash with the key.
    pub verify_hash: bool,
    /// Permission to derive other keys from this key.
    pub derive: bool,
}

/// Definition of the key ID.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Id {
    pub(crate) id: psa_crypto_sys::psa_key_id_t,
    pub(crate) handle: Option<psa_crypto_sys::psa_key_handle_t>,
}

impl Id {
    pub(crate) fn handle(self) -> Result<psa_crypto_sys::psa_key_handle_t> {
        Ok(match self.handle {
            Some(handle) => handle,
            None => {
                let mut handle = 0;
                status_to_result(unsafe { psa_crypto_sys::psa_open_key(self.id, &mut handle) })?;

                handle
            }
        })
    }

    pub(crate) fn close_handle(self, handle: psa_crypto_sys::psa_key_handle_t) -> Result<()> {
        if self.handle.is_none() {
            status_to_result(unsafe { psa_crypto_sys::psa_close_key(handle) })
        } else {
            Ok(())
        }
    }
}

impl Id {
    /// Create a new Id from a persistent key ID
    pub fn from_persistent_key_id(id: u32) -> Self {
        Id { id, handle: None }
    }
}

impl From<Attributes> for psa_crypto_sys::psa_key_attributes_t {
    fn from(_attributes: Attributes) -> Self {
        unsafe { psa_crypto_sys::psa_key_attributes_init() }
    }
}

#[cfg(test)]
mod tests {
    use super::{Attributes, Lifetime, Policy, Type, UsageFlags};
    use crate::types::algorithm::{
        Aead, AeadWithDefaultLengthTag, Algorithm, AsymmetricSignature, Cipher, FullLengthMac,
        Hash, Mac, SignHash,
    };

    #[test]
    fn usage_flags() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let mut attributes = Attributes {
            key_type: Type::RsaKeyPair,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };

        assert!(!attributes.is_exportable());
        assert!(!attributes.is_hash_signable());
        assert!(!attributes.is_hash_verifiable());
        attributes.policy.usage_flags.export = true;
        assert!(attributes.is_exportable());
        assert!(!attributes.is_hash_signable());
        assert!(!attributes.is_hash_verifiable());
        attributes.policy.usage_flags.sign_hash = true;
        assert!(attributes.is_exportable());
        assert!(attributes.is_hash_signable());
        assert!(!attributes.is_hash_verifiable());
        attributes.policy.usage_flags.verify_hash = true;
        assert!(attributes.is_exportable());
        assert!(attributes.is_hash_signable());
        assert!(attributes.is_hash_verifiable());
    }

    #[test]
    fn permits_good_alg() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let attributes = Attributes {
            key_type: Type::Hmac,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: true,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };
        assert!(attributes.is_alg_permitted(alg));
    }

    #[test]
    fn permits_bad_alg() {
        let permitted_alg = Algorithm::Mac(Mac::FullLength(FullLengthMac::Hmac {
            hash_alg: Hash::Sha1,
        }));
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha1.into(),
        });
        let attributes = Attributes {
            key_type: Type::Hmac,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: true,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };
        assert!(!attributes.is_alg_permitted(alg));
    }

    #[test]
    fn permits_wildcard_alg() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Any,
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha1.into(),
        });
        let attributes = Attributes {
            key_type: Type::Hmac,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: true,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };
        assert!(attributes.is_alg_permitted(alg));
    }

    #[test]
    fn permits_bad_wildcard_alg() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Any,
        });
        let attributes = Attributes {
            key_type: Type::Hmac,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: true,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };
        assert!(!attributes.is_alg_permitted(alg));
    }

    #[test]
    fn compat_rsa() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let mut attributes = Attributes {
            key_type: Type::RsaKeyPair,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };

        assert!(attributes.is_compatible_with_alg(alg));
        attributes.key_type = Type::RsaPublicKey;
        assert!(attributes.is_compatible_with_alg(alg));
    }

    #[test]
    fn compat_raw_data() {
        let permitted_alg = Algorithm::None;
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let attributes = Attributes {
            key_type: Type::RawData,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };

        assert!(!attributes.is_compatible_with_alg(alg));
    }

    #[test]
    fn compat_block_cipher() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let mut alg = Algorithm::Cipher(Cipher::Ofb);
        let mut attributes = Attributes {
            key_type: Type::Aes,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };

        assert!(attributes.is_compatible_with_alg(alg));
        attributes.key_type = Type::Des;
        assert!(attributes.is_compatible_with_alg(alg));
        attributes.key_type = Type::Camellia;
        assert!(attributes.is_compatible_with_alg(alg));
        alg = Algorithm::Aead(Aead::AeadWithDefaultLengthTag(
            AeadWithDefaultLengthTag::Ccm,
        ));
        assert!(attributes.is_compatible_with_alg(alg));
        attributes.key_type = Type::Des;
        assert!(!attributes.is_compatible_with_alg(alg));
    }

    #[test]
    fn compat_chacha() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let alg = Algorithm::Aead(Aead::AeadWithDefaultLengthTag(
            AeadWithDefaultLengthTag::Chacha20Poly1305,
        ));
        let attributes = Attributes {
            key_type: Type::Chacha20,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };

        assert!(attributes.is_compatible_with_alg(alg));
    }

    #[test]
    fn bad_compat() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
        let attributes = Attributes {
            key_type: Type::Hmac,
            bits: 1024,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: permitted_alg,
            },
        };

        assert!(!attributes.is_compatible_with_alg(alg));
    }
}
