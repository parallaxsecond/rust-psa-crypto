// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Key types

#![allow(deprecated)]
#[cfg(feature = "operations")]
use crate::initialized;
#[cfg(feature = "interface")]
use crate::types::algorithm::{Aead, AsymmetricEncryption, AsymmetricSignature, Mac};
use crate::types::algorithm::{Algorithm, Cipher, KeyAgreement, RawKeyAgreement};
#[cfg(feature = "operations")]
use crate::types::status::Status;
use crate::types::status::{Error, Result};
#[cfg(feature = "interface")]
use core::convert::{TryFrom, TryInto};
use core::fmt;
use log::error;
pub use psa_crypto_sys::{self, psa_key_id_t, PSA_KEY_ID_USER_MAX, PSA_KEY_ID_USER_MIN};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Native definition of the attributes needed to fully describe
/// a cryptographic key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
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

    /// Check export in a fallible way
    ///
    /// # Example
    ///
    /// ```
    /// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
    /// use psa_crypto::types::algorithm::{Algorithm, AsymmetricSignature, Hash};
    ///
    /// let mut usage_flags: UsageFlags = Default::default();
    /// let mut attributes = Attributes {
    ///     key_type: Type::RsaKeyPair,
    ///     bits: 1024,
    ///     lifetime: Lifetime::Volatile,
    ///     policy: Policy {
    ///         usage_flags,
    ///         permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
    ///             hash_alg: Hash::Sha256.into(),
    ///         }),
    ///     },
    /// };

    /// // Can not export because the export flag is set to false.
    /// attributes.can_export().unwrap_err();
    /// ```
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

    /// Check hash signing permission in a fallible way
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

    /// Check hash verifying permission in a fallible way
    pub fn can_verify_hash(self) -> Result<()> {
        if self.is_hash_verifiable() {
            Ok(())
        } else {
            error!("Key attributes do not permit verifying hashes.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if a key has permission to sign a message
    pub fn is_message_signable(self) -> bool {
        self.policy.usage_flags.sign_hash | self.policy.usage_flags.sign_message
    }

    /// Check message signing permission in a fallible way
    pub fn can_sign_message(self) -> Result<()> {
        if self.is_message_signable() {
            Ok(())
        } else {
            error!("Key attributes do not permit signing messages.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if a key has permission to verify a message
    pub fn is_message_verifiable(self) -> bool {
        self.policy.usage_flags.verify_hash | self.policy.usage_flags.verify_message
    }

    /// Check message verifying permission in a fallible way
    pub fn can_verify_message(self) -> Result<()> {
        if self.is_message_verifiable() {
            Ok(())
        } else {
            error!("Key attributes do not permit verifying messages.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if a key has permissions to encrypt a message
    pub fn is_encrypt_permitted(self) -> bool {
        self.policy.usage_flags.encrypt
    }

    /// Check encrypt permission in a fallible way
    pub fn can_encrypt_message(self) -> Result<()> {
        if self.is_encrypt_permitted() {
            Ok(())
        } else {
            error!("Key attributes do not permit encrypting messages.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if a key has permissions to decrypt a message
    pub fn is_decrypt_permitted(self) -> bool {
        self.policy.usage_flags.decrypt
    }

    /// Check decrypt permission in a fallible way
    pub fn can_decrypt_message(self) -> Result<()> {
        if self.is_decrypt_permitted() {
            Ok(())
        } else {
            error!("Key attributes do not permit decrypting messages.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if a key has permissions to be derived from
    pub fn is_derivable(self) -> bool {
        self.policy.usage_flags.derive
    }

    /// Check derive permission of a fallible way
    pub fn can_derive_from(self) -> Result<()> {
        if self.is_derivable() {
            Ok(())
        } else {
            error!("Key attributes do not permit derivation.");
            Err(Error::NotPermitted)
        }
    }

    /// Check if can be converted into psa_key_attributes_t
    #[cfg(feature = "interface")]
    pub fn can_convert_into_psa(self) -> Result<()> {
        let _ = psa_crypto_sys::psa_key_attributes_t::try_from(self)?;
        Ok(())
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

    /// Check if alg is permitted in a fallible way
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
    ///
    /// # Example
    ///
    /// ```
    /// use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
    /// use psa_crypto::types::algorithm::{Algorithm, AsymmetricSignature, Hash};
    ///
    /// let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
    ///     hash_alg: Hash::Sha256.into(),
    /// });
    /// let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
    ///     hash_alg: Hash::Sha256.into(),
    /// });
    /// let mut usage_flags: UsageFlags = Default::default();
    /// let mut attributes = Attributes {
    ///     key_type: Type::RsaKeyPair,
    ///     bits: 1024,
    ///     lifetime: Lifetime::Volatile,
    ///     policy: Policy {
    ///         usage_flags,
    ///         permitted_algorithms: permitted_alg,
    ///     },
    /// };

    /// assert!(attributes.is_compatible_with_alg(alg));
    /// attributes.key_type = Type::RsaPublicKey;
    /// assert!(attributes.is_compatible_with_alg(alg));
    /// ```
    pub fn is_compatible_with_alg(self, alg: Algorithm) -> bool {
        match self.key_type {
            Type::RawData => false,
            Type::Hmac => alg.is_hmac(),
            Type::Derive => matches!(alg, Algorithm::KeyDerivation(_)),
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
                } else {
                    matches!(alg, Algorithm::AsymmetricEncryption(_))
                }
            }
            Type::EccKeyPair { .. } | Type::EccPublicKey { .. } => match alg {
                Algorithm::KeyAgreement(KeyAgreement::Raw(RawKeyAgreement::Ecdh))
                | Algorithm::KeyAgreement(KeyAgreement::WithKeyDerivation {
                    ka_alg: RawKeyAgreement::Ecdh,
                    ..
                }) => true,
                Algorithm::AsymmetricSignature(sign_alg) => sign_alg.is_ecc_alg(),
                _ => false,
            },
            Type::DhKeyPair { .. } | Type::DhPublicKey { .. } => matches!(
                alg,
                Algorithm::KeyAgreement(KeyAgreement::Raw(RawKeyAgreement::Ffdh))
                    | Algorithm::KeyAgreement(KeyAgreement::WithKeyDerivation {
                        ka_alg: RawKeyAgreement::Ffdh,
                        ..
                    })
            ),
        }
    }

    /// Check if alg is compatible in a fallible way
    pub fn compatible_with_alg(self, alg: Algorithm) -> Result<()> {
        if self.is_compatible_with_alg(alg) {
            Ok(())
        } else {
            error!("Key attributes are not compatible with specified algorithm.");
            Err(Error::NotPermitted)
        }
    }

    #[cfg(feature = "operations")]
    pub(crate) fn reset(attributes: &mut psa_crypto_sys::psa_key_attributes_t) {
        unsafe { psa_crypto_sys::psa_reset_key_attributes(attributes) };
    }

    /// Gets the attributes for a given key ID
    ///
    /// The `Id` structure can be created with the `from_persistent_key_id` constructor on `Id`.
    ///
    /// # Example
    ///
    /// ```
    /// # use psa_crypto::operations::key_management;
    /// # use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
    /// # use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
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
    /// let my_key_id = key_management::generate(attributes, None).unwrap();
    /// //...
    /// let key_attributes = Attributes::from_key_id(my_key_id);
    /// ```
    #[cfg(feature = "operations")]
    pub fn from_key_id(key_id: Id) -> Result<Self> {
        initialized()?;
        let mut key_attributes = unsafe { psa_crypto_sys::psa_key_attributes_init() };
        Status::from(unsafe {
            psa_crypto_sys::psa_get_key_attributes(key_id.0, &mut key_attributes)
        })
        .to_result()?;
        let attributes = Attributes::try_from(key_attributes);
        Attributes::reset(&mut key_attributes);
        attributes
    }

    /// Sufficient size for a buffer to export the key, if supported
    #[cfg(feature = "interface")]
    pub fn export_key_output_size(self) -> Result<usize> {
        Attributes::export_key_output_size_base(self.key_type, self.bits)
    }

    /// Sufficient size for a buffer to export the public key, if supported
    #[cfg(feature = "interface")]
    pub fn export_public_key_output_size(self) -> Result<usize> {
        match self.key_type {
            Type::RsaKeyPair
            | Type::RsaPublicKey
            | Type::EccKeyPair { .. }
            | Type::EccPublicKey { .. }
            | Type::DhKeyPair { .. }
            | Type::DhPublicKey { .. } => {
                let pub_type = self.key_type.key_type_public_key_of_key_pair()?;
                Attributes::export_key_output_size_base(pub_type, self.bits)
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Sufficient size for a buffer to export the given key type, if supported
    #[cfg(feature = "interface")]
    fn export_key_output_size_base(key_type: Type, bits: usize) -> Result<usize> {
        match unsafe { psa_crypto_sys::PSA_EXPORT_KEY_OUTPUT_SIZE(key_type.try_into()?, bits) } {
            0 => Err(Error::NotSupported),
            size => Ok(size),
        }
    }

    /// Sufficient buffer size for a signature using the given key, if the key is supported
    #[cfg(feature = "interface")]
    pub fn sign_output_size(self, alg: AsymmetricSignature) -> Result<usize> {
        self.compatible_with_alg(alg.into())?;
        Ok(unsafe {
            psa_crypto_sys::PSA_SIGN_OUTPUT_SIZE(self.key_type.try_into()?, self.bits, alg.into())
        })
    }

    /// Sufficient buffer size for an encrypted message using the given asymmetric encryption algorithm
    #[cfg(feature = "interface")]
    pub fn asymmetric_encrypt_output_size(self, alg: AsymmetricEncryption) -> Result<usize> {
        self.compatible_with_alg(alg.into())?;
        Ok(unsafe {
            psa_crypto_sys::PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(
                self.key_type.try_into()?,
                self.bits,
                alg.into(),
            )
        })
    }

    /// Sufficient buffer size for a decrypted message using the given asymmetric encryption algorithm
    #[cfg(feature = "interface")]
    pub fn asymmetric_decrypt_output_size(self, alg: AsymmetricEncryption) -> Result<usize> {
        self.compatible_with_alg(alg.into())?;
        Ok(unsafe {
            psa_crypto_sys::PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(
                self.key_type.try_into()?,
                self.bits,
                alg.into(),
            )
        })
    }

    /// Sufficient buffer size for the MAC of the specified algorithm, if compatible
    #[cfg(feature = "interface")]
    pub fn mac_length(self, mac_alg: Mac) -> Result<usize> {
        self.compatible_with_alg(mac_alg.into())?;
        let size = unsafe {
            psa_crypto_sys::PSA_MAC_LENGTH(self.key_type.try_into()?, self.bits, mac_alg.into())
        };
        // PSA_MAC_LENGTH will return 0 for incompatible algorithms
        // and other errors. Since we need > 0 mac_length to allocate
        // space for the mac itself, treat 0 as an error.
        if size > 0 {
            Ok(size)
        } else {
            Err(Error::DataInvalid)
        }
    }

    /// Sufficient buffer size for an encrypted message using the given aead algorithm
    #[cfg(feature = "interface")]
    pub fn aead_encrypt_output_size(self, alg: Aead, plaintext_len: usize) -> Result<usize> {
        self.compatible_with_alg(alg.into())?;
        Ok(unsafe {
            psa_crypto_sys::PSA_AEAD_ENCRYPT_OUTPUT_SIZE(
                self.key_type.try_into()?,
                alg.into(),
                plaintext_len,
            )
        })
    }

    /// Sufficient buffer size for an encrypted message using the given aead algorithm
    #[cfg(feature = "interface")]
    pub fn aead_decrypt_output_size(self, alg: Aead, ciphertext_len: usize) -> Result<usize> {
        self.compatible_with_alg(alg.into())?;
        Ok(unsafe {
            psa_crypto_sys::PSA_AEAD_DECRYPT_OUTPUT_SIZE(
                self.key_type.try_into()?,
                alg.into(),
                ciphertext_len,
            )
        })
    }

    /// The length of a tag for an AEAD algorithm
    #[cfg(feature = "interface")]
    pub fn aead_tag_length(self, alg: Aead) -> Result<usize> {
        self.compatible_with_alg(alg.into())?;
        Ok(psa_crypto_sys::PSA_AEAD_TAG_LENGTH(
            self.key_type.try_into()?,
            self.bits,
            alg.into(),
        ))
    }

    /// Sufficient buffer size for the resulting shared secret from a raw key agreement
    #[cfg(feature = "interface")]
    pub fn raw_key_agreement_output_size(self, alg: RawKeyAgreement) -> Result<usize> {
        if alg == RawKeyAgreement::Ffdh {
            return Err(Error::NotSupported);
        }
        self.compatible_with_alg(KeyAgreement::Raw(alg).into())?;
        Ok(unsafe {
            psa_crypto_sys::PSA_RAW_ECDH_KEY_AGREEMENT_OUTPUT_SIZE(
                self.key_type.try_into()?,
                self.bits,
            )
        })
    }
}

/// The lifetime of a key indicates where it is stored and which application and system actions
/// will create and destroy it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
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

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::RawData => write!(f, "Raw data"),
            Type::Hmac => write!(f, "HMAC key"),
            Type::Derive => write!(f, "Derivation key"),
            Type::Aes => write!(f, "Key for an algorithm based on AES"),
            Type::Des => write!(f, "Key for an algorithm based on DES or 3DES"),
            Type::Camellia => write!(f, "Key for an algorithm based on Camellia"),
            Type::Arc4 => write!(f, "Key for the RC4 stream cipher"),
            Type::Chacha20 => write!(f, "Key for an algorithm based on ChaCha20"),
            Type::RsaPublicKey => write!(f, "RSA public key"),
            Type::RsaKeyPair => write!(f, "RSA key pair"),
            Type::EccKeyPair { curve_family } => write!(f, "ECC key pair (using {})", curve_family),
            Type::EccPublicKey { curve_family } => {
                write!(f, "ECC public key (using {})", curve_family)
            }
            Type::DhKeyPair { group_family } => {
                write!(f, "Diffie-Hellman key pair (using {})", group_family)
            }
            Type::DhPublicKey { group_family } => {
                write!(f, "Diffie-Hellman public key (using {})", group_family)
            }
        }
    }
}

impl Type {
    /// Checks if a key type is ECC key pair with any curve family inside.
    pub fn is_ecc_key_pair(self) -> bool {
        matches!(self, Type::EccKeyPair { .. })
    }

    /// Checks if a key type is ECC public key with any curve family inside.
    ///
    /// # Example
    ///
    /// ```
    /// use psa_crypto::types::key::{Type, EccFamily};
    ///
    /// assert!(Type::EccPublicKey { curve_family: EccFamily::SecpK1}.is_ecc_public_key());
    /// ```
    pub fn is_ecc_public_key(self) -> bool {
        matches!(self, Type::EccPublicKey { .. })
    }

    /// Checks if a key type is RSA public key.
    pub fn is_rsa_public_key(self) -> bool {
        matches!(self, Type::RsaPublicKey)
    }

    /// Checks if a key type is DH public key with any group family inside.
    pub fn is_dh_public_key(self) -> bool {
        matches!(self, Type::DhPublicKey { .. })
    }

    /// Checks if a key type is DH key pair with any group family inside.
    pub fn is_dh_key_pair(self) -> bool {
        matches!(self, Type::DhKeyPair { .. })
    }

    /// Checks if a key type is an asymmetric public key type.
    pub fn is_public_key(self) -> bool {
        self.is_rsa_public_key() || self.is_ecc_public_key() || self.is_dh_public_key()
    }

    /// If key is public or key pair, returns the corresponding public key type.
    #[cfg(feature = "interface")]
    pub fn key_type_public_key_of_key_pair(self) -> Result<Type> {
        match self {
            Type::RsaKeyPair
            | Type::RsaPublicKey
            | Type::EccKeyPair { .. }
            | Type::EccPublicKey { .. }
            | Type::DhKeyPair { .. }
            | Type::DhPublicKey { .. } => {
                Ok(
                    unsafe {
                        psa_crypto_sys::PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(self.try_into()?)
                    }
                    .try_into()?,
                )
            }
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Enumeration of elliptic curve families supported. They are needed to create an ECC key.
/// The specific curve used for each family is given by the `bits` field of the key attributes.
/// See the book for more details.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
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

impl fmt::Display for EccFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EccFamily::SecpK1 => write!(f, "SEC Koblitz curves over prime fields"),
            EccFamily::SecpR1 => write!(f, "SEC random curves over prime fields"),
            EccFamily::SecpR2 => write!(f, "SEC additional random curves over prime fields"),
            EccFamily::SectK1 => write!(f, "SEC Koblitz curves over binary fields"),
            EccFamily::SectR1 => write!(f, "SEC random curves over binary fields"),
            EccFamily::SectR2 => write!(f, "SEC additional random curves over binary fields"),
            EccFamily::BrainpoolPR1 => write!(f, "Brainpool P random curves"),
            EccFamily::Frp => write!(f, "FRP curve"),
            EccFamily::Montgomery => write!(f, "Montgomery curve"),
        }
    }
}

/// Enumeration of Diffie Hellman group families supported.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum DhFamily {
    /// Diffie-Hellman groups defined in RFC 7919 Appendix A.
    /// This family includes groups with the following `bits`: 2048, 3072, 4096, 6144, 8192.
    /// An implementation can support all of these sizes or only a subset.
    Rfc7919,
}

impl fmt::Display for DhFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhFamily::Rfc7919 => write!(f, "Diffie-Hellman groups defined in RFC 7919 Appendix A"),
        }
    }
}

/// Definition of the key policy, what is permitted to do with the key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Policy {
    /// Usage flags for the key.
    pub usage_flags: UsageFlags,
    /// Permitted algorithms to be used with the key.
    pub permitted_algorithms: Algorithm,
}

/// Definition of the usage flags. They encode what kind of operations are permitted on the key.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct UsageFlags {
    /// Permission to export the key.
    export: bool,
    /// Permission to copy the key.
    copy: bool,
    /// Permission for the implementation to cache the key.
    cache: bool,
    /// Permission to encrypt a message with the key.
    encrypt: bool,
    /// Permission to decrypt a message with the key.
    decrypt: bool,
    /// Permission to sign a message with the key.
    sign_message: bool,
    /// Permission to verify a message signature with the key.
    verify_message: bool,
    /// Permission to sign a message hash with the key.
    sign_hash: bool,
    /// Permission to verify a message hash with the key.
    verify_hash: bool,
    /// Permission to derive other keys from this key.
    derive: bool,
}

impl UsageFlags {
    ///Setter for the export flag
    pub fn set_export(&mut self) -> &mut Self {
        self.export = true;
        self
    }
    ///Getter for the export flag
    pub fn export(&self) -> bool {
        self.export
    }
    ///Setter for the copy flag
    pub fn set_copy(&mut self) -> &mut Self {
        self.copy = true;
        self
    }
    ///Getter for the copy flag
    pub fn copy(&self) -> bool {
        self.copy
    }
    ///Setter for the cache flag
    pub fn set_cache(&mut self) -> &mut Self {
        self.cache = true;
        self
    }
    ///Getter for the cache flag
    pub fn cache(&self) -> bool {
        self.cache
    }
    ///Setter for the encrypt flag
    pub fn set_encrypt(&mut self) -> &mut Self {
        self.encrypt = true;
        self
    }
    ///Getter for the encrypt flag
    pub fn encrypt(&self) -> bool {
        self.encrypt
    }
    ///Setter for the decrypt flag
    pub fn set_decrypt(&mut self) -> &mut Self {
        self.decrypt = true;
        self
    }
    ///Getter for the decrypt flag
    pub fn decrypt(&self) -> bool {
        self.decrypt
    }
    ///Setter for the sign_hash flag (also sets the sign_message flag)
    pub fn set_sign_hash(&mut self) -> &mut Self {
        self.sign_hash = true;
        self.sign_message = true;
        self
    }
    ///Getter for the sign_hash flag
    pub fn sign_hash(&self) -> bool {
        self.sign_hash
    }
    ///Setter for the sign_message flag
    pub fn set_sign_message(&mut self) -> &mut Self {
        self.sign_message = true;
        self
    }
    ///Getter for the sign_message flag
    pub fn sign_message(&self) -> bool {
        self.sign_message
    }
    ///Setter for the verify_hash flag (also sets the varify_message flag)
    pub fn set_verify_hash(&mut self) -> &mut Self {
        self.verify_hash = true;
        self.verify_message = true;
        self
    }
    ///Getter for the verify_hash flag
    pub fn verify_hash(&self) -> bool {
        self.verify_hash
    }
    ///Setter for the verify_message flag
    pub fn set_verify_message(&mut self) -> &mut Self {
        self.verify_message = true;
        self
    }
    ///Getter for the verify_message flag
    pub fn verify_message(&self) -> bool {
        self.verify_message
    }
    ///Setter for the derive flag
    pub fn set_derive(&mut self) -> &mut Self {
        self.derive = true;
        self
    }
    ///Getter for the derive flag
    pub fn derive(&self) -> bool {
        self.derive
    }
}

/// Definition of the key ID.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Id(pub(crate) psa_key_id_t);

impl Id {
    /// Create a new Id from a persistent key ID
    #[cfg(feature = "operations")]
    pub fn from_persistent_key_id(id: u32) -> Result<Self> {
        // Checking if the id is one of a persistent key that exists by fetching its attributes.
        let _ = Attributes::from_key_id(Id(id))?;

        Ok(Id(id))
    }
}

#[cfg(feature = "interface")]
impl TryFrom<Attributes> for psa_crypto_sys::psa_key_attributes_t {
    type Error = Error;
    fn try_from(attributes: Attributes) -> Result<Self> {
        let mut attrs = unsafe { psa_crypto_sys::psa_key_attributes_init() };
        unsafe { psa_crypto_sys::psa_set_key_lifetime(&mut attrs, attributes.lifetime.into()) };
        unsafe {
            psa_crypto_sys::psa_set_key_usage_flags(
                &mut attrs,
                attributes.policy.usage_flags.into(),
            )
        };
        unsafe {
            psa_crypto_sys::psa_set_key_algorithm(
                &mut attrs,
                attributes.policy.permitted_algorithms.try_into()?,
            )
        };
        unsafe { psa_crypto_sys::psa_set_key_type(&mut attrs, attributes.key_type.try_into()?) };
        unsafe { psa_crypto_sys::psa_set_key_bits(&mut attrs, attributes.try_into()?) };

        Ok(attrs)
    }
}

#[cfg(feature = "interface")]
impl TryFrom<Attributes> for usize {
    type Error = Error;
    // Check if key size is correct for the key type
    fn try_from(attributes: Attributes) -> Result<Self> {
        // For some operations like import 0 size is permitted
        if attributes.bits == 0 {
            return Ok(attributes.bits);
        }
        match attributes.key_type {
            Type::EccKeyPair { curve_family } | Type::EccPublicKey { curve_family } => {
                match curve_family {
                    // SEC random curves over prime fields.
                    EccFamily::SecpR1 => match attributes.bits {
                        192 | 224 | 256 | 284 | 521 => Ok(attributes.bits),
                        _ => {
                            error!("Requested key size is not supported ({})", attributes.bits);
                            Err(Error::InvalidArgument)
                        }
                    },
                    // SEC Koblitz curves over prime fields.
                    EccFamily::SecpK1 => match attributes.bits {
                        192 | 224 | 256 => Ok(attributes.bits),
                        _ => {
                            error!("Requested key size is not supported ({})", attributes.bits);
                            Err(Error::InvalidArgument)
                        }
                    },
                    // SEC Koblitz curves over binary fields
                    EccFamily::SectK1 => match attributes.bits {
                        233 | 239 | 283 | 409 | 571 => Ok(attributes.bits),
                        _ => {
                            error!("Requested key size is not supported ({})", attributes.bits);
                            Err(Error::InvalidArgument)
                        }
                    },
                    // SEC random curves over binary fields
                    EccFamily::SectR1 => match attributes.bits {
                        233 | 283 | 409 | 571 => Ok(attributes.bits),
                        _ => {
                            error!("Requested key size is not supported ({})", attributes.bits);
                            Err(Error::InvalidArgument)
                        }
                    },
                    // Brainpool P random curves
                    EccFamily::BrainpoolPR1 => match attributes.bits {
                        192 | 224 | 256 | 320 | 384 | 512 => Ok(attributes.bits),
                        _ => {
                            error!("Requested key size is not supported ({})", attributes.bits);
                            Err(Error::InvalidArgument)
                        }
                    },
                    // Curve used primarily in France and elsewhere in Europe.
                    EccFamily::Frp => match attributes.bits {
                        256 => Ok(attributes.bits),
                        _ => {
                            error!("Requested key size is not supported ({})", attributes.bits);
                            Err(Error::InvalidArgument)
                        }
                    },
                    // Montgomery curves
                    EccFamily::Montgomery => match attributes.bits {
                        255 | 448 => Ok(attributes.bits),
                        _ => {
                            error!("Requested key size is not supported ({})", attributes.bits);
                            Err(Error::InvalidArgument)
                        }
                    },
                    _ => {
                        // We don't (yet?) implement checks for other curve families
                        Ok(attributes.bits)
                    }
                }
            }
            _ => {
                // TO-DO We don't (yet?) implement checks for other types
                Ok(attributes.bits)
            }
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_key_attributes_t> for Attributes {
    type Error = Error;
    fn try_from(attributes: psa_crypto_sys::psa_key_attributes_t) -> Result<Self> {
        Ok(Attributes {
            lifetime: unsafe { psa_crypto_sys::psa_get_key_lifetime(&attributes).into() },
            key_type: unsafe { psa_crypto_sys::psa_get_key_type(&attributes).try_into()? },
            bits: unsafe { psa_crypto_sys::psa_get_key_bits(&attributes) },
            policy: Policy {
                usage_flags: unsafe { psa_crypto_sys::psa_get_key_usage_flags(&attributes).into() },
                permitted_algorithms: unsafe {
                    psa_crypto_sys::psa_get_key_algorithm(&attributes).try_into()?
                },
            },
        })
    }
}

#[cfg(feature = "interface")]
impl From<Lifetime> for psa_crypto_sys::psa_key_lifetime_t {
    fn from(lifetime: Lifetime) -> Self {
        match lifetime {
            Lifetime::Volatile => psa_crypto_sys::PSA_KEY_LIFETIME_VOLATILE,
            Lifetime::Persistent => psa_crypto_sys::PSA_KEY_LIFETIME_PERSISTENT,
            Lifetime::Custom(value) => value,
        }
    }
}

#[cfg(feature = "interface")]
impl From<psa_crypto_sys::psa_key_lifetime_t> for Lifetime {
    fn from(lifetime: psa_crypto_sys::psa_key_lifetime_t) -> Self {
        match lifetime {
            psa_crypto_sys::PSA_KEY_LIFETIME_VOLATILE => Lifetime::Volatile,
            psa_crypto_sys::PSA_KEY_LIFETIME_PERSISTENT => Lifetime::Persistent,
            value => Lifetime::Custom(value),
        }
    }
}

#[cfg(feature = "interface")]
impl From<UsageFlags> for psa_crypto_sys::psa_key_usage_t {
    fn from(flags: UsageFlags) -> Self {
        let mut usage_flags = 0;
        if flags.export {
            usage_flags |= psa_crypto_sys::PSA_KEY_USAGE_EXPORT;
        }
        if flags.encrypt {
            usage_flags |= psa_crypto_sys::PSA_KEY_USAGE_ENCRYPT;
        }
        if flags.decrypt {
            usage_flags |= psa_crypto_sys::PSA_KEY_USAGE_DECRYPT;
        }
        //TODO: not yet implemented in Mbed Crypto, uncomment when added
        //if flags.sign_message {
        //  usage_flags |= psa_crypto_sys::PSA_KEY_USAGE_SIGN_MESSAGE;
        //}
        if flags.sign_hash {
            usage_flags |= psa_crypto_sys::PSA_KEY_USAGE_SIGN_HASH;
        }
        //if flags.verify_message {
        //  usage_flags |= psa_crypto_sys::PSA_KEY_USAGE_VERIFY_MESSAGE;
        //}
        if flags.verify_hash {
            usage_flags |= psa_crypto_sys::PSA_KEY_USAGE_VERIFY_HASH;
        }
        if flags.derive {
            usage_flags |= psa_crypto_sys::PSA_KEY_USAGE_DERIVE;
        }
        if flags.copy {
            usage_flags |= psa_crypto_sys::PSA_KEY_USAGE_COPY;
        }
        usage_flags
    }
}

#[cfg(feature = "interface")]
impl From<psa_crypto_sys::psa_key_usage_t> for UsageFlags {
    fn from(flags: psa_crypto_sys::psa_key_usage_t) -> Self {
        UsageFlags {
            export: flags & psa_crypto_sys::PSA_KEY_USAGE_EXPORT > 0,
            copy: false,
            cache: false,
            encrypt: flags & psa_crypto_sys::PSA_KEY_USAGE_ENCRYPT > 0,
            decrypt: flags & psa_crypto_sys::PSA_KEY_USAGE_DECRYPT > 0,
            sign_message: flags & psa_crypto_sys::PSA_KEY_USAGE_SIGN_MESSAGE > 0,
            verify_message: flags & psa_crypto_sys::PSA_KEY_USAGE_VERIFY_MESSAGE > 0,
            sign_hash: flags & psa_crypto_sys::PSA_KEY_USAGE_SIGN_HASH > 0,
            verify_hash: flags & psa_crypto_sys::PSA_KEY_USAGE_VERIFY_HASH > 0,
            derive: flags & psa_crypto_sys::PSA_KEY_USAGE_DERIVE > 0,
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<EccFamily> for psa_crypto_sys::psa_ecc_family_t {
    type Error = Error;
    fn try_from(family: EccFamily) -> Result<Self> {
        match family {
            EccFamily::SecpK1 => Ok(psa_crypto_sys::PSA_ECC_FAMILY_SECP_K1),
            EccFamily::SecpR1 => Ok(psa_crypto_sys::PSA_ECC_FAMILY_SECP_R1),
            EccFamily::SecpR2 => Ok(psa_crypto_sys::PSA_ECC_FAMILY_SECP_R2),
            EccFamily::SectK1 => Ok(psa_crypto_sys::PSA_ECC_FAMILY_SECT_K1),
            EccFamily::SectR1 => Ok(psa_crypto_sys::PSA_ECC_FAMILY_SECT_R1),
            EccFamily::SectR2 => Ok(psa_crypto_sys::PSA_ECC_FAMILY_SECT_R2),
            EccFamily::BrainpoolPR1 => Ok(psa_crypto_sys::PSA_ECC_FAMILY_BRAINPOOL_P_R1),
            EccFamily::Frp => Err(Error::NotSupported),
            EccFamily::Montgomery => Ok(psa_crypto_sys::PSA_ECC_FAMILY_MONTGOMERY),
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_ecc_family_t> for EccFamily {
    type Error = Error;
    fn try_from(family: psa_crypto_sys::psa_ecc_family_t) -> Result<Self> {
        match family {
            psa_crypto_sys::PSA_ECC_FAMILY_SECP_K1 => Ok(EccFamily::SecpK1),
            psa_crypto_sys::PSA_ECC_FAMILY_SECP_R1 => Ok(EccFamily::SecpR1),
            psa_crypto_sys::PSA_ECC_FAMILY_SECP_R2 => Ok(EccFamily::SecpR2),
            psa_crypto_sys::PSA_ECC_FAMILY_SECT_R1 => Ok(EccFamily::SectR1),
            psa_crypto_sys::PSA_ECC_FAMILY_SECT_R2 => Ok(EccFamily::SectR2),
            psa_crypto_sys::PSA_ECC_FAMILY_BRAINPOOL_P_R1 => Ok(EccFamily::BrainpoolPR1),
            //psa_crypto_sys::PSA_ECC_FAMILY_FRP => Ok(EccFamily::Frp),
            psa_crypto_sys::PSA_ECC_FAMILY_MONTGOMERY => Ok(EccFamily::Montgomery),
            f => {
                error!("Can not recognize the ECC family: {:?}.", f);
                Err(Error::GenericError)
            }
        }
    }
}

#[cfg(feature = "interface")]
impl From<DhFamily> for psa_crypto_sys::psa_dh_family_t {
    fn from(group: DhFamily) -> Self {
        match group {
            DhFamily::Rfc7919 => psa_crypto_sys::PSA_DH_FAMILY_RFC7919,
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_dh_family_t> for DhFamily {
    type Error = Error;
    fn try_from(group: psa_crypto_sys::psa_dh_family_t) -> Result<Self> {
        match group {
            psa_crypto_sys::PSA_DH_FAMILY_RFC7919 => Ok(DhFamily::Rfc7919),
            f => {
                error!("Can not recognize the DH family: {:?}.", f);
                Err(Error::GenericError)
            }
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<Type> for psa_crypto_sys::psa_key_type_t {
    type Error = Error;
    fn try_from(key_type: Type) -> Result<Self> {
        match key_type {
            Type::RawData => Ok(psa_crypto_sys::PSA_KEY_TYPE_RAW_DATA),
            Type::Hmac => Ok(psa_crypto_sys::PSA_KEY_TYPE_HMAC),
            Type::Derive => Ok(psa_crypto_sys::PSA_KEY_TYPE_DERIVE),
            Type::Aes => Ok(psa_crypto_sys::PSA_KEY_TYPE_AES),
            Type::Des => Ok(psa_crypto_sys::PSA_KEY_TYPE_DES),
            Type::Camellia => Ok(psa_crypto_sys::PSA_KEY_TYPE_CAMELLIA),
            Type::Arc4 => Ok(psa_crypto_sys::PSA_KEY_TYPE_ARC4),
            Type::Chacha20 => Ok(psa_crypto_sys::PSA_KEY_TYPE_CHACHA20),
            Type::RsaPublicKey => Ok(psa_crypto_sys::PSA_KEY_TYPE_RSA_PUBLIC_KEY),
            Type::RsaKeyPair => Ok(psa_crypto_sys::PSA_KEY_TYPE_RSA_KEY_PAIR),
            Type::EccKeyPair { curve_family } => Ok(psa_crypto_sys::PSA_KEY_TYPE_ECC_KEY_PAIR(
                curve_family.try_into()?,
            )),
            Type::EccPublicKey { curve_family } => Ok(psa_crypto_sys::PSA_KEY_TYPE_ECC_PUBLIC_KEY(
                curve_family.try_into()?,
            )),
            Type::DhKeyPair { group_family } => Ok(psa_crypto_sys::PSA_KEY_TYPE_DH_KEY_PAIR(
                group_family.into(),
            )),
            Type::DhPublicKey { group_family } => Ok(psa_crypto_sys::PSA_KEY_TYPE_DH_PUBLIC_KEY(
                group_family.into(),
            )),
        }
    }
}

#[cfg(feature = "interface")]
impl TryFrom<psa_crypto_sys::psa_key_type_t> for Type {
    type Error = Error;
    fn try_from(key_type: psa_crypto_sys::psa_key_type_t) -> Result<Self> {
        match key_type {
            psa_crypto_sys::PSA_KEY_TYPE_RAW_DATA => Ok(Type::RawData),
            psa_crypto_sys::PSA_KEY_TYPE_HMAC => Ok(Type::Hmac),
            psa_crypto_sys::PSA_KEY_TYPE_DERIVE => Ok(Type::Derive),
            psa_crypto_sys::PSA_KEY_TYPE_AES => Ok(Type::Aes),
            psa_crypto_sys::PSA_KEY_TYPE_DES => Ok(Type::Des),
            psa_crypto_sys::PSA_KEY_TYPE_CAMELLIA => Ok(Type::Camellia),
            psa_crypto_sys::PSA_KEY_TYPE_ARC4 => Ok(Type::Arc4),
            psa_crypto_sys::PSA_KEY_TYPE_CHACHA20 => Ok(Type::Chacha20),
            psa_crypto_sys::PSA_KEY_TYPE_RSA_PUBLIC_KEY => Ok(Type::RsaPublicKey),
            psa_crypto_sys::PSA_KEY_TYPE_RSA_KEY_PAIR => Ok(Type::RsaKeyPair),
            key_type if psa_crypto_sys::PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) => {
                Ok(Type::EccKeyPair {
                    curve_family: psa_crypto_sys::PSA_KEY_TYPE_ECC_GET_FAMILY(key_type)
                        .try_into()?,
                })
            }
            key_type if psa_crypto_sys::PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type) => {
                Ok(Type::EccPublicKey {
                    curve_family: psa_crypto_sys::PSA_KEY_TYPE_ECC_GET_FAMILY(key_type)
                        .try_into()?,
                })
            }
            key_type if psa_crypto_sys::PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(key_type) => {
                Ok(Type::DhPublicKey {
                    group_family: psa_crypto_sys::PSA_KEY_TYPE_DH_GET_FAMILY(key_type)
                        .try_into()?,
                })
            }
            key_type if psa_crypto_sys::PSA_KEY_TYPE_IS_DH_KEY_PAIR(key_type) => {
                Ok(Type::DhKeyPair {
                    group_family: psa_crypto_sys::PSA_KEY_TYPE_DH_GET_FAMILY(key_type)
                        .try_into()?,
                })
            }
            key_type => {
                error!("Can not recognize the key type: {:?}.", key_type);
                Err(Error::GenericError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags};
    use crate::types::algorithm::{
        Aead, AeadWithDefaultLengthTag, Algorithm, AsymmetricSignature, Cipher, FullLengthMac,
        Hash, Mac, SignHash,
    };
    use core::convert::TryInto;

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

        assert!(!attributes.is_derivable());
        attributes.policy.usage_flags.derive = true;
        assert!(attributes.is_derivable())
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

    #[test]
    fn convert() {
        let mut attrs = unsafe { psa_crypto_sys::psa_key_attributes_init() };
        unsafe {
            psa_crypto_sys::psa_set_key_lifetime(
                &mut attrs,
                psa_crypto_sys::PSA_KEY_LIFETIME_VOLATILE,
            )
        };
        unsafe {
            psa_crypto_sys::psa_set_key_usage_flags(
                &mut attrs,
                psa_crypto_sys::PSA_KEY_USAGE_SIGN_MESSAGE
                    | psa_crypto_sys::PSA_KEY_USAGE_VERIFY_MESSAGE,
            )
        };
        unsafe {
            psa_crypto_sys::psa_set_key_algorithm(
                &mut attrs,
                psa_crypto_sys::PSA_ALG_ECDSA(psa_crypto_sys::PSA_ALG_SHA_256),
            )
        };
        unsafe {
            psa_crypto_sys::psa_set_key_type(
                &mut attrs,
                psa_crypto_sys::PSA_KEY_TYPE_ECC_KEY_PAIR(psa_crypto_sys::PSA_ECC_FAMILY_SECP_K1),
            )
        };
        unsafe { psa_crypto_sys::psa_set_key_bits(&mut attrs, 2048) };

        assert_eq!(
            Attributes {
                key_type: Type::EccKeyPair {
                    curve_family: EccFamily::SecpK1,
                },
                bits: 2048,
                lifetime: Lifetime::Volatile,
                policy: Policy {
                    usage_flags: UsageFlags {
                        export: false,
                        copy: false,
                        cache: false,
                        encrypt: false,
                        decrypt: false,
                        sign_message: true,
                        verify_message: true,
                        sign_hash: false,
                        verify_hash: false,
                        derive: false,
                    },
                    permitted_algorithms: AsymmetricSignature::Ecdsa {
                        hash_alg: Hash::Sha256.into(),
                    }
                    .into(),
                },
            },
            attrs.try_into().unwrap()
        );
    }
}
