// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! # PSA Types
pub mod algorithm;
pub mod key;
pub mod status;

use zeroize::Zeroize;

macro_rules! zeroize_on_drop {
    ($type:ty) => {
        impl Drop for $type {
            fn drop(&mut self) {
                self.zeroize();
            }
        }
    };
}

zeroize_on_drop!(algorithm::Algorithm);
zeroize_on_drop!(algorithm::Hash);
zeroize_on_drop!(algorithm::FullLengthMac);
zeroize_on_drop!(algorithm::Mac);
zeroize_on_drop!(algorithm::Cipher);
zeroize_on_drop!(algorithm::AeadWithDefaultLengthTag);
zeroize_on_drop!(algorithm::Aead);
zeroize_on_drop!(algorithm::SignHash);
zeroize_on_drop!(algorithm::AsymmetricSignature);
zeroize_on_drop!(algorithm::AsymmetricEncryption);
zeroize_on_drop!(algorithm::RawKeyAgreement);
zeroize_on_drop!(algorithm::KeyAgreement);
zeroize_on_drop!(algorithm::KeyDerivation);

zeroize_on_drop!(key::DhFamily);
zeroize_on_drop!(key::EccFamily);
zeroize_on_drop!(key::Type);
zeroize_on_drop!(key::Lifetime);
zeroize_on_drop!(key::Policy);
zeroize_on_drop!(key::Id);
zeroize_on_drop!(key::Attributes);
zeroize_on_drop!(key::UsageFlags);

zeroize_on_drop!(status::Status);
zeroize_on_drop!(status::Error);
