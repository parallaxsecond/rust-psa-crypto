// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use psa_crypto::types::algorithm::{Algorithm, AsymmetricSignature, Hash};
use psa_crypto::types::key::{Attributes, Lifetime, Policy, Type, UsageFlags};

#[test]
fn generate_integration_test() {
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
        bits: 1024,
        policy: Policy {
            usage_flags: UsageFlags {
                sign_hash: true,
                verify_hash: true,
                sign_message: true,
                verify_message: true,
                export: true,
                encrypt: false,
                decrypt: false,
                cache: false,
                copy: false,
                derive: false,
            },
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };
    let mut test_client = test_tools::TestClient::new();

    // Ensure that a large number of keys can be generated
    for key_index in 1..101u32 {
        test_client.generate(attributes.clone(), key_index);
    }
}

#[test]
fn import_integration_test() {
    const KEY_DATA: [u8; 140] = [
        48, 129, 137, 2, 129, 129, 0, 153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247, 20,
        102, 253, 217, 247, 246, 142, 107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109, 16, 81,
        135, 72, 112, 132, 150, 175, 128, 173, 182, 122, 227, 214, 196, 130, 54, 239, 93, 5, 203,
        185, 233, 61, 159, 156, 7, 161, 87, 48, 234, 105, 161, 108, 215, 211, 150, 168, 156, 212,
        6, 63, 81, 24, 101, 72, 160, 97, 243, 142, 86, 10, 160, 122, 8, 228, 178, 252, 35, 209,
        222, 228, 16, 143, 99, 143, 146, 241, 186, 187, 22, 209, 86, 141, 24, 159, 12, 146, 44,
        111, 254, 183, 54, 229, 109, 28, 39, 22, 141, 173, 85, 26, 58, 9, 128, 27, 57, 131, 2, 3,
        1, 0, 1,
    ];

    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaPublicKey,
        bits: 1024,
        policy: Policy {
            usage_flags: UsageFlags {
                sign_hash: true,
                sign_message: true,
                verify_hash: true,
                verify_message: true,
                ..Default::default()
            },
            permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256.into(),
            }
            .into(),
        },
    };

    let mut test_client = test_tools::TestClient::new();

    // Ensure that a large number of keys can be imported
    for key_index in 101..201u32 {
        test_client.import(attributes.clone(), key_index, &KEY_DATA);
    }
}

mod test_tools {
    use psa_crypto::operations::key_management;
    use psa_crypto::types::key::{Attributes, Id};

    pub struct TestClient {
        keys: Vec<Id>,
    }

    impl TestClient {
        pub fn new() -> Self {
            psa_crypto::init().unwrap();
            TestClient { keys: Vec::new() }
        }

        pub fn generate(&mut self, attributes: Attributes, key_id: u32) {
            self.keys
                .push(key_management::generate(&attributes, Some(key_id)).unwrap());
        }

        pub fn import(&mut self, attributes: Attributes, key_id: u32, key_data: &[u8]) {
            self.keys
                .push(key_management::import(&attributes, Some(key_id), key_data).unwrap());
        }
    }

    impl Drop for TestClient {
        fn drop(&mut self) {
            for key in self.keys.clone() {
                unsafe { key_management::destroy(&key) }.unwrap();
            }
        }
    }
}
