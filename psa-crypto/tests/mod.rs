// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::multiple_crate_versions)]

use psa_crypto::operations::key_management;
use psa_crypto::types::algorithm::{Algorithm, AsymmetricSignature, Hash};
use psa_crypto::types::key::{Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags};

mod aead;
mod hash;
mod key_agreement;
mod mac;

#[test]
fn generate_integration_test() {
    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_verify_message();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
        bits: 1024,
        policy: Policy {
            usage_flags,
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
        test_client.generate(attributes, Some(key_index));
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

    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_verify_hash().set_sign_hash();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaPublicKey,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256.into(),
            }
            .into(),
        },
    };

    let mut test_client = test_tools::TestClient::new();

    // Ensure that a large number of keys can be imported
    for key_index in 101..201u32 {
        test_client.import(attributes, key_index, &KEY_DATA);
    }
}

#[test]
fn export_key_pair_test() {
    const PRIVATE_KEY: &str = "MIICWwIBAAKBgQCd+EKeRmZCKLmg7LasWqpKA9/01linY75ujilf6v/Kb8UP9r/E\
        cO75Pvi2YPnYhBadmVOVxMOqS2zmKm1a9VTegT8dN9Unf2s2KbKrKXupaQTXcrGG\
        SB/BmHeWeiqidEMw7i9ysjHK4KEuacmYmZpvKAnNWMyvQgjGgGNpsNzqawIDAQAB\
        AoGAcHlAxXyOdnCUqpWgAtuS/5v+q06qVJRaFFE3+ElT0oj+ID2pkG5wWBqT7xbh\
        DV4O1CtFLg+o2OlXIhH3RpoC0D0x3qfvDpY5nJUUhP/w7mtGOwvB08xhXBN2M9fk\
        PNqGdrzisvxTry3rp9qDduZlv1rTCsx8+ww3iI4Q0coD4fECQQD4KAMgIS7Vu+Vm\
        zQmJfVfzYCVdr4X3Z/JOEexb3eu9p1Qj904sLu9Ds5NO7atT+qtDYVxgH5kQIrKk\
        mFNAx3NdAkEAovZ+DaorhkDiL/gFVzwoShyc1A6AWkH791sDlns2ETZ1WwE/ccYu\
        uJill/5XA9RKw6whUDzzNTsv7bFkCruAZwJARP5y6ALxz5DfFfbZuPU1d7/6g5Ki\
        b4fh8VzAV0ZbHa6hESLYBCbEdRE/WolvwfiGl0RBd6QxXTAYdPS46ODLLQJARrz4\
        urXDbuN7S5c9ukBCvOjuqp4g2Q0LcrPvOsMBFTeueXJxN9HvNfIM741X+DGOwqFV\
        VJ8gc1rd0y/NXVtGwQJAc2w23nTmZ/olcMVRia1+AFsELcCnD+JqaJ2AEF1Ng6Ix\
        V/X2l32v6t3B57sw/8ce3LCheEdqLHlSOpQiaD7Qfw==";

    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_sign_hash().set_verify_hash().set_export();
    let attributes = Attributes {
        key_type: Type::RsaKeyPair,
        bits: 1024,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags,
            permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256.into(),
            }
            .into(),
        },
    };
    psa_crypto::init().unwrap();
    let mut test_client = test_tools::TestClient::new();
    let decoded_pk = base64::decode(PRIVATE_KEY).unwrap();

    let id = test_client.import(attributes, 201, &decoded_pk);

    let buffer_size = attributes.export_key_output_size().unwrap();
    let mut data = vec![0; buffer_size];
    let size = test_client.export_key_pair(id, &mut data).unwrap();
    data.resize(size, 0);
    assert_eq!(decoded_pk, data);
}

#[test]
fn copy_key_success() {
    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_export().set_copy();
    let attributes = Attributes {
        key_type: Type::RsaKeyPair,
        bits: 1024,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::None,
        },
    };
    let mut test_client = test_tools::TestClient::new();

    let key_id = test_client.generate(attributes, None);
    let copied_key_id = test_client.copy_key(key_id, attributes, None);
    let mut original_key_material = vec![0; attributes.export_key_output_size().unwrap()];
    let mut copied_key_material = vec![0; attributes.export_key_output_size().unwrap()];
    test_client
        .export_key_pair(key_id, &mut original_key_material)
        .unwrap();
    test_client
        .export_key_pair(copied_key_id, &mut copied_key_material)
        .unwrap();
    assert_eq!(original_key_material, copied_key_material);
}

#[test]
fn copy_key_incompatible_copy_attrs() {
    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_copy().set_export();
    let attributes = Attributes {
        key_type: Type::RsaKeyPair,
        bits: 1024,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::None,
        },
    };

    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_copy().set_export();
    let incompatible_copy_attrs = Attributes {
        key_type: Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        bits: 448,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::None,
        },
    };

    let mut test_client = test_tools::TestClient::new();

    let key_id = test_client.generate(attributes, None);
    let _copied_key_id = key_management::copy(key_id, incompatible_copy_attrs, None).unwrap_err();
}

mod test_tools {
    use psa_crypto::operations::key_management;
    use psa_crypto::types::key::{Attributes, Id};
    use psa_crypto::types::status::Result;

    pub struct TestClient {
        keys: Vec<Id>,
    }

    impl TestClient {
        pub fn new() -> Self {
            psa_crypto::init().unwrap();
            TestClient { keys: Vec::new() }
        }

        pub fn generate(&mut self, attributes: Attributes, key_id: Option<u32>) -> Id {
            let id = key_management::generate(attributes, key_id).unwrap();
            self.keys.push(id);
            id
        }

        pub fn import(&mut self, attributes: Attributes, key_id: u32, key_data: &[u8]) -> Id {
            let id = key_management::import(attributes, Some(key_id), key_data).unwrap();
            self.keys.push(id);
            id
        }

        pub fn export_key_pair(&mut self, key_id: Id, key_data: &mut [u8]) -> Result<usize> {
            key_management::export(key_id, key_data)
        }

        pub fn copy_key(
            &mut self,
            key_id: Id,
            attributes: Attributes,
            id_for_new_persistent_key: Option<u32>,
        ) -> Id {
            let id = key_management::copy(key_id, attributes, id_for_new_persistent_key).unwrap();
            self.keys.push(id);
            id
        }
    }

    impl Drop for TestClient {
        fn drop(&mut self) {
            for key in self.keys.clone() {
                unsafe { key_management::destroy(key) }.unwrap();
            }
        }
    }
}
