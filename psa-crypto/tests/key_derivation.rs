use psa_crypto::operations::{key_derivation, key_management};
use psa_crypto::types::algorithm::{Hash, KeyAgreement, KeyDerivation, RawKeyAgreement};
use psa_crypto::types::key::{Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags};
use psa_crypto::types::key_derivation::{Input, InputSecret, Inputs, Operation};

const PEER_PUBLIC_KEY: [u8; 65] = [
    0x04, 0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7, 0x02, 0x70, 0x39, 0x8c,
    0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf,
    0x63, 0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c, 0x13, 0xc5, 0x8d,
    0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f, 0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72,
    0xab,
];
const PRIVATE_KEY_DATA: [u8; 32] = [
    0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92, 0xda, 0xa2, 0x31, 0x6d, 0xe5,
    0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8, 0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57, 0x86, 0x2d, 0x14, 0x33,
];

#[test]
fn output_key() {
    const KEY_DATA: [u8; 23] = [0; 23];
    let attributes = Attributes {
        key_type: Type::Derive,
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                derive: true,
                ..Default::default()
            },
            permitted_algorithms: KeyDerivation::Hkdf {
                hash_alg: Hash::Sha256,
            }
            .into(),
        },
    };

    let derived_key_attributes = Attributes {
        key_type: Type::RawData,
        bits: 8,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                derive: true,
                ..Default::default()
            },
            permitted_algorithms: KeyDerivation::Hkdf {
                hash_alg: Hash::Sha256,
            }
            .into(),
        },
    };

    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
    let info = vec![20; 0x3f];
    let operation = Operation {
        inputs: Inputs::Hkdf {
            hash_alg: Hash::Sha256,
            salt: None,
            secret: InputSecret::Input(Input::Key(my_key)),
            info: Input::Bytes(&info),
        },
        capacity: None,
    };
    let _new_key = key_derivation::output_key(operation, derived_key_attributes, None).unwrap();
}

#[test]
#[ignore]
fn output_key_with_key_agreement() {
    let key_agreement_alg = RawKeyAgreement::Ecdh;
    let key_agr_attributes = Attributes {
        key_type: Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                derive: true,
                ..Default::default()
            },
            permitted_algorithms: KeyAgreement::WithKeyDerivation {
                ka_alg: key_agreement_alg,
                kdf_alg: KeyDerivation::Hkdf {
                    hash_alg: Hash::Sha256,
                },
            }
            .into(),
        },
    };
    const KEY_DATA: [u8; 23] = [0; 23];
    let attributes = Attributes {
        key_type: Type::RawData,
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                derive: true,
                ..Default::default()
            },
            permitted_algorithms: KeyAgreement::WithKeyDerivation {
                ka_alg: key_agreement_alg,
                kdf_alg: KeyDerivation::Hkdf {
                    hash_alg: Hash::Sha256,
                },
            }
            .into(),
        },
    };
    let derived_key_attributes = Attributes {
        key_type: Type::RawData,
        bits: 8,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                derive: true,
                ..Default::default()
            },
            permitted_algorithms: KeyDerivation::Hkdf {
                hash_alg: Hash::Sha256,
            }
            .into(),
        },
    };

    psa_crypto::init().unwrap();
    let key_agreement_key =
        key_management::import(key_agr_attributes, None, &PRIVATE_KEY_DATA).unwrap();
    let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
    let operation = Operation {
        inputs: Inputs::Hkdf {
            hash_alg: Hash::Sha256,
            salt: None,
            secret: InputSecret::KeyAgreement {
                alg: key_agreement_alg,
                private_key: key_agreement_key,
                peer_key: &PEER_PUBLIC_KEY,
            },
            info: Input::Key(my_key),
        },
        capacity: None,
    };
    let _new_key = key_derivation::output_key(operation, derived_key_attributes, None).unwrap();
}
