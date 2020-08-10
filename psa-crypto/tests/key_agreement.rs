use psa_crypto::operations::{key_agreement, key_management};
use psa_crypto::types::algorithm::{KeyAgreement, RawKeyAgreement};
use psa_crypto::types::key::{Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags};
use psa_crypto::types::status::Error;

const PEER_PUBLIC_KEY: [u8; 65] = [
    0x04, 0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7, 0x02, 0x70, 0x39, 0x8c,
    0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf,
    0x63, 0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c, 0x13, 0xc5, 0x8d,
    0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f, 0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72,
    0xab,
];

const OUR_KEY_DATA: [u8; 32] = [
    0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92, 0xda, 0xa2, 0x31, 0x6d, 0xe5,
    0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8, 0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57, 0x86, 0x2d, 0x14, 0x33,
];

const EXPECTED_OUTPUT: [u8; 32] = [
    0xd6, 0x84, 0x0f, 0x6b, 0x42, 0xf6, 0xed, 0xaf, 0xd1, 0x31, 0x16, 0xe0, 0xe1, 0x25, 0x65, 0x20,
    0x2f, 0xef, 0x8e, 0x9e, 0xce, 0x7d, 0xce, 0x03, 0x81, 0x24, 0x64, 0xd0, 0x4b, 0x94, 0x42, 0xde,
];

#[test]
fn key_agreement() {
    let alg = RawKeyAgreement::Ecdh;
    let attributes = Attributes {
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
            permitted_algorithms: KeyAgreement::Raw(alg).into(),
        },
    };

    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &OUR_KEY_DATA).unwrap();
    let mut output = vec![0; 1024];
    let size =
        key_agreement::raw_key_agreement(alg, my_key, &PEER_PUBLIC_KEY, &mut output).unwrap();
    output.resize(size, 0);
    assert_eq!(&EXPECTED_OUTPUT[..], &output[..])
}

#[test]
fn key_agreement_incompatible_keys() {
    const RSA_PUB_KEY_DATA: [u8; 140] = [
        48, 129, 137, 2, 129, 129, 0, 153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247, 20,
        102, 253, 217, 247, 246, 142, 107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109, 16, 81,
        135, 72, 112, 132, 150, 175, 128, 173, 182, 122, 227, 214, 196, 130, 54, 239, 93, 5, 203,
        185, 233, 61, 159, 156, 7, 161, 87, 48, 234, 105, 161, 108, 215, 211, 150, 168, 156, 212,
        6, 63, 81, 24, 101, 72, 160, 97, 243, 142, 86, 10, 160, 122, 8, 228, 178, 252, 35, 209,
        222, 228, 16, 143, 99, 143, 146, 241, 186, 187, 22, 209, 86, 141, 24, 159, 12, 146, 44,
        111, 254, 183, 54, 229, 109, 28, 39, 22, 141, 173, 85, 26, 58, 9, 128, 27, 57, 131, 2, 3,
        1, 0, 1,
    ];

    let alg = RawKeyAgreement::Ecdh;
    let attributes = Attributes {
        key_type: Type::RsaPublicKey,
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                derive: true,
                ..Default::default()
            },
            permitted_algorithms: KeyAgreement::Raw(alg).into(),
        },
    };

    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &RSA_PUB_KEY_DATA).unwrap();
    let mut output = vec![0; 1024];
    let result = key_agreement::raw_key_agreement(alg, my_key, &PEER_PUBLIC_KEY, &mut output);
    assert_eq!(Err(Error::InvalidArgument), result);
}

#[test]
fn key_agreement_no_derive_flag() {
    let alg = RawKeyAgreement::Ecdh;
    let attributes = Attributes {
        key_type: Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                ..Default::default()
            },
            permitted_algorithms: KeyAgreement::Raw(alg).into(),
        },
    };

    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &OUR_KEY_DATA).unwrap();
    let mut output = vec![0; 1024];
    let result = key_agreement::raw_key_agreement(alg, my_key, &PEER_PUBLIC_KEY, &mut output);
    assert_eq!(Err(Error::NotPermitted), result);
}
