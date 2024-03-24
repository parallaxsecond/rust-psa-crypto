use psa_crypto::operations::key_management::import;
use psa_crypto::operations::mac::{compute_mac, verify_mac};
use psa_crypto::types::algorithm::{Algorithm, FullLengthMac, Hash, Mac};
use psa_crypto::types::key::{Attributes, Lifetime, Policy, Type, UsageFlags};
use psa_crypto::types::status::Result;

const KEY: [u8; 32] = [
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
];

// "hello mac"
const MESSAGE: [u8; 9] = [0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x6d, 0x61, 0x63];

const EXPECTED_HMAC_SHA256: [u8; 32] = [
    0x6d, 0x20, 0x70, 0xf, 0x9, 0x82, 0x70, 0xf8, 0x6c, 0x42, 0x13, 0xbe, 0xff, 0x13, 0x68, 0x3c,
    0x31, 0x79, 0xce, 0xf5, 0x68, 0x56, 0xde, 0xf9, 0xb9, 0x5f, 0x72, 0x9, 0x62, 0xf4, 0xd, 0x8a,
];
const EXPECTED_HMAC_RIPEMD160: [u8; 20] = [
    0x39, 0xcf, 0x6b, 0xbd, 0x4a, 0xd6, 0xfd, 0x2c, 0x23, 0xb5, 0xa4, 0x1d, 0x94, 0xe3, 0xde, 0x7f,
    0x1c, 0xa3, 0xf0, 0x73,
];
const EXPECTED_CMAC_AES: [u8; 16] = [
    0x2b, 0x93, 0xe2, 0xaa, 0x77, 0xb2, 0xb1, 0xe7, 0xa, 0x12, 0xb, 0xfc, 0xaf, 0x47, 0x12, 0xc4,
];

const NOT_EXPECTED: [u8; 1] = [0x00];

fn get_attrs(alg: &Mac, key_type: Type) -> Attributes {
    let mut usage = UsageFlags::default();
    let _ = usage.set_sign_hash().set_verify_hash();
    Attributes {
        key_type,
        bits: 256,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: usage,
            permitted_algorithms: Algorithm::Mac(*alg),
        },
    }
}

fn test_mac_compute(mac_alg: Mac, key_type: Type, expected: &[u8]) -> Result<()> {
    println!("{:?}", &mac_alg);
    let attributes = get_attrs(&mac_alg, key_type);
    psa_crypto::init()?;
    let my_key = import(attributes, None, &KEY)?;
    let buffer_size = attributes.mac_length(mac_alg)?;
    let mut mac = vec![0; buffer_size];
    compute_mac(my_key, mac_alg, &MESSAGE, &mut mac)?;
    assert_eq!(expected, mac);
    Ok(())
}

fn test_mac_verify(mac_alg: Mac, key_type: Type, expected: &[u8]) -> Result<()> {
    println!("{:?}", &mac_alg);
    let attributes = get_attrs(&mac_alg, key_type);
    psa_crypto::init()?;
    let my_key = import(attributes, None, &KEY)?;
    verify_mac(my_key, mac_alg, &MESSAGE, expected)?;
    Ok(())
}

#[test]
fn mac_compute_full_hmac_sha256() {
    let mac_alg = Mac::FullLength(FullLengthMac::Hmac {
        hash_alg: Hash::Sha256,
    });
    test_mac_compute(mac_alg, Type::Hmac, &EXPECTED_HMAC_SHA256).expect("successful mac");
}

#[test]
fn mac_compute_full_hmac_ripemd160() {
    let mac_alg = Mac::FullLength(FullLengthMac::Hmac {
        hash_alg: Hash::Ripemd160,
    });
    test_mac_compute(mac_alg, Type::Hmac, &EXPECTED_HMAC_RIPEMD160).expect("successful mac");
}

#[test]
fn mac_compute_full_cmac() {
    let mac_alg = Mac::FullLength(FullLengthMac::Cmac);
    test_mac_compute(mac_alg, Type::Aes, &EXPECTED_CMAC_AES).expect("successful mac");
}

#[test]
fn mac_compute_full_cbcmac() {
    let mac_alg = Mac::FullLength(FullLengthMac::CbcMac);
    test_mac_compute(mac_alg, Type::Aes, &NOT_EXPECTED).expect_err("CbcMac not supported");
}

#[test]
fn mac_compute_truncated_hmac_sha256() {
    let mac_alg = Mac::Truncated {
        mac_alg: FullLengthMac::Hmac {
            hash_alg: Hash::Sha256,
        },
        mac_length: 10,
    };
    test_mac_compute(mac_alg, Type::Hmac, &EXPECTED_HMAC_SHA256[0..10]).expect("successful mac");
}

#[test]
fn mac_compute_truncated_hmac_ripemd160() {
    let mac_alg = Mac::Truncated {
        mac_alg: FullLengthMac::Hmac {
            hash_alg: Hash::Ripemd160,
        },
        mac_length: 10,
    };
    test_mac_compute(mac_alg, Type::Hmac, &EXPECTED_HMAC_RIPEMD160[0..10]).expect("successful mac");
}

#[test]
fn mac_compute_truncated_cmac() {
    let mac_alg = Mac::Truncated {
        mac_alg: FullLengthMac::Cmac,
        mac_length: 10,
    };
    test_mac_compute(mac_alg, Type::Aes, &EXPECTED_CMAC_AES[0..10]).expect("successful mac");
}

#[test]
fn mac_verify_full_hmac_sha256() {
    let mac_alg = Mac::FullLength(FullLengthMac::Hmac {
        hash_alg: Hash::Sha256,
    });
    test_mac_verify(mac_alg, Type::Hmac, &EXPECTED_HMAC_SHA256).expect("successful mac");
}

#[test]
fn mac_verify_full_hmac_ripemd160() {
    let mac_alg = Mac::FullLength(FullLengthMac::Hmac {
        hash_alg: Hash::Ripemd160,
    });
    test_mac_verify(mac_alg, Type::Hmac, &EXPECTED_HMAC_RIPEMD160).expect("successful mac");
}

#[test]
fn mac_verify_full_cmac() {
    let mac_alg = Mac::FullLength(FullLengthMac::Cmac);
    test_mac_verify(mac_alg, Type::Aes, &EXPECTED_CMAC_AES).expect("successful mac");
}

#[test]
fn mac_verify_full_cbcmac() {
    let mac_alg = Mac::FullLength(FullLengthMac::CbcMac);
    test_mac_verify(mac_alg, Type::Aes, &NOT_EXPECTED).expect_err("CbcMac not supported");
}

#[test]
fn mac_verify_truncated_hmac_sha256() {
    let mac_alg = Mac::Truncated {
        mac_alg: FullLengthMac::Hmac {
            hash_alg: Hash::Sha256,
        },
        mac_length: 10,
    };
    test_mac_verify(mac_alg, Type::Hmac, &EXPECTED_HMAC_SHA256[0..10]).expect("successful mac");
}

#[test]
fn mac_verify_truncated_hmac_ripemd160() {
    let mac_alg = Mac::Truncated {
        mac_alg: FullLengthMac::Hmac {
            hash_alg: Hash::Ripemd160,
        },
        mac_length: 10,
    };
    test_mac_verify(mac_alg, Type::Hmac, &EXPECTED_HMAC_RIPEMD160[0..10]).expect("successful mac");
}

#[test]
fn mac_verify_truncated_cmac() {
    let mac_alg = Mac::Truncated {
        mac_alg: FullLengthMac::Cmac,
        mac_length: 10,
    };
    test_mac_verify(mac_alg, Type::Aes, &EXPECTED_CMAC_AES[0..10]).expect("successful mac");
}
