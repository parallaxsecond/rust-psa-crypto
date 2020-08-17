use psa_crypto::operations::{aead, key_management};
use psa_crypto::types::algorithm::{Aead, AeadWithDefaultLengthTag};
use psa_crypto::types::key::{Attributes, Lifetime, Policy, Type, UsageFlags};
use psa_crypto::types::status::Error;

const KEY_DATA: [u8; 16] = [
    0x41, 0x89, 0x35, 0x1B, 0x5C, 0xAE, 0xA3, 0x75, 0xA0, 0x29, 0x9E, 0x81, 0xC6, 0x21, 0xBF, 0x43,
];
const NONCE: [u8; 13] = [
    0x48, 0xc0, 0x90, 0x69, 0x30, 0x56, 0x1e, 0x0a, 0xb0, 0xef, 0x4c, 0xd9, 0x72,
];
const ADDITIONAL_DATA: [u8; 32] = [
    0x40, 0xa2, 0x7c, 0x1d, 0x1e, 0x23, 0xea, 0x3d, 0xbe, 0x80, 0x56, 0xb2, 0x77, 0x48, 0x61, 0xa4,
    0xa2, 0x01, 0xcc, 0xe4, 0x9f, 0x19, 0x99, 0x7d, 0x19, 0x20, 0x6d, 0x8c, 0x8a, 0x34, 0x39, 0x51,
];
const DECRYPTED_DATA: [u8; 24] = [
    0x45, 0x35, 0xd1, 0x2b, 0x43, 0x77, 0x92, 0x8a, 0x7c, 0x0a, 0x61, 0xc9, 0xf8, 0x25, 0xa4, 0x86,
    0x71, 0xea, 0x05, 0x91, 0x07, 0x48, 0xc8, 0xef,
];
const ENCRYPTED_DATA: [u8; 40] = [
    0x26, 0xc5, 0x69, 0x61, 0xc0, 0x35, 0xa7, 0xe4, 0x52, 0xcc, 0xe6, 0x1b, 0xc6, 0xee, 0x22, 0x0d,
    0x77, 0xb3, 0xf9, 0x4d, 0x18, 0xfd, 0x10, 0xb6, 0xd8, 0x0e, 0x8b, 0xf8, 0x0f, 0x4a, 0x46, 0xca,
    0xb0, 0x6d, 0x43, 0x13, 0xf0, 0xdb, 0x9b, 0xe9,
];

#[test]
fn aead_encrypt_aes_ccm() {
    let alg = Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm);
    let attributes = Attributes {
        key_type: Type::Aes,
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                encrypt: true,
                ..Default::default()
            },
            permitted_algorithms: alg.into(),
        },
    };
    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
    let output_buffer_size =
        unsafe { psa_crypto_sys::PSA_AEAD_ENCRYPT_OUTPUT_SIZE(alg.into(), DECRYPTED_DATA.len()) };
    let mut output_buffer = vec![0; output_buffer_size];
    let length = aead::encrypt(
        my_key,
        alg,
        &NONCE,
        &ADDITIONAL_DATA,
        &DECRYPTED_DATA,
        &mut output_buffer,
    )
    .unwrap();
    output_buffer.resize(length, 0);
    assert_eq!(&ENCRYPTED_DATA[..], &output_buffer[..]);
}

#[test]
fn aead_encrypt_aes_ccm_no_encrypt_usage_flag() {
    let alg = Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm);
    let attributes = Attributes {
        key_type: Type::Aes,
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                ..Default::default()
            },
            permitted_algorithms: alg.into(),
        },
    };
    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
    let output_buffer_size =
        unsafe { psa_crypto_sys::PSA_AEAD_ENCRYPT_OUTPUT_SIZE(alg.into(), DECRYPTED_DATA.len()) };
    let mut output_buffer = vec![0; output_buffer_size];
    let result = aead::encrypt(
        my_key,
        alg,
        &NONCE,
        &ADDITIONAL_DATA,
        &DECRYPTED_DATA,
        &mut output_buffer,
    );
    assert_eq!(Err(Error::NotPermitted), result)
}

#[test]
fn aead_decrypt_aes_ccm() {
    let alg = Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm);
    let attributes = Attributes {
        key_type: Type::Aes,
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                decrypt: true,
                ..Default::default()
            },
            permitted_algorithms: alg.into(),
        },
    };
    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
    let output_buffer_size =
        unsafe { psa_crypto_sys::PSA_AEAD_DECRYPT_OUTPUT_SIZE(alg.into(), ENCRYPTED_DATA.len()) };
    let mut output_buffer = vec![0; output_buffer_size];
    let length = aead::decrypt(
        my_key,
        alg,
        &NONCE,
        &ADDITIONAL_DATA,
        &ENCRYPTED_DATA,
        &mut output_buffer,
    )
    .unwrap();
    output_buffer.resize(length, 0);
    assert_eq!(&DECRYPTED_DATA[..], &output_buffer[..]);
}

#[test]
fn aead_decrypt_aes_ccm_no_decrypt_usage_flag() {
    let alg = Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm);
    let attributes = Attributes {
        key_type: Type::Aes,
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                ..Default::default()
            },
            permitted_algorithms: alg.into(),
        },
    };
    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
    let output_buffer_size =
        unsafe { psa_crypto_sys::PSA_AEAD_DECRYPT_OUTPUT_SIZE(alg.into(), ENCRYPTED_DATA.len()) };
    let mut output_buffer = vec![0; output_buffer_size];
    let result = aead::decrypt(
        my_key,
        alg,
        &NONCE,
        &ADDITIONAL_DATA,
        &ENCRYPTED_DATA,
        &mut output_buffer,
    );
    assert_eq!(Err(Error::NotPermitted), result);
}

#[test]
fn aead_decrypt_aes_ccm_invalid_signature() {
    const RANDOM_INPUT_DATA: [u8; 23] = [
        0x08, 0xE8, 0xCF, 0x97, 0xD8, 0x20, 0xEA, 0x25, 0x84, 0x60, 0xE9, 0x6A, 0xD9, 0xCF, 0x52,
        0x89, 0x05, 0x4D, 0x89, 0x5C, 0xEA, 0xC4, 0x7C,
    ];
    let alg = Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm);
    let attributes = Attributes {
        key_type: Type::Aes,
        bits: 0,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: UsageFlags {
                decrypt: true,
                ..Default::default()
            },
            permitted_algorithms: alg.into(),
        },
    };
    psa_crypto::init().unwrap();
    let my_key = key_management::import(attributes, None, &KEY_DATA).unwrap();
    let output_buffer_size = unsafe {
        psa_crypto_sys::PSA_AEAD_DECRYPT_OUTPUT_SIZE(alg.into(), RANDOM_INPUT_DATA.len())
    };
    let mut output_buffer = vec![0; output_buffer_size];
    let result = aead::decrypt(
        my_key,
        alg,
        &NONCE,
        &ADDITIONAL_DATA,
        &RANDOM_INPUT_DATA,
        &mut output_buffer,
    );
    assert_eq!(Err(Error::InvalidSignature), result);
}
