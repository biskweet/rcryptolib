#[path = "common.rs"]
mod common;
use common::print_bytes_as_hex;

use rcryptolib::cipher::aes::{AES128, AES192, AES256};
use rcryptolib::cipher::blockcipher_mode::{BlockCipher};

#[test]
fn t_aes128() {
    let mut aes = AES128::new();

    // FIPS example
    let original = u128::to_be_bytes(0x3243f6a8885a308d313198a2e0370734);
    let seckey = u128::to_be_bytes(0x2b7e151628aed2a6abf7158809cf4f3c);
    let target = u128::to_be_bytes(0x3925841d02dc09fbdc118597196a0b32);

    let mut data = original.clone();
    aes.encrypt_block(&mut data, &seckey);

    print!("\nOutput encryption: ");
    (&data, 0);

    assert_eq!(data, target);

    aes.decrypt_block(&mut data, &seckey);

    print!("\nOutput decryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, original);

    // ==========

    let original = u128::to_be_bytes(0x00000000000000000000000000000000);
    let seckey = u128::to_be_bytes(0x0123456789ABCDEF0123456789ABCDEF);
    let target = u128::to_be_bytes(0x79ABC5C23868AD84D388CE61110A6274);

    let mut data = original.clone();
    aes.encrypt_block(&mut data, &seckey);

    print!("\nOutput encryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, target);

    aes.decrypt_block(&mut data, &seckey);

    print!("\nOutput decryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, original);

    // ==========

    let original = u128::to_be_bytes(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    let seckey = u128::to_be_bytes(0x0123456789ABCDEF0123456789ABCDEF);
    let target = u128::to_be_bytes(0xD15601BA930B26C3D04EBCB530C68D90);

    let mut data = original.clone();
    aes.encrypt_block(&mut data, &seckey);

    print!("\nOutput encryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, target);

    aes.decrypt_block(&mut data, &seckey);

    print!("\nOutput decryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, original);
}


#[test]
fn t_aes192() {
    let mut aes = AES192::new();

    // FIPS example
    let original : [u8; _] = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
    let seckey : [u8; _]   = [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b];
    let target : [u8; _]   = [0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc];

    let mut data = original.clone();
    aes.encrypt_block(&mut data, &seckey);

    print!("\nOutput encryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, target);

    aes.decrypt_block(&mut data, &seckey);

    print!("\nOutput decryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, original);

    // ==========

    let original : [u8; _] = u128::to_be_bytes(0x00112233445566778899aabbccddeeff);
    let seckey : [u8; _]   = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    let target : [u8; _]   = u128::to_be_bytes(0xdda97ca4864cdfe06eaf70a0ec0d7191);

    let mut data = original.clone();
    aes.encrypt_block(&mut data, &seckey);

    print!("\nOutput encryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, target);

    aes.decrypt_block(&mut data, &seckey);

    print!("\nOutput decryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, original);
}


#[test]
fn t_aes256() {
    let mut aes = AES256::new();

    // FIPS example
    let original : [u8; _] = u128::to_be_bytes(0x00112233445566778899aabbccddeeff);
    let seckey : [u8; _]   = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
    let target : [u8; _]   = u128::to_be_bytes(0x8ea2b7ca516745bfeafc49904b496089);

    let mut data = original.clone();
    aes.encrypt_block(&mut data, &seckey);

    print!("\nOutput encryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, target);

    aes.decrypt_block(&mut data, &seckey);

    print!("\nOutput decryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, original);

    // ==========

    let original : [u8; _] = u128::to_be_bytes(0x6bc1bee22e409f96e93d7e117393172a);
    let seckey : [u8; _]   = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];
    let target : [u8; _]   = u128::to_be_bytes(0xf3eed1bdb5d2a03c064b5a7e3db181f8);

    let mut data = original.clone();
    aes.encrypt_block(&mut data, &seckey);

    print!("\nOutput encryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, target);

    aes.decrypt_block(&mut data, &seckey);

    print!("\nOutput decryption: ");
    print_bytes_as_hex(&data, 0);

    assert_eq!(data, original);
}
