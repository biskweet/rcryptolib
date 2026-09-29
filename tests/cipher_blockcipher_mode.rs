#[path = "common.rs"]
mod common;
use common::print_bytes_as_hex;

use rcryptolib::cipher::aes::{AES128};
use rcryptolib::cipher::blockcipher_mode::{CBC, ECB};

#[test]
fn t_cbc() {
    let mut aes = AES128::new();

    let indata = "input data long input data".as_bytes();
    let seckey : [u8; 16] = u128::to_be_bytes(0x0123456789ABCDEF0123456789ABCDEF);
    let iv : [u8; 16] = u128::to_be_bytes(0xBADDCAFEDEADBEEF01234567890FF1CE);

    print!("Key: ");
    print_bytes_as_hex(&seckey, 0);

    print!("IV: ");
    print_bytes_as_hex(&iv, 0);

    let mut encrypted = vec![0; (indata.len() / 16 + 1) * 16];
    aes.cbc_encrypt(
        indata,
        &mut encrypted,
        &seckey,
        &iv,
    );

    print!("\nOutput: ");
    print_bytes_as_hex(&encrypted, 0);

    let target = [
        0x3D, 0xD5, 0xB3, 0x59, 0xA6, 0x59, 0x6E, 0x7D,
        0x72, 0x4A, 0x05, 0x36, 0xE1, 0x79, 0xB6, 0xDF,
        0x6E, 0xC8, 0x0F, 0x09, 0x40, 0xDE, 0xF1, 0x88,
        0x6D, 0x65, 0xA0, 0xBF, 0x9B, 0x7A, 0xA7, 0xBD
    ];

    print!("Target: ");
    print_bytes_as_hex(&target, 0);

    assert_eq!(target, encrypted[..]);

    let mut decrypted = vec![0; encrypted.len()];
    aes.cbc_decrypt(
        &encrypted,
    &mut decrypted,
        &seckey,
        &iv,
    );

    print!("\nDecrypted output: ");
    println!("{:?}", decrypted);

    assert_eq!(indata[..26], decrypted[..26]);

    // =============

    let indata = "exact blocksize exact blocksize!".as_bytes();
    let seckey : [u8; 16] = u128::to_be_bytes(0x0123456789ABCDEF0123456789ABCDEF);
    let iv : [u8; 16] = u128::to_be_bytes(0xBADDCAFEDEADBEEF01234567890FF1CE);

    print!("Key: ");
    print_bytes_as_hex(&seckey, 0);

    print!("IV: ");
    print_bytes_as_hex(&iv, 0);

    let mut encrypted = vec![0; (indata.len() / 16 + 1) * 16];
    aes.cbc_encrypt(
        indata,
        &mut encrypted,
        &seckey,
        &iv,
    );

    print!("\nOutput: ");
    print_bytes_as_hex(&encrypted, 0);

    let target = [
        0xF8, 0x3E, 0x5F, 0x1A, 0xA4, 0x66, 0x71, 0x8B,
        0x1D, 0x64, 0x14, 0x19, 0x78, 0x7D, 0x7E, 0xF7,
        0x0C, 0x82, 0x9C, 0x22, 0xA3, 0xA2, 0xA2, 0x1E,
        0x10, 0x97, 0xC8, 0x70, 0x56, 0xBE, 0x5D, 0xA1,
        0xC1, 0x73, 0xB5, 0x54, 0x4D, 0x3B, 0x9E, 0xE3,
        0xAB, 0xE3, 0x6F, 0x6B, 0x26, 0x76, 0x70, 0xB6
    ];

    print!("Target: ");
    print_bytes_as_hex(&target, 0);

    assert_eq!(target, encrypted[..]);

    let mut decrypted = vec![0; encrypted.len()];
    aes.cbc_decrypt(
        &encrypted,
    &mut decrypted,
        &seckey,
        &iv,
    );

    print!("\nDecrypted output: ");
    println!("{:?}", decrypted);

    assert_eq!(indata[..32], decrypted[..32]);
}

#[test]
fn t_ecb() {
    let mut aes = AES128::new();

    let indata = "input data long input data".as_bytes();
    let seckey : [u8; 16] = u128::to_be_bytes(0x0123456789ABCDEF0123456789ABCDEF);
    let iv : [u8; 16] = u128::to_be_bytes(0xBADDCAFEDEADBEEF01234567890FF1CE);

    print!("Key: ");
    print_bytes_as_hex(&seckey, 0);

    print!("IV: ");
    print_bytes_as_hex(&iv, 0);

    let mut encrypted = vec![0; (indata.len() / 16 + 1) * 16];
    aes.ecb_encrypt(
        indata,
        &mut encrypted,
        &seckey,
    );

    print!("\nOutput: ");
    print_bytes_as_hex(&encrypted, 0);

    let target = [
        0x52, 0xA6, 0x11, 0xEC, 0x17, 0x49, 0x8B, 0x44,
        0xAA, 0x09, 0xEC, 0x50, 0xBE, 0x3E, 0x4E, 0xFB,
        0x47, 0xD3, 0x6F, 0x9D, 0x7A, 0x11, 0x8A, 0xA7,
        0xAC, 0xC1
    ];

    print!("Target: ");
    print_bytes_as_hex(&target, 0);

    assert_eq!(target, encrypted[..26]);

    let mut decrypted = vec![0; encrypted.len()];
    aes.ecb_decrypt(
        &encrypted,
    &mut decrypted,
        &seckey,
    );

    print!("\nDecrypted output: ");
    println!("{:?}", decrypted);

    assert_eq!(indata[..], decrypted[..26]);
}
