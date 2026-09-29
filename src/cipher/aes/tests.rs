use crate::common::print_bytes_as_hex;
use super::*;

#[test]
fn t_mix_columns() {
    let mut aes = AES256::new();

    let source = [
        0x01, 0x01, 0x01, 0x01,
        0x63, 0x47, 0xA2, 0xF0,
        0xF2, 0x0A, 0x22, 0x5C,
        0xC6, 0xC6, 0xC6, 0xC6,
    ];

    let mut state = source.clone();

    let target: [u8; 16] = [
        0x01, 0x01, 0x01, 0x01,
        0x5D, 0xE0, 0x70, 0xBB,
        0x9F, 0xDC, 0x58, 0x9D,
        0xC6, 0xC6, 0xC6, 0xC6,
    ];

    println!("Before");
    print_bytes_as_hex(&state, 4);

aes.mix_columns(&mut state);

    println!("\nAfter");
    print_bytes_as_hex(&state, 4);

    assert_eq!(state, target);
}


#[test]
fn t_shift_rows() {
    let mut aes = AES128::new();
    let source : [u8; 16] = [
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];

    let mut state = source.clone();

    let target : [u8; 16] = [
        0x00, 0x05, 0x0a, 0x0f,
        0x04, 0x09, 0x0e, 0x03,
        0x08, 0x0d, 0x02, 0x07,
        0x0c, 0x01, 0x06, 0x0b,
    ];


    println!("Before");
    print_bytes_as_hex(&state, 4);

    aes.shift_rows(&mut state);

    println!("\nAfter");
    print_bytes_as_hex(&state, 4);

    assert_eq!(state, target);
}

#[test]
fn t_shift_rows_inv() {
    let mut aes = AES128::new();
    let source : [u8; 16] = [
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
    ];

    let mut state = source.clone();

    aes.shift_rows(&mut state);
    aes.shift_rows_inv(&mut state);

    assert_eq!(state, source);
}


#[test]
fn t_mix_columns_inv() {
    let mut aes = AES128::new();
    let source : [u8; 16] = [
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
    ];

    let mut state = source.clone();

    aes.mix_columns(&mut state);
    aes.mix_columns_inv(&mut state);

    assert_eq!(state, source);
}
