use crate::hash::common::print_bytes_as_hex;
use super::*;

#[test]
fn t_mix_columns() {
    let mut aes = AES256::new();
    aes.state = [
        0x01, 0x01, 0x01, 0x01,
        0x63, 0x47, 0xA2, 0xF0,
        0xF2, 0x0A, 0x22, 0x5C,
        0xC6, 0xC6, 0xC6, 0xC6,
    ];

    let target: [u8; 16] = [
        0x01, 0x01, 0x01, 0x01,
        0x5D, 0xE0, 0x70, 0xBB,
        0x9F, 0xDC, 0x58, 0x9D,
        0xC6, 0xC6, 0xC6, 0xC6,
    ];

    println!("Before");
    print_bytes_as_hex(&aes.state[0..4]);
    print_bytes_as_hex(&aes.state[4..8]);
    print_bytes_as_hex(&aes.state[8..12]);
    print_bytes_as_hex(&aes.state[12..16]);

    aes.mix_columns();

    println!("\nAfter");
    print_bytes_as_hex(&aes.state[0..4]);
    print_bytes_as_hex(&aes.state[4..8]);
    print_bytes_as_hex(&aes.state[8..12]);
    print_bytes_as_hex(&aes.state[12..16]);

    assert!(aes.state[0..4].iter().eq(target[0..4].iter()));
    assert!(aes.state[4..8].iter().eq(target[4..8].iter()));
    assert!(aes.state[8..12].iter().eq(target[8..12].iter()));
    assert!(aes.state[12..16].iter().eq(target[12..16].iter()));
}

fn t_shift_rows() {
    let mut aes = AES256::new();
    aes.state = [
        0x01, 0x01, 0x01, 0x01,
        0x63, 0x47, 0xA2, 0xF0,
        0xF2, 0x0A, 0x22, 0x5C,
        0xC6, 0xC6, 0xC6, 0xC6,
    ];

    let target: [u8; 16] = [
        0x01, 0x01, 0x01, 0x01,
        0xF0, 0x63, 0x47, 0xA2,
        0x22, 0x5C, 0xF2, 0x0A,
        0xC6, 0xC6, 0xC6, 0xC6,
    ];


    println!("Before");
    print_bytes_as_hex(&aes.state[0..4]);
    print_bytes_as_hex(&aes.state[4..8]);
    print_bytes_as_hex(&aes.state[8..12]);
    print_bytes_as_hex(&aes.state[12..16]);

    aes.shift_rows();

    println!("\nAfter");
    print_bytes_as_hex(&aes.state[0..4]);
    print_bytes_as_hex(&aes.state[4..8]);
    print_bytes_as_hex(&aes.state[8..12]);
    print_bytes_as_hex(&aes.state[12..16]);

    assert!(aes.state[0..4].iter().eq(target[0..4].iter()));
    assert!(aes.state[4..8].iter().eq(target[4..8].iter()));
    assert!(aes.state[8..12].iter().eq(target[8..12].iter()));
    assert!(aes.state[12..16].iter().eq(target[12..16].iter()));
}


// fn t_add_round_key() {
//     let mut aes = AES256::new();
//     aes.state = [
//         0x01, 0x01, 0x01, 0x01,
//         0x63, 0x47, 0xA2, 0xF0,
//         0xF2, 0x0A, 0x22, 0x5C,
//         0xC6, 0xC6, 0xC6, 0xC6,
//     ];
//
//     let target: [u8; 16] = [
//         0x01 ^ 0x0F, 0x01 ^ 0x0B, 0x01 ^ 0x07, 0x01 ^ 0x03,
//         0x63 ^ 0x0E, 0x47 ^ 0x0A, 0xA2 ^ 0x06, 0xF0 ^ 0x02,
//         0xF2 ^ 0x0D, 0x0A ^ 0x09, 0x22 ^ 0x05, 0x5C ^ 0x01,
//         0xC6 ^ 0x0C, 0xC6 ^ 0x08, 0xC6 ^ 0x04, 0xC6 ^ 0x00,
//     ];
//
//
//
//
// }