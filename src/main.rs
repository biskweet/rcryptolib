use macrotime;
use rand::{random, RngExt};

use rcryptolib::hash::sha1::sha1;
use rcryptolib::hash::sha2::sha2;

use sha1::Digest;
use sha1::Sha1;
use sha2::Sha256;
use rcryptolib::common::array_unpack_u32_u8;

fn deinterleave32_naive(input: &u32) -> (u16, u16) {
    let mut output1 = 0;
    let mut output2 = 0;
    for i in (0..32).step_by(2) {
        output1 <<= 1;
        output1 |= ((input >> i) & 1) as u16;
    }

    for i in (1..32).step_by(2) {
        output2 <<= 1;
        output2 |= ((input >> i) & 1) as u16;
    }

    (output1, output2)
}


fn deinterleave32_naive_v2(input: &u32) -> (u16, u16) {
    let mut output1 = 0;
    let mut output2 = 0;
    for i in 0..16 {
        output1 <<= 1;
        output1 |= ((input >> (i * 2)) & 1) as u16;
    }

    for i in 0..16 {
        output2 <<= 1;
        // println!("{}", i * 2 + 1);
        output2 |= ((input >> (i * 2 + 1)) & 1) as u16;
    }

    (output1, output2)
}



fn deinterleave32_naive_v3(input: &u32) -> (u16, u16) {
    let mut output1 = 0;
    let mut output2 = 0;
    for i in 0..16 {
        let j: u32 = i * 2;
        output1 <<= 1;
        output1 |= ((input >> (j)) & 1) as u16;
        output2 <<= 1;
        output2 |= ((input >> (j + 1)) & 1) as u16;
    }

    (output1, output2)
}


fn deinterleave32_naive_v3_noextract(input: &u32) -> (u16, u16) {
    let mut output1 = 0;
    let mut output2 = 0;
    for i in 0..16 {
        output1 <<= 1;
        output1 |= ((input >> (i * 2)) & 1) as u16;
        output2 <<= 1;
        output2 |= ((input >> (i * 2 + 1)) & 1) as u16;
    }

    (output1, output2)
}


fn deinterleave32(input: &u32) -> (u16, u16) {
    let input = *input as u64;
    let mut output = (((input) << 31) | input) & 0x5555555555555555;
    output = (output | (output >> 1)) & 0x3333333333333333;
    output = (output | (output >> 2)) & 0x0f0f0f0f0f0f0f0f;
    output = (output | (output >> 4)) & 0x00ff00ff00ff00ff;
    output = output | (output >> 8);

    ((output & 0xffff) as u16, (output >> 32) as u16)
}

fn unpacker_idiomatic(hash: &[u32; 5]) -> [u8; 20] {
    let mut digest = [0u8; 4 * 5];

    digest[0..4].copy_from_slice(&hash[0].to_be_bytes());
    digest[4..8].copy_from_slice(&hash[1].to_be_bytes());
    digest[8..12].copy_from_slice(&hash[2].to_be_bytes());
    digest[12..16].copy_from_slice(&hash[3].to_be_bytes());
    digest[16..20].copy_from_slice(&hash[4].to_be_bytes());

    digest
}

fn unpacker_idiomatic_elegant(hash: &[u32; 5]) -> [u8; 20] {
    let mut digest = [0u8; 4 * 5];

    for (i, word) in hash.iter().enumerate() {
        digest[i * 4.. (i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }

    digest
}


fn unpacker_c(hash: &[u32; 5]) -> [u8; 20] {
    let mut digest = [0u8; 4 * 5];

    array_unpack_u32_u8(hash, &mut digest);

    digest
}


#[allow(dead_code)]
fn benchmark_unpacker() {
    let src : u32 = random();



    macrotime::dbg_time!("deinterleave32", {
        for _ in 0..10_000_000 {
            let _result = deinterleave32(&src);
        }
    });

    macrotime::dbg_time!("deinterleave32_naive", {
        for _ in 0..10_000_000 {
            let _result = deinterleave32_naive(&src);
        }
    });

    macrotime::dbg_time!("deinterleave32_naive_v2", {
        for _ in 0..10_000_000 {
            let _result = deinterleave32_naive_v2(&src);
        }
    });

    macrotime::dbg_time!("deinterleave32_naive_v3", {
        for _ in 0..10_000_000 {
            let _result = deinterleave32_naive_v3(&src);
        }
    });

    macrotime::dbg_time!("deinterleave32_naive_v3_noextract", {
        for _ in 0..10_000_000 {
            let _result = deinterleave32_naive_v3_noextract(&src);
        }
    });

    let src : [u32; 5] = random();

    macrotime::dbg_time!("unpacker_idiomatic", {
        for _ in 0..100_000_000 {
            let _result = unpacker_idiomatic(&src);
        }
    });

    macrotime::dbg_time!("unpacker_idiomatic_elegant", {
        for _ in 0..100_000_000 {
            let _result = unpacker_idiomatic_elegant(&src);
        }
    });

    macrotime::dbg_time!("unpacker_c", {
        for _ in 0..100_000_000 {
            let _result = unpacker_c(&src);
        }
    });
}


#[allow(dead_code)]
fn benchmark_sha1() {
    const INPUT_SIZE: usize = 1000;
    const NB_ITEMS: usize = 1_000_000;
    let mut src_data = vec![0u8; NB_ITEMS];
    rand::rng().fill(&mut src_data);

    macrotime::dbg_time!("Homemade SHA1", {
        let (chunks, _) = src_data.as_chunks::<INPUT_SIZE>();
        for data in chunks {
            sha1(data);
        }
    });

    macrotime::dbg_time!("Crate SHA1", {
        let (chunks, _) = src_data.as_chunks::<INPUT_SIZE>();
        for data in chunks {
            let mut hasher = Sha1::new();
            hasher.update(data);
        }
    });
}


#[allow(dead_code)]
fn benchmark_sha2() {
    const INPUT_SIZE: usize = 10_000;
    const NB_ITEMS: usize = 1_000_000;
    let mut src_data = vec![0u8; NB_ITEMS];
    rand::rng().fill(&mut src_data);

    macrotime::dbg_time!("Homemade SHA256", {
        let (chunks, _) = src_data.as_chunks::<INPUT_SIZE>();
        for data in chunks {
            sha2(data);
        }
    });

    macrotime::dbg_time!("Crate SHA256", {
        let (chunks, _) = src_data.as_chunks::<INPUT_SIZE>();
        for data in chunks {
            let mut hasher = Sha256::new();
            hasher.update(data);
        }
    });
}

pub fn main() {
    benchmark_sha1();
    benchmark_sha2();
}
