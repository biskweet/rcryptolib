use macrotime;
use rand::RngExt;
use sha2::{Digest, Sha256};
use crate::hash::utils;

pub mod hash;



fn main() {
    let input = "my super message!";

    println!("Input: {:x?}", input.as_bytes());

    let mut rng = rand::rng();

    const INPUT_SIZE: usize = 1000;

    let sources = (0..1_000_000).map(|_| {
        let input: [u8; INPUT_SIZE] = rng.random();
        input
    });

    let t1 = macrotime::time!({
        for src_data in sources {
            let mut hasher = Sha256::new();
            hasher.update(&src_data);
        }
    });

    let sources = (0..1_000_000).map(|_| {
        let input: [u8; INPUT_SIZE] = rng.random();
        input
    });

    let t2 = macrotime::time!({
        for src_data in sources {
            hash::sha2::sha2(&src_data);
        }
    });

    println!("Crate SHA256: {:.2} seconds", t1.as_secs_f32());
    println!("Homemade SHA256: {:.2} seconds ({:.2}x as much)", t2.as_secs_f32(), t2.as_secs_f32() / t1.as_secs_f32());

    let digest = hash::sha2::sha2(input.as_bytes());

    print!("\nHash: ");
    utils::print_bytes_as_hex(&digest);
}
