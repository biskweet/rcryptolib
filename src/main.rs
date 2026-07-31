use macrotime::dbg_time;
use rand::RngExt;
use sha2::{Digest, Sha256};
use crate::hash::utils;

pub mod hash;



fn main() {
    let input = "my super message!";

    println!("Input: {:x?}", input.as_bytes());

    let mut rng = rand::rng();

    const INPUT_SIZE: usize = 500;

    let sources = (0..1_000_000).map(|_| {
        let input: [u8; INPUT_SIZE] = rng.random();
        input
    });

    dbg_time!("homemade sha256", {
        for src_data in sources {
            hash::sha2::sha2(&src_data);
            // let mut hasher = Sha256::new();
            // hasher.update(&src_data);
        }
    });

    let sources = (0..1_000_000).map(|_| {
        let input: [u8; INPUT_SIZE] = rng.random();
        input
    });

    dbg_time!("crate sha256", {
        for src_data in sources {
            let mut hasher = Sha256::new();
            hasher.update(&src_data);
        }
    });

    let digest = hash::sha2::sha2(input.as_bytes());

    print!("\nHash: ");
    utils::print_bytes_as_hex(&digest);
}
