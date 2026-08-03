use macrotime;
use rand::RngExt;
use sha1::{Digest, Sha1};
use crate::hash::utils;

pub mod hash;



fn main() {
    let input = "my super message!my super message!my super message!my super message!my super message!my super message!";

    print!("Input: ");
    utils::print_bytes_as_hex(input.as_bytes());

    const INPUT_SIZE: usize = 1000;
    const NB_ITEMS: usize = 1_000_000;

    let mut rng = rand::rng();

    let sources = (0..NB_ITEMS).map(|_| {
        let input: [u8; INPUT_SIZE] = rng.random();
        input
    });

    let t1 = macrotime::time!({
        for src_data in sources {
            let mut hasher = Sha1::new();
            hasher.update(&src_data);
        }
    });

    let sources = (0..1_000_000).map(|_| {
        let input: [u8; INPUT_SIZE] = rng.random();
        input
    });

    let t2 = macrotime::time!({
        for src_data in sources {
            hash::sha1::sha1(&src_data);
        }
    });

    println!("Crate SHA1: {:.2} seconds", t1.as_secs_f32());
    println!("Homemade SHA1: {:.2} seconds ({:.2}x as much)", t2.as_secs_f32(), t2.as_secs_f32() / t1.as_secs_f32());

    let digest = hash::sha1::sha1(input.as_bytes());

    print!("\nHash: ");
    utils::print_bytes_as_hex(&digest);
}
