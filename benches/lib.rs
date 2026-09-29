#![feature(test)]

extern crate test;

use rand::{RngExt};
use rcryptolib::hash::sha1::sha1;
use rcryptolib::hash::sha2::sha2;

use sha1::Digest;
use sha1::Sha1;
use sha2::Sha256;


fn sha1_crate(bytes: &[u8]) {
    let mut sh = Sha1::new();
    sh.update(&bytes);
}


fn sha256_crate(bytes: &[u8]) {
    let mut sh = Sha256::new();
    sh.update(&bytes);
}


macro_rules! gen_bench {
    ($func:ident, $size:expr, $identifier:ident) => {
        #[bench]
        fn $identifier(bencher: &mut test::Bencher) {
            let mut data = vec![0u8; $size];
            rand::rng().fill(&mut data);

            bencher.iter(|| {
                $func(&data);
            });
        }
    };
}


gen_bench!(sha1, 1_000, sha1_1_000);
gen_bench!(sha1, 10_000, sha1_10_000);
gen_bench!(sha1, 100_000, sha1_100_000);
gen_bench!(sha1, 1_000_000, sha1_1_000_000);

gen_bench!(sha1_crate, 1_000, sha1_crate_1_000);
gen_bench!(sha1_crate, 10_000, sha1_crate_10_000);
gen_bench!(sha1_crate, 100_000, sha1_crate_100_000);
gen_bench!(sha1_crate, 1_000_000, sha1_crate_1_000_000);

gen_bench!(sha2, 1_000, sha2_1_000);
gen_bench!(sha2, 10_000, sha2_10_000);
gen_bench!(sha2, 100_000, sha2_100_000);
gen_bench!(sha2, 1_000_000, sha2_1_000_000);

gen_bench!(sha256_crate, 1_000, sha256_crate_1_000);
gen_bench!(sha256_crate, 10_000, sha256_crate_10_000);
gen_bench!(sha256_crate, 100_000, sha256_crate_100_000);
gen_bench!(sha256_crate, 1_000_000, sha256_crate_1_000_000);
