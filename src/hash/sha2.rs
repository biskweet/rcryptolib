// Reference: RFC 6234 (https://www.ietf.org/rfc/rfc6234.txt)

use crate::bytes_to_word;
use crate::hash::utils;

macro_rules! shr   { ($x:expr, $n:expr) => { ($x) >> ($n) } }

macro_rules! rotr  { ($x:expr, $n:expr) => { ($x).rotate_right($n) } }

macro_rules! ch    { ($x:expr, $y:expr, $z:expr) => { (($x) & ($y)) ^ ((!($x)) & ($z)) } }

macro_rules! maj   { ($x:expr, $y:expr, $z:expr) => { ($x) & (($y) | ($z)) | (($y) & ($z)) } }

macro_rules! bsig0 { ($x:expr) => { rotr!($x,  2) ^ rotr!($x, 13) ^ rotr!($x, 22) } }

macro_rules! bsig1 { ($x:expr) => { rotr!($x,  6) ^ rotr!($x, 11) ^ rotr!($x, 25) } }

macro_rules! ssig0 { ($x:expr) => { rotr!($x,  7) ^ rotr!($x, 18) ^  shr!($x,  3) } }

macro_rules! ssig1 { ($x:expr) => { rotr!($x, 17) ^ rotr!($x, 19) ^  shr!($x, 10) } }


const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];


fn process_block(block: &[u8; 64], hash: &mut[u32; 8]) {
    let mut message_schedule = [0u32; 64];

    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];
    let mut e = hash[4];
    let mut f = hash[5];
    let mut g = hash[6];
    let mut h = hash[7];

    for t in (0..64).step_by(4) {
        message_schedule[t / 4] = bytes_to_word!(block, t);

        let t1 = h + bsig1!(e) + ch!(e, f, g) + K[t / 4] + message_schedule[t / 4];
        let t2 = bsig0!(a) + maj!(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    for t in 16..64 {
        message_schedule[t] =
            ssig1!(message_schedule[t - 2])  + message_schedule[t - 7] +
            ssig0!(message_schedule[t - 15]) + message_schedule[t - 16];

        let t1 = h + bsig1!(e) + ch!(e, f, g) + K[t] + message_schedule[t];
        let t2 = bsig0!(a) + maj!(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }


    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}


fn sha256(message: &[u8], padding: &[u8]) -> [u32; 8] {
    let mut hash: [u32; 8] = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    let (message_chunks, message_tail) = message.as_chunks::<64>();
    let (padding_head, padding_chunks) = padding.as_rchunks::<64>();

    for chunk in message_chunks {
        process_block(chunk, &mut hash);
    }

    // Now if there a seam between the two arrays, process it
    if message_tail.len() > 0 {
        let mut seam = [0u8; 64];
        seam[..message_tail.len()].copy_from_slice(message_tail);
        seam[message_tail.len()..].copy_from_slice(padding_head);

        process_block(&seam, &mut hash);
    }

    for chunk in padding_chunks {
        process_block(chunk, &mut hash);
    }

    hash
}


pub fn sha2(message: &[u8]) -> [u8; 4 * 8] {
    let mut padding = [0u8; 2 * 64];
    let padding_length = utils::sha_compute_padding(message, &mut padding, 64, 8);

    let hash = sha256(message, &padding[0..padding_length]);

    let mut digest = [0u8; 4 * 8];

    for (i, word) in hash.iter().enumerate() {
        digest[i * 4]     = ((word & 0xFF000000) >> 24) as u8;
        digest[i * 4 + 1] = ((word & 0x00FF0000) >> 16) as u8;
        digest[i * 4 + 2] = ((word & 0x0000FF00) >>  8) as u8;
        digest[i * 4 + 3] = ((word & 0x000000FF))       as u8;
    }

    digest
}
