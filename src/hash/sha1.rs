// Reference: RFC 3164 (https://www.ietf.org/rfc/rfc3174.txt)

use crate::{bytes_to_word, common};
use crate::utils::array_unpack_u32_u8;

macro_rules! s {
    ($x:expr, $n:expr) => { ($x).rotate_left($n) };
}


macro_rules! f {
    ($t: expr, $B:expr, $C:expr, $D:expr) => {
        if ($t) < 20 {
            ($B) & ($C) | (!($B) & ($D))
        } else if ($t) < 40 {
            ($B) ^ ($C) ^ ($D)
        } else if ($t) < 60 {
            (($B) & ($C)) | (($B) & ($D)) | (($C) & ($D))
        } else {
            ($B) ^ ($C) ^ ($D)
        }
    };
}


macro_rules! k {
    ($t: expr) => {
        if ($t) < 20 {
            0x5A827999
        } else if ($t) < 40 {
            0x6ED9EBA1
        } else if ($t) < 60 {
            0x8F1BBCDC
        } else {
            0xCA62C1D6
        }
    };
}


fn process_block(block: &[u8; 64], hash: &mut [u32; 5]) {
    let mut msg_schedule = [0u32; 80];

    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];
    let mut e = hash[4];

    for t in 0..16 {
        msg_schedule[t] = bytes_to_word!(block, t * 4);

        let temp = s!(a, 5).wrapping_add(f!(t, b, c, d))
                           .wrapping_add(e)
                           .wrapping_add(msg_schedule[t])
                           .wrapping_add(k!(t));
        e = d;
        d = c;
        c = s!(b, 30);
        b = a;
        a = temp;
    }

    for t in 16..80 {
        msg_schedule[t] = s!(
            msg_schedule[t - 3] ^ msg_schedule[t - 8] ^ msg_schedule[t - 14] ^ msg_schedule[t - 16],
            1
        );

        let temp = s!(a, 5).wrapping_add(f!(t, b, c, d))
                           .wrapping_add(e)
                           .wrapping_add(msg_schedule[t])
                           .wrapping_add(k!(t));
        e = d;
        d = c;
        c = s!(b, 30);
        b = a;
        a = temp;
    }

    hash[0] = hash[0].wrapping_add(a);
    hash[1] = hash[1].wrapping_add(b);
    hash[2] = hash[2].wrapping_add(c);
    hash[3] = hash[3].wrapping_add(d);
    hash[4] = hash[4].wrapping_add(e);
}


pub fn sha1(message: &[u8]) -> [u8; 4 * 5] {
    let mut padding = [0u8; 2 * 64];
    let padding_length = common::sha_compute_padding(message, &mut padding, 64, 8);

    let mut hash: [u32; 5] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ];

    let (message_chunks, message_tail) = message.as_chunks::<64>();
    let (padding_head, padding_chunks) = padding[0..padding_length].as_rchunks::<64>();

    for block in message_chunks {
        process_block(block, &mut hash);
    }

    // Now if there a seam between the two arrays, process it
    if message_tail.len() > 0 {
        let mut seam = [0u8; 64];
        seam[..message_tail.len()].copy_from_slice(message_tail);
        seam[message_tail.len()..].copy_from_slice(padding_head);

        process_block(&seam, &mut hash);
    }

    for block in padding_chunks {
        process_block(block, &mut hash);
    }

    let mut digest = [0u8; 4 * 5];

    array_unpack_u32_u8(&hash, &mut digest);

    digest
}
