pub fn print_bytes_as_hex(digest: &[u8], wordsize: usize) {
    for (i, byte) in digest.iter().enumerate() {
        if wordsize > 0 && i > 0 && i.is_multiple_of(wordsize) {
            println!();
        }

        print!("{:02x}", byte);
    }
    println!();
}

#[inline]
pub fn array_unpack_u32_u8(a: &[u32], b: &mut [u8]) {
    for (i, word) in a.iter().enumerate() {
        b[i * 4]     = ((word & 0xFF000000) >> 24) as u8;
        b[i * 4 + 1] = ((word & 0x00FF0000) >> 16) as u8;
        b[i * 4 + 2] = ((word & 0x0000FF00) >>  8) as u8;
        b[i * 4 + 3] = ((word & 0x000000FF))       as u8;
    }
}

