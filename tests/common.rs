pub fn print_bytes_as_hex(digest: &[u8], wordsize: usize) {
    for (i, byte) in digest.iter().enumerate() {
        if wordsize > 0 && i > 0 && i.is_multiple_of(wordsize) {
            println!();
        }

        print!("{:02x}", byte);
    }
    println!();
}
