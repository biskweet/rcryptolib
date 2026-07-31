pub fn sha_compute_padding(message: &[u8], padding: &mut [u8], block_size: usize, message_length_intsize: usize) -> usize {
    // Computes the padding by reference in the mutable parameter, and returns its size in bytes

    let message_length = message.len();

    let last_block_size = message_length % block_size;

    let padding_length = if last_block_size <= (block_size - message_length_intsize) {
        // pad until the end of the current block
        (block_size - message_length_intsize) - last_block_size
    } else {
        // add a second block for padding
        block_size - last_block_size + (block_size - message_length_intsize)
    };

    // Set the first bit at 1 in the padding
    padding[0] = 0b1000_0000;

    // Now write the initial message length in the last 8 bytes
    // Here we are assuming that the target architecture is x64
    for byte_id in 0..message_length_intsize {
        padding[padding_length + message_length_intsize - 1 - byte_id] =
            (((message_length * 8) >> (8 * byte_id)) & 0xFF) as u8;
        //         # of bits in msg
    }

    padding_length + message_length_intsize
}

pub fn print_block(block: &[u8]) {
    for (j, byte) in block.iter().enumerate() {
        if j % 16 == 0 {
            print!("\n");
        } else if j % 4 == 0 {
            print!(" ");
        }

        print!("{:02x}", byte);
    }
    println!();
}

pub fn print_bytes_as_hex(digest: &[u8]) {
    for byte in digest {
        print!("{:02x}", byte);
    }
    println!();
}
