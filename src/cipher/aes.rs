// References: FIPS (https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf)
// References: Wiki (https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) and its subarticles

use crate::cipher::aes::common::BlockCipherMode;

macro_rules! gf_timex {
    ($x:expr) => { (($x) << 1) ^ ((($x) >> 7) * 0x1B) };
}

macro_rules! gf_timex_plus1 {
    ($x:expr) => { gf_timex!($x) ^ ($x) };
}


const S : [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
];


const RC : [u8; 10] = [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 ];


type AES128 = AES<16, 176>;  // 176 = 16 * (10 + 1)
type AES192 = AES<24, 208>;  // 208 = 16 * (12 + 1)
type AES256 = AES<32, 240>;  // 240 = 16 * (14 + 1)


struct AES<const KEYLENGTH_IN_BYTES: usize, const EXPLENGTH_IN_BYTES: usize> {
    state: [u8; 16],
    // round: usize,
    expanded_key: [u8; EXPLENGTH_IN_BYTES],
}


impl<const KEYLENGTH_IN_BYTES: usize, const EXPLENGTH_IN_BYTES: usize> AES<KEYLENGTH_IN_BYTES, EXPLENGTH_IN_BYTES> {
    fn new() -> Self {
        let state = [0u8; 16];
        let expanded_key = [0u8; EXPLENGTH_IN_BYTES];

        Self { state, expanded_key }
    }

    fn key_expansion(&mut self, cipher_key: &[u8; KEYLENGTH_IN_BYTES]) {
        let n = KEYLENGTH_IN_BYTES / 4;
        assert!(n == 4 || n == 6 || n == 8);

        self.expanded_key[0..KEYLENGTH_IN_BYTES].copy_from_slice(cipher_key);

        for word_index in n..EXPLENGTH_IN_BYTES / 4 {
            let i = word_index * 4;
            let remainder = word_index % n;

            if remainder == 0 {
                self.expanded_key[i + 0] = self.expanded_key[i + 0 - KEYLENGTH_IN_BYTES] ^ S[self.expanded_key[i - 3] as usize] ^ RC[word_index / n];
                self.expanded_key[i + 1] = self.expanded_key[i + 1 - KEYLENGTH_IN_BYTES] ^ S[self.expanded_key[i - 2] as usize];
                self.expanded_key[i + 2] = self.expanded_key[i + 2 - KEYLENGTH_IN_BYTES] ^ S[self.expanded_key[i - 1] as usize];
                self.expanded_key[i + 3] = self.expanded_key[i + 3 - KEYLENGTH_IN_BYTES] ^ S[self.expanded_key[i - 4] as usize];
            } else if n == 8 && remainder == 4 {
                self.expanded_key[i + 0] = self.expanded_key[i + 0 - KEYLENGTH_IN_BYTES] ^ S[self.expanded_key[i - 4] as usize];
                self.expanded_key[i + 1] = self.expanded_key[i + 1 - KEYLENGTH_IN_BYTES] ^ S[self.expanded_key[i - 3] as usize];
                self.expanded_key[i + 2] = self.expanded_key[i + 2 - KEYLENGTH_IN_BYTES] ^ S[self.expanded_key[i - 2] as usize];
                self.expanded_key[i + 3] = self.expanded_key[i + 3 - KEYLENGTH_IN_BYTES] ^ S[self.expanded_key[i - 1] as usize];
            } else {
                self.expanded_key[i + 0] = self.expanded_key[i + 0 - KEYLENGTH_IN_BYTES] ^ self.expanded_key[i - 4];
                self.expanded_key[i + 1] = self.expanded_key[i + 1 - KEYLENGTH_IN_BYTES] ^ self.expanded_key[i - 3];
                self.expanded_key[i + 2] = self.expanded_key[i + 2 - KEYLENGTH_IN_BYTES] ^ self.expanded_key[i - 2];
                self.expanded_key[i + 3] = self.expanded_key[i + 3 - KEYLENGTH_IN_BYTES] ^ self.expanded_key[i - 1];
            }
        }
    }

    fn sub_bytes(&mut self) {
        for byte in self.state.iter_mut() {
            *byte = S[*byte as usize];
        }
    }

    fn shift_rows(&mut self) {
        let state = &mut self.state;
        ( state[1], state[5], state[9],  state[13] ) = ( state[13], state[1],  state[5],  state[9] );
        ( state[2], state[6], state[10], state[14] ) = ( state[10], state[14], state[2],  state[6] );
        ( state[3], state[7], state[11], state[15] ) = ( state[7],  state[11], state[15], state[3] );
    }

    fn mix_columns(&mut self) {
        let state = &mut self.state;

        for i in (0..16).step_by(4) {
            let (x0, x1, x2, x3) = (state[i], state[i + 1], state[i + 2], state[i + 3]);

            // 2, 3, 1, 1
            state[i + 0] = gf_timex!(x0) ^ gf_timex_plus1!(x1) ^ (x2) ^ (x3);

            // 1, 2, 3, 1
            state[i + 1] = (x0) ^ gf_timex!(x1) ^ gf_timex_plus1!(x2) ^ (x3);

            // 1, 1, 2, 3
            state[i + 2] = (x0) ^ (x1) ^ gf_timex!(x2) ^ gf_timex_plus1!(x3);

            // 3, 1, 1, 2
            state[i + 3] = gf_timex_plus1!(x0) ^ (x1) ^ (x2) ^ gf_timex!(x3);
         }
    }

    fn add_round_key(&mut self, round_index: usize) {
        let round_key = &self.expanded_key[round_index * 16..(round_index + 1) * 16];

        // Assume -O3 will automatically SIMD out the operation
        for i in 0..16 {
            self.state[i] ^= round_key[i];
        }
    }

    fn round(&mut self, round_index: usize) {
        // Alternatively, there is the _mm_aesenc_si128 intrinsic for that.
        // But it's less fun!

        self.sub_bytes();
        self.shift_rows();
        self.mix_columns();
        self.add_round_key(round_index);
    }
}


pub fn aes128(message: &[u8], cipher_key: &[u8], mode: BlockCipherMode) -> Vec<u8> { aes(message, cipher_key, 10, mode) }

pub fn aes192(message: &[u8], cipher_key: &[u8], mode: BlockCipherMode) -> Vec<u8> { aes(message, cipher_key, 12, mode) }

pub fn aes256(message: &[u8], cipher_key: &[u8], mode: BlockCipherMode) -> Vec<u8> { aes(message, cipher_key, 14, mode) }


fn aes(message: &[u8], cipher_key: &[u8], nb_rounds: u32, mode: BlockCipherMode) -> Vec<u8> {
    unimplemented!()
}

#[cfg(test)]
mod tests;
pub mod common;
