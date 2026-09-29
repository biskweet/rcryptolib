// References: FIPS (https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf)
// References: Wiki (https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) and its subarticles

use crate::cipher::blockcipher_mode::{BlockCipher};

macro_rules! gf_x2 {
    ($x:expr) => { (($x) << 1) ^ ((($x) >> 7) * 0x1B) };
}

macro_rules! gf_x3 {
    ($x:expr) => { gf_x2!($x) ^ ($x) };
}

macro_rules! gf_x9 {
    ($x:expr) => { gf_x2!(gf_x2!(gf_x2!($x))) ^ $x };
    // ($x:expr) => { gf_x3!(gf_x3!($x)) };
}

macro_rules! gf_x11 {
    ($x:expr) => { gf_x2!(gf_x2!(gf_x2!($x)) ^ $x) ^ $x };
    // ($x:expr) => { gf_x2!(gf_x2!(gf_x2!($x)) ^ $x) ^ $x };
}

macro_rules! gf_x13 {
    ($x:expr) => { gf_x2!(gf_x2!(gf_x2!($x) ^ $x)) ^ $x };
    // ($x:expr) => { gf_x2!(gf_x2!(gf_x2!($x)) ^ $x) ^ $x };
}

macro_rules! gf_x14 {
    ($x:expr) => { gf_x2!(gf_x2!(gf_x2!($x) ^ $x) ^ $x) };
    // ($x:expr) => { gf_x2!(gf_x3!(gf_x2!($x)) ^ $x) };
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


const SINV : [u8; 256] = [
   0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
   0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
   0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
   0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
   0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
   0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
   0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
   0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
   0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
   0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
   0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
   0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
   0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
   0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
   0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
   0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
];


const RC : [u8; 10] = [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 ];


pub struct AES<const BLKLEN: usize, const KEYLEN: usize, const EXPLEN: usize, const NROUNDS: usize> {
    pub expanded_key: [u8; EXPLEN],
}

impl<const BLKLEN: usize, const KEYLEN: usize, const EXPLEN: usize, const NROUNDS: usize> AES<BLKLEN, KEYLEN, EXPLEN, NROUNDS> {
    pub fn key_expansion(&mut self, cipher_key: &[u8; KEYLEN]) {
        let n = KEYLEN / 4;
        assert!(n == 4 || n == 6 || n == 8);

        self.expanded_key[0..KEYLEN].copy_from_slice(cipher_key);

        for word_index in n..EXPLEN / 4 {
            let i = word_index * 4;
            let remainder = word_index % n;

            if remainder == 0 {
                self.expanded_key[i + 0] = self.expanded_key[i + 0 - KEYLEN] ^ S[self.expanded_key[i - 3] as usize] ^ RC[word_index / n - 1];
                self.expanded_key[i + 1] = self.expanded_key[i + 1 - KEYLEN] ^ S[self.expanded_key[i - 2] as usize];
                self.expanded_key[i + 2] = self.expanded_key[i + 2 - KEYLEN] ^ S[self.expanded_key[i - 1] as usize];
                self.expanded_key[i + 3] = self.expanded_key[i + 3 - KEYLEN] ^ S[self.expanded_key[i - 4] as usize];
            } else if n == 8 && remainder == 4 {
                self.expanded_key[i + 0] = self.expanded_key[i + 0 - KEYLEN] ^ S[self.expanded_key[i - 4] as usize];
                self.expanded_key[i + 1] = self.expanded_key[i + 1 - KEYLEN] ^ S[self.expanded_key[i - 3] as usize];
                self.expanded_key[i + 2] = self.expanded_key[i + 2 - KEYLEN] ^ S[self.expanded_key[i - 2] as usize];
                self.expanded_key[i + 3] = self.expanded_key[i + 3 - KEYLEN] ^ S[self.expanded_key[i - 1] as usize];
            } else {
                self.expanded_key[i + 0] = self.expanded_key[i + 0 - KEYLEN] ^ self.expanded_key[i - 4];
                self.expanded_key[i + 1] = self.expanded_key[i + 1 - KEYLEN] ^ self.expanded_key[i - 3];
                self.expanded_key[i + 2] = self.expanded_key[i + 2 - KEYLEN] ^ self.expanded_key[i - 2];
                self.expanded_key[i + 3] = self.expanded_key[i + 3 - KEYLEN] ^ self.expanded_key[i - 1];
            }
        }
    }

    fn add_round_key(&mut self, state: &mut [u8; BLKLEN], round_index: usize) {
        let round_key = &self.expanded_key[round_index * BLKLEN..round_index * BLKLEN + BLKLEN];

        // Assume -O3 will SIMD out the operation automatically
        for i in 0..BLKLEN {
            state[i] ^= round_key[i];
        }
    }

    fn sub_bytes(&mut self, state: &mut [u8; BLKLEN]) {
        for byte in state.iter_mut() {
            *byte = S[*byte as usize];
        }
    }

    fn shift_rows(&mut self, state: &mut [u8; BLKLEN]) {
        ( state[1], state[5], state[9],  state[13] ) = ( state[5],  state[9],  state[13], state[1]  );
        ( state[2], state[6], state[10], state[14] ) = ( state[10], state[14], state[2],  state[6]  );
        ( state[3], state[7], state[11], state[15] ) = ( state[15], state[3],  state[7],  state[11] );
    }

    fn mix_columns(&mut self, state: &mut [u8; BLKLEN]) {
        for i in (0..16).step_by(4) {
            let (x0, x1, x2, x3) = (state[i], state[i + 1], state[i + 2], state[i + 3]);

            // 2, 3, 1, 1
            state[i + 0] = gf_x2!(x0) ^ gf_x3!(x1) ^ (x2) ^ (x3);

            // 1, 2, 3, 1
            state[i + 1] = (x0) ^ gf_x2!(x1) ^ gf_x3!(x2) ^ (x3);

            // 1, 1, 2, 3
            state[i + 2] = (x0) ^ (x1) ^ gf_x2!(x2) ^ gf_x3!(x3);

            // 3, 1, 1, 2
            state[i + 3] = gf_x3!(x0) ^ (x1) ^ (x2) ^ gf_x2!(x3);
         }
    }

    fn round(&mut self, state: &mut [u8; BLKLEN], round_index: usize) {
        // Alternatively, there is the _mm_aesenc_si128 intrinsic for that.
        // But it's less fun!

        self.sub_bytes(state);
        self.shift_rows(state);
        self.mix_columns(state);
        self.add_round_key(state, round_index);
    }

    fn sub_bytes_inv(&mut self, state: &mut [u8; BLKLEN]) {
        for byte in state.iter_mut() {
            *byte = SINV[*byte as usize];
        }
    }

    fn shift_rows_inv(&mut self, state: &mut [u8; BLKLEN]) {
        ( state[1], state[5], state[9],  state[13] ) = ( state[13], state[1],  state[5],  state[9] );
        ( state[2], state[6], state[10], state[14] ) = ( state[10], state[14], state[2],  state[6] );
        ( state[3], state[7], state[11], state[15] ) = ( state[7],  state[11], state[15], state[3] );
    }

    fn mix_columns_inv(&mut self, state: &mut [u8; BLKLEN]) {
        for i in (0..16).step_by(4) {
            let (x0, x1, x2, x3) = (state[i], state[i + 1], state[i + 2], state[i + 3]);

            // 14, 11, 13, 9
            state[i + 0] = gf_x14!(x0) ^ gf_x11!(x1) ^ gf_x13!(x2) ^ gf_x9!(x3);

            // 9, 14, 11, 13
            state[i + 1] = gf_x9!(x0) ^ gf_x14!(x1) ^ gf_x11!(x2) ^ gf_x13!(x3);

            // 13, 9, 14, 11
            state[i + 2] = gf_x13!(x0) ^ gf_x9!(x1) ^ gf_x14!(x2) ^ gf_x11!(x3);

            // 11, 13, 9, 14
            state[i + 3] = gf_x11!(x0) ^ gf_x13!(x1) ^ gf_x9!(x2) ^ gf_x14!(x3);
         }
    }

    fn round_inv(&mut self, state: &mut [u8; BLKLEN], round_index: usize) {
        self.add_round_key(state, round_index);
        self.mix_columns_inv(state);
        self.shift_rows_inv(state);
        self.sub_bytes_inv(state);
    }
}


impl<const BLKLEN: usize, const KEYLEN: usize, const EXPLEN: usize, const NROUNDS: usize> BlockCipher<BLKLEN, KEYLEN> for AES<BLKLEN, KEYLEN, EXPLEN, NROUNDS> {
    fn encrypt_block(&mut self, block: &mut [u8; BLKLEN], key: &[u8; KEYLEN]) {
        // self.reset();

        self.key_expansion(key);
        self.add_round_key(block, 0);

        // block.copy_from_slice(&u128::to_be_bytes(0x875e402f063d6e732b5f3019bb801a85));
        for i in 1..NROUNDS {
            self.round(block, i);
        }

        self.sub_bytes(block);
        self.shift_rows(block);
        self.add_round_key(block, NROUNDS);
    }

    fn decrypt_block(&mut self, block: &mut [u8; BLKLEN], key: &[u8; KEYLEN]) {
        self.key_expansion(key);

        self.add_round_key(block, NROUNDS);

        self.shift_rows_inv(block);
        self.sub_bytes_inv(block);

        for i in (1..NROUNDS).rev() {
            self.round_inv(block, i);
        }

        self.add_round_key(block, 0);
    }
}


impl AES<16, 16, 176, 10> {
    pub fn new() -> Self {
        let expanded_key = [0u8; 176];

        Self { expanded_key }
    }
}

impl AES<16, 24, 208, 12> {
    pub fn new() -> Self {
        let expanded_key = [0u8; 208];

        Self { expanded_key }
    }
}

impl AES<16, 32, 240, 14> {
    pub fn new() -> Self {
        let expanded_key = [0u8; 240];

        Self { expanded_key }
    }
}


pub type AES128 = AES<16, 16, 176, 10>;
pub type AES192 = AES<16, 24, 208, 12>;
pub type AES256 = AES<16, 32, 240, 14>;


impl Default for AES128 {
    fn default() -> Self { Self::new() }
}


impl Default for AES192 {
    fn default() -> Self { Self::new() }
}


impl Default for AES256 {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests;
