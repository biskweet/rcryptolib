use std::hint::assert_unchecked;

pub struct DecryptionError;


pub trait BlockCipher<const BLKLEN: usize, const KEYLEN: usize> {
    fn encrypt_block(&mut self, block: &mut [u8; BLKLEN], key: &[u8; KEYLEN]);
    fn decrypt_block(&mut self, block: &mut [u8; BLKLEN], key: &[u8; KEYLEN]);
}

pub trait CBC<const BLKLEN: usize, const KEYLEN: usize>: BlockCipher<BLKLEN, KEYLEN> {
    fn cbc_encrypt(&mut self, indata: &[u8], outdata: &mut [u8], key: &[u8; KEYLEN], iv: &[u8; BLKLEN]) {
        assert_eq!(outdata.len(), (indata.len() / BLKLEN + 1) * BLKLEN, "Output vector of invalid size.");
        unsafe { assert_unchecked( outdata.len().is_multiple_of(BLKLEN) ); }  // Compiler hint

        outdata[..indata.len()].copy_from_slice(indata);

        // Apply padding -- we follow PKCS#7 style padding (pad value is the length of padding)
        for i in indata.len()..outdata.len() {
            outdata[i] = (outdata.len() - indata.len()) as u8;
        }

        let mut iv = *iv;

        let (blocks, _) = outdata.as_chunks_mut::<BLKLEN>();
        for block in blocks {
            // xor iv with block
            block.iter_mut().zip(iv.iter()).for_each(|(x1, x2)| *x1 ^= *x2);

            self.encrypt_block(block, key);
            iv = *block;
        }
    }

    fn cbc_decrypt(&mut self, indata: &[u8], outdata: &mut [u8], key: &[u8; KEYLEN], iv: &[u8; BLKLEN]) {
        assert_eq!(indata.len(), outdata.len(), "Output vector of invalid size.");
        assert!( indata.len().is_multiple_of(BLKLEN) );
        unsafe { assert_unchecked( outdata.len().is_multiple_of(BLKLEN) ); }  // Compiler hint

        outdata[..indata.len()].copy_from_slice(indata);

        let mut iv = *iv;

        let (blocks, _) = outdata.as_chunks_mut::<BLKLEN>();
        let (cipher_blocks, _) = indata.as_chunks::<BLKLEN>();
        for (block, cipher_block) in blocks.iter_mut().zip(cipher_blocks) {
            self.decrypt_block(block, key);

            // xor iv with block
            block.iter_mut().zip(iv.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
            iv = *cipher_block;
        }
    }
}

pub trait ECB<const BLKLEN: usize, const KEYLEN: usize>: BlockCipher<BLKLEN, KEYLEN> {
    fn ecb_encrypt(&mut self, indata: &[u8], outdata: &mut [u8], key: &[u8; KEYLEN]) {
        assert_eq!(outdata.len(), (indata.len() / BLKLEN + 1) * BLKLEN, "Output buffer of invalid size.");
        unsafe { assert_unchecked( outdata.len().is_multiple_of(BLKLEN) ); }  // Compiler hint

        outdata[..indata.len()].copy_from_slice(indata);

        // Apply zero padding for ECB
        for i in indata.len()..outdata.len() {
            outdata[i] = 0;
        }

        let (blocks, _) = outdata.as_chunks_mut::<BLKLEN>();
        for block in blocks {
            self.encrypt_block(block, key);
        }
    }

    fn ecb_decrypt(&mut self, indata: &[u8], outdata: &mut [u8], key: &[u8; KEYLEN]) {
        assert_eq!(indata.len(), outdata.len(), "Output buffer of invalid size.");
        unsafe { assert_unchecked( outdata.len().is_multiple_of(BLKLEN) ); }  // Compiler hint

        outdata[..indata.len()].copy_from_slice(indata);

        let (blocks, _) = outdata.as_chunks_mut::<BLKLEN>();
        for block in blocks {
            self.decrypt_block(block, key);
        }
    }
}

impl<const BLKLEN: usize, const KEYLEN: usize, AnyBlockCipher: BlockCipher<BLKLEN, KEYLEN>> CBC<BLKLEN, KEYLEN> for AnyBlockCipher {}

impl<const BLKLEN: usize, const KEYLEN: usize, AnyBlockCipher: BlockCipher<BLKLEN, KEYLEN>> ECB<BLKLEN, KEYLEN> for AnyBlockCipher {}
