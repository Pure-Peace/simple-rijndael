use crate::{
    paddings::{Padding, Pkcs7Padding, ZeroPadding},
    rijndael::Rijndael,
    Errors,
};

macro_rules! impl_rijndael_cbc {
    ($padding: ident) => {
        impl RijndaelCbc<$padding> {
            #[inline(always)]
            pub fn new(key: &[u8], block_size: usize) -> Result<Self, Errors> {
                Ok(Self {
                    rijndael: Rijndael::new(key, block_size)?,
                    padding: $padding(block_size),
                })
            }

            #[inline(always)]
            pub fn encrypt(&self, iv: &[u8], source: Vec<u8>) -> Result<Vec<u8>, Errors> {
                let ppt = self.padding.encode(source);
                let length = ppt.len();
                let mut offset = 0;
                let mut ct = Vec::with_capacity(length);
                let mut v = iv.into();
                let mut block;
                loop {
                    block = self.rijndael.encrypt(
                        &self.x_or_block(v, &ppt[offset..(offset + self.rijndael.block_size)]),
                    )?;
                    ct.extend(&block);
                    offset += self.rijndael.block_size;

                    if offset >= length {
                        break;
                    }
                    v = block;
                }
                Ok(ct)
            }

            #[inline(always)]
            pub fn decrypt(&self, iv: &[u8], cipher: Vec<u8>) -> Result<Vec<u8>, Errors> {
                let length = cipher.len();
                if (length % self.rijndael.block_size) != 0 {
                    return Err(Errors::InvalidDataSize);
                }
                let mut ppt = Vec::with_capacity(length);
                let mut offset = 0;
                let mut v = iv;
                loop {
                    let block = &cipher[offset..(offset + self.rijndael.block_size)];
                    let decrypted = self.rijndael.decrypt(&block)?;
                    ppt.append(&mut self.x_or_block(decrypted, v));
                    offset += self.rijndael.block_size;

                    if offset >= length {
                        break;
                    }
                    v = block;
                }
                Ok(self.padding.decode(ppt)?)
            }

            #[inline(always)]
            pub fn x_or_block(&self, mut b1: Vec<u8>, b2: &[u8]) -> Vec<u8> {
                for i in 0..self.rijndael.block_size {
                    b1[i] ^= b2[i]
                }
                b1
            }
        }
    };
}

#[derive(Debug)]
pub struct RijndaelCbc<P: Padding> {
    pub rijndael: Rijndael,
    pub padding: P,
}

impl_rijndael_cbc!(ZeroPadding);
impl_rijndael_cbc!(Pkcs7Padding);
