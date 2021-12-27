use crate::types::CryptResult;
use crate::{
    paddings::{Padding, Pkcs7Padding, ZeroPadding},
    rijndael::Rijndael,
};

macro_rules! implRijndaelCBC {
    ($padding: ident) => {
        impl RijndaelCbc<$padding> {
            #[inline(always)]
            pub fn new(key: Vec<u8>, block_size: usize) -> Result<Self, String> {
                Ok(Self {
                    rijndael: Rijndael::new(key, block_size)?,
                    padding: $padding(block_size),
                })
            }

            #[inline(always)]
            pub fn encrypt(
                &self,
                iv: Vec<u8>,
                source: Vec<u8>,
            ) -> Result<CryptResult, String> {
                let ppt = self.padding.encode(source);
                let mut offset = 0;
                let mut ct = Vec::with_capacity(ppt.len());
                let mut v = iv;
                loop {
                    let mut block = ppt[offset..(offset + self.rijndael.block_size)].into();
                    block = self.x_or_block(&block, &v);
                    block = self.rijndael.encrypt(&block)?;
                    ct.extend(block.clone());
                    offset += self.rijndael.block_size;

                    if offset >= ppt.len() {
                        break;
                    }
                    v = block;
                }
                Ok(ct)
            }

            #[inline(always)]
            pub fn decrypt(
                &self,
                iv: Vec<u8>,
                cipher: Vec<u8>,
            ) -> Result<CryptResult, Vec<u8>> {
                if (cipher.len() % self.rijndael.block_size) != 0 {
                    return Err("Invalid size".into());
                }
                let mut ppt = Vec::with_capacity(cipher.len());
                let mut offset = 0;
                let mut v = iv;
                loop {
                    let block = cipher[offset..(offset + self.rijndael.block_size)].into();
                    let decrypted = self.rijndael.decrypt(&block)?;
                    ppt.extend(self.x_or_block(&decrypted, &v));
                    offset += self.rijndael.block_size;

                    if offset >= cipher.len() {
                        break;
                    }
                    v = block;
                }
                Ok(self.padding.decode(ppt)?)
            }

            #[inline(always)]
            pub fn x_or_block(&self, b1: &Vec<u8>, b2: &Vec<u8>) -> Vec<u8> {
                (0..self.rijndael.block_size)
                    .map(|i| b1[i] ^ b2[i])
                    .collect()
            }
        }
    };
}

#[derive(Debug)]
pub struct RijndaelCbc<P: Padding> {
    pub rijndael: Rijndael,
    pub padding: P,
}

implRijndaelCBC!(ZeroPadding);
implRijndaelCBC!(Pkcs7Padding);
