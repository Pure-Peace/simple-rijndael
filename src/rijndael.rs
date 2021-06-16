use crate::constants::*;
use crate::types::Cipher;
use crate::types::CryptResult;

#[derive(Debug)]
pub struct Rijndael {
    pub block_size: usize,
    pub key: Vec<u8>,
    pub k_e: Vec<Vec<u32>>,
    pub k_d: Vec<Vec<u32>>,
}

impl Rijndael {
    #[inline(always)]
    pub fn new(key: Vec<u8>, block_size: usize) -> Result<Self, &'static str> {
        if !VALID.contains(&block_size) {
            return Err("Invalid block size");
        }
        if !VALID.contains(&key.len()) {
            return Err("Invalid key size");
        }
        let rounds = if block_size == 32 {
            14
        } else {
            let base = match key.len() {
                16 => 10,
                24 => 12,
                32 => 14,
                _ => return Err("Invalid key size2"),
            };
            if key.len() > 16 {
                base
            } else {
                base + 2
            }
        };
        let b_c = block_size / 4;
        // encryption round keys
        let mut k_e = vec![vec![0; b_c]; rounds + 1];
        // decryption round keys
        let mut k_d = k_e.clone();
        let round_key_count = (rounds + 1) * b_c;
        let k_c = key.len() / 4;

        // copy user material bytes into temporary ints
        let mut tk = (0..k_c)
            .map(|i| {
                let s = 4 * i;
                ((key[s] as u32) << 24)
                    | ((key[s + 1] as u32) << 16)
                    | ((key[s + 2] as u32) << 8)
                    | (key[s + 3] as u32)
            })
            .collect::<Vec<u32>>();

        let mut t = 0;
        let mut j = 0;
        while j < k_c && t < round_key_count {
            k_e[t / b_c][t % b_c] = tk[j];
            k_d[rounds - (t / b_c)][t % b_c] = tk[j];
            j += 1;
            t += 1;
        }
        let mut r_con_pointer = 0;
        loop {
            let mut tt = tk[k_c - 1];
            tk[0] ^= ((S[(tt >> 16) as usize & 0xFF] & 0xFF) as u32) << 24
                ^ ((S[(tt >> 8) as usize & 0xFF] & 0xFF) as u32) << 16
                ^ ((S[tt as usize & 0xFF] & 0xFF) as u32) << 8
                ^ ((S[(tt >> 24) as usize & 0xFF] & 0xFF) as u32)
                ^ ((R_CON[r_con_pointer] & 0xFF) as u32) << 24;

            r_con_pointer += 1;
            if k_c != 8 {
                for i in 1..k_c {
                    tk[i] ^= tk[i - 1];
                }
            } else {
                for i in 1..(k_c / 2) {
                    tk[i] ^= tk[i - 1];
                }
                tt = tk[((k_c / 2) - 1)];
                tk[(k_c / 2)] ^= ((S[tt as usize & 0xFF] & 0xFF) as u32)
                    ^ ((S[(tt >> 8) as usize & 0xFF] & 0xFF) as u32) << 8
                    ^ ((S[(tt >> 16) as usize & 0xFF] & 0xFF) as u32) << 16
                    ^ ((S[(tt >> 24) as usize & 0xFF] & 0xFF) as u32) << 24;
                for i in ((k_c / 2) + 1)..k_c {
                    tk[i] ^= tk[(i - 1)];
                }
            }
            j = 0;
            while j < k_c && t < round_key_count {
                k_e[(t / b_c)][(t % b_c)] = tk[j];
                k_d[(rounds - (t / b_c))][(t % b_c)] = tk[j];
                j += 1;
                t += 1;
            }
            if t >= round_key_count {
                break;
            }
        }
        for r in 1..rounds {
            for j in 0..b_c {
                let tt = k_d[r][j];
                k_d[r][j] = U1[(tt >> 24) as usize & 0xFF]
                    ^ U2[(tt >> 16) as usize & 0xFF]
                    ^ U3[(tt >> 8) as usize & 0xFF]
                    ^ U4[tt as usize & 0xFF];
            }
        }
        Ok(Self {
            block_size,
            key,
            k_e,
            k_d,
        })
    }

    //#[inline(always)]
    pub fn encrypt(&self, source: &Vec<u8>) -> Result<Cipher, &'static str> {
        if source.len() != self.block_size {
            return Err("wrong block length");
        }
        let b_c = self.block_size / 4;
        let rounds = self.k_e.len() - 1;
        let s_c = match b_c {
            4 => 0,
            6 => 1,
            _ => 2,
        };
        let s1 = SHIFTS[s_c][1][0];
        let s2 = SHIFTS[s_c][2][0];
        let s3 = SHIFTS[s_c][3][0];
        let mut a = vec![0; b_c];
        // temporary work array
        let mut t = Vec::with_capacity(b_c);
        // source to ints + key
        for i in 0..b_c {
            let s = 4 * i;
            t.push(
                ((source[s] as u32) << 24
                    | (source[s + 1] as u32) << 16
                    | (source[s + 2] as u32) << 8
                    | (source[s + 3] as u32))
                    ^ self.k_e[0][i],
            );
        }
        // apply round transforms
        for r in 1..rounds {
            for i in 0..b_c {
                a[i] = (T1[(t[i] >> 24) as usize & 0xFF]
                    ^ T2[(t[(i + s1 as usize) % b_c] >> 16) as usize & 0xFF]
                    ^ T3[(t[(i + s2 as usize) % b_c] >> 8) as usize & 0xFF]
                    ^ T4[t[(i + s3 as usize) % b_c] as usize & 0xFF])
                    ^ self.k_e[r][i];
            }
            t = a.clone();
        }
        // last round is special
        let mut result = Vec::with_capacity(source.len());
        for i in 0..b_c {
            let tt = self.k_e[rounds][i];
            result.push(((S[((t[i] >> 24) as usize & 0xFF)] as u32 ^ (tt >> 24)) & 0xFF) as u8);
            result.push(
                ((S[((t[((i + s1 as usize) % b_c)] >> 16) as usize & 0xFF)] as u32 ^ (tt >> 16))
                    & 0xFF) as u8,
            );
            result.push(
                ((S[((t[((i + s2 as usize) % b_c)] >> 8) as usize & 0xFF)] as u32 ^ (tt >> 8))
                    & 0xFF) as u8,
            );
            result.push(
                ((S[(t[((i + s3 as usize) % b_c)] as usize & 0xFF)] as u32 ^ tt) & 0xFF) as u8,
            );
        }
        Ok(result)
    }

    #[inline(always)]
    pub fn decrypt(&self, block_cipher: &Cipher) -> Result<CryptResult, &'static str> {
        if block_cipher.len() != self.block_size {
            return Err("wrong block length");
        }
        let b_c = self.block_size / 4;
        let rounds = self.k_d.len() - 1;
        let s_c = match b_c {
            4 => 0,
            6 => 1,
            _ => 2,
        };
        let s1 = SHIFTS[s_c][1][1];
        let s2 = SHIFTS[s_c][2][1];
        let s3 = SHIFTS[s_c][3][1];
        let mut a = vec![0; b_c];
        let mut t = a.clone();
        for i in 0..b_c {
            let s = 4 * i;
            t[i] = ((block_cipher[s] as u32) << 24
                | (block_cipher[s + 1] as u32) << 16
                | (block_cipher[s + 2] as u32) << 8
                | (block_cipher[s + 3] as u32))
                ^ self.k_d[0][i];
        }
        for r in 1..rounds {
            for i in 0..b_c {
                a[i] = (T5[(t[i] >> 24) as usize & 0xFF]
                    ^ T6[(t[(i + s1 as usize) % b_c] >> 16) as usize & 0xFF]
                    ^ T7[(t[(i + s2 as usize) % b_c] >> 8) as usize & 0xFF]
                    ^ T8[t[(i + s3 as usize) % b_c] as usize & 0xFF])
                    ^ self.k_d[r][i];
            }
            t = a.clone();
        }
        let mut result = Vec::with_capacity(block_cipher.len());
        for i in 0..b_c {
            let tt = self.k_d[rounds][i];
            result.push(((SI[((t[i] >> 24) as usize & 0xFF)] as u32 ^ (tt >> 24)) & 0xFF) as u8);
            result.push(
                ((SI[((t[((i + s1 as usize) % b_c)] >> 16) as usize & 0xFF)] as u32 ^ (tt >> 16))
                    & 0xFF) as u8,
            );
            result.push(
                ((SI[((t[((i + s2 as usize) % b_c)] >> 8) as usize & 0xFF)] as u32 ^ (tt >> 8))
                    & 0xFF) as u8,
            );
            result.push(
                ((SI[(t[((i + s3 as usize) % b_c)] as usize & 0xFF)] as u32 ^ tt) & 0xFF) as u8,
            );
        }
        Ok(result)
    }
}
