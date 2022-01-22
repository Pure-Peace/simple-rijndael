use crate::{constants::*, Errors};

macro_rules! require {
    ($condition: expr, $err: expr) => {
        if !$condition {
            return Err($err);
        }
    };
}

#[derive(Debug)]
pub struct Rijndael {
    pub block_size: usize,
    pub rounds: usize,
    pub b_c: usize,
    pub s_c: usize,
    pub k_e: RoundKeys,
    pub k_d: RoundKeys,
}

impl Rijndael {
    #[inline(always)]
    pub fn new(key: &[u8], block_size: usize) -> Result<Self, Errors> {
        require!(VALID.contains(&block_size), Errors::InvalidBlockSize);
        require!(VALID.contains(&key.len()), Errors::InvalidKeySize);
        let rounds = if block_size == 32 || key.len() == 32 {
            14
        } else {
            if block_size == 16 && key.len() == 16 {
                10
            } else {
                12
            }
        };
        let b_c = block_size / 4;
        let s_c = match b_c {
            4 => 0,
            6 => 1,
            _ => 2,
        };
        // encryption round keys
        let mut k_e = ROUND_KEYS;
        // decryption round keys
        let mut k_d = ROUND_KEYS;
        let round_key_count = (rounds + 1) * b_c;
        let k_c = key.len() / 4;

        // copy user material bytes into temporary ints
        let mut tk = EMPTY_BLOCK;
        for i in 0..k_c {
            let s = 4 * i;
            tk[i] = ((key[s] as u32) << 24)
                | ((key[s + 1] as u32) << 16)
                | ((key[s + 2] as u32) << 8)
                | (key[s + 3] as u32);
        }

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
            rounds,
            b_c,
            s_c,
            k_e,
            k_d,
        })
    }

    //#[inline(always)]
    pub fn encrypt(&self, source: &[u8]) -> Result<Vec<u8>, Errors> {
        require!(source.len() == self.block_size, Errors::InvalidBlockSize);
        let s1 = SHIFTS[self.s_c][1][0];
        let s2 = SHIFTS[self.s_c][2][0];
        let s3 = SHIFTS[self.s_c][3][0];
        let mut a = EMPTY_BLOCK;
        // temporary work array
        let mut t = EMPTY_BLOCK;
        // source to ints + key
        for i in 0..self.b_c {
            let s = 4 * i;
            t[i] = ((source[s] as u32) << 24
                | (source[s + 1] as u32) << 16
                | (source[s + 2] as u32) << 8
                | (source[s + 3] as u32))
                ^ self.k_e[0][i];
        }
        // apply round transforms
        for r in 1..self.rounds {
            for i in 0..self.b_c {
                a[i] = (T1[(t[i] >> 24) as usize & 0xFF]
                    ^ T2[(t[(i + s1 as usize) % self.b_c] >> 16) as usize & 0xFF]
                    ^ T3[(t[(i + s2 as usize) % self.b_c] >> 8) as usize & 0xFF]
                    ^ T4[t[(i + s3 as usize) % self.b_c] as usize & 0xFF])
                    ^ self.k_e[r][i];
            }
            t = a;
        }
        // last round is special
        let mut result = Vec::with_capacity(source.len());
        for i in 0..self.b_c {
            let tt = self.k_e[self.rounds][i];
            unsafe {
                push4(
                    &mut result,
                    ((S[((t[i] >> 24) as usize & 0xFF)] as u32 ^ (tt >> 24)) & 0xFF) as u8,
                    ((S[((t[((i + s1 as usize) % self.b_c)] >> 16) as usize & 0xFF)] as u32
                        ^ (tt >> 16))
                        & 0xFF) as u8,
                    ((S[((t[((i + s2 as usize) % self.b_c)] >> 8) as usize & 0xFF)] as u32
                        ^ (tt >> 8))
                        & 0xFF) as u8,
                    ((S[(t[((i + s3 as usize) % self.b_c)] as usize & 0xFF)] as u32 ^ tt) & 0xFF)
                        as u8,
                );
            }
        }
        Ok(result)
    }

    #[inline(always)]
    pub fn decrypt(&self, block_cipher: &[u8]) -> Result<Vec<u8>, Errors> {
        require!(
            block_cipher.len() == self.block_size,
            Errors::InvalidBlockSize
        );
        let s1 = SHIFTS[self.s_c][1][1];
        let s2 = SHIFTS[self.s_c][2][1];
        let s3 = SHIFTS[self.s_c][3][1];
        let mut a = EMPTY_BLOCK;
        let mut t = EMPTY_BLOCK;
        for i in 0..self.b_c {
            let s = 4 * i;
            t[i] = ((block_cipher[s] as u32) << 24
                | (block_cipher[s + 1] as u32) << 16
                | (block_cipher[s + 2] as u32) << 8
                | (block_cipher[s + 3] as u32))
                ^ self.k_d[0][i];
        }
        for r in 1..self.rounds {
            for i in 0..self.b_c {
                a[i] = (T5[(t[i] >> 24) as usize & 0xFF]
                    ^ T6[(t[(i + s1 as usize) % self.b_c] >> 16) as usize & 0xFF]
                    ^ T7[(t[(i + s2 as usize) % self.b_c] >> 8) as usize & 0xFF]
                    ^ T8[t[(i + s3 as usize) % self.b_c] as usize & 0xFF])
                    ^ self.k_d[r][i];
            }
            t = a;
        }
        let mut result = Vec::with_capacity(block_cipher.len());
        unsafe {
            for i in 0..self.b_c {
                let tt = self.k_d[self.rounds][i];
                push4(
                    &mut result,
                    ((SI[((t[i] >> 24) as usize & 0xFF)] as u32 ^ (tt >> 24)) & 0xFF) as u8,
                    ((SI[((t[((i + s1 as usize) % self.b_c)] >> 16) as usize & 0xFF)] as u32
                        ^ (tt >> 16))
                        & 0xFF) as u8,
                    ((SI[((t[((i + s2 as usize) % self.b_c)] >> 8) as usize & 0xFF)] as u32
                        ^ (tt >> 8))
                        & 0xFF) as u8,
                    ((SI[(t[((i + s3 as usize) % self.b_c)] as usize & 0xFF)] as u32 ^ tt) & 0xFF)
                        as u8,
                );
            }
        }
        Ok(result)
    }
}

unsafe fn push4(dst: &mut Vec<u8>, val1: u8, val2: u8, val3: u8, val4: u8) {
    let length = dst.len();
    let end = dst.as_mut_ptr();
    std::ptr::write(end.add(length), val1);
    std::ptr::write(end.add(length + 1), val2);
    std::ptr::write(end.add(length + 2), val3);
    std::ptr::write(end.add(length + 3), val4);
    dst.set_len(dst.len() + 4);
}
