macro_rules! ensure_size {
    ($source: ident, $self: ident) => {
        if ($source.len() % $self.0) != 0 {
            return Err("Invalid size".into());
        };
    };
}

pub trait Padding {
    fn encode(&self, input_vec: Vec<u8>) -> Vec<u8>;
    fn decode(&self, source: Vec<u8>) -> Result<Vec<u8>, Vec<u8>>;
}

#[derive(Debug)]
pub struct ZeroPadding(pub usize);

impl Padding for ZeroPadding {
    #[inline(always)]
    fn encode(&self, mut input_vec: Vec<u8>) -> Vec<u8> {
        let pad_size = self.0 - ((input_vec.len() + self.0 - 1) % self.0 + 1);
        input_vec.append(&mut vec![0u8; pad_size]);
        input_vec
    }

    #[inline(always)]
    fn decode(&self, source: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        ensure_size!(source, self);
        let mut offset = source.len();
        if offset == 0 {
            return Ok(vec![]);
        }
        let end = (offset - self.0) + 1;
        while offset > end {
            offset -= 1;
            if source.get(offset).is_some() {
                return Ok(source[..(offset + 1)].into());
            }
        }
        Ok(source[..end].into())
    }
}

#[derive(Debug)]
pub struct Pkcs7Padding(pub usize);

impl Padding for Pkcs7Padding {
    #[inline(always)]
    fn encode(&self, mut input_vec: Vec<u8>) -> Vec<u8> {
        let pad_size = self.0 - (input_vec.len() % self.0);
        input_vec.append(&mut vec![pad_size as u8; pad_size]);
        input_vec
    }

    #[inline(always)]
    fn decode(&self, source: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        ensure_size!(source, self);
        let pad_size = source[source.len() - 1];
        let end = source.len() - pad_size as usize;
        Ok(source[..end].into())
    }
}
