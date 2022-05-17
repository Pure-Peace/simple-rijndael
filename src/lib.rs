#[cfg(test)]
pub mod tests;

pub mod constants;
pub mod impls;
pub mod paddings;
pub mod rijndael;

#[derive(Debug)]
pub enum Errors {
    InvalidDataSize,
    InvalidBlockSize,
    InvalidKeySize,
}

#[cfg(feature = "std")]
impl std::error::Error for Errors {}

#[cfg(feature = "std")]
impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Errors::InvalidDataSize => write!(f, "Invalid Data Size"),
            Errors::InvalidBlockSize => write!(f, "Invalid Block Size"),
            Errors::InvalidKeySize => write!(f, "Invalid Key Size"),
        }
    }
}