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
