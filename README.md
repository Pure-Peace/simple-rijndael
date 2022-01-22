# simple-rijndael

*rijndael-cbc encryption and decryption algorithm implemented in pure Rust (supports zero-padding or pkcs7)*

### Test

```
cargo test
```

### Benchmark

```
cargo bench
```

### Examples

```rust
use simple_rijndael::Errors;

const OSU_KEY: &[u8; 32] = b"osu!-scoreburgr---------20210520";
const OSU_DECRYPTED: [u8; 160] = [
    99, 53, 49, 97, 101, 101, 53, 54, 98, 98, 53, 49, 57, 53, 50, 52, 52, 50, 53, 50, 100, 49, 57,
    48, 98, 97, 97, 53, 52, 98, 52, 57, 58, 80, 117, 114, 101, 80, 101, 97, 99, 101, 32, 58, 56,
    49, 53, 55, 55, 50, 54, 50, 53, 97, 100, 97, 100, 54, 51, 57, 55, 51, 53, 97, 48, 52, 52, 101,
    56, 97, 98, 97, 57, 51, 54, 48, 58, 52, 52, 58, 49, 56, 58, 54, 58, 52, 58, 54, 58, 50, 48, 58,
    51, 56, 54, 52, 53, 58, 50, 54, 58, 70, 97, 108, 115, 101, 58, 70, 58, 54, 52, 58, 70, 97, 108,
    115, 101, 58, 48, 58, 50, 49, 48, 54, 49, 53, 48, 54, 52, 52, 51, 49, 58, 50, 48, 50, 49, 48,
    53, 50, 48, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
];
const OSU_CRYPTED: [u8; 160] = [
    185, 209, 243, 33, 128, 187, 132, 199, 140, 189, 1, 129, 139, 66, 200, 37, 126, 34, 238, 100,
    93, 124, 192, 252, 31, 121, 2, 130, 138, 123, 69, 66, 122, 208, 169, 15, 120, 22, 148, 19, 87,
    203, 229, 139, 179, 89, 138, 56, 160, 239, 238, 254, 34, 119, 136, 225, 209, 226, 69, 117, 97,
    49, 225, 198, 91, 192, 196, 12, 32, 235, 103, 141, 142, 168, 29, 102, 252, 65, 191, 137, 136,
    170, 72, 165, 127, 49, 83, 201, 115, 26, 79, 200, 119, 28, 238, 34, 76, 25, 185, 164, 182, 254,
    66, 148, 18, 36, 27, 36, 59, 165, 220, 95, 164, 115, 128, 12, 5, 161, 18, 236, 221, 167, 247,
    104, 25, 29, 146, 225, 104, 140, 249, 175, 131, 158, 93, 143, 106, 146, 114, 220, 128, 33, 114,
    191, 232, 103, 94, 169, 90, 105, 8, 85, 33, 140, 198, 71, 40, 65, 215, 29,
];

#[test]
fn test_dec() {
    assert_eq!(osu_dec().unwrap(), OSU_DECRYPTED.to_vec())
}

#[test]
fn test_enc() {
    assert_eq!(osu_enc().unwrap(), OSU_CRYPTED.to_vec())
}

#[test]
fn test_pkcs7() {
    use simple_rijndael::impls::RijndaelCbc;
    use simple_rijndael::paddings::Pkcs7Padding;

    let test_data = b"This string is used to test Pkcs7Padding".to_vec();
    let key = b"128 bit key test";
    let iv = b"128 bit iv_ test";
    let r = RijndaelCbc::<Pkcs7Padding>::new(key, 16).unwrap();
    let result = r.encrypt(iv, test_data.clone()).unwrap();
    assert_eq!(
        result,
        vec![
            48, 107, 126, 49, 231, 35, 146, 225, 28, 112, 54, 23, 106, 236, 11, 57, 126, 253, 228,
            202, 30, 190, 239, 164, 0, 255, 148, 52, 176, 36, 32, 241, 163, 213, 33, 243, 202, 7,
            221, 94, 84, 37, 77, 160, 242, 223, 108, 162,
        ]
    );

    let decrypted_result = r.decrypt(iv, result).unwrap();
    assert_eq!(decrypted_result, test_data);
}

#[inline(always)]
pub fn osu_enc() -> Result<Vec<u8>, Errors> {
    use simple_rijndael::impls::RijndaelCbc;
    use simple_rijndael::paddings::ZeroPadding;

    let iv = &[
        240, 124, 26, 154, 27, 186, 98, 170, 95, 190, 213, 103, 13, 128, 39, 59, 217, 84, 68, 144,
        173, 93, 117, 132, 33, 213, 96, 154, 228, 231, 197, 162,
    ];
    let source = OSU_DECRYPTED.to_vec();
    Ok(RijndaelCbc::<ZeroPadding>::new(OSU_KEY, 32)?.encrypt(iv, source)?)
}

#[inline(always)]
pub fn osu_dec() -> Result<Vec<u8>, Errors> {
    use simple_rijndael::impls::RijndaelCbc;
    use simple_rijndael::paddings::ZeroPadding;

    let iv = &[
        240, 124, 26, 154, 27, 186, 98, 170, 95, 190, 213, 103, 13, 128, 39, 59, 217, 84, 68, 144,
        173, 93, 117, 132, 33, 213, 96, 154, 228, 231, 197, 162,
    ];
    let cipher = OSU_CRYPTED.to_vec();
    Ok(RijndaelCbc::<ZeroPadding>::new(OSU_KEY, 32)?.decrypt(iv, cipher)?)
}


```
