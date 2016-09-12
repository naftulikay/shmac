// thank you to rust docs and dnaq/sodiumoxide!
use libc::{c_int, c_ulonglong, size_t};
use std::mem;

#[repr(C)]
pub struct crypto_hash_sha256_state {
    state: [u32; 8],
    count: [u32; 2],
    buf: [u8; 64],
}

#[repr(C)]
pub struct crypto_auth_hmacsha256_state {
    ictx: crypto_hash_sha256_state,
    octx: crypto_hash_sha256_state,
}

const crypto_auth_hmacsha256_BYTES: usize = 32;
const crypto_auth_hmacsha256_KEYBYTES: usize = 32;

#[repr(C)]
pub struct crypto_hash_sha512_state {
    state: [u64; 8],
    count: [u64; 2],
    buf: [u8; 128],
}

#[repr(C)]
pub struct crypto_auth_hmacsha512_state {
    ictx: crypto_hash_sha512_state,
    octx: crypto_hash_sha512_state,
}

const crypto_auth_hmacsha512_BYTES: usize = 64;
const crypto_auth_hmacsha512_KEYBYTES: usize = 32;

#[link(name = "sodium")]
extern {
    /**
     * HMAC-SHA256 Operations and Constants
     * https://github.com/dnaq/sodiumoxide/blob/master/libsodium-sys/src/crypto_auth_hmacsha256.rs
     * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_auth/hmacsha256/cp/hmac_hmacsha256.c
     * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_verify/32/ref/verify_32.c
     */
    fn crypto_auth_hmacsha256_bytes() -> size_t;

    fn crypto_auth_hmacsha256_keybytes() -> size_t;

    fn crypto_auth_hmacsha256_init(
        state: *mut crypto_auth_hmacsha256_state,
        key: *const u8,
        keylen: size_t
    ) -> c_int;

    fn crypto_auth_hmacsha256_update(
        state: *mut crypto_auth_hmacsha256_state,
        m: *const u8,
        mlen: c_ulonglong
    ) -> c_int;

    fn crypto_auth_hmacsha256_final(
        state: *mut crypto_auth_hmacsha256_state,
        a: *mut [u8; crypto_auth_hmacsha256_BYTES]
    ) -> c_int;

    fn crypto_verify_32(
        x: *const [u8; 32],
        y: *const [u8; 32],
    ) -> c_int;

    /**
     * HMAC-SHA512 Operations
     * https://github.com/dnaq/sodiumoxide/blob/master/libsodium-sys/src/crypto_auth_hmacsha512.rs
     * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_auth/hmacsha512/cp/hmac_hmacsha512.c
     * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_verify/64/ref/verify_64.c
     */
    pub fn crypto_auth_hmacsha512_bytes() -> size_t;

    pub fn crypto_auth_hmacsha512_keybytes() -> size_t;

    pub fn crypto_auth_hmacsha512_init(
        state: *mut crypto_auth_hmacsha512_state,
        key: *const u8,
        keylen: size_t,
    ) -> c_int;

    pub fn crypto_auth_hmacsha512_update(
        state: *mut crypto_auth_hmacsha512_state,
        m: *const u8,
        mlen: c_ulonglong,
    ) -> c_int;

    pub fn crypto_auth_hmacsha512_final(
        state: *mut crypto_auth_hmacsha512_state,
        a: *mut [u8; crypto_auth_hmacsha512_BYTES],
    ) -> c_int;

    pub fn crypto_verify_64(
        x: *const [u8; 64],
        y: *const [u8; 64],
    ) -> c_int;
}

pub fn get_hmac_sha512_digest_size() -> usize {
    return unsafe { crypto_auth_hmacsha256_bytes() as usize };
}

#[test]
fn test_hmac_sha256() {
    unsafe {
        let mut context: crypto_auth_hmacsha256_state = mem::uninitialized();
        let key = b"";
        let message = b"";
        let mut output = [0; 32];

        crypto_auth_hmacsha256_init(&mut context, key.as_ptr(), key.len());
        crypto_auth_hmacsha256_update(&mut context, message.as_ptr(),
            message.len() as c_ulonglong);
        crypto_auth_hmacsha256_final(&mut context, &mut output);

        let expected = [0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec, 0x77, 0x2f, 0x95, 0xd7,
            0x78, 0xc3, 0x5f, 0xc5, 0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53, 0xc6, 0xc7,
            0x12, 0x14, 0x42, 0x92, 0xc5, 0xad];

        assert_eq!(expected, output);
        assert_eq!(0, crypto_verify_32(&expected, &output));
    }
}

#[test]
fn test_hmac_sha512() {
    unsafe {
        let mut context: crypto_auth_hmacsha512_state = mem::uninitialized();
        let key = b"";
        let message = b"";
        let mut output = [0; 64];

        crypto_auth_hmacsha512_init(&mut context, key.as_ptr(), key.len());
        crypto_auth_hmacsha512_update(&mut context, message.as_ptr(),
            message.len() as c_ulonglong);
        crypto_auth_hmacsha512_final(&mut context, &mut output);

        let expected = [0xb9, 0x36, 0xce, 0xe8, 0x6c, 0x9f, 0x87, 0xaa, 0x5d, 0x3c, 0x6f, 0x2e,
            0x84, 0xcb, 0x5a, 0x42, 0x39, 0xa5, 0xfe, 0x50, 0x48, 0x0a, 0x6e, 0xc6, 0x6b, 0x70,
            0xab, 0x5b, 0x1f, 0x4a, 0xc6, 0x73, 0x0c, 0x6c, 0x51, 0x54, 0x21, 0xb3, 0x27, 0xec,
            0x1d, 0x69, 0x40, 0x2e, 0x53, 0xdf, 0xb4, 0x9a, 0xd7, 0x38, 0x1e, 0xb0, 0x67, 0xb3,
            0x38, 0xfd, 0x7b, 0x0c, 0xb2, 0x22, 0x47, 0x22, 0x5d, 0x47];

        assert_eq!(expected[..], output[..]);
        assert_eq!(0, crypto_verify_64(&expected, &output));
    }
}

#[test]
fn test_crypto_auth_hmacsha256_bytes() {
    assert!(unsafe { crypto_auth_hmacsha256_bytes() as usize } ==
            crypto_auth_hmacsha256_BYTES)
}
#[test]
fn test_crypto_auth_hmacsha256_keybytes() {
    assert!(unsafe { crypto_auth_hmacsha256_keybytes() as usize } ==
            crypto_auth_hmacsha256_KEYBYTES)
}

#[test]
fn test_crypto_auth_hmacsha512_bytes() {
    assert!(unsafe { crypto_auth_hmacsha512_bytes() as usize } ==
            crypto_auth_hmacsha512_BYTES)
}
#[test]
fn test_crypto_auth_hmacsha512_keybytes() {
    assert!(unsafe { crypto_auth_hmacsha512_keybytes() as usize } ==
            crypto_auth_hmacsha512_KEYBYTES)
}
