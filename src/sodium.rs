// thank you to rust docs and dnaq/sodiumoxide!
use libc::{c_int, c_ulonglong, size_t};

#[repr(C)]
pub struct crypto_hash_sha256_state {
    state: [u32; 8],
    count: [u32; 2],
    buf: [u8; 64],
}

#[repr(C)]
struct crypto_auth_hmacsha256_state {
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
struct crypto_auth_hmacsha512_state {
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
    fn crypto_auth_hmacsha512_bytes() -> size_t;

    fn crypto_auth_hmacsha512_keybytes() -> size_t;

    fn crypto_auth_hmacsha512_init(
        state: *mut crypto_auth_hmacsha512_state,
        key: *const u8,
        keylen: size_t,
    ) -> c_int;

    fn crypto_auth_hmacsha512_update(
        state: *mut crypto_auth_hmacsha512_state,
        m: *const u8,
        mlen: c_ulonglong,
    ) -> c_int;

    fn crypto_auth_hmacsha512_final(
        state: *mut crypto_auth_hmacsha512_state,
        a: *mut [u8; crypto_auth_hmacsha512_BYTES],
    ) -> c_int;

    fn crypto_verify_64(
        x: *const [u8; 64],
        y: *const [u8; 64],
    ) -> c_int;
}

pub fn get_hmac_sha512_digest_size() -> usize {
    return unsafe { crypto_auth_hmacsha256_bytes() as usize };
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
