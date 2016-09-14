/**
 * libsodium HMAC bindings.
 *
 * Our chosen HMAC construction is HMAC-SHA512, taking only 256 bits of output. Though at first
 * glance it would appear that using the full 512 bit output would be better, the advantage here
 * is that in the event of finding a length extension attack against HMAC (no public attacks
 * exist), it would be impossible to use such an attack against this construction.
 *
 * Since only 256 bits of output are kept, it is impossible to construct the full hash function
 * state and execute a length-extension attack.
 *
 * Until a fair amount of cryptanalysis is done against SHA-3 Keccak, SHA-512/256 is a good idea
 * and is the default HMAC construction used by libsodium.
 */

use libc::{c_int, c_ulonglong, size_t};
use std::mem;

#[repr(C)]
pub struct crypto_hash_sha512_state {
    state: [u64; 8],
    count: [u64; 2],
    buf: [u8; 128],
}

#[repr(C)]
pub struct crypto_auth_hmacsha512256_state {
    ictx: crypto_hash_sha512_state,
    octx: crypto_hash_sha512_state,
}

const CRYPTO_AUTH_HMACSHA512256_BYTES: usize = 32;

const CRYPTO_AUTH_HMACSHA512256_KEYBYTES: usize = 32;

#[link(name = "sodium")]
extern {

    pub fn crypto_auth_hmacsha512256_bytes() -> size_t;

    pub fn crypto_auth_hmacsha512256_keybytes() -> size_t;

    pub fn crypto_auth_hmacsha512256_init(
        state: *mut crypto_auth_hmacsha512256_state,
        key: *const u8,
        keylen: size_t,
    ) -> c_int;

    pub fn crypto_auth_hmacsha512256_update(
        state: *mut crypto_auth_hmacsha512256_state,
        input: *const u8,
        inputlen: c_ulonglong,
    ) -> c_int;

    pub fn crypto_auth_hmacsha512256_final(
        state: *mut crypto_auth_hmacsha512256_state,
        out: *mut [u8; CRYPTO_AUTH_HMACSHA512256_BYTES],
    ) -> c_int;
}

#[test]
fn test_crypto_auth_hmacsha512256_bytes() {
    assert_eq!(CRYPTO_AUTH_HMACSHA512256_BYTES,
        unsafe { crypto_auth_hmacsha512256_bytes() as usize });
}

#[test]
fn test_crypto_auth_hmacsha512256_keybytes() {
    assert_eq!(CRYPTO_AUTH_HMACSHA512256_KEYBYTES,
        unsafe { crypto_auth_hmacsha512256_keybytes() as usize });
}

/// Test the entire HMAC-SHA512/256 libsodium construction
#[test]
fn test_crypto_auth_hmacsha512256() {
    unsafe {
        let mut context: crypto_auth_hmacsha512256_state = mem::zeroed();
        let key = b"";
        let message = b"";

        let expected = [0xb9, 0x36, 0xce, 0xe8, 0x6c, 0x9f, 0x87, 0xaa, 0x5d, 0x3c, 0x6f, 0x2e,
            0x84, 0xcb, 0x5a, 0x42, 0x39, 0xa5, 0xfe, 0x50, 0x48, 0x0a, 0x6e, 0xc6, 0x6b, 0x70,
            0xab, 0x5b, 0x1f, 0x4a, 0xc6, 0x73];

        let mut output = [0; CRYPTO_AUTH_HMACSHA512256_BYTES];

        crypto_auth_hmacsha512256_init(&mut context, key.as_ptr(), key.len());
        crypto_auth_hmacsha512256_update(&mut context, message.as_ptr(),
            message.len() as c_ulonglong);
        crypto_auth_hmacsha512256_final(&mut context, &mut output);

        assert_eq!(expected[..], output[..]);
    }
}
