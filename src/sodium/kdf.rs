/**
 * libsodium KDF bindings.
 */

use libc::{c_int, c_ulonglong, size_t};

#[link(name = "sodium")]
extern {

    // int crypto_pwhash_argon2i(unsigned char * const out,
    //                       unsigned long long outlen,
    //                       const char * const passwd,
    //                       unsigned long long passwdlen,
    //                       const unsigned char * const salt,
    //                       unsigned long long opslimit, size_t memlimit,
    //                       int alg)

    fn crypto_pwhash_argon2i(
        out: *mut [u8],
        outlen: c_ulonglong,
        passwd: *const u8,
        passwdlen: c_ulonglong,
        salt: *const u8,
        opslimit: c_ulonglong,
        memlimit: size_t,
        alg: c_int,
    ) -> c_int;

    fn crypto_pwhash_argon2i_saltbytes() -> size_t;
}

pub const CRYPTO_PWHASH_ARGON2I_SALTBYTES: usize = 16;

#[test]
fn test_crypto_pwhash_argon2i_saltbytes() {
    assert_eq!(CRYPTO_PWHASH_ARGON2I_SALTBYTES,
        unsafe { crypto_pwhash_argon2i_saltbytes() })
}
