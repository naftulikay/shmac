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
        out: *mut u8,
        outlen: c_ulonglong,
        passwd: *const u8,
        passwdlen: c_ulonglong,
        salt: *const u8,
        opslimit: c_ulonglong,
        memlimit: size_t,
        alg: c_int,
    ) -> c_int;

    fn crypto_pwhash_argon2i_saltbytes() -> size_t;
    fn crypto_pwhash_argon2i_alg_argon2i13() -> c_int;

}

pub const CRYPTO_PWHASH_ARGON2I_SALTBYTES: usize = 16;

pub const CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13: isize = 1;

#[repr(C)]
pub enum Argon2iAlgorithms {
    Argon2i13 = CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13,
}

pub fn safe_crypto_pwhash_argon2i(outlen: usize, passwd: Vec<u8>,
        salt: [u8; CRYPTO_PWHASH_ARGON2I_SALTBYTES], opslimit: u64, memlimit: usize,
        alg: Argon2iAlgorithms) -> Result<Vec<u8>, i64> {

    let mut vec: Vec<u8> = Vec::with_capacity(outlen);

    let rc = unsafe {
        crypto_pwhash_argon2i(vec.as_mut_ptr(), vec.len() as c_ulonglong, passwd.as_ptr(),
            passwd.len() as c_ulonglong, salt.as_ptr(), opslimit as c_ulonglong,
            memlimit as size_t, alg as c_int)
    };

    Ok(vec)
}

#[test]
fn test_crypto_pwhash_argon2i_saltbytes() {
    assert_eq!(CRYPTO_PWHASH_ARGON2I_SALTBYTES, unsafe { crypto_pwhash_argon2i_saltbytes() })
}

#[test]
fn test_crypto_pwhash_argon2i_alg_argon2i13() {
    assert_eq!(CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13,
        unsafe { crypto_pwhash_argon2i_alg_argon2i13 () } as isize)
}
