extern crate libc;

pub mod sodium;

use std::mem;
use sodium::hmac::{
    crypto_auth_hmacsha512256_state,
    crypto_auth_hmacsha512256_init,
    crypto_auth_hmacsha512256_update,
    crypto_auth_hmacsha512256_final,
};
use sodium::utils::{
    crypto_verify_32,
};

struct HMAC {
    state: crypto_auth_hmacsha512256_state,
}

impl HMAC {

    fn new(key: &[u8]) -> HMAC {
        let state = unsafe {
            let mut state: crypto_auth_hmacsha512256_state = mem::zeroed();
            if 0 != crypto_auth_hmacsha512256_init(&mut state, key.as_ptr(), key.len()) {
                panic!("unable to initialize a HMAC instance from libsodium");
            }
            state
        };

        return HMAC { state: state };
    }

    fn verify(a: [u8; 32], b: [u8; 32]) -> bool {
        return 0 == unsafe { crypto_verify_32(&a, &b) };
    }

    fn write(&mut self, data: &[u8]) {
        unsafe {
            if 0 != crypto_auth_hmacsha512256_update(&mut self.state, data.as_ptr(),
                    data.len() as libc::c_ulonglong) {
                panic!("unable to write data into an HMAC instance via libsodium");
            }
        }
    }

    /// This method is not idempotent!
    fn digest(&mut self) -> [u8; 32] {
        unsafe {
            let mut output = [0; 32];
            if 0 != crypto_auth_hmacsha512256_final(&mut self.state, &mut output) {
                panic!("unable to compute the HMAC digest via libsodium");
            }

            return output;
        }
    }
}

#[test]
fn test_hmac_workflow() {
    let expected = [0xb9, 0x36, 0xce, 0xe8, 0x6c, 0x9f, 0x87, 0xaa, 0x5d, 0x3c, 0x6f, 0x2e,
        0x84, 0xcb, 0x5a, 0x42, 0x39, 0xa5, 0xfe, 0x50, 0x48, 0x0a, 0x6e, 0xc6, 0x6b, 0x70,
        0xab, 0x5b, 0x1f, 0x4a, 0xc6, 0x73];

    let mut mac = HMAC::new("".as_bytes());
    mac.write("".as_bytes());

    assert_eq!(expected[..], mac.digest()[..]);
}

#[test]
fn test_hmac_verify() {
    let expected = [0xb9, 0x36, 0xce, 0xe8, 0x6c, 0x9f, 0x87, 0xaa, 0x5d, 0x3c, 0x6f, 0x2e,
        0x84, 0xcb, 0x5a, 0x42, 0x39, 0xa5, 0xfe, 0x50, 0x48, 0x0a, 0x6e, 0xc6, 0x6b, 0x70,
        0xab, 0x5b, 0x1f, 0x4a, 0xc6, 0x73];

    let mut mac = HMAC::new("".as_bytes());
    mac.write("".as_bytes());

    assert!(HMAC::verify(expected, mac.digest()));
}
