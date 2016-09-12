extern crate shmac;

use std::fmt::format;
use shmac::sodium::get_hmac_sha512_digest_size;

fn main() {
    println!("Hello, World!");
    let ds: usize = get_hmac_sha512_digest_size();
    println!("sha512 digest size: {}", ds);
}
