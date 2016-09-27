extern crate shmac;

use shmac::sodium::kdf::{safe_argon2i_hash_raw_32, Argon2ErrorCodes};

fn main() {
    // println!("Hello, World! {:?}", [1, 255, 127].iter().map(|x| { format!("{:#x}", x) }).collect::<Vec<String>>());

    let passphrase = "passphrase";
    let salt = [0; 32];

    safe_argon2i_hash_raw_32(3, 12, 1, passphrase.as_bytes(), &salt).and_then(|n| {
        Ok(n)
    });

    // generate().and_then(|result| {
    //     println!("thing");
    //     Ok(result)
    // });
}
