extern crate shmac;

fn main() {
    println!("Hello, World! {:?}", [1, 255, 127].iter().map(|x| { format!("{:#x}", x) }).collect::<Vec<String>>());
}
