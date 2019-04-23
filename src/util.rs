use rand::Rng;

pub fn rand_string<R: Rng>(rng: &mut R, size: usize) -> String {
    const RAND_CHAR_TABLE: &[u8; 62] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let mut s = String::new();
    s.reserve(size);
    for _ in 0..size {
        s.push(RAND_CHAR_TABLE[rng.gen_range(0, 62)] as char);
    }
    s
}
