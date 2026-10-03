// Rust twin of linux_filestat_c/chains.c (OI-37 `chains`): chained hash table with
// links into one node pool. Links are pool indices with u32::MAX as "none" (the
// safe-Rust representation); bounds checks are left to rustc.
use std::io::Write;

const NODES: usize = 1 << 20;
const BUCKETS: usize = 1 << 16;
const NONE: u32 = u32::MAX;

#[inline]
fn next_key(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

fn main() {
    let mut keys = vec![0u64; NODES];
    let mut next = vec![NONE; NODES];
    let mut buckets = vec![NONE; BUCKETS];
    let mut x = 0x9E3779B97F4A7C15u64;
    for i in 0..NODES {
        x = next_key(x);
        let b = (x >> 48) as usize;
        keys[i] = x;
        next[i] = buckets[b];
        buckets[b] = i as u32;
    }
    let (mut found, mut steps) = (0u64, 0u64);
    x = 0x9E3779B97F4A7C15u64;
    for _ in 0..NODES {
        x = next_key(x);
        let mut cur = buckets[(x >> 48) as usize];
        while cur != NONE {
            steps += 1;
            if keys[cur as usize] == x {
                found += 1;
                break;
            }
            cur = next[cur as usize];
        }
    }
    let text = format!("{} {}\n", found, steps);
    let status = if std::io::stdout().lock().write_all(text.as_bytes()).is_ok() { 0 } else { 3 };
    std::process::exit(status);
}
