// Rust twin of linux_filestat_c/filestat.c (U1.3 `filestat`); same observable contract.
use std::fs::File;
use std::io::{Read, Write};

#[link(name = "z")]
extern "C" {
    fn crc32(crc: u64, buf: *const u8, len: u32) -> u64;
}

const BUFFER_BYTES: usize = 65536;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let mut table = vec![0u64; 256];
    let mut file = match File::open("input.dat") {
        Ok(file) => file,
        Err(_) => return 2,
    };
    let (mut bytes, mut lines, mut words, mut hash, mut prev_ws) = (0u64, 0u64, 0u64, 0xcbf29ce484222325u64, 1u64);
    let mut crc = 0u64;
    loop {
        let n = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return 3,
        };
        crc = unsafe { crc32(crc, buffer.as_ptr(), n as u32) };
        for &byte in &buffer[..n] {
            let c = byte as u64;
            let ws = ((c == b' ' as u64) | (c == b'\n' as u64) | (c == b'\t' as u64) | (c == b'\r' as u64)) as u64;
            bytes += 1;
            lines += (c == b'\n' as u64) as u64;
            words += (ws ^ 1) & prev_ws;
            prev_ws = ws;
            hash = (hash ^ c).wrapping_mul(0x100000001b3);
            table[byte as usize] += 1;
        }
    }
    let (mut best, mut best_count) = (0u64, 0u64);
    for k in 0..256 {
        if table[k] > best_count {
            best = k as u64;
            best_count = table[k];
        }
    }
    let text = format!("{} {} {} {} {} {}\n", bytes, lines, words, hash, crc, best);
    match std::io::stdout().lock().write_all(text.as_bytes()) {
        Ok(()) => 0,
        Err(_) => 3,
    }
}
