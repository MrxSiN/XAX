// Rust twin of jsonmin_c/jsonmin.c: same contract and algorithm (recursive descent,
// 512-deep limit, 16 MiB input capacity), for measurement only.
use std::io::{Read, Write};

const CAPACITY: usize = 16 << 20;
const MAX_DEPTH: u32 = 512;

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    out: Vec<u8>,
}

impl<'a> Parser<'a> {
    #[inline]
    fn at_end(&self) -> bool { self.pos >= self.input.len() }
    #[inline]
    fn peek(&self) -> u8 { self.input[self.pos] }
    #[inline]
    fn copy(&mut self) { self.out.push(self.input[self.pos]); self.pos += 1; }
    #[inline]
    fn ws(&mut self) {
        while self.pos < self.input.len() && matches!(self.input[self.pos], b' ' | b'\t' | b'\n' | b'\r') { self.pos += 1; }
    }
    #[inline]
    fn optional(&self, c: u8) -> bool { self.pos < self.input.len() && self.input[self.pos] == c }

    fn string(&mut self) -> u32 {
        self.copy();
        loop {
            if self.at_end() { return 1; }
            let c = self.peek();
            if c < 0x20 { return 3; }
            self.copy();
            if c == b'\\' {
                if self.at_end() { return 1; }
                let e = self.peek();
                if e == b'u' {
                    self.copy();
                    for _ in 0..4 {
                        if self.at_end() { return 1; }
                        if !self.peek().is_ascii_hexdigit() { return 4; }
                        self.copy();
                    }
                } else if matches!(e, b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') {
                    self.copy();
                } else {
                    return 4;
                }
            } else if c == b'"' {
                return 0;
            }
        }
    }

    fn digits(&mut self) -> u32 {
        let mut count = 0;
        while self.pos < self.input.len() && self.peek().is_ascii_digit() { self.copy(); count += 1; }
        if count > 0 { 0 } else { 5 }
    }

    fn number(&mut self) -> u32 {
        if self.optional(b'-') { self.copy(); }
        if self.at_end() { return 5; }
        if self.peek() == b'0' { self.copy(); } else if self.digits() != 0 { return 5; }
        if self.optional(b'.') { self.copy(); if self.digits() != 0 { return 5; } }
        if self.optional(b'e') || self.optional(b'E') {
            self.copy();
            if self.optional(b'+') || self.optional(b'-') { self.copy(); }
            if self.digits() != 0 { return 5; }
        }
        0
    }

    fn literal(&mut self) -> u32 {
        for word in [&b"true"[..], &b"false"[..], &b"null"[..]] {
            if self.peek() == word[0] {
                for &expected in word {
                    if self.at_end() { return 1; }
                    if self.peek() != expected { return 6; }
                    self.copy();
                }
                return 0;
            }
        }
        6
    }

    fn container(&mut self, depth: u32, closing: u8, keyed: bool) -> u32 {
        self.copy();
        self.ws();
        if self.optional(closing) { self.copy(); return 0; }
        loop {
            if keyed {
                self.ws();
                if !self.optional(b'"') { return 10; }
                let status = self.string();
                if status != 0 { return status; }
                self.ws();
                if !self.optional(b':') { return 11; }
                self.copy();
            }
            let status = self.value(depth);
            if status != 0 { return status; }
            self.ws();
            if self.optional(b',') { self.copy(); continue; }
            if !self.optional(closing) { return if keyed { 12 } else { 9 }; }
            self.copy();
            return 0;
        }
    }

    fn value(&mut self, depth: u32) -> u32 {
        if depth > MAX_DEPTH { return 7; }
        self.ws();
        if self.at_end() { return 1; }
        match self.peek() {
            b'{' => self.container(depth + 1, b'}', true),
            b'[' => self.container(depth + 1, b']', false),
            b'"' => self.string(),
            b'-' | b'0'..=b'9' => self.number(),
            b't' | b'f' | b'n' => self.literal(),
            _ => 8,
        }
    }
}

fn main() {
    let mut input = Vec::with_capacity(CAPACITY + 1);
    if std::io::stdin().lock().take(CAPACITY as u64 + 1).read_to_end(&mut input).is_err() || input.len() > CAPACITY {
        std::process::exit(2);
    }
    let mut parser = Parser { input: &input, pos: 0, out: Vec::with_capacity(CAPACITY + 1) };
    let mut status = parser.value(0);
    if status == 0 { parser.ws(); if parser.pos != input.len() { status = 13; } }
    if status != 0 {
        eprintln!("jsonmin: invalid JSON at byte {}", parser.pos);
        std::process::exit(1);
    }
    parser.out.push(b'\n');
    if std::io::stdout().lock().write_all(&parser.out).is_err() { std::process::exit(2); }
}
