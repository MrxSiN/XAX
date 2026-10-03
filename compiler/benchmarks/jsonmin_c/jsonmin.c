/* C twin of benchmarks/jsonmin.py: same contract, same algorithm (recursive
 * descent, 512-deep limit, 16 MiB input capacity), for measurement only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CAPACITY (16u << 20)
#define MAX_DEPTH 512u

static unsigned char *in, *out;
static unsigned pos, len, olen;

static int at_end(void) { return pos >= len; }
static void copy(void) { out[olen++] = in[pos++]; }
static void ws(void) { while (pos < len && (in[pos] == ' ' || in[pos] == '\t' || in[pos] == '\n' || in[pos] == '\r')) pos++; }
static int optional(unsigned char c) { return pos < len && in[pos] == c; }
static int is_digit(unsigned char c) { return c >= '0' && c <= '9'; }

static int string(void) {
    copy();
    for (;;) {
        if (at_end()) return 1;
        unsigned char c = in[pos];
        if (c < 0x20) return 3;
        copy();
        if (c == '\\') {
            if (at_end()) return 1;
            unsigned char e = in[pos];
            if (e == 'u') {
                copy();
                for (int i = 0; i < 4; i++) {
                    if (at_end()) return 1;
                    unsigned char h = in[pos];
                    if (!(is_digit(h) || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F'))) return 4;
                    copy();
                }
            } else if (strchr("\"\\/bfnrt", e) && e) {
                copy();
            } else {
                return 4;
            }
        } else if (c == '"') {
            return 0;
        }
    }
}

static int digits(void) {
    unsigned count = 0;
    while (pos < len && is_digit(in[pos])) { copy(); count++; }
    return count ? 0 : 5;
}

static int number(void) {
    if (optional('-')) copy();
    if (at_end()) return 5;
    if (in[pos] == '0') copy(); else if (digits()) return 5;
    if (optional('.')) { copy(); if (digits()) return 5; }
    if (optional('e') || optional('E')) {
        copy();
        if (optional('+') || optional('-')) copy();
        if (digits()) return 5;
    }
    return 0;
}

static int literal(void) {
    static const char *words[] = {"true", "false", "null"};
    for (int w = 0; w < 3; w++) {
        if (in[pos] == (unsigned char)words[w][0]) {
            for (const char *p = words[w]; *p; p++) {
                if (at_end()) return 1;
                if (in[pos] != (unsigned char)*p) return 6;
                copy();
            }
            return 0;
        }
    }
    return 6;
}

static int value(unsigned depth);

static int container(unsigned depth, unsigned char closing, int keyed) {
    copy();
    ws();
    if (optional(closing)) { copy(); return 0; }
    for (;;) {
        if (keyed) {
            ws();
            if (!optional('"')) return 10;
            int status = string();
            if (status) return status;
            ws();
            if (!optional(':')) return 11;
            copy();
        }
        int status = value(depth);
        if (status) return status;
        ws();
        if (optional(',')) { copy(); continue; }
        if (!optional(closing)) return keyed ? 12 : 9;
        copy();
        return 0;
    }
}

static int value(unsigned depth) {
    if (depth > MAX_DEPTH) return 7;
    ws();
    if (at_end()) return 1;
    unsigned char c = in[pos];
    if (c == '{') return container(depth + 1, '}', 1);
    if (c == '[') return container(depth + 1, ']', 0);
    if (c == '"') return string();
    if (c == '-' || is_digit(c)) return number();
    if (c == 't' || c == 'f' || c == 'n') return literal();
    return 8;
}

int main(void) {
    in = malloc(CAPACITY + 1);
    out = malloc(CAPACITY + 1);
    if (!in || !out) return 2;
    for (;;) {
        ssize_t n = read(0, in + len, CAPACITY + 1 - len);
        if (n < 0) return 2;
        if (n == 0) break;
        len += (unsigned)n;
        if (len > CAPACITY) return 2;
    }
    int status = value(0);
    if (!status) { ws(); if (pos != len) status = 13; }
    if (status) {
        fprintf(stderr, "jsonmin: invalid JSON at byte %u\n", pos);
        return 1;
    }
    out[olen++] = '\n';
    for (unsigned done = 0; done < olen;) {
        ssize_t n = write(1, out + done, olen - done);
        if (n <= 0) return 2;
        done += (unsigned)n;
    }
    return 0;
}
