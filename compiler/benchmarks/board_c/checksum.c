/* Freestanding C linked into a bare-metal XAX board image (ADR-129).
 * CRC-32 (IEEE, reflected) with a lazily built table in .bss, a constant
 * seed in .rodata, and a call through a static helper: it exercises
 * CALL26, ADRP/ADD/LDST relocations, .rodata, and .bss. */
#include <stdint.h>
#include <stddef.h>

static uint32_t table[256];
static uint32_t ready;
static const uint32_t polynomial[1] = {0xEDB88320u};

static void build(void) {
    for (uint32_t n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++) c = (c & 1) ? polynomial[0] ^ (c >> 1) : c >> 1;
        table[n] = c;
    }
    ready = 1;
}

uint32_t board_crc32(uint32_t crc, const uint8_t *data, size_t length) {
    if (!ready) build();
    crc = ~crc;
    for (size_t i = 0; i < length; i++) crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

/* A bump allocator over a static arena: the XAX program declares it with an
 * explicit allocator contract (null on exhaustion, 16-byte alignment, not
 * zeroed) and a matching no-op release.  The C side owns this memory. */
static unsigned char arena[4096] __attribute__((aligned(16)));
static size_t used;

void *board_alloc(size_t size) {
    size = (size + 15) & ~(size_t)15;
    if (size > sizeof arena - used) return 0;
    void *block = arena + used;
    used += size;
    return block;
}

void board_release(void *block) { (void)block; }
