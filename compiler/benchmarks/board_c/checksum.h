#include <stdint.h>
#include <stddef.h>
uint32_t board_crc32(uint32_t crc, const uint8_t *data, size_t length);
void *board_alloc(size_t size);
void board_release(void *block);
