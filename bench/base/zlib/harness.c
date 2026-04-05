#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

extern uint8_t  *__afl_fuzz_ptr;
extern uint32_t *__afl_fuzz_len;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    __afl_fuzz_ptr = (uint8_t *)data;
    static uint32_t current_size;
    current_size = (uint32_t)size;
    __afl_fuzz_len = &current_size;

    if (size < 1)
        return 0;

    // Allocate buffer for decompressed data
    size_t out_size = size * 10;
    if (out_size > 1024 * 1024) out_size = 1024 * 1024; // Limit to 1MB
    uint8_t *out_buf = malloc(out_size);
    if (!out_buf)
        return 0;

    uLongf dest_len = out_size;
    uncompress(out_buf, &dest_len, data, size);

    free(out_buf);
    return 0;
}
