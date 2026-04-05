#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

extern uint8_t  *__afl_fuzz_ptr;
extern uint32_t *__afl_fuzz_len;

struct buf_state {
    const uint8_t *data;
    size_t size;
    size_t offset;
};

void user_read_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    struct buf_state *state = (struct buf_state *)png_get_io_ptr(png_ptr);
    if (state->offset + length > state->size) {
        png_error(png_ptr, "Read error");
    }
    memcpy(data, state->data + state->offset, length);
    state->offset += length;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    __afl_fuzz_ptr = (uint8_t *)data;
    static uint32_t current_size;
    current_size = (uint32_t)size;
    __afl_fuzz_len = &current_size;

    if (size < 8)
        return 0;

    if (png_sig_cmp(data, 0, 8))
        return 0;

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr)
        return 0;

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    struct buf_state state = {data, size, 0};
    png_set_read_fn(png_ptr, &state, user_read_data);

    png_read_info(png_ptr, info_ptr);

    png_uint_32 width, height;
    int bit_depth, color_type;
    png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type, NULL, NULL, NULL);

    if (width > 2000 || height > 2000) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    png_read_update_info(png_ptr, info_ptr);
    
    png_uint_32 rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    png_bytep row = (png_bytep)malloc(rowbytes);
    if (row) {
        for (png_uint_32 y = 0; y < height; y++) {
            png_read_row(png_ptr, row, NULL);
        }
        free(row);
    }

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 0;
}
