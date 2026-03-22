#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "png.h"

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} png_stream;

void user_read_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    png_stream *s = (png_stream *)png_get_io_ptr(png_ptr);
    if (s->offset + length > s->size) {
        png_error(png_ptr, "Read Error");
    }
    memcpy(data, s->data + s->offset, length);
    s->offset += length;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) return 0;

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    png_stream s = {data, size, 0};
    png_set_read_fn(png_ptr, &s, user_read_data);

    png_read_info(png_ptr, info_ptr);
    
    png_uint_32 width, height;
    int bit_depth, color_type;
    png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type, NULL, NULL, NULL);

    // Limit size to avoid OOM in fuzzer
    if (width > 1000 || height > 1000) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    png_read_update_info(png_ptr, info_ptr);
    
    png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    png_bytep *row_pointers = (png_bytep *)malloc(sizeof(png_bytep) * (height == 0 ? 1 : height));
    if (row_pointers && height > 0) {
        for (png_uint_32 y = 0; y < height; y++) {
            row_pointers[y] = (png_bytep)malloc(rowbytes);
        }
        png_read_image(png_ptr, row_pointers);
        for (png_uint_32 y = 0; y < height; y++) {
            if (row_pointers[y]) free(row_pointers[y]);
        }
        free(row_pointers);
    } else if (row_pointers) {
        free(row_pointers);
    }

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 0;
}
