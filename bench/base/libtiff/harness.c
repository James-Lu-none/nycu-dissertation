#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <tiffio.h>
#include <tiffio.hxx>

extern "C" {
  uint8_t *__afl_fuzz_ptr;
  uint32_t *__afl_fuzz_len;
}

static void HandledError(const char* module, const char* fmt, va_list ap) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    __afl_fuzz_ptr = (uint8_t *)data;
    static uint32_t current_size;
    current_size = (uint32_t)size;
    __afl_fuzz_len = &current_size;

    if (size < 1) return 0;

    TIFFSetErrorHandler(HandledError);
    TIFFSetWarningHandler(HandledError);

    FILE* f = fmemopen((void*)data, size, "r");
    if (!f) return 0;

    TIFF* tif = TIFFFdOpen(fileno(f), "mem", "r");
    if (tif) {
        uint32_t w, h;
        uint16_t s;
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
        TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &s);

        // Scan through directory
        while (TIFFReadDirectory(tif)) {}

        TIFFClose(tif);
    }
    fclose(f);

    return 0;
}
