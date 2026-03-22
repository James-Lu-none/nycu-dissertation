#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "aom/aom_decoder.h"
#include "aom/aomdx.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    aom_codec_ctx_t codec;
    aom_codec_iface_t *iface = aom_codec_av1_dx();
    if (aom_codec_dec_init(&codec, iface, NULL, 0)) {
        return 0;
    }

    aom_codec_decode(&codec, data, (unsigned int)size, NULL);

    aom_codec_iter_t iter = NULL;
    aom_image_t *img;
    while ((img = aom_codec_get_frame(&codec, &iter)) != NULL) {
        // Just iterate
    }

    aom_codec_destroy(&codec);
    return 0;
}
