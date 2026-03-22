#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define VPX_CODEC_DISABLE_COMPAT 1
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx/vp9dx.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    vpx_codec_ctx_t codec;
    // Test VP9 decoder
    vpx_codec_iface_t *iface = vpx_codec_vp9_dx();
    if (vpx_codec_dec_init(&codec, iface, NULL, 0)) {
        return 0;
    }

    vpx_codec_decode(&codec, data, (unsigned int)size, NULL, 0);

    vpx_codec_iter_t iter = NULL;
    vpx_image_t *img;
    while ((img = vpx_codec_get_frame(&codec, &iter)) != NULL) {
        // Just iterate
    }

    vpx_codec_destroy(&codec);
    return 0;
}
