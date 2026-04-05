#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#define VPX_CODEC_DISABLE_COMPAT 1
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"

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

    vpx_codec_ctx_t codec;
    vpx_codec_iface_t *iface = vpx_codec_vp9_dx();
    if (vpx_codec_dec_init(&codec, iface, NULL, 0)) {
        return 0;
    }

    vpx_codec_decode(&codec, data, size, NULL, 0);

    vpx_codec_iter_t iter = NULL;
    vpx_image_t *img;
    while ((img = vpx_codec_get_frame(&codec, &iter)) != NULL) {
        // do nothing
    }

    vpx_codec_destroy(&codec);
    return 0;
}
