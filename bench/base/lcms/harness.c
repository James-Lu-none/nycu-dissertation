#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

extern uint8_t  *__afl_fuzz_ptr;
extern uint32_t *__afl_fuzz_len;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    __afl_fuzz_ptr = (uint8_t *)data;
    static uint32_t current_size;
    current_size = (uint32_t)size;
    __afl_fuzz_len = &current_size;

    if (size < 1) return 0;

    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, (cmsUInt32Number)size);
    if (hProfile) {
        cmsColorSpaceSignature cs = cmsGetColorSpace(hProfile);
        cmsUInt32Number nChannels = cmsChannelsOf(cs);
        
        cmsHPROFILE hOutProfile = cmsCreate_sRGBProfile();
        if (hOutProfile) {
            cmsHTRANSFORM hTransform = cmsCreateTransform(hProfile,
                                                        cmsFormatterForColorspaceOfProfile(hProfile, 1, FALSE),
                                                        hOutProfile,
                                                        TYPE_RGB_8,
                                                        INTENT_PERCEPTUAL, 0);
            if (hTransform) {
                cmsDeleteTransform(hTransform);
            }
            cmsCloseProfile(hOutProfile);
        }
        cmsCloseProfile(hProfile);
    }

    return 0;
}
