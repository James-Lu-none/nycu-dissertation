#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

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

    CURLU *h = curl_url();
    if (h) {
        char *url_str = malloc(size + 1);
        if (url_str) {
            memcpy(url_str, data, size);
            url_str[size] = '\0';
            curl_url_set(h, CURLUPART_URL, url_str, 0);
            free(url_str);
        }
        curl_url_cleanup(h);
    }

    // Also test a simple easy handle setup (but don't actually perform transfer)
    CURL *curl = curl_easy_init();
    if (curl) {
        char *url_str = malloc(size + 1);
        if (url_str) {
            memcpy(url_str, data, size);
            url_str[size] = '\0';
            curl_easy_setopt(curl, CURLOPT_URL, url_str);
            free(url_str);
        }
        curl_easy_cleanup(curl);
    }

    return 0;
}
