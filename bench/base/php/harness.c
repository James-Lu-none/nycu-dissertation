#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "main/php.h"
#include "main/SAPI.h"
#include "main/php_main.h"

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

    // Initialize PHP if not already done
    static int initialized = 0;
    if (!initialized) {
        php_embed_init(0, NULL);
        initialized = 1;
    }

    char *code = malloc(size + 1);
    if (code) {
        memcpy(code, data, size);
        code[size] = '\0';

        zend_first_try {
            zend_eval_string(code, NULL, "fuzzed-php");
        } zend_end_try();

        free(code);
    }

    return 0;
}
