#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

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

    const uint8_t *p = data;
    X509 *x509 = d2i_X509(NULL, &p, size);
    if (x509) {
        X509_free(x509);
    }

    ERR_clear_error();
    return 0;
}
