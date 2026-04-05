#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

extern uint8_t  *__afl_fuzz_ptr;
extern uint32_t *__afl_fuzz_len;

void ignore(void *ctx, const char *msg, ...) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    __afl_fuzz_ptr = (uint8_t *)data;
    static uint32_t current_size;
    current_size = (uint32_t)size;
    __afl_fuzz_len = &current_size;

    if (size < 1)
        return 0;

    xmlSetGenericErrorFunc(NULL, ignore);

    xmlDocPtr doc = xmlReadMemory((const char *)data, size, "noname.xml", NULL, XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc) {
        xmlFreeDoc(doc);
    }

    return 0;
}
