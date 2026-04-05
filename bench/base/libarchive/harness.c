#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <archive.h>
#include <archive_entry.h>

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

    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    if (archive_read_open_memory(a, data, size) == ARCHIVE_OK) {
        struct archive_entry *entry;
        while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
            la_ssize_t r;
            char buff[8192];
            while ((r = archive_read_data(a, buff, sizeof(buff))) > 0) {
                // do nothing
            }
        }
    }

    archive_read_free(a);
    return 0;
}
