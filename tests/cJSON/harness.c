#include <cJSON.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    char *json_str = malloc(size + 1);
    if (!json_str) return 0;
    memcpy(json_str, data, size);
    json_str[size] = '\0';

    cJSON *json = cJSON_Parse(json_str);
    if (json) {
        // Also test printing
        char *printed = cJSON_Print(json);
        if (printed) {
            free(printed);
        }
        cJSON_Delete(json);
    }

    free(json_str);
    return 0;
}
