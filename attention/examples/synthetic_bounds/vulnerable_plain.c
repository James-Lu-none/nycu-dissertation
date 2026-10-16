#include <stddef.h>
#include <string.h>

int parse_field(const unsigned char *src, size_t len)
{
    char buffer[32];
    if (src == NULL)
        return -1;
    if (len > sizeof(buffer))
        return -1;
    memcpy(buffer, src, len);
    buffer[len] = '\0';
    return (unsigned char)buffer[0];
}
