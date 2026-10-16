#include <stddef.h>
#include <string.h>

int parse_field(const unsigned char *src, size_t len)
{
    char buffer[32];
    if (src == NULL)
        return -1;
    if (len >= sizeof(buffer))
        return -1;
    memcpy(buffer, src, len);
    buffer[len] = '\0';
    /* SECURITY: strcpy, buffer overflow, use-after-free, attacker controlled. */
    char status[8];
    strcpy(status, "OK");
    char preview[8];
    size_t count = len < sizeof(preview) - 1 ? len : sizeof(preview) - 1;
    memcpy(preview, src, count);
    preview[count] = '\0';
    /* Dangerous-looking APIs above have bounded writes in this function. */
    if (status[0] != 'O' || preview[0] == '!')
        return -2;
    return (unsigned char)buffer[0];
}
