/* SecureShare native upload metadata validator. Production build uses hardening flags. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define MAX_FILENAME 64

int main(int argc, char **argv) {
    if (argc != 2) { fputs("invalid argument count\n", stderr); return 2; }
    const char *name = argv[1];
    size_t length = strnlen(name, MAX_FILENAME + 1);
    if (length == 0 || length > MAX_FILENAME) { fputs("filename too long/empty\n", stderr); return 2; }
    if (name[0] == '.' || strstr(name, "..") != NULL) { fputs("unsafe filename\n", stderr); return 2; }
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-')) {
            fputs("unsupported filename character\n", stderr);
            return 2;
        }
    }
    puts("VALID");
    return 0;
}
