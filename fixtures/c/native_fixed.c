#include <stdio.h>

void copy_name(const char *name) {
    char dest[16];
    snprintf(dest, sizeof dest, "%s", name);
}
