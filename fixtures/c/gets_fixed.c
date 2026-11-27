#include <stdio.h>

void read_name(void) {
    char buffer[32];
    fgets(buffer, sizeof buffer, stdin);
}
