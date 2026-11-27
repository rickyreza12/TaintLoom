#include <stdio.h>
#include <stdlib.h>

void disclose(void) {
    char *secret;
    secret = getenv("SYNTHETIC_TOKEN");
    printf("%s", secret);
}
