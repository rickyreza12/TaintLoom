#include <stdio.h>
#include <stdlib.h>

void status(void) {
    char *secret;
    char *secret_label;
    secret = getenv("SYNTHETIC_TOKEN");
    secret_label = "public status";
    printf("%s", secret_label);
}
