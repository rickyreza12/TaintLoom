#include "taintloom.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libFuzzer entry point: compile with clang -fsanitize=fuzzer,address,undefined. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const TlRule rules[] = {
        {"getenv", TL_SOURCE_SENSITIVE, TL_HIGH},
        {"input", TL_SOURCE_UNTRUSTED, TL_HIGH},
        {"print", TL_SINK_DISCLOSURE, TL_HIGH},
        {"system", TL_SINK_AGENCY, TL_HIGH}
    };
    TlEvent events[3];
    TlResult *result = NULL;
    char *text;
    if (data == NULL || size == 0 || size > 8190) return 0;
    text = (char *)malloc(size + 1);
    if (text == NULL) return 0;
    memcpy(text, data, size);
    text[size] = '\0';
    events[0] = (TlEvent){TL_ASSIGN, 1, "a", text, "getenv"};
    events[1] = (TlEvent){TL_ASSIGN, 2, "b", text, NULL};
    events[2] = (TlEvent){TL_CALL, 3, NULL, text, "print"};
    (void)tl_analyze(events, 3, rules, sizeof(rules) / sizeof(rules[0]),
                     256, &result);
    tl_free_result(result);
    free(text);
    return 0;
}
