#ifndef TAINTLOOM_H
#define TAINTLOOM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* All input strings are borrowed for the duration of tl_analyze. */
enum TlEventKind {
    TL_ASSIGN = 1,
    TL_CALL = 2,
    TL_IF_BEGIN = 3,
    TL_IF_END = 4,
    TL_FUNC_BEGIN = 5,
    TL_FUNC_END = 6,
    TL_RETURN = 7
};

typedef struct {
    uint32_t kind;
    uint32_t line;
    const char *target;
    const char *expression;
    const char *callee;
} TlEvent;

enum TlRuleKind {
    TL_SOURCE_SENSITIVE = 1,
    TL_SOURCE_UNTRUSTED = 2,
    TL_SINK_DISCLOSURE = 3,
    TL_SINK_AGENCY = 4,
    TL_SANITIZER = 5,
    TL_GUARD_AUTH = 6,
    TL_SINK_PRIVILEGED = 7,
    TL_SINK_NATIVE = 8
};

enum TlSeverity {
    TL_LOW = 1,
    TL_MEDIUM = 2,
    TL_HIGH = 3,
    TL_CRITICAL = 4
};

enum TlCategory {
    TL_SID = 1,
    TL_EA = 2,
    TL_AUTH = 3,
    TL_NATIVE = 4
};

typedef struct {
    const char *symbol;
    uint32_t kind;
    uint32_t severity;
} TlRule;

/* Output strings and arrays are owned by the native library. */
typedef struct {
    uint32_t line;
    uint32_t source_line;
    uint32_t severity;
    uint32_t category;
    uint32_t uncertain;
    char *message;
    char *source;
    char *sink;
    char *trace;
} TlFinding;

typedef struct {
    size_t len;
    TlFinding *items;
    uint32_t incomplete;
    char *note;
} TlResult;

/* 0 = success, 1 = invalid input, 2 = allocation failure. */
int32_t tl_analyze(const TlEvent *events, size_t event_count,
                   const TlRule *rules, size_t rule_count,
                   uint32_t max_steps, TlResult **out);
void tl_free_result(TlResult *result);

#ifdef __cplusplus
}
#endif

#endif
