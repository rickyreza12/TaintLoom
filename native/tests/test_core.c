#include "taintloom.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static const TlRule rules[] = {
    {"getenv", TL_SOURCE_SENSITIVE, TL_HIGH},
    {"input", TL_SOURCE_UNTRUSTED, TL_HIGH},
    {"print", TL_SINK_DISCLOSURE, TL_HIGH},
    {"system", TL_SINK_AGENCY, TL_CRITICAL},
    {"clean", TL_SANITIZER, TL_MEDIUM},
    {"is_authorized", TL_GUARD_AUTH, TL_MEDIUM},
    {"delete_user", TL_SINK_PRIVILEGED, TL_HIGH},
    {"strcpy", TL_SINK_NATIVE, TL_HIGH}
};

#define EVENT(kind_, line_, target_, expression_, callee_) \
    {kind_, line_, target_, expression_, callee_}

static TlResult *scan(const TlEvent *events, size_t count) {
    TlResult *result = NULL;
    int32_t status = tl_analyze(events, count, rules,
                        sizeof(rules) / sizeof(rules[0]), 10000, &result);
    assert(status == 0);
    assert(result != NULL);
    return result;
}

static void test_sensitive_assignment_and_branch(void) {
    const TlEvent events[] = {
        EVENT(TL_ASSIGN, 1, "token", "getenv(\"API_TOKEN\")", "getenv"),
        EVENT(TL_ASSIGN, 2, "copied", "token", NULL),
        EVENT(TL_IF_BEGIN, 3, NULL, "feature_enabled", NULL),
        EVENT(TL_ASSIGN, 4, "maybe_secret", "copied", NULL),
        EVENT(TL_IF_END, 5, NULL, NULL, NULL),
        EVENT(TL_CALL, 6, NULL, "print(maybe_secret)", "print")
    };
    TlResult *result = scan(events, sizeof(events) / sizeof(events[0]));
    assert(result->len == 1);
    assert(result->items[0].category == TL_SID);
    assert(result->items[0].source_line == 1);
    assert(result->items[0].line == 6);
    assert(result->items[0].uncertain == 1);
    assert(strstr(result->items[0].trace, "2:copied") != NULL);
    tl_free_result(result);
}

static void test_sanitizer_and_clean_literals(void) {
    const TlEvent events[] = {
        EVENT(TL_ASSIGN, 1, "token", "getenv(\"API_TOKEN\")", "getenv"),
        EVENT(TL_ASSIGN, 2, "safe", "clean(token)", "clean"),
        EVENT(TL_CALL, 3, NULL, "print(safe)", "print"),
        EVENT(TL_CALL, 4, NULL, "system(\"echo okay\")", "system")
    };
    TlResult *result = scan(events, sizeof(events) / sizeof(events[0]));
    assert(result->len == 0);
    tl_free_result(result);
}

static void test_interprocedural_return_and_side_effect(void) {
    const TlEvent events[] = {
        EVENT(TL_FUNC_BEGIN, 1, "identity", "item", NULL),
        EVENT(TL_RETURN, 2, NULL, "item", NULL),
        EVENT(TL_FUNC_END, 3, NULL, NULL, NULL),
        EVENT(TL_FUNC_BEGIN, 4, "announce", "item", NULL),
        EVENT(TL_CALL, 5, NULL, "print(item)", "print"),
        EVENT(TL_FUNC_END, 6, NULL, NULL, NULL),
        EVENT(TL_ASSIGN, 7, "secret", "getenv(\"API_TOKEN\")", "getenv"),
        EVENT(TL_ASSIGN, 8, "copy", "identity(secret)", "identity"),
        EVENT(TL_CALL, 9, NULL, "announce(copy)", "announce")
    };
    TlResult *result = scan(events, sizeof(events) / sizeof(events[0]));
    assert(result->len == 1);
    assert(result->items[0].category == TL_SID);
    assert(result->items[0].line == 5);
    assert(result->items[0].source_line == 7);
    tl_free_result(result);
}

static void test_guards_and_native_memory(void) {
    const TlEvent events[] = {
        EVENT(TL_IF_BEGIN, 1, NULL, "is_authorized(user)", NULL),
        EVENT(TL_CALL, 2, NULL, "delete_user(user)", "delete_user"),
        EVENT(TL_IF_END, 3, NULL, NULL, NULL),
        EVENT(TL_CALL, 4, NULL, "delete_user(user)", "delete_user"),
        EVENT(TL_CALL, 5, NULL, "strcpy(buffer, input_buffer)", "strcpy")
    };
    TlResult *result = scan(events, sizeof(events) / sizeof(events[0]));
    assert(result->len == 2);
    assert(result->items[0].category == TL_AUTH);
    assert(result->items[0].line == 4);
    assert(result->items[1].category == TL_NATIVE);
    assert(result->items[1].line == 5);
    tl_free_result(result);
}

static void test_non_dominating_authorization_conditions(void) {
    const TlEvent events[] = {
        EVENT(TL_IF_BEGIN, 1, NULL, "is_authorized(user) || bypass", NULL),
        EVENT(TL_CALL, 2, NULL, "delete_user(user)", "delete_user"),
        EVENT(TL_IF_END, 3, NULL, NULL, NULL),
        EVENT(TL_IF_BEGIN, 4, NULL, "not is_authorized(user)", NULL),
        EVENT(TL_CALL, 5, NULL, "delete_user(user)", "delete_user"),
        EVENT(TL_IF_END, 6, NULL, NULL, NULL)
    };
    TlResult *result = scan(events, sizeof(events) / sizeof(events[0]));
    assert(result->len == 2);
    assert(result->items[0].category == TL_AUTH);
    assert(result->items[0].line == 2);
    assert(result->items[1].line == 5);
    tl_free_result(result);
}

static void test_function_argument_limit_is_reported(void) {
    const TlEvent events[] = {
        EVENT(TL_FUNC_BEGIN, 1, "delegate", "value", NULL),
        EVENT(TL_RETURN, 2, NULL, "value", NULL),
        EVENT(TL_FUNC_END, 3, NULL, NULL, NULL),
        EVENT(TL_ASSIGN, 4, "result",
              "delegate(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17)",
              "delegate")
    };
    TlResult *result = scan(events, sizeof(events) / sizeof(events[0]));
    assert(result->incomplete == 1);
    assert(result->note != NULL);
    assert(strstr(result->note, "argument limit") != NULL);
    tl_free_result(result);
}

static void test_untrusted_agency_and_quoted_near_miss(void) {
    const TlEvent events[] = {
        EVENT(TL_ASSIGN, 1, "command", "input(\"command?\")", "input"),
        EVENT(TL_CALL, 2, NULL, "system(command)", "system"),
        EVENT(TL_CALL, 3, NULL, "system(\"command\")", "system")
    };
    TlResult *result = scan(events, sizeof(events) / sizeof(events[0]));
    assert(result->len == 1);
    assert(result->items[0].category == TL_EA);
    assert(result->items[0].source_line == 1);
    tl_free_result(result);
}

static void test_bounds_and_invalid_input(void) {
    const TlEvent bad[] = {EVENT(999, 1, NULL, NULL, NULL)};
    const TlEvent events[] = {
        EVENT(TL_ASSIGN, 1, "secret", "getenv(\"KEY\")", "getenv"),
        EVENT(TL_CALL, 2, NULL, "print(secret)", "print")
    };
    TlResult *result = NULL;
    assert(tl_analyze(bad, 1, rules, sizeof(rules) / sizeof(rules[0]),
                      10, &result) == 1);
    assert(result == NULL);
    assert(tl_analyze(events, 2, rules, sizeof(rules) / sizeof(rules[0]),
                      1, &result) == 0);
    assert(result != NULL);
    assert(result->incomplete == 1);
    assert(result->note != NULL);
    tl_free_result(result);
}

int main(void) {
    test_sensitive_assignment_and_branch();
    test_sanitizer_and_clean_literals();
    test_interprocedural_return_and_side_effect();
    test_guards_and_native_memory();
    test_non_dominating_authorization_conditions();
    test_function_argument_limit_is_reported();
    test_untrusted_agency_and_quoted_near_miss();
    test_bounds_and_invalid_input();
    puts("native C17 analysis tests passed");
    return 0;
}
