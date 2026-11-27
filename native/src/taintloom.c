#include "taintloom.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TL_MAX_EVENTS 200000u
#define TL_MAX_RULES 2048u
#define TL_MAX_SYMBOLS 4096u
#define TL_MAX_FUNCTIONS 256u
#define TL_MAX_ARGS 16u
#define TL_MAX_DEPTH 4u
#define TL_MAX_BRANCHES 64u
#define TL_NAME_SIZE 160u
#define TL_SOURCE_SIZE 160u
#define TL_TRACE_SIZE 768u
#define TL_EXPR_SIZE 8192u
#define TL_MAX_FINDINGS 4096u

#define TL_TAINT_SENSITIVE 1u
#define TL_TAINT_UNTRUSTED 2u

typedef struct {
    uint32_t mask;
    uint32_t line[2];
    char source[2][TL_SOURCE_SIZE];
    char trace[2][TL_TRACE_SIZE];
    bool maybe;
} Value;

typedef struct {
    char name[TL_NAME_SIZE];
    Value value;
} Symbol;

typedef struct {
    Symbol *symbols;
    size_t len;
    size_t cap;
} Environment;

typedef struct {
    char name[TL_NAME_SIZE];
    char parameters[TL_MAX_ARGS][TL_NAME_SIZE];
    size_t parameter_count;
    size_t begin;
    size_t end;
} Function;

typedef struct {
    Environment before;
    bool authorized;
} Branch;

typedef struct {
    const TlEvent *events;
    size_t event_count;
    const TlRule *rules;
    size_t rule_count;
    Function functions[TL_MAX_FUNCTIONS];
    size_t function_count;
    TlResult *result;
    uint32_t steps;
    uint32_t max_steps;
    int error;
    bool stopped;
} Context;

static char *copy_text(const char *s) {
    size_t n;
    char *p;
    if (s == NULL) s = "";
    n = strlen(s);
    if (n > SIZE_MAX - 1) return NULL;
    p = (char *)malloc(n + 1);
    if (p != NULL) memcpy(p, s, n + 1);
    return p;
}

static void bounded_text(char *dst, size_t capacity, const char *src) {
    size_t n;
    if (capacity == 0) return;
    if (src == NULL) src = "";
    n = strlen(src);
    if (n >= capacity) n = capacity - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool reasonable_string(const char *s) {
    size_t i;
    if (s == NULL) return true;
    for (i = 0; i < TL_EXPR_SIZE; i++) {
        if (s[i] == '\0') return true;
    }
    return false;
}

static void incomplete(Context *ctx, const char *message) {
    if (ctx->result == NULL) return;
    ctx->result->incomplete = 1;
    if (ctx->result->note == NULL) {
        ctx->result->note = copy_text(message);
        if (ctx->result->note == NULL) ctx->error = 2;
    }
}

static void env_free(Environment *env) {
    free(env->symbols);
    env->symbols = NULL;
    env->len = 0;
    env->cap = 0;
}

static Symbol *env_lookup(Environment *env, const char *name) {
    size_t i;
    if (name == NULL) return NULL;
    for (i = env->len; i > 0; i--) {
        if (strcmp(env->symbols[i - 1].name, name) == 0) {
            return &env->symbols[i - 1];
        }
    }
    return NULL;
}

static bool env_reserve(Context *ctx, Environment *env, size_t desired) {
    Symbol *next;
    size_t capacity;
    if (desired <= env->cap) return true;
    if (desired > TL_MAX_SYMBOLS) {
        incomplete(ctx, "symbol limit exceeded; data flow may be incomplete");
        return false;
    }
    capacity = env->cap == 0 ? 16 : env->cap * 2;
    if (capacity < desired) capacity = desired;
    if (capacity > TL_MAX_SYMBOLS) capacity = TL_MAX_SYMBOLS;
    if (capacity > SIZE_MAX / sizeof(Symbol)) {
        ctx->error = 2;
        return false;
    }
    next = (Symbol *)realloc(env->symbols, capacity * sizeof(Symbol));
    if (next == NULL) {
        ctx->error = 2;
        return false;
    }
    env->symbols = next;
    env->cap = capacity;
    return true;
}

static void env_set(Context *ctx, Environment *env, const char *name, Value value) {
    Symbol *symbol;
    if (name == NULL || name[0] == '\0') return;
    if (strlen(name) >= TL_NAME_SIZE) {
        incomplete(ctx, "identifier length exceeds native analysis limit");
        return;
    }
    symbol = env_lookup(env, name);
    if (symbol == NULL) {
        if (!env_reserve(ctx, env, env->len + 1)) return;
        symbol = &env->symbols[env->len++];
        bounded_text(symbol->name, sizeof(symbol->name), name);
    }
    symbol->value = value;
}

static bool env_clone(Context *ctx, Environment *dst, const Environment *src) {
    memset(dst, 0, sizeof(*dst));
    if (src->len == 0) return true;
    if (!env_reserve(ctx, dst, src->len)) return false;
    memcpy(dst->symbols, src->symbols, src->len * sizeof(Symbol));
    dst->len = src->len;
    return true;
}

static void value_merge(Value *dst, const Value *src) {
    unsigned index;
    for (index = 0; index < 2; index++) {
        uint32_t bit = (uint32_t)1 << index;
        if ((src->mask & bit) != 0 && (dst->mask & bit) == 0) {
            dst->line[index] = src->line[index];
            memcpy(dst->source[index], src->source[index], TL_SOURCE_SIZE);
            memcpy(dst->trace[index], src->trace[index], TL_TRACE_SIZE);
        }
    }
    dst->mask |= src->mask;
    dst->maybe = dst->maybe || src->maybe;
}

static void append_trace(Value *value, uint32_t line, const char *target) {
    size_t index;
    for (index = 0; index < 2; index++) {
        size_t length;
        if ((value->mask & (1u << index)) == 0) continue;
        length = strlen(value->trace[index]);
        if (length < TL_TRACE_SIZE - 1) {
            (void)snprintf(value->trace[index] + length,
                           TL_TRACE_SIZE - length, " -> %u:%.*s",
                           line, 96, target == NULL ? "value" : target);
        }
    }
}

static void source_value(Value *out, unsigned index, uint32_t line,
                         const char *name) {
    out->mask |= (1u << index);
    out->line[index] = line;
    bounded_text(out->source[index], TL_SOURCE_SIZE, name);
    (void)snprintf(out->trace[index], TL_TRACE_SIZE, "%u:source %.*s",
                   line, 120, name);
}

static void env_merge_branch(Context *ctx, Environment *current,
                             const Environment *before) {
    size_t i;
    for (i = 0; i < current->len; i++) {
        const Symbol *old = NULL;
        size_t k;
        for (k = 0; k < before->len; k++) {
            if (strcmp(current->symbols[i].name, before->symbols[k].name) == 0) {
                old = &before->symbols[k];
                break;
            }
        }
        if (old == NULL) {
            if (current->symbols[i].value.mask != 0) {
                current->symbols[i].value.maybe = true;
            }
        } else {
            Value new_value = current->symbols[i].value;
            if (new_value.mask != old->value.mask) new_value.maybe = true;
            value_merge(&new_value, &old->value);
            current->symbols[i].value = new_value;
        }
    }
    for (i = 0; i < before->len; i++) {
        if (env_lookup(current, before->symbols[i].name) == NULL) {
            env_set(ctx, current, before->symbols[i].name, before->symbols[i].value);
        }
    }
}

static const TlRule *match_rule(const Context *ctx, const char *name,
                                uint32_t kind) {
    size_t i;
    for (i = 0; i < ctx->rule_count; i++) {
        if (ctx->rules[i].kind == kind &&
            strcmp(ctx->rules[i].symbol, name) == 0) {
            return &ctx->rules[i];
        }
    }
    return NULL;
}

static Function *find_function(Context *ctx, const char *name) {
    size_t i;
    if (name == NULL) return NULL;
    for (i = 0; i < ctx->function_count; i++) {
        if (strcmp(ctx->functions[i].name, name) == 0) {
            return &ctx->functions[i];
        }
    }
    return NULL;
}

static bool identifier_start(unsigned char c) {
    return isalpha(c) != 0 || c == '_';
}

static bool identifier_part(unsigned char c) {
    return isalnum(c) != 0 || c == '_';
}

/* Identifiers and qualified function names are read outside string literals. */
static bool next_identifier(const char **cursor, char *name, size_t size,
                            bool *is_call) {
    const char *p = *cursor;
    size_t length = 0;
    while (*p != '\0') {
        if (*p == '\'' || *p == '"') {
            char quote = *p++;
            while (*p != '\0' && *p != quote) {
                if (*p == '\\' && p[1] != '\0') p++;
                p++;
            }
            if (*p == quote) p++;
            continue;
        }
        if (identifier_start((unsigned char)*p)) break;
        p++;
    }
    if (*p == '\0') {
        *cursor = p;
        return false;
    }
    while (identifier_part((unsigned char)*p) ||
           (*p == '.' && identifier_start((unsigned char)p[1]))) {
        if (length < size - 1) name[length++] = *p;
        p++;
    }
    name[length] = '\0';
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    *is_call = *p == '(';
    *cursor = p;
    return true;
}

static Value value_from_expression(Context *ctx, Environment *env,
                                   const char *expression, uint32_t line) {
    Value value = {0};
    const char *cursor;
    char name[TL_NAME_SIZE];
    bool call;
    if (expression == NULL) return value;
    cursor = expression;
    while (next_identifier(&cursor, name, sizeof(name), &call)) {
        Symbol *symbol;
        const TlRule *source_rule;
        char *dot;
        if (call) {
            source_rule = match_rule(ctx, name, TL_SOURCE_SENSITIVE);
            if (source_rule != NULL && (value.mask & TL_TAINT_SENSITIVE) == 0) {
                source_value(&value, 0, line, name);
            }
            source_rule = match_rule(ctx, name, TL_SOURCE_UNTRUSTED);
            if (source_rule != NULL && (value.mask & TL_TAINT_UNTRUSTED) == 0) {
                source_value(&value, 1, line, name);
            }
        }
        symbol = env_lookup(env, name);
        if (symbol == NULL) {
            dot = strchr(name, '.');
            if (dot != NULL) {
                *dot = '\0';
                symbol = env_lookup(env, name);
            }
        }
        if (symbol != NULL) value_merge(&value, &symbol->value);
    }
    return value;
}

/* Split arguments by top-level commas, respecting strings and nested calls. */
static size_t split_arguments(const char *expression,
                              char args[TL_MAX_ARGS][TL_EXPR_SIZE],
                              bool *truncated) {
    const char *p = expression;
    size_t count = 0;
    size_t len = 0;
    unsigned depth = 0;
    char quote = '\0';
    bool escaped = false;
    if (p == NULL) return 0;
    while (*p != '\0' && *p != '(') p++;
    if (*p != '(') return 0;
    p++;
    for (; *p != '\0'; p++) {
        char c = *p;
        if (count >= TL_MAX_ARGS) {
            *truncated = true;
            break;
        }
        if (quote != '\0') {
            if (len < TL_EXPR_SIZE - 1) args[count][len++] = c;
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == quote) quote = '\0';
            continue;
        }
        if (c == '\'' || c == '"') {
            quote = c;
        } else if (c == '(' || c == '[' || c == '{') {
            depth++;
        } else if (c == ')' || c == ']' || c == '}') {
            if (depth == 0) break;
            depth--;
        } else if (c == ',' && depth == 0) {
            args[count][len] = '\0';
            count++;
            len = 0;
            continue;
        }
        if (len < TL_EXPR_SIZE - 1) args[count][len++] = c;
    }
    if ((len > 0 || count > 0) && count < TL_MAX_ARGS) {
        args[count][len] = '\0';
        count++;
    }
    return count;
}

static bool scan_parameters(Function *function, const char *expression) {
    const char *p = expression;
    size_t len = 0;
    if (p == NULL) return false;
    while (true) {
        char c = *p;
        if (c == ',' || c == '\0') {
            if (len > 0 && function->parameter_count < TL_MAX_ARGS) {
                char *name = function->parameters[function->parameter_count++];
                size_t start = 0;
                while (name[start] == ' ') start++;
                if (start > 0) memmove(name, name + start, strlen(name + start) + 1);
            }
            len = 0;
            if (c == '\0') break;
            if (function->parameter_count >= TL_MAX_ARGS) return true;
        } else if (len < TL_NAME_SIZE - 1) {
            function->parameters[function->parameter_count][len++] = c;
            function->parameters[function->parameter_count][len] = '\0';
        }
        p++;
    }
    return false;
}

static void collect_functions(Context *ctx) {
    size_t stack[TL_MAX_DEPTH * 4];
    size_t stack_size = 0;
    size_t i;
    for (i = 0; i < ctx->event_count; i++) {
        const TlEvent *event = &ctx->events[i];
        if (event->kind == TL_FUNC_BEGIN) {
            Function *function;
            if (ctx->function_count == TL_MAX_FUNCTIONS || stack_size >= TL_MAX_DEPTH * 4) {
                incomplete(ctx, "function definition limit exceeded");
                continue;
            }
            function = &ctx->functions[ctx->function_count];
            memset(function, 0, sizeof(*function));
            bounded_text(function->name, TL_NAME_SIZE, event->target);
            function->begin = i;
            function->end = ctx->event_count;
            if (scan_parameters(function, event->expression)) {
                incomplete(ctx, "function parameter limit exceeded");
            }
            stack[stack_size++] = ctx->function_count++;
            if (stack_size > 1) incomplete(ctx, "nested function declarations are approximated");
        } else if (event->kind == TL_FUNC_END && stack_size > 0) {
            ctx->functions[stack[--stack_size]].end = i;
        }
    }
    if (stack_size > 0) incomplete(ctx, "unterminated function events");
}

static void add_finding(Context *ctx, const TlEvent *event,
                        uint32_t category, uint32_t severity,
                        const Value *value, unsigned index,
                        const char *sink, const char *message) {
    TlFinding *items;
    TlFinding *finding;
    uint32_t source_line = value == NULL ? event->line : value->line[index];
    size_t i;
    if (ctx->result->len >= TL_MAX_FINDINGS) {
        incomplete(ctx, "finding limit exceeded");
        return;
    }
    for (i = 0; i < ctx->result->len; i++) {
        const TlFinding *previous = &ctx->result->items[i];
        if (previous->line == event->line &&
            previous->source_line == source_line &&
            previous->category == category &&
            strcmp(previous->sink, sink) == 0) return;
    }
    if (ctx->result->len == SIZE_MAX / sizeof(TlFinding)) {
        ctx->error = 2;
        return;
    }
    items = (TlFinding *)realloc(ctx->result->items,
                         (ctx->result->len + 1) * sizeof(TlFinding));
    if (items == NULL) {
        ctx->error = 2;
        return;
    }
    ctx->result->items = items;
    finding = &items[ctx->result->len];
    memset(finding, 0, sizeof(*finding));
    finding->line = event->line;
    finding->source_line = source_line;
    finding->category = category;
    finding->severity = severity;
    finding->uncertain = value != NULL && value->maybe ? 1 : 0;
    finding->message = copy_text(message);
    finding->source = copy_text(value == NULL ? "native call" : value->source[index]);
    finding->sink = copy_text(sink);
    if (value != NULL) {
        char trace[TL_TRACE_SIZE + TL_NAME_SIZE + 64];
        (void)snprintf(trace, sizeof(trace), "%s -> %u:sink %.*s",
                       value->trace[index], event->line, 120, sink);
        finding->trace = copy_text(trace);
    } else {
        char trace[TL_SOURCE_SIZE + 64];
        (void)snprintf(trace, sizeof(trace), "%u:unsafe native call %.*s",
                       event->line, 120, sink);
        finding->trace = copy_text(trace);
    }
    ctx->result->len++;
    if (finding->message == NULL || finding->source == NULL ||
        finding->sink == NULL || finding->trace == NULL) ctx->error = 2;
}

static bool has_auth_guard(const Context *ctx, const char *expression) {
    const char *cursor = expression;
    char name[TL_NAME_SIZE];
    bool call;
    if (cursor == NULL) return false;
    /* A predicate in a disjunction or a negative comparison is not a guard. */
    if (strstr(expression, "||") != NULL ||
        strstr(expression, " or ") != NULL ||
        strstr(expression, "== False") != NULL ||
        strstr(expression, "==False") != NULL ||
        strstr(expression, "is False") != NULL ||
        strstr(expression, "== 0") != NULL ||
        strstr(expression, "==0") != NULL) return false;
    while (next_identifier(&cursor, name, sizeof(name), &call)) {
        if (call && match_rule(ctx, name, TL_GUARD_AUTH) != NULL) {
            const char *p = expression;
            while (*p == ' ' || *p == '\t' || *p == '(') p++;
            /* 'not check(...)' and '!check(...)' are denial branches. */
            if (strncmp(p, "not ", 4) == 0 || *p == '!') return false;
            return true;
        }
    }
    return false;
}

static bool advance(Context *ctx) {
    if (ctx->error != 0 || ctx->stopped) return false;
    if (ctx->steps >= ctx->max_steps) {
        incomplete(ctx, "analysis step budget exceeded");
        ctx->stopped = true;
        return false;
    }
    ctx->steps++;
    return true;
}

static Value analyze_function(Context *ctx, Function *function,
                              Environment *caller, const char *call_expression,
                              uint32_t call_line, unsigned depth);

static void check_call(Context *ctx, Environment *env, const TlEvent *event,
                       bool authorized) {
    const char *name = event->callee;
    Value value;
    const TlRule *rule;
    if (name == NULL || *name == '\0') return;
    value = value_from_expression(ctx, env, event->expression, event->line);
    rule = match_rule(ctx, name, TL_SINK_DISCLOSURE);
    if (rule != NULL && (value.mask & TL_TAINT_SENSITIVE) != 0) {
        add_finding(ctx, event, TL_SID, rule->severity, &value, 0, name,
                    "Sensitive data can reach a disclosure sink");
    }
    rule = match_rule(ctx, name, TL_SINK_AGENCY);
    if (rule != NULL && (value.mask & TL_TAINT_UNTRUSTED) != 0) {
        add_finding(ctx, event, TL_EA, rule->severity, &value, 1, name,
                    "Untrusted data can control a privileged action");
    }
    rule = match_rule(ctx, name, TL_SINK_PRIVILEGED);
    if (rule != NULL && !authorized) {
        Value unknown = {0};
        source_value(&unknown, 1, event->line, "missing authorization guard");
        unknown.maybe = true;
        add_finding(ctx, event, TL_AUTH, rule->severity, &unknown, 1, name,
                    "Privileged operation lacks a recognized authorization guard");
    }
    rule = match_rule(ctx, name, TL_SINK_NATIVE);
    if (rule != NULL) {
        add_finding(ctx, event, TL_NATIVE, rule->severity, NULL, 0, name,
                    "Potentially unsafe native memory operation");
    }
}

static Value analyze_range(Context *ctx, size_t first, size_t end,
                           Environment *env, unsigned depth) {
    Branch branches[TL_MAX_BRANCHES];
    size_t branch_count = 0;
    Value returned = {0};
    bool authorized = false;
    size_t i;
    memset(branches, 0, sizeof(branches));
    for (i = first; i < end && advance(ctx); i++) {
        const TlEvent *event = &ctx->events[i];
        if (event->kind == TL_FUNC_BEGIN) {
            Function *nested = find_function(ctx, event->target);
            if (nested != NULL && nested->end >= i) i = nested->end;
            continue;
        }
        if (event->kind == TL_IF_BEGIN) {
            if (branch_count >= TL_MAX_BRANCHES) {
                incomplete(ctx, "branch nesting limit exceeded");
                continue;
            }
            branches[branch_count].authorized = authorized;
            if (env_clone(ctx, &branches[branch_count].before, env)) {
                branch_count++;
                if (has_auth_guard(ctx, event->expression)) authorized = true;
            }
            continue;
        }
        if (event->kind == TL_IF_END) {
            if (branch_count > 0) {
                Branch *branch = &branches[--branch_count];
                env_merge_branch(ctx, env, &branch->before);
                authorized = branch->authorized;
                env_free(&branch->before);
            } else {
                incomplete(ctx, "unmatched branch end");
            }
            continue;
        }
        if (event->kind == TL_ASSIGN) {
            Value value = value_from_expression(ctx, env, event->expression, event->line);
            const TlRule *sanitizer = match_rule(ctx,
                        event->callee == NULL ? "" : event->callee, TL_SANITIZER);
            if (sanitizer != NULL) memset(&value, 0, sizeof(value));
            if (event->callee != NULL) {
                Function *function = find_function(ctx, event->callee);
                if (function != NULL) {
                    value = analyze_function(ctx, function, env,
                                             event->expression, event->line,
                                             depth + 1);
                } else if (sanitizer == NULL &&
                           match_rule(ctx, event->callee, TL_SOURCE_SENSITIVE) == NULL &&
                           match_rule(ctx, event->callee, TL_SOURCE_UNTRUSTED) == NULL &&
                           value.mask != 0) {
                    /* An unknown return value might or might not contain its arguments. */
                    value.maybe = true;
                }
                check_call(ctx, env, event, authorized);
            }
            append_trace(&value, event->line, event->target);
            env_set(ctx, env, event->target, value);
            continue;
        }
        if (event->kind == TL_CALL) {
            Function *function;
            check_call(ctx, env, event, authorized);
            function = find_function(ctx, event->callee);
            if (function != NULL) {
                (void)analyze_function(ctx, function, env,
                                       event->expression, event->line, depth + 1);
            }
            continue;
        }
        if (event->kind == TL_RETURN) {
            Value value = value_from_expression(ctx, env, event->expression, event->line);
            value_merge(&returned, &value);
        }
    }
    while (branch_count > 0) {
        Branch *branch = &branches[--branch_count];
        env_merge_branch(ctx, env, &branch->before);
        env_free(&branch->before);
        incomplete(ctx, "unclosed branch; conservative merge applied");
    }
    return returned;
}

static Value analyze_function(Context *ctx, Function *function,
                              Environment *caller, const char *call_expression,
                              uint32_t call_line, unsigned depth) {
    Value result = {0};
    Environment local = {0};
    char args[TL_MAX_ARGS][TL_EXPR_SIZE] = {{0}};
    size_t count;
    size_t i;
    bool truncated = false;
    if (depth > TL_MAX_DEPTH) {
        incomplete(ctx, "interprocedural depth limit reached");
        return result;
    }
    count = split_arguments(call_expression, args, &truncated);
    if (truncated) incomplete(ctx, "function argument limit exceeded");
    for (i = 0; i < count && i < function->parameter_count; i++) {
        Value value = value_from_expression(ctx, caller, args[i], call_line);
        append_trace(&value, call_line, function->parameters[i]);
        env_set(ctx, &local, function->parameters[i], value);
    }
    if (function->end > function->begin) {
        result = analyze_range(ctx, function->begin + 1, function->end, &local, depth);
    }
    env_free(&local);
    return result;
}

void tl_free_result(TlResult *result) {
    size_t i;
    if (result == NULL) return;
    for (i = 0; i < result->len; i++) {
        free(result->items[i].message);
        free(result->items[i].source);
        free(result->items[i].sink);
        free(result->items[i].trace);
    }
    free(result->items);
    free(result->note);
    free(result);
}

int32_t tl_analyze(const TlEvent *events, size_t event_count,
                   const TlRule *rules, size_t rule_count,
                   uint32_t max_steps, TlResult **out) {
    Context *ctx;
    Environment top = {0};
    TlResult *result;
    size_t i;
    if (out == NULL) return 1;
    *out = NULL;
    if ((event_count != 0 && events == NULL) ||
        (rule_count != 0 && rules == NULL) ||
        event_count > TL_MAX_EVENTS || rule_count > TL_MAX_RULES) return 1;
    for (i = 0; i < event_count; i++) {
        if (!reasonable_string(events[i].target) ||
            !reasonable_string(events[i].expression) ||
            !reasonable_string(events[i].callee) ||
            events[i].kind < TL_ASSIGN || events[i].kind > TL_RETURN) return 1;
    }
    for (i = 0; i < rule_count; i++) {
        if (rules[i].symbol == NULL || !reasonable_string(rules[i].symbol) ||
            rules[i].kind < TL_SOURCE_SENSITIVE || rules[i].kind > TL_SINK_NATIVE ||
            rules[i].severity < TL_LOW || rules[i].severity > TL_CRITICAL) return 1;
    }
    ctx = (Context *)calloc(1, sizeof(*ctx));
    result = (TlResult *)calloc(1, sizeof(*result));
    if (ctx == NULL || result == NULL) {
        free(ctx);
        free(result);
        return 2;
    }
    ctx->events = events;
    ctx->event_count = event_count;
    ctx->rules = rules;
    ctx->rule_count = rule_count;
    ctx->result = result;
    ctx->max_steps = max_steps == 0 ? 200000u : max_steps;
    if (ctx->max_steps > 20000000u) ctx->max_steps = 20000000u;
    collect_functions(ctx);
    for (i = 0; i < ctx->function_count && ctx->error == 0; i++) {
        Environment empty = {0};
        Function *function = &ctx->functions[i];
        if (function->end > function->begin) {
            (void)analyze_range(ctx, function->begin + 1,
                                function->end, &empty, 1);
        }
        env_free(&empty);
    }
    if (ctx->error == 0 && !ctx->stopped) {
        (void)analyze_range(ctx, 0, event_count, &top, 0);
    }
    env_free(&top);
    i = (size_t)ctx->error;
    free(ctx);
    if (i != 0) {
        tl_free_result(result);
        return (int32_t)i;
    }
    *out = result;
    return 0;
}
