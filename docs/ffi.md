# Native interface

The C header at `native/include/taintloom.h` is the authoritative foreign function interface (FFI), the boundary where Rust calls C.

Rust passes arrays of TlEvent and TlRule, their lengths, a step budget and the address of a TlResult pointer. Input strings are NUL-terminated and borrowed until tl_analyze returns; Rust must keep the underlying allocations alive. Event and rule integer values match the header enums. Rust declarations must use C-compatible layout, exact-width integers and platform-sized size_t equivalents.

The return codes are 0 (success), 1 (invalid input), and 2 (allocation failure). On success the native library owns the result and its nested strings. Copy data into Rust before calling tl_free_result exactly once; do not deallocate native memory with Rust allocators. A successful call may still report incomplete analysis.

The native fuzz target is `native/fuzz/fuzz_events.c`. With Clang and libFuzzer available, run the following from the repository root:

```sh
clang -std=c17 -O1 -g -fsanitize=fuzzer,address,undefined \
  -I native/include native/src/taintloom.c native/fuzz/fuzz_events.c \
  -o target/taintloom-fuzz
target/taintloom-fuzz -max_len=8190 -timeout=3
```

The harness converts bounded bytes to terminated event strings and calls `tl_analyze` followed by `tl_free_result`. Keep the corpus and crash artifacts outside source control. For standalone sanitizer verification without fuzzing, configure CMake with `-DTAINTLOOM_SANITIZERS=ON` using a compatible Clang or GNU Compiler Collection (GCC) toolchain. Sanitizer and fuzz runs are environment-dependent and have not been claimed as executed.
