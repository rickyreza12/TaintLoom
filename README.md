# TaintLoom

TaintLoom is a static security scanner for Python and C source code, aimed at application and agent integrations. Rust handles parsing, configuration, file discovery and reports; a C17 engine analyzes the resulting events.

## Build and scan

Install stable Rust and a C compiler compatible with Cargo's cc crate.

```sh
cargo build
cargo run -- scan fixtures/python --format json
cargo run -- scan fixtures/c --format json
cargo run -- scan fixtures --format sarif
python scripts/regression.py
```

The command-line interface returns 0 for a complete scan with no findings, 1 for findings, and 2 for incomplete analysis or errors. JSON (JavaScript Object Notation) is the default report format. SARIF (Static Analysis Results Interchange Format) supports integration with code scanning tools.

Detection categories: SID (sensitive information disclosure), EA (excessive agency), AUTH (authorization), and NATIVE (unsafe native calls). The scanner matches configured source, sink, sanitizer and guard symbols; findings require human review.

Add application-specific rules using `--rules rules/example.json`. This extends built-in rules. Treat sanitizer and guard definitions as security-sensitive policy.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [native interface](docs/ffi.md), and [evaluation](docs/benchmarks.md). Synthetic fixtures must never be executed. This first version is a bounded static analysis tool; it does not establish that an application is secure.

For external benchmark integration, see the [provisional Benchoryx contract](docs/benchoryx.md).
