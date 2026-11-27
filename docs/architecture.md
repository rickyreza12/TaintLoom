# Architecture

Rust discovers supported files, reads source within size bounds, parses Python or C with Tree-sitter, lowers relevant syntax to ordered events, and passes those events to the C17 analysis engine. Native findings are copied into Rust report structures before native allocation is released.

Events represent function entry/exit, assignment, calls, conditional boundaries and returns. Rules define symbol roles for sensitive or untrusted sources, disclosure or agency sinks, sanitizers, authorization guards, privileged sinks and unsafe native calls.

The event representation loses information from the original syntax tree. Pointer aliases, dynamic dispatch, indirect calls, reflection, macros, complex control flow, and cross-file resolution must not be assumed to be fully modeled. Unsupported syntax may cause incomplete reports; absence of a warning is not proof that every language construct is modeled.

The current command limits input size to 2 MiB per file, traversal depth and file count, parser events and native analysis steps. Consult source for authoritative limits. Findings contain source and sink information, line locations, severity and uncertainty. Reports must preserve incomplete status so automation can distinguish a clean result from an interrupted scan.
