# Threat model

The protected assets are application secrets, user data, privileged tool operations, and native memory safety. Untrusted inputs include scanned repository contents and rule configuration. Analysis is offline and does not require executing target code.

| Risk | Example | Expected analysis |
|---|---|---|
| Sensitive information disclosure | Secret reaches logging | Source-to-disclosure flow |
| Excessive agency | User input reaches command execution | Untrusted-to-agency flow |
| Missing authorization | Privileged action without configured guard | Guard check |
| Unsafe native calls | Unbounded C string copy | Configured native sink |

Source contents and findings can themselves contain secrets; restrict report access and retention. Run against a read-only checkout under a low-privilege account with resource limits. Do not trust rules from an untrusted repository without review: a falsely declared sanitizer or authorization predicate could suppress findings.

A configured guard is a syntactic signal, not verification of the underlying identity or permission policy. Sanitizers are context-dependent; shell quoting does not establish that a command is authorized. Runtime prompt injection, model behavior, network authorization, and exploitation are outside the scope of the scanner. No finding-free scan should be interpreted as a security guarantee.
