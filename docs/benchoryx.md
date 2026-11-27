# Benchoryx integration contract

This is a provisional consumer contract for connecting Benchoryx to TaintLoom. It describes TaintLoom's existing command-line interface (CLI); no official Benchoryx interface, endpoint, authentication scheme or installed integration is assumed.

Invoke the compiled binary with an argument array:

```text
taintloom scan <source-path> --format json
```

Use a timeout and a restricted working directory. Do not execute scanned source files. Capture standard output as JavaScript Object Notation (JSON) and standard error as diagnostics.

## Version 1 report

| Field | Type | Meaning |
|---|---|---|
| schema_version | integer | 1 for this contract |
| incomplete | boolean | Analysis could not be completed reliably |
| warnings | array of strings | Scanner diagnostics |
| findings | array of objects | Reported security findings |

Each finding includes string fields path, severity, category, message, source, sink and trace; integer fields line and source_line; and boolean uncertain. Line numbers are one-based when known, and a source line of zero can indicate no source location. Categories are SID (sensitive information disclosure), EA (excessive agency), AUTH (authorization), and NATIVE (unsafe native calls). Severity values are low, medium, high and critical. Preserve uncertainty and unknown values rather than treating them as verified vulnerabilities.

Exit 0 means complete with no findings; exit 1 means complete with findings; exit 2 means incomplete or failed. A failed invocation may produce no JSON. Reject an unknown schema version and any disagreement between exit status and completeness; never score an incomplete scan as clean. Store results securely because paths, traces and diagnostics may include sensitive source details.

## Example adapter

```python
import json
import subprocess

def scan(binary, path):
    proc = subprocess.run(
        [str(binary), "scan", str(path), "--format", "json"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError("Scanner failed or returned incomplete analysis")
    report = json.loads(proc.stdout)
    if report["schema_version"] != 1 or report["incomplete"]:
        raise ValueError("Unsupported or incomplete report")
    if not isinstance(report["findings"], list):
        raise ValueError("Invalid findings")
    if proc.returncode != int(bool(report["findings"])):
        raise ValueError("Exit status disagrees with findings")
    return report
```

The adapter returns TaintLoom's report unchanged; a Benchoryx-specific translation remains to be defined against that project's actual interface. Version 1 is the current scanner schema, not a promise of compatibility with an unverified external service.
