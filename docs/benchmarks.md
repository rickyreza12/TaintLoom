# Reproducible evaluation

Run `python scripts/regression.py` after building. Each fixture has a declared expected finding set; the script checks exit status, report completeness and category/sink pairs. It never executes fixture code.

Fixture-level precision = true positives / (true positives + false positives); recall = true positives / (true positives + false negatives); F1 is their harmonic mean. A positive fixture is one with any finding, regardless of category. Exact category/sink matching and duplicate detection remain separate mandatory checks. Metrics include only complete, valid scanner responses; supported-case coverage reports that denominator divided by all labeled fixtures. Undefined ratios and unavailable peak memory are JSON null. Elapsed wall time includes all fixture process startup and scanning. Do not interpret results on synthetic fixtures as real-world accuracy.

Build and execute the native C17 unit tests on Linux or Windows (CMake and a compatible C compiler required):

```sh
cmake -S native -B target/native-tests -DCMAKE_BUILD_TYPE=Debug
cmake --build target/native-tests --config Debug
ctest --test-dir target/native-tests -C Debug --output-on-failure
cargo build --locked
python scripts/regression.py
```

The continuous integration matrix runs these commands on Windows and Linux. Debug configuration keeps C assertions enabled. Missing compiler or failed native tests cause the job to fail.

Run `python scripts/benchmark.py` for an optional local comparison with Semgrep and CodeQL. Supply explicit local Semgrep configuration or CodeQL database/query suite as required by the script. Tools missing from PATH are reported as unavailable; tools with missing configuration are skipped. No external downloads are initiated by the harness.

Reported wall-clock time includes the invoked process startup. Raw findings are tool-specific and are not directly comparable because rule coverage, query configuration and language support differ. CodeQL databases must be prepared separately against the same fixture revision; database creation time is excluded. Record tool versions, command arguments, revision, platform and configuration when sharing results. A meaningful precision/recall comparison requires mapping each tool's findings to the same labeled cases.

No benchmark measurements are claimed in this document.

If the optional Python psutil package is already installed, regression collects the scanner process resident set size (RSS), meaning memory resident in physical memory, approximately every 5 milliseconds. The reported maximum is an observed lower bound across individual scans, not a guaranteed true peak. It is null when any fixture has no valid memory sample; memory_sampled_cases records coverage. The package is not required for regression correctness.

See [the provisional Benchoryx integration contract](benchoryx.md) for the scanner's versioned report interface.
