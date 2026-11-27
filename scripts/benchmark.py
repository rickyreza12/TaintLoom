"""Measure local scanner processes; missing tools/configuration are explicit."""
import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]

def run(name, executable, arguments, accepted, config=True):
    path = shutil.which(executable)
    if not path:
        return {"tool": name, "status": "unavailable"}
    if not config:
        return {"tool": name, "status": "skipped", "reason": "local configuration required"}
    command = [path, *arguments]
    try:
        start = time.perf_counter()
        proc = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
        elapsed = time.perf_counter() - start
        return {"tool": name, "status": "completed" if proc.returncode in accepted else "failed", "command": command, "seconds": elapsed, "exit_code": proc.returncode}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"tool": name, "status": "failed", "reason": str(exc)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(ROOT / "target" / "debug" / ("taintloom.exe" if sys.platform == "win32" else "taintloom")))
    parser.add_argument("--semgrep-config", type=pathlib.Path)
    parser.add_argument("--codeql-db", type=pathlib.Path)
    parser.add_argument("--codeql-suite", type=pathlib.Path)
    args = parser.parse_args()
    fixtures = str(ROOT / "fixtures")
    results = [run("TaintLoom", args.binary, ["scan", fixtures, "--format", "json"], {0, 1})]
    config = args.semgrep_config
    results.append(run("Semgrep", "semgrep", ["scan", "--metrics=off", "--disable-version-check", "--config", str(config), "--json", fixtures], {0, 1}, bool(config and config.is_file())))
    db, suite = args.codeql_db, args.codeql_suite
    with tempfile.TemporaryDirectory() as tmp:
        results.append(run("CodeQL", "codeql", ["database", "analyze", str(db), str(suite), "--format=sarifv2.1.0", "--output=" + str(pathlib.Path(tmp) / "results.sarif")], {0}, bool(db and db.is_dir() and suite and suite.is_file())))
    print(json.dumps(results, indent=2))
    return any(r["status"] == "failed" for r in results)

if __name__ == "__main__":
    sys.exit(main())
