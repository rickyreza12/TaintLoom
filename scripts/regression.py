"""Check source-only synthetic cases against the scanner's JSON contract."""
import argparse
import json
import pathlib
import subprocess
import sys
import time
import tempfile

try:
    import psutil
except ImportError:
    psutil = None

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED = {
    "python/disclosure_vulnerable.py": {("SID", "print")},
    "python/agency_vulnerable.py": {("EA", "os.system")},
    "python/authorization_vulnerable.py": {("AUTH", "delete_user")},
    "c/disclosure_vulnerable.c": {("SID", "printf")},
    "c/native_vulnerable.c": {("NATIVE", "strcpy")},
    "c/gets_vulnerable.c": {("NATIVE", "gets")},
    "c/authorization_vulnerable.c": {("AUTH", "delete_user")},
}

NEGATIVE = {
    "python/disclosure_fixed.py", "python/agency_fixed.py",
    "python/authorization_fixed.py", "python/near_miss.py",
    "c/disclosure_fixed.c", "c/native_fixed.c", "c/gets_fixed.c",
    "c/authorization_fixed.c", "c/near_miss.c",
}

def ratio(numerator, denominator):
    return numerator / denominator if denominator else None

def scan(command):
    if psutil is None:
        return subprocess.run(command, capture_output=True, text=True, timeout=30, check=False), None
    peak = None
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        with subprocess.Popen(command, stdout=stdout, stderr=stderr) as child:
            deadline = time.monotonic() + 30
            try:
                observer = psutil.Process(child.pid)
            except psutil.Error:
                observer = None
            try:
                while child.poll() is None:
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(command, 30)
                    if observer is not None:
                        try:
                            rss = observer.memory_info().rss
                            peak = max(peak or 0, rss) if rss > 0 else peak
                        except psutil.Error:
                            observer = None
                    time.sleep(0.005)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
            stdout.seek(0)
            stderr.seek(0)
            return subprocess.CompletedProcess(command, child.returncode, stdout.read().decode("utf-8"), stderr.read().decode("utf-8", errors="replace")), peak

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary or ROOT / "target" / "debug" / ("taintloom.exe" if sys.platform == "win32" else "taintloom")
    failures = []
    started = time.perf_counter()
    tp = fp = fn = tn = supported = 0
    memory_samples = []
    paths = sorted(p for p in (ROOT / "fixtures").rglob("*") if p.suffix in {".py", ".c"})
    labels = set(EXPECTED) | NEGATIVE
    if labels != {p.relative_to(ROOT / "fixtures").as_posix() for p in paths}:
        raise SystemExit("fixture set differs from explicitly labeled cases")
    for path in paths:
        name = path.relative_to(ROOT / "fixtures").as_posix()
        expected = EXPECTED.get(name, set())
        try:
            proc, observed_peak = scan([str(binary.resolve()), "scan", str(path), "--format", "json"])
            if observed_peak is not None:
                memory_samples.append(observed_peak)
            report = json.loads(proc.stdout)
            actual = {(f["category"], f["sink"]) for f in report["findings"]}
            if report["schema_version"] == 1 and not report["incomplete"] and proc.returncode == bool(actual):
                supported += 1
                if expected and actual:
                    tp += 1
                elif expected:
                    fn += 1
                elif actual:
                    fp += 1
                else:
                    tn += 1
            if proc.returncode != bool(expected) or report["schema_version"] != 1 or report["incomplete"] or actual != expected or len(report["findings"]) != len(expected):
                failures.append(f"{name}: expected {expected}, got {actual}; exit={proc.returncode}; warnings={report.get('warnings')}")
            else:
                print(f"PASS {name}")
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
            failures.append(f"{name}: {exc}")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    print(f"{len(paths)-len(failures)}/{len(paths)} cases passed")
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    print(json.dumps({
        "fixture_metrics": {
            "true_positive": tp, "false_positive": fp,
            "false_negative": fn, "true_negative": tn,
            "precision": precision, "recall": recall,
            "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "supported_cases": supported, "total_cases": len(paths),
            "supported_case_coverage": ratio(supported, len(paths)),
            "wall_seconds": time.perf_counter() - started,
            "peak_memory_bytes": max(memory_samples) if len(memory_samples) == len(paths) else None,
            "memory_sampled_cases": len(memory_samples),
            "peak_memory_note": "Maximum observed scanner resident set size, sampled every 5 ms; lower bound, not a guaranteed peak" if len(memory_samples) == len(paths) else "Incomplete memory sampling or optional psutil unavailable",
        }
    }, indent=2))
    return bool(failures)

if __name__ == "__main__":
    sys.exit(main())
