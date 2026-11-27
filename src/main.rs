mod ffi;
mod parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Debug)]
struct Event {
    kind: u32,
    line: u32,
    target: String,
    expression: String,
    callee: String,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    SourceSensitive,
    SourceUntrusted,
    SinkDisclosure,
    SinkAgency,
    Sanitizer,
    GuardAuth,
    SinkPrivileged,
    SinkNative,
}
impl Kind {
    fn code(self) -> u32 {
        self as u32 + 1
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    fn code(self) -> u32 {
        self as u32 + 1
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    symbol: String,
    kind: Kind,
    severity: Severity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    rules: Vec<Rule>,
}
#[derive(Serialize)]
struct Finding {
    path: String,
    line: u32,
    source_line: u32,
    severity: String,
    category: String,
    uncertain: bool,
    message: String,
    source: String,
    sink: String,
    trace: String,
}
#[derive(Serialize)]
struct Report {
    schema_version: u32,
    incomplete: bool,
    warnings: Vec<String>,
    findings: Vec<Finding>,
}

fn defaults() -> Vec<Rule> {
    use Kind::*;
    use Severity::*;
    [
        ("get_secret", SourceSensitive, High),
        ("read_secret", SourceSensitive, High),
        ("os.getenv", SourceSensitive, High),
        ("input", SourceUntrusted, High),
        ("request", SourceUntrusted, High),
        ("request.json", SourceUntrusted, High),
        ("send", SinkDisclosure, High),
        ("send_response", SinkDisclosure, High),
        ("print", SinkDisclosure, High),
        ("log", SinkDisclosure, High),
        ("execute_tool", SinkAgency, High),
        ("run_tool", SinkAgency, High),
        ("sanitize", Sanitizer, Medium),
        ("authorized", GuardAuth, High),
        ("is_authorized", GuardAuth, High),
        ("delete_user", SinkPrivileged, High),
        ("getenv", SourceSensitive, High),
        ("printf", SinkDisclosure, High),
        ("os.system", SinkAgency, Critical),
        ("system", SinkAgency, Critical),
        ("strcpy", SinkNative, High),
        ("sprintf", SinkNative, High),
        ("gets", SinkNative, High),
        ("shlex.quote", Sanitizer, Medium),
    ]
    .into_iter()
    .map(|(s, kind, severity)| Rule {
        symbol: s.into(),
        kind,
        severity,
    })
    .collect()
}
const MAX_BYTES: u64 = 2 * 1024 * 1024;
fn bounded_read(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > MAX_BYTES {
        return Err(format!("{} exceeds input size limit", path.display()));
    }
    String::from_utf8(buf).map_err(|_| format!("{} is not UTF-8", path.display()))
}
fn language(path: &Path) -> Option<bool> {
    match path.extension().and_then(|x| x.to_str()) {
        Some("py") => Some(true),
        Some("c" | "h") => Some(false),
        _ => None,
    }
}
fn collect(path: &Path, files: &mut Vec<PathBuf>, depth: usize) -> Result<(), String> {
    if depth > 64 || files.len() >= 4096 {
        return Err("directory scan limit reached".into());
    }
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_file() {
        if language(path).is_some() {
            files.push(path.to_owned());
        }
        return Ok(());
    }
    if !meta.is_dir() {
        return Ok(());
    }
    let mut entries = fs::read_dir(path)
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        if matches!(
            entry.file_name().to_str(),
            Some(".git" | "target" | ".venv" | "__pycache__")
        ) {
            continue;
        }
        collect(&entry.path(), files, depth + 1)?;
    }
    Ok(())
}
fn sarif(report: &Report) -> serde_json::Value {
    let results=report.findings.iter().map(|f|json!({
        "ruleId":f.category,
        "level":match f.severity.as_str(){"critical"|"high"=>"error","medium"=>"warning",_=>"note"},
        "message":{"text":f.message},
        "locations":[{"physicalLocation":{"artifactLocation":{"uri":f.path.replace('\\',"/")},"region":{"startLine":f.line.max(1)}}}],
        "properties":{"source":f.source,"sink":f.sink,"sourceLine":f.source_line,"trace":f.trace,"uncertain":f.uncertain,"severity":f.severity}
    })).collect::<Vec<_>>();
    json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"TaintLoom","version":env!("CARGO_PKG_VERSION"),"rules":[{"id":"SID"},{"id":"EA"},{"id":"AUTH"},{"id":"NATIVE"}]}},"invocations":[{"executionSuccessful":!report.incomplete,"toolExecutionNotifications":report.warnings.iter().map(|w|json!({"level":"warning","message":{"text":w}})).collect::<Vec<_>>()}],"results":results}]})
}
fn run() -> Result<u8, String> {
    let mut args = std::env::args_os().skip(1);
    let command = args
        .next()
        .ok_or("usage: taintloom scan <path> [--format json|sarif|text] [--rules rules.json]")?;
    if command == "--help" || command == "-h" {
        println!("taintloom scan <path> [--format json|sarif|text] [--rules rules.json]");
        return Ok(0);
    }
    if command != "scan" {
        return Err("expected scan command".into());
    }
    let path = PathBuf::from(args.next().ok_or("missing scan path")?);
    let mut format = "json".to_owned();
    let mut rules = defaults();
    while let Some(option) = args.next() {
        let value = args.next().ok_or("missing option value")?;
        match option.to_str() {
            Some("--format") => {
                format = value.into_string().map_err(|_| "invalid format")?;
                if !matches!(format.as_str(), "json" | "sarif" | "text") {
                    return Err("unknown report format".into());
                }
            }
            Some("--rules") => {
                let config: RuleFile = serde_json::from_str(&bounded_read(Path::new(&value))?)
                    .map_err(|e| e.to_string())?;
                rules.extend(config.rules);
            }
            _ => return Err("unknown option".into()),
        }
    }
    if rules.len() > 1024
        || rules
            .iter()
            .any(|r| r.symbol.is_empty() || r.symbol.len() > 256 || r.symbol.contains('\0'))
    {
        return Err("invalid rule symbols or rule count".into());
    }
    let mut report = Report {
        schema_version: 1,
        incomplete: false,
        warnings: Vec::new(),
        findings: Vec::new(),
    };
    let mut files = Vec::new();
    if let Err(e) = collect(&path, &mut files, 0) {
        report.warnings.push(e);
    }
    if files.is_empty() {
        report
            .warnings
            .push("no supported source files found".into());
    }
    for file in files {
        let display = file.to_string_lossy().replace('\\', "/");
        let scan = bounded_read(&file)
            .and_then(|source| parser::parse(&source, language(&file).unwrap()))
            .and_then(|(events, warnings)| {
                report
                    .warnings
                    .extend(warnings.into_iter().map(|w| format!("{display}: {w}")));
                ffi::analyze(&events, &rules, &display, 100_000)
            });
        match scan {
            Ok((findings, incomplete, note)) => {
                report.findings.extend(findings);
                if incomplete {
                    report.warnings.push(format!(
                        "{display}: {}",
                        if note.is_empty() {
                            "native analysis incomplete"
                        } else {
                            &note
                        }
                    ));
                }
            }
            Err(e) => report.warnings.push(format!("{display}: {e}")),
        }
    }
    report.incomplete = !report.warnings.is_empty();
    match format.as_str() {
        "sarif" => println!(
            "{}",
            serde_json::to_string_pretty(&sarif(&report)).map_err(|e| e.to_string())?
        ),
        "text" => {
            for f in &report.findings {
                println!(
                    "{}:{} {} {} {}",
                    f.path, f.line, f.severity, f.category, f.message
                );
            }
            for w in &report.warnings {
                println!("warning: {w}");
            }
        }
        _ => println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        ),
    }
    Ok(if report.incomplete {
        2
    } else if !report.findings.is_empty() {
        1
    } else {
        0
    })
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("taintloom: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn analyze_source(source: &str, python: bool, rules: &[Rule]) -> Vec<Finding> {
        let (events, warnings) = parser::parse(source, python).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let (findings, incomplete, note) =
            ffi::analyze(&events, rules, "fixture", 100_000).unwrap();
        assert!(!incomplete, "{note}");
        findings
    }

    #[test]
    fn native_flow_through_c_pointer() {
        let findings = analyze_source(
            "void f(void) {\n char *secret = getenv(\"SYNTHETIC\");\n char *copy = secret;\n printf(\"%s\", copy);\n}",
            false,
            &defaults(),
        );
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(
            (&*f.category, &*f.source, &*f.sink),
            ("SID", "getenv", "printf")
        );
        assert_eq!((f.source_line, f.line), (2, 4));
        assert!(f.trace.contains("copy"));
    }

    #[test]
    fn custom_rules_reach_native_analysis() {
        let config: RuleFile = serde_json::from_str(
            r#"{"rules":[{"symbol":"read_fixture","kind":"source_sensitive","severity":"high"},{"symbol":"publish_fixture","kind":"sink_disclosure","severity":"critical"}]}"#,
        ).unwrap();
        let findings = analyze_source(
            "def f():\n    x = read_fixture()\n    publish_fixture(x)\n",
            true,
            &config.rules,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(findings[0].sink, "publish_fixture");
        let report = Report {
            schema_version: 1,
            incomplete: false,
            warnings: vec![],
            findings,
        };
        let output = sarif(&report);
        assert_eq!(output["version"], "2.1.0");
        assert_eq!(output["runs"][0]["results"][0]["ruleId"], "SID");
        assert_eq!(
            output["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            3
        );
    }
}
