use crate::{Event, Finding, Rule};
use std::ffi::{c_char, CStr, CString};
use std::ptr;

#[repr(C)]
struct RawEvent {
    kind: u32,
    line: u32,
    target: *const c_char,
    expression: *const c_char,
    callee: *const c_char,
}
#[repr(C)]
struct RawRule {
    symbol: *const c_char,
    kind: u32,
    severity: u32,
}
#[repr(C)]
struct RawFinding {
    line: u32,
    source_line: u32,
    severity: u32,
    category: u32,
    uncertain: u32,
    message: *mut c_char,
    source: *mut c_char,
    sink: *mut c_char,
    trace: *mut c_char,
}
#[repr(C)]
struct RawResult {
    len: usize,
    items: *mut RawFinding,
    incomplete: u32,
    note: *mut c_char,
}
extern "C" {
    fn tl_analyze(
        events: *const RawEvent,
        n: usize,
        rules: *const RawRule,
        nr: usize,
        steps: u32,
        out: *mut *mut RawResult,
    ) -> i32;
    fn tl_free_result(result: *mut RawResult);
}
struct OwnedResult(*mut RawResult);
impl Drop for OwnedResult {
    fn drop(&mut self) {
        unsafe { tl_free_result(self.0) }
    }
}
fn cstring(s: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| "input contains embedded NUL".into())
}
fn copy_string(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}
pub fn analyze(
    events: &[Event],
    rules: &[Rule],
    path: &str,
    steps: u32,
) -> Result<(Vec<Finding>, bool, String), String> {
    let strings = events
        .iter()
        .map(|e| {
            Ok([
                cstring(&e.target)?,
                cstring(&e.expression)?,
                cstring(&e.callee)?,
            ])
        })
        .collect::<Result<Vec<_>, String>>()?;
    let symbols = rules
        .iter()
        .map(|r| cstring(&r.symbol))
        .collect::<Result<Vec<_>, _>>()?;
    let raw_events: Vec<_> = events
        .iter()
        .zip(&strings)
        .map(|(e, s)| RawEvent {
            kind: e.kind,
            line: e.line,
            target: s[0].as_ptr(),
            expression: s[1].as_ptr(),
            callee: s[2].as_ptr(),
        })
        .collect();
    let raw_rules: Vec<_> = rules
        .iter()
        .zip(&symbols)
        .map(|(r, s)| RawRule {
            symbol: s.as_ptr(),
            kind: r.kind.code(),
            severity: r.severity.code(),
        })
        .collect();
    let mut out = ptr::null_mut();
    let status = unsafe {
        tl_analyze(
            raw_events.as_ptr(),
            raw_events.len(),
            raw_rules.as_ptr(),
            raw_rules.len(),
            steps,
            &mut out,
        )
    };
    if out.is_null() {
        return Err(format!("native analysis failed ({status})"));
    }
    let guard = OwnedResult(out);
    if status != 0 {
        return Err(format!("native analysis failed ({status})"));
    }
    let result = unsafe { &*guard.0 };
    if result.len > 100_000 || (result.len != 0 && result.items.is_null()) {
        return Err("invalid native result".into());
    }
    let items = if result.len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(result.items, result.len) }
    };
    let findings = items
        .iter()
        .map(|f| Finding {
            path: path.into(),
            line: f.line,
            source_line: f.source_line,
            severity: match f.severity {
                1 => "low",
                2 => "medium",
                3 => "high",
                4 => "critical",
                _ => "unknown",
            }
            .into(),
            category: match f.category {
                1 => "SID",
                2 => "EA",
                3 => "AUTH",
                4 => "NATIVE",
                _ => "UNKNOWN",
            }
            .into(),
            uncertain: f.uncertain != 0,
            message: copy_string(f.message),
            source: copy_string(f.source),
            sink: copy_string(f.sink),
            trace: copy_string(f.trace),
        })
        .collect();
    Ok((findings, result.incomplete != 0, copy_string(result.note)))
}
