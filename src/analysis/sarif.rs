//! SARIF 2.1.0 export for analysis diagnostics (`--format sarif`).
//!
//! The mapping follows the tool's own diagnostic taxonomy: each
//! `DiagnosticCause` becomes one rule (the same taxonomy `--suppress_warnings`
//! uses), with CWE tags where the mapping is solid. Diagnostics arrive here
//! already sorted, suppressed-warnings filtered, and memory-safety filtered,
//! so both formats report exactly the same set.

use rustc_span::source_map::SourceMap;
use serde_json::{json, Value};

use crate::analysis::diagnostics::{Diagnostic, DiagnosticCause};

const SARIF_SCHEMA: &str = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// One diagnostic located at a resolved source region. Region values are
/// 1-based and INCLUSIVE (SARIF convention); `end_col` is omitted when the
/// span ends exactly at a line boundary (the region then extends to the
/// end of the line).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SarifDiagnostic {
    pub cause: String,
    pub message: String,
    pub uri: String,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: Option<u32>,
    pub is_error: bool,
    pub is_memory_safety: bool,
}

/// Resolve a diagnostic's rustc span into a SARIF diagnostic. The text
/// output renders the raw span through the compiler's diagnostic machinery;
/// here the same span is resolved against the source map.
pub fn from_diagnostics(
    source_map: &SourceMap,
    diagnostics: &[Diagnostic],
    deny_warnings: bool,
) -> Vec<SarifDiagnostic> {
    diagnostics
        .iter()
        .map(|diag| {
            let span = diag.span;
            let start = source_map.lookup_char_pos(span.lo());
            let end = source_map.lookup_char_pos(span.hi());
            // span.hi() points one past the last character, so its 0-based
            // column equals the 1-based inclusive column of the last
            // character; a column of 0 means the span ends at a line
            // boundary — omit endColumn instead.
            let (end_line, end_col) = if end.col.0 == 0 && end.line > start.line {
                (end.line - 1, None)
            } else {
                (end.line, Some(end.col.0 as u32))
            };
            let start_col = start.col.0 as u32 + 1;
            // Zero-width spans can make the inclusive end column precede the
            // start column; clamp so the region stays well-formed.
            let end_col = end_col.map(|col| col.max(start_col));
            let uri = match &start.file.name {
                rustc_span::FileName::Real(real) => real
                    .local_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| format!("{:?}", real)),
                other => format!("{:?}", other),
            };
            SarifDiagnostic {
                cause: format!("{:?}", diag.cause),
                message: diag.message.clone(),
                uri,
                start_line: start.line as u32,
                start_col,
                end_line: end_line as u32,
                end_col,
                is_error: diag.is_error || deny_warnings,
                is_memory_safety: diag.is_memory_safety,
            }
        })
        .collect()
}

/// The rule identity and description for a diagnostic cause.
fn rule_for(cause: &str) -> (String, String, &'static str) {
    let (id, desc, cwe) = match cause {
        "Bitwise" => ("bitwise-overflow", "Possible bit-wise overflow", "CWE-190"),
        "Arithmetic" => (
            "arithmetic-overflow",
            "Provable arithmetic overflow",
            "CWE-190",
        ),
        "Assembly" => ("inline-assembly", "Possible memory-safety issue in inline assembly", ""),
        "Comparison" => (
            "comparison-operands",
            "Comparison operands that are provably unequal or unordered",
            "",
        ),
        "DivZero" => ("division-by-zero", "Provable division or remainder by zero", "CWE-369"),
        "Memory" => (
            "memory-safety",
            "Provable memory-safety issue (out-of-bounds, use-after-free, double free)",
            "CWE-119",
        ),
        "Panic" => ("panic", "Provable panic site", "CWE-248"),
        "Index" => ("index-out-of-bounds", "Provable out-of-bounds access", "CWE-125"),
        _ => ("other", "Other diagnostic", ""),
    };
    (format!("rust-mir-checker/{}", id), desc.to_owned(), cwe)
}

fn rule_descriptor(cause: &str) -> Value {
    let (id, desc, cwe) = rule_for(cause);
    let mut rule = json!({
        "id": id,
        "name": cause,
        "shortDescription": { "text": desc },
        "fullDescription": { "text": format!(
            "rust-mir-checker numerical/VC analysis diagnostic ({})",
            cause
        )},
    });
    if !cwe.is_empty() {
        rule["properties"] = json!({ "cwe": [cwe] });
    }
    rule
}

/// Build one complete SARIF 2.1.0 log from the converted diagnostics.
pub fn build_sarif_log(crate_name: &str, diagnostics: &[SarifDiagnostic]) -> Value {
    let mut results: Vec<Value> = Vec::new();
    let mut rules: Vec<Value> = Vec::new();
    let mut seen_rules: Vec<String> = Vec::new();
    let mut artifacts: Vec<Value> = Vec::new();
    let mut seen_uris: Vec<String> = Vec::new();

    for diag in diagnostics {
        let (rule_id, _, _) = rule_for(&diag.cause);
        if !seen_rules.iter().any(|c| c == &diag.cause) {
            seen_rules.push(diag.cause.clone());
            rules.push(rule_descriptor(&diag.cause));
        }
        if !seen_uris.iter().any(|u| u == &diag.uri) {
            seen_uris.push(diag.uri.clone());
            artifacts.push(json!({ "location": { "uri": diag.uri } }));
        }
        let mut region = json!({
            "startLine": diag.start_line,
            "startColumn": diag.start_col,
        });
        if diag.end_line != diag.start_line {
            region["endLine"] = json!(diag.end_line);
        }
        if let Some(end_col) = diag.end_col {
            region["endColumn"] = json!(end_col);
        }
        results.push(json!({
            "ruleId": rule_id,
            "level": if diag.is_error { "error" } else { "warning" },
            "message": { "text": diag.message },
            "locations": [{ "physicalLocation": {
                "artifactLocation": { "uri": diag.uri },
                "region": region,
            }}],
            "properties": {
                "detector": "rust-mir-checker",
                "cause": diag.cause,
                "isError": diag.is_error,
                "isMemorySafety": diag.is_memory_safety,
            },
        }));
    }

    json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "rust-mir-checker",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/lizhuohua/rust-mir-checker",
                "rules": rules,
            }},
            "results": results,
            "artifacts": artifacts,
            "automationDetails": { "id": format!("mir-checker-scan/{}", crate_name) },
            "invocations": [{ "executionSuccessful": true }],
            "properties": {
                "columnConvention": "1-based lines/columns; region endColumn is inclusive; a missing endColumn extends to the end of the line",
            },
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag(cause: DiagnosticCause, message: &str, is_error: bool) -> SarifDiagnostic {
        SarifDiagnostic {
            cause: format!("{:?}", cause),
            message: message.to_owned(),
            uri: "src/main.rs".to_owned(),
            start_line: 8,
            start_col: 5,
            end_line: 8,
            end_col: Some(22),
            is_error,
            is_memory_safety: false,
        }
    }

    #[test]
    fn test_build_sarif_log_shape() {
        let log = build_sarif_log(
            "test_crate",
            &[
                diag(DiagnosticCause::Index, "Provably error: index out of bound", true),
                diag(DiagnosticCause::DivZero, "Possible error: division by zero", false),
            ],
        );
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "rust-mir-checker");
        assert_eq!(run["automationDetails"]["id"], "mir-checker-scan/test_crate");
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "rust-mir-checker/index-out-of-bounds");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        let region = &results[0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 8);
        assert_eq!(region["startColumn"], 5);
        assert_eq!(region["endColumn"], 22);
        // rules registered once per cause with CWE tags
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["properties"]["cwe"][0], "CWE-125");
        assert_eq!(rules[1]["properties"]["cwe"][0], "CWE-369");
        let uris: Vec<&str> = run["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["location"]["uri"].as_str().unwrap())
            .collect();
        assert_eq!(uris, vec!["src/main.rs"]);
    }

    #[test]
    fn test_missing_end_column_omitted() {
        let mut d = diag(DiagnosticCause::Memory, "message", true);
        d.end_line = 9;
        d.end_col = None;
        let log = build_sarif_log("c", &[d]);
        let region = &log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["endLine"], 9);
        assert!(region.get("endColumn").is_none());
    }
}
