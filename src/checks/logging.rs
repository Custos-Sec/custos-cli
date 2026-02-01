//! PRIV-006, PRIV-007: Logging privacy issues

use super::{extract_code_snippet, Finding};
use crate::report::Severity;
use once_cell::sync::Lazy;
use regex::Regex;

// PRIV-006: Sensitive data in logs
static MSG_WITH_DATA_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"msg!\s*\(\s*"[^"]*\{[^}]*\}[^"]*""#).expect("Invalid regex")
});

static SOL_LOG_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"sol_log\s*\([^)]+\)"#).expect("Invalid regex")
});

static SENSITIVE_LOG_PATTERNS: &[&str] = &[
    "user", "owner", "authority",
    "key", "secret", "private",
    "email", "address", "phone",
];

// PRIV-007: Debug logging in production
static PRINTLN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"println!\s*\(").expect("Invalid regex")
});

static DBG_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"dbg!\s*\(").expect("Invalid regex")
});

static DEBUG_MACRO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"debug!\s*\(").expect("Invalid regex")
});

pub fn check(content: &str, file: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Skip test files
    if (file.contains("test") && !file.contains("test_fixtures")) || file.contains("mock") || file.contains("example") {
        return findings;
    }

    let lines: Vec<&str> = content.lines().collect();

    // Track test module context
    let mut in_test_module = false;
    let mut next_is_test_module = false;
    let mut in_test_fn = false;
    let mut test_fn_brace_depth: usize = 0;

    for (line_idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let line_num = line_idx + 1;

        let open_braces = trimmed.matches('{').count();
        let close_braces = trimmed.matches('}').count();

        // Check for #[cfg(test)] or #[cfg(debug_assertions)]
        if trimmed.contains("#[cfg(test)]") || trimmed.contains("#[cfg(debug_assertions)]") {
            if trimmed.contains("mod ") {
                in_test_module = true;
            } else {
                next_is_test_module = true;
            }
        }

        if next_is_test_module && (trimmed.starts_with("mod ") || trimmed.starts_with("pub mod ")) {
            in_test_module = true;
            next_is_test_module = false;
        }

        if !in_test_module && trimmed.contains("#[test]") {
            in_test_fn = true;
            test_fn_brace_depth = 0;
        }

        if in_test_fn {
            test_fn_brace_depth = test_fn_brace_depth.saturating_add(open_braces);
            test_fn_brace_depth = test_fn_brace_depth.saturating_sub(close_braces);
            if test_fn_brace_depth == 0 && close_braces > 0 {
                in_test_fn = false;
            }
        }

        let in_test_context = in_test_module || in_test_fn;
        if in_test_context {
            continue;
        }

        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        // PRIV-006: Check for msg! with potentially sensitive data
        if MSG_WITH_DATA_REGEX.is_match(trimmed) {
            let line_lower = trimmed.to_lowercase();

            for pattern in SENSITIVE_LOG_PATTERNS.iter() {
                if line_lower.contains(pattern) {
                    findings.push(Finding::new(
                        "PRIV-006",
                        "Sensitive Data in Logs",
                        Severity::Medium,
                        file,
                        line_num,
                        &extract_code_snippet(content, line_num),
                        &format!(
                            "Log statement may expose '{}'. Events are publicly indexed. Use hashed/truncated identifiers instead.",
                            pattern
                        ),
                    ));
                    break;
                }
            }
        }

        // Check sol_log
        if SOL_LOG_REGEX.is_match(trimmed) {
            let line_lower = trimmed.to_lowercase();

            for pattern in SENSITIVE_LOG_PATTERNS.iter() {
                if line_lower.contains(pattern) {
                    findings.push(Finding::new(
                        "PRIV-006",
                        "Sensitive Data in sol_log",
                        Severity::Medium,
                        file,
                        line_num,
                        &extract_code_snippet(content, line_num),
                        "sol_log output is publicly visible. Remove sensitive data or use hashed identifiers.",
                    ));
                    break;
                }
            }
        }

        // PRIV-007: Debug logging in production code
        if PRINTLN_REGEX.is_match(trimmed) {
            findings.push(Finding::new(
                "PRIV-007",
                "println! in Production Code",
                Severity::Low,
                file,
                line_num,
                &extract_code_snippet(content, line_num),
                "Remove println! from production code. Use msg! for on-chain logging if needed, but be mindful of data exposure.",
            ));
        }

        if DBG_REGEX.is_match(trimmed) {
            findings.push(Finding::new(
                "PRIV-007",
                "dbg! Macro in Production Code",
                Severity::Low,
                file,
                line_num,
                &extract_code_snippet(content, line_num),
                "Remove dbg! macro from production code. It may expose internal state.",
            ));
        }

        if DEBUG_MACRO_REGEX.is_match(trimmed) && !in_test_context {
            findings.push(Finding::new(
                "PRIV-007",
                "debug! Macro in Production Code",
                Severity::Low,
                file,
                line_num,
                &extract_code_snippet(content, line_num),
                "Wrap debug! in #[cfg(debug_assertions)] to prevent exposure in release builds.",
            ));
        }
    }

    findings
}
