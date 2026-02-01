//! PRIV-008, PRIV-009: Access control issues with privacy impact

use super::{extract_code_snippet, find_line_number, Finding};
use crate::report::Severity;
use once_cell::sync::Lazy;
use regex::Regex;

static ACCOUNTS_STRUCT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)#\[derive\([^)]*Accounts[^)]*\)\]\s*pub\s+struct\s+(\w+)[^{]*\{([^}]+)\}").expect("Invalid regex")
});

static INVOKE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"invoke\s*\(|invoke_signed\s*\(").expect("Invalid regex")
});

static PROGRAM_CHECK_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"program_id|check_id|crate::ID|ctx\.program_id").expect("Invalid regex")
});

pub fn check(content: &str, file: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Skip test files
    if (file.contains("test") && !file.contains("test_fixtures")) || file.contains("mock") {
        return findings;
    }

    let lines: Vec<&str> = content.lines().collect();

    // PRIV-009: Check Accounts structs for missing constraints
    for caps in ACCOUNTS_STRUCT_REGEX.captures_iter(content) {
        let struct_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let struct_body = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        let has_authority = struct_body.contains("authority") ||
                           struct_body.contains("owner") ||
                           struct_body.contains("admin");
        let has_signer = struct_body.contains("Signer<");

        if struct_body.contains("Account<") && !has_authority && !has_signer {
            let name_lower = struct_name.to_lowercase();
            if name_lower.contains("update") ||
               name_lower.contains("modify") ||
               name_lower.contains("transfer") ||
               name_lower.contains("withdraw") {
                let struct_start = caps.get(0).map(|m| m.start()).unwrap_or(0);
                let line = find_line_number(content, struct_start);

                findings.push(Finding::new(
                    "PRIV-009",
                    &format!("Sensitive Operation Without Authority: '{}'", struct_name),
                    Severity::Medium,
                    file,
                    line,
                    &format!("struct {} {{ ... }}", struct_name),
                    "Add an authority/signer field to verify who can perform this operation.",
                ));
            }
        }
    }

    // Check for CPI without program validation
    let mut cpi_line: Option<usize> = None;
    for (line_idx, line) in lines.iter().enumerate() {
        if INVOKE_REGEX.is_match(line) {
            cpi_line = Some(line_idx);
        }

        if let Some(cpi_idx) = cpi_line {
            if line_idx > cpi_idx + 5 {
                let start = cpi_idx.saturating_sub(50);
                let end = (cpi_idx + 5).min(lines.len());
                let context: String = lines[start..end].join("\n");

                // Safe patterns
                let is_safe_cpi = context.contains("system_instruction::")
                    || context.contains("spl_token::instruction::")
                    || context.contains("spl_token_2022::instruction::")
                    || context.contains("spl_token::id()")
                    || context.contains("system_program::id()")
                    || context.contains("anchor_spl::")
                    || context.contains("&spl_token::ID")
                    || context.contains("&system_program::ID")
                    || (context.contains("&self.") && context.contains("_instruction"))
                    || (context.contains("&self.") && context.contains("_program"));

                if !PROGRAM_CHECK_REGEX.is_match(&context) && !is_safe_cpi {
                    findings.push(Finding::new(
                        "PRIV-009",
                        "CPI Without Program Validation",
                        Severity::Medium,
                        file,
                        cpi_idx + 1,
                        &extract_code_snippet(content, cpi_idx + 1),
                        "Verify target program ID before CPI to prevent data interception by malicious programs.",
                    ));
                }
                cpi_line = None;
            }
        }
    }

    findings
}
