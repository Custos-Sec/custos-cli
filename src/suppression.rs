//! Suppression comment parsing for Custos
//!
//! Supports inline comments to suppress specific findings:
//! - `// custos-ignore` - Suppress all findings on this line
//! - `// custos-ignore-next-line` - Suppress all findings on the next line
//! - `// custos-ignore[PRIV-001]` - Suppress specific rule on this line
//! - `// custos-ignore[PRIV-001, PRIV-002]` - Suppress multiple rules
//! - `/* custos-ignore */` - Block comment variant

use crate::checks::Finding;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

/// Regex patterns for suppression comments
/// Note: We check line-by-line, so multiline flags not needed

// Match "// custos-ignore" NOT followed by "[" or "-" (to avoid matching custos-ignore-next-line or custos-ignore[...])
static IGNORE_LINE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"//\s*custos-ignore\s*$").expect("Invalid regex")
});

static IGNORE_NEXT_LINE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"//\s*custos-ignore-next-line").expect("Invalid regex")
});

static IGNORE_RULES: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"//\s*custos-ignore\s*\[([^\]]+)\]").expect("Invalid regex")
});

static IGNORE_BLOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"/\*\s*custos-ignore(?:\s*\[([^\]]+)\])?\s*\*/").expect("Invalid regex")
});

static IGNORE_FILE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"//\s*custos-ignore-file(?:\s*\[([^\]]+)\])?").expect("Invalid regex")
});

/// Parsed suppressions for a file
#[derive(Debug, Default)]
pub struct Suppressions {
    /// Lines where all rules are suppressed
    pub suppressed_lines: HashSet<usize>,
    /// Lines where specific rules are suppressed: line -> set of rule IDs
    pub suppressed_rules: HashMap<usize, HashSet<String>>,
    /// File-level suppressions (all lines)
    pub file_suppressed_all: bool,
    /// File-level rule-specific suppressions
    pub file_suppressed_rules: HashSet<String>,
}

impl Suppressions {
    /// Check if a finding should be suppressed
    pub fn is_suppressed(&self, finding: &Finding) -> bool {
        // File-level suppression
        if self.file_suppressed_all {
            return true;
        }
        if self.file_suppressed_rules.contains(&finding.id) {
            return true;
        }

        // Line-level suppression
        if self.suppressed_lines.contains(&finding.line) {
            return true;
        }

        // Rule-specific line suppression
        if let Some(rules) = self.suppressed_rules.get(&finding.line) {
            if rules.contains(&finding.id) {
                return true;
            }
        }

        false
    }

    /// Get count of suppressions
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.suppressed_lines.len() + self.suppressed_rules.len()
    }
}

/// Parse suppression comments from file content
pub fn parse_suppressions(content: &str) -> Suppressions {
    let mut suppressions = Suppressions::default();
    let lines: Vec<&str> = content.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;

        // Check for file-level suppression (usually at top of file)
        if line_num <= 10 {
            if let Some(caps) = IGNORE_FILE.captures(line) {
                if let Some(rules_match) = caps.get(1) {
                    let rules = parse_rule_list(rules_match.as_str());
                    suppressions.file_suppressed_rules.extend(rules);
                } else {
                    suppressions.file_suppressed_all = true;
                }
                continue;
            }
        }

        // Check for custos-ignore-next-line
        if IGNORE_NEXT_LINE.is_match(line) {
            // Also check for rule-specific
            if let Some(caps) = IGNORE_RULES.captures(line) {
                if let Some(rules_match) = caps.get(1) {
                    let rules = parse_rule_list(rules_match.as_str());
                    let next_line = line_num + 1;
                    suppressions.suppressed_rules
                        .entry(next_line)
                        .or_default()
                        .extend(rules);
                }
            } else {
                suppressions.suppressed_lines.insert(line_num + 1);
            }
            continue;
        }

        // Check for custos-ignore with specific rules
        if let Some(caps) = IGNORE_RULES.captures(line) {
            if let Some(rules_match) = caps.get(1) {
                let rules = parse_rule_list(rules_match.as_str());
                suppressions.suppressed_rules
                    .entry(line_num)
                    .or_default()
                    .extend(rules);
            }
            continue;
        }

        // Check for plain custos-ignore (suppress all on this line)
        if IGNORE_LINE.is_match(line) {
            suppressions.suppressed_lines.insert(line_num);
            continue;
        }

        // Check for block comment suppression
        if let Some(caps) = IGNORE_BLOCK.captures(line) {
            if let Some(rules_match) = caps.get(1) {
                let rules = parse_rule_list(rules_match.as_str());
                suppressions.suppressed_rules
                    .entry(line_num)
                    .or_default()
                    .extend(rules);
            } else {
                suppressions.suppressed_lines.insert(line_num);
            }
        }
    }

    suppressions
}

/// Parse a comma-separated list of rule IDs
fn parse_rule_list(rules_str: &str) -> Vec<String> {
    rules_str
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Filter findings by applying suppressions
#[allow(dead_code)]
pub fn filter_suppressed(findings: Vec<Finding>, content: &str) -> Vec<Finding> {
    let suppressions = parse_suppressions(content);
    findings
        .into_iter()
        .filter(|f| !suppressions.is_suppressed(f))
        .collect()
}

/// Filter findings using pre-parsed suppressions
pub fn filter_with_suppressions(findings: Vec<Finding>, suppressions: &Suppressions) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| !suppressions.is_suppressed(f))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;

    fn make_finding(id: &str, line: usize) -> Finding {
        Finding::new(id, "Test", Severity::Medium, "test.rs", line, "", "")
    }

    #[test]
    fn test_ignore_line() {
        let content = r#"
            let secret = "key"; // custos-ignore
            let other = "value";
        "#;
        let suppressions = parse_suppressions(content);

        assert!(suppressions.is_suppressed(&make_finding("PRIV-001", 2)));
        assert!(!suppressions.is_suppressed(&make_finding("PRIV-001", 3)));
    }

    #[test]
    fn test_ignore_next_line() {
        let content = r#"
            // custos-ignore-next-line
            let secret = "key";
            let other = "value";
        "#;
        let suppressions = parse_suppressions(content);

        assert!(suppressions.is_suppressed(&make_finding("PRIV-001", 3)));
        assert!(!suppressions.is_suppressed(&make_finding("PRIV-001", 4)));
    }

    #[test]
    fn test_ignore_specific_rule() {
        let content = r#"
            let secret = "key"; // custos-ignore[PRIV-001]
        "#;
        let suppressions = parse_suppressions(content);

        assert!(suppressions.is_suppressed(&make_finding("PRIV-001", 2)));
        assert!(!suppressions.is_suppressed(&make_finding("PRIV-002", 2)));
    }

    #[test]
    fn test_ignore_multiple_rules() {
        let content = r#"
            let secret = "key"; // custos-ignore[PRIV-001, PRIV-002]
        "#;
        let suppressions = parse_suppressions(content);

        assert!(suppressions.is_suppressed(&make_finding("PRIV-001", 2)));
        assert!(suppressions.is_suppressed(&make_finding("PRIV-002", 2)));
        assert!(!suppressions.is_suppressed(&make_finding("PRIV-003", 2)));
    }

    #[test]
    fn test_file_level_suppression() {
        let content = r#"
            // custos-ignore-file
            let secret = "key";
            let other = "value";
        "#;
        let suppressions = parse_suppressions(content);

        assert!(suppressions.is_suppressed(&make_finding("PRIV-001", 3)));
        assert!(suppressions.is_suppressed(&make_finding("PRIV-002", 4)));
    }

    #[test]
    fn test_file_level_specific_rules() {
        let content = r#"
            // custos-ignore-file[PRIV-001]
            let secret = "key";
            let other = "value";
        "#;
        let suppressions = parse_suppressions(content);

        assert!(suppressions.is_suppressed(&make_finding("PRIV-001", 3)));
        assert!(!suppressions.is_suppressed(&make_finding("PRIV-002", 3)));
    }

    #[test]
    fn test_block_comment() {
        let content = r#"
            let secret = "key"; /* custos-ignore */
        "#;
        let suppressions = parse_suppressions(content);

        assert!(suppressions.is_suppressed(&make_finding("PRIV-001", 2)));
    }

    #[test]
    fn test_filter_suppressed() {
        let content = r#"
            let secret = "key"; // custos-ignore
            let other = "value";
        "#;

        let findings = vec![
            make_finding("PRIV-001", 2),
            make_finding("PRIV-001", 3),
        ];

        let filtered = filter_suppressed(findings, content);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].line, 3);
    }

    #[test]
    fn test_case_insensitive_rules() {
        let content = r#"
            let secret = "key"; // custos-ignore[priv-001]
        "#;
        let suppressions = parse_suppressions(content);

        assert!(suppressions.is_suppressed(&make_finding("PRIV-001", 2)));
    }
}
