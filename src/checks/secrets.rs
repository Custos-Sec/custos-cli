//! PRIV-001, PRIV-002, PRIV-003: Hardcoded secrets detection

use super::{extract_code_snippet, find_line_number, Finding};
use crate::report::Severity;
use once_cell::sync::Lazy;
use regex::Regex;

// PRIV-001: Hardcoded private keys
static PRIVATE_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:const\s+)?\w*?(private[_\s]?key|secret[_\s]?key|priv[_\s]?key)[^=]*=\s*["'][^"']{20,}["']"#
    ).expect("Invalid regex")
});

static KEY_BYTES_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:const\s+)?\w*?(private[_\s]?key|secret[_\s]?key|signing[_\s]?key)[^=]*=\s*\[[0-9,\s]{50,}\]"#
    ).expect("Invalid regex")
});

static BASE64_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:const\s+)?(?:[A-Z_]*?)(?:private[_\s]?key|secret[_\s]?key|key[_\s]?base64|key[_\s]?b64|MASTER[_\s]?KEY|BACKUP[_\s]?KEY)[^=]*=\s*["'][A-Za-z0-9+/=]{40,}["']"#
    ).expect("Invalid regex")
});

static HEX_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:const\s+)?(?:[A-Z_]*?)(?:private[_\s]?key|secret[_\s]?key|key[_\s]?hex|MASTER[_\s]?KEY)[^=]*=\s*["'][0-9a-fA-F]{40,}["']"#
    ).expect("Invalid regex")
});

// PRIV-002: Mnemonic phrases
static MNEMONIC_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:const\s+)?(?:[A-Z_]*?)(?:mnemonic|seed[_\s]?phrase|recovery[_\s]?phrase|BACKUP[_\s]?SEED)[^=]*=\s*["'][a-z\s]{20,}["']"#
    ).expect("Invalid regex")
});

static SEED_PHRASE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:const\s+)?(seed[_\s]?phrase|recovery[_\s]?phrase)[^=]*=\s*["'][^"']+["']"#
    ).expect("Invalid regex")
});

static MNEMONIC_BASE64_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:const\s+)?(?:[A-Z_]*?)(?:mnemonic|seed[_\s]?phrase|recovery[_\s]?phrase|BACKUP[_\s]?SEED|BACKUP[_\s]?MNEMONIC|PRIVATE_KEY_BASE64)[^=]*=\s*["'][A-Za-z0-9+/=]{30,}["']"#
    ).expect("Invalid regex")
});

static STRUCT_FIELD_SECRET_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:private[_\s]?key|secret[_\s]?key|ADMIN[_\s]?KEY|BACKUP[_\s]?KEY)\s*:\s*["'][A-Za-z0-9+/=]{30,}["']"#
    ).expect("Invalid regex")
});

static MNEMONIC_CSV_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(mnemonic|seed[_\s]?phrase)[^=]*=\s*["']([a-z]+,)+[a-z]+["']"#
    ).expect("Invalid regex")
});

// PRIV-003: Hardcoded seed bytes
static SEED_BYTES_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(seed|secret)[^=]*=\s*\[\s*0[xX][0-9a-fA-F]"#
    ).expect("Invalid regex")
});

// Base58 private key (Solana format ~88 chars)
static BASE58_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"["'][1-9A-HJ-NP-Za-km-z]{80,90}["']"#
    ).expect("Invalid regex")
});

pub fn check(content: &str, file: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Skip test files
    if (file.contains("test") && !file.contains("test_fixtures")) || file.contains("mock") {
        return findings;
    }

    // PRIV-001: Hardcoded Private Key
    for mat in PRIVATE_KEY_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        findings.push(Finding::new(
            "PRIV-001",
            "Hardcoded Private Key",
            Severity::Critical,
            file,
            line,
            &extract_code_snippet(content, line),
            "Remove hardcoded private keys. Use environment variables or a secure key management system.",
        ));
    }

    for mat in KEY_BYTES_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        findings.push(Finding::new(
            "PRIV-001",
            "Hardcoded Private Key (Byte Array)",
            Severity::Critical,
            file,
            line,
            &extract_code_snippet(content, line),
            "Remove hardcoded key bytes. Load keys from secure storage at runtime.",
        ));
    }

    // Base58 keys
    for mat in BASE58_KEY_REGEX.find_iter(content) {
        let matched = mat.as_str();
        if matched.len() > 85 {
            let line = find_line_number(content, mat.start());
            let line_content = content.lines().nth(line - 1).unwrap_or("");
            if line_content.trim().starts_with("//") || line_content.trim().starts_with("*") {
                continue;
            }
            findings.push(Finding::new(
                "PRIV-001",
                "Possible Hardcoded Private Key (Base58)",
                Severity::Critical,
                file,
                line,
                &extract_code_snippet(content, line),
                "This looks like a Solana private key. Remove it and use secure key management.",
            ));
        }
    }

    // Base64-encoded keys
    for mat in BASE64_KEY_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        let line_content = content.lines().nth(line - 1).unwrap_or("");
        if line_content.trim().starts_with("//") || line_content.trim().starts_with("*") {
            continue;
        }
        if line_content.to_lowercase().contains("test") || line_content.to_lowercase().contains("example") {
            continue;
        }
        findings.push(Finding::new(
            "PRIV-001",
            "Possible Base64-Encoded Private Key",
            Severity::Critical,
            file,
            line,
            &extract_code_snippet(content, line),
            "This appears to be a base64-encoded private key. Remove it and use environment variables.",
        ));
    }

    // Hex-encoded keys
    for mat in HEX_KEY_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        let line_content = content.lines().nth(line - 1).unwrap_or("");
        if line_content.trim().starts_with("//") || line_content.trim().starts_with("*") {
            continue;
        }
        if line_content.to_lowercase().contains("test") || line_content.to_lowercase().contains("example") {
            continue;
        }
        findings.push(Finding::new(
            "PRIV-001",
            "Possible Hex-Encoded Private Key",
            Severity::Critical,
            file,
            line,
            &extract_code_snippet(content, line),
            "This appears to be a hex-encoded private key. Remove it and use secure key management.",
        ));
    }

    // Struct field secrets
    for mat in STRUCT_FIELD_SECRET_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        let line_content = content.lines().nth(line - 1).unwrap_or("");
        if line_content.trim().starts_with("//") || line_content.trim().starts_with("*") {
            continue;
        }
        findings.push(Finding::new(
            "PRIV-001",
            "Hardcoded Secret in Struct Initialization",
            Severity::Critical,
            file,
            line,
            &extract_code_snippet(content, line),
            "Remove hardcoded secrets from struct initialization. Use dependency injection or environment variables.",
        ));
    }

    // PRIV-002: Exposed Mnemonic
    for mat in MNEMONIC_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        findings.push(Finding::new(
            "PRIV-002",
            "Exposed Mnemonic Phrase",
            Severity::Critical,
            file,
            line,
            &extract_code_snippet(content, line),
            "Never hardcode mnemonic phrases. They grant full access to all derived accounts.",
        ));
    }

    for mat in SEED_PHRASE_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        findings.push(Finding::new(
            "PRIV-002",
            "Exposed Seed/Recovery Phrase",
            Severity::Critical,
            file,
            line,
            &extract_code_snippet(content, line),
            "Remove seed phrases from code. Use secure key derivation at runtime.",
        ));
    }

    // Base64 mnemonics
    for mat in MNEMONIC_BASE64_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        let line_content = content.lines().nth(line - 1).unwrap_or("");
        if line_content.to_lowercase().contains("test") || line_content.to_lowercase().contains("example") {
            continue;
        }
        let matched = mat.as_str();
        if matched.len() > 30 && !matched.contains("http") {
            findings.push(Finding::new(
                "PRIV-002",
                "Possible Base64-Encoded Mnemonic",
                Severity::Critical,
                file,
                line,
                &extract_code_snippet(content, line),
                "This appears to be a base64-encoded seed phrase. Remove it and use secure key derivation.",
            ));
        }
    }

    // CSV mnemonics
    for mat in MNEMONIC_CSV_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        let line_content = content.lines().nth(line - 1).unwrap_or("");
        if line_content.to_lowercase().contains("test") || line_content.to_lowercase().contains("example") {
            continue;
        }
        findings.push(Finding::new(
            "PRIV-002",
            "Exposed Mnemonic (Comma-Separated Format)",
            Severity::Critical,
            file,
            line,
            &extract_code_snippet(content, line),
            "Never hardcode mnemonics in any format. They grant full access to all derived accounts.",
        ));
    }

    // PRIV-003: Hardcoded Seed Bytes
    for mat in SEED_BYTES_REGEX.find_iter(content) {
        let line = find_line_number(content, mat.start());
        let line_content = content.lines().nth(line - 1).unwrap_or("");

        // Skip PDA-related patterns
        let pda_keywords = ["PDA", "pda", "find_program_address", "derive_pda", "program_address", "bump", ".as_ref()", "key()"];
        if pda_keywords.iter().any(|k| line_content.contains(k)) {
            continue;
        }

        // Check surrounding lines for PDA context
        let nearby_lines = content.lines().collect::<Vec<_>>();
        let start_check = if line >= 3 { line - 3 } else { 0 };
        let end_check = if line + 2 < nearby_lines.len() { line + 2 } else { nearby_lines.len() };

        let mut has_pda_context = false;
        for i in start_check..end_check {
            if let Some(surrounding) = nearby_lines.get(i) {
                if pda_keywords.iter().any(|k| surrounding.contains(k)) {
                    has_pda_context = true;
                    break;
                }
            }
        }

        if has_pda_context || line_content.contains("b\"") {
            continue;
        }

        findings.push(Finding::new(
            "PRIV-003",
            "Hardcoded Seed Bytes",
            Severity::High,
            file,
            line,
            &extract_code_snippet(content, line),
            "Seed bytes may be cryptographic secrets. Consider loading from secure storage.",
        ));
    }

    findings
}
