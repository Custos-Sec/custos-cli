//! PRIV-010+: Anchor-specific privacy and security checks
//!
//! This module uses lightweight AST parsing for accurate PDA seed analysis,
//! plus regex patterns for additional Anchor-specific vulnerability detection.
//!
//! ## Checks
//! - PRIV-010: Enumerable PDA (static seeds only)
//! - PRIV-011: Missing signer check
//! - PRIV-012: Missing owner check
//! - PRIV-013: CPI validation issues
//! - PRIV-014: Account closing vulnerability
//! - PRIV-015: Reinitialization risk
//! - PRIV-016: Unsafe arithmetic in token operations

use super::{extract_code_snippet, find_line_number, Finding};
use crate::parser::{parse_structs, get_pda_fields, StructInfo};
use crate::report::Severity;
use once_cell::sync::Lazy;
use regex::Regex;

// Regex for emit! macro - still useful for event analysis
static EMIT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"emit!\s*\(\s*(\w+)\s*\{"#).expect("Invalid regex")
});

// Regex for missing signer checks
#[allow(dead_code)]
static SIGNER_CHECK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Signer<'info>").expect("Invalid regex")
});

// Regex for potential authority without signer
static AUTHORITY_WITHOUT_SIGNER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"pub\s+(\w*authority\w*)\s*:\s*(?:Account|AccountInfo|UncheckedAccount)").expect("Invalid regex")
});

// Regex for CPI without program validation
static CPI_INVOKE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"invoke(?:_signed)?\s*\(").expect("Invalid regex")
});

// Regex for account close operations
static ACCOUNT_CLOSE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"close\s*=\s*(\w+)").expect("Invalid regex")
});

// Regex for init without checking if already initialized
static INIT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"#\[account\s*\(\s*init(?:_if_needed)?").expect("Invalid regex")
});

// Regex for unchecked arithmetic
static UNCHECKED_MATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:amount|balance|lamports|total|fee|price)\s*[\+\-\*]\s*").expect("Invalid regex")
});

// Regex for program ID validation
static PROGRAM_CHECK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Program<'info,\s*(\w+)>").expect("Invalid regex")
});

// Regex for owner check constraint
#[allow(dead_code)]
static OWNER_CONSTRAINT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"constraint\s*=.*owner").expect("Invalid regex")
});

// Regex for has_one constraint
#[allow(dead_code)]
static HAS_ONE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"has_one\s*=\s*(\w+)").expect("Invalid regex")
});

// Regex for UncheckedAccount (potential danger)
static UNCHECKED_ACCOUNT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"UncheckedAccount<'info>").expect("Invalid regex")
});

// Regex for AccountInfo (raw, needs manual checks)
static RAW_ACCOUNT_INFO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"AccountInfo<'info>").expect("Invalid regex")
});

// Regex for #[account(mut)] without proper guards
static MUT_ACCOUNT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"#\[account\s*\(\s*mut\s*(?:,|[^\)]*)\s*\)\]").expect("Invalid regex")
});

static EVENT_SENSITIVE_FIELDS: &[&str] = &[
    "amount", "balance", "lamports",
    "user", "owner", "authority", "recipient", "sender",
    "price", "fee", "total",
];

/// Global config/state seed prefixes that are intentionally static
const GLOBAL_SEED_PREFIXES: &[&str] = &[
    "global", "config", "state", "protocol", "program",
    "admin", "settings", "params", "fee",
    // Bridge-specific patterns (cross-chain bridges use global PDAs intentionally)
    "bridge", "guardian", "sequence", "emitter", "posted", "message",
    "wormhole", "vaa", "custody", "endpoint", "relayer",
    // DeFi infrastructure patterns
    "oracle", "price", "pool", "vault", "reserve", "treasury",
];

pub fn check(content: &str, file: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Skip test files
    if (file.contains("test") && !file.contains("test_fixtures")) || file.contains("mock") {
        return findings;
    }

    // Parse structs for accurate PDA analysis
    let structs = parse_structs(content);

    // Check PDAs using parsed struct info
    for s in &structs {
        check_pda_seeds(s, content, file, &mut findings);
    }

    // Check for emit! with sensitive data (regex-based, events aren't in struct definitions)
    check_emit_events(content, file, &mut findings);

    // Additional Anchor-specific checks
    check_missing_signer(content, file, &mut findings);
    check_uninitialized_state(content, file, &mut findings);
    check_unchecked_accounts(content, file, &mut findings);
    check_cpi_validation(content, file, &mut findings);
    check_account_closing(content, file, &mut findings);
    check_reinitialization(content, file, &mut findings);
    check_unsafe_arithmetic(content, file, &mut findings);

    findings
}

/// Check PDA seeds using parsed struct information
fn check_pda_seeds(s: &StructInfo, content: &str, file: &str, findings: &mut Vec<Finding>) {
    if !s.is_accounts_context {
        return;
    }

    let pda_fields = get_pda_fields(s);

    for (field, seeds_str) in pda_fields {
        // Analyze the seeds
        let analysis = analyze_seeds(seeds_str);

        if analysis.is_static_only && !analysis.is_global_config {
            let confidence = calculate_pda_confidence(&analysis, &field.name, &s.name);

            let mut finding = Finding::new(
                "PRIV-010",
                &format!("Enumerable PDA: '{}'", field.name),
                Severity::Medium,
                file,
                field.line,
                &extract_code_snippet(content, field.line),
                "PDA uses only static seeds. Anyone can predict and enumerate these accounts. Add user-specific seeds like: authority.key().as_ref()",
            );

            finding.confidence = confidence;
            finding.evidence = analysis.evidence;

            findings.push(finding);
        }
    }
}

/// Seed analysis result
struct SeedAnalysis {
    is_static_only: bool,
    is_global_config: bool,
    has_user_seed: bool,
    static_seeds: Vec<String>,
    dynamic_seeds: Vec<String>,
    evidence: Vec<String>,
}

/// Analyze seeds string to determine if it's enumerable
fn analyze_seeds(seeds_str: &str) -> SeedAnalysis {
    let mut analysis = SeedAnalysis {
        is_static_only: true,
        is_global_config: false,
        has_user_seed: false,
        static_seeds: Vec::new(),
        dynamic_seeds: Vec::new(),
        evidence: Vec::new(),
    };

    // Method call patterns - these always indicate dynamic values
    let method_patterns = [".key()", ".as_ref()", ".to_le_bytes()", ".to_bytes()"];

    for pattern in method_patterns {
        if seeds_str.contains(pattern) {
            analysis.is_static_only = false;
            analysis.has_user_seed = true;
            analysis.dynamic_seeds.push(pattern.to_string());
        }
    }

    // Variable patterns - only match as identifiers outside of byte string literals
    // We need to check these appear as variable references, not inside b"..."
    let var_patterns = ["authority", "owner", "payer", "signer"];

    // Extract content outside of byte string literals for variable matching
    // Remove all b"..." and b "..." patterns first
    let outside_strings = Regex::new(r#"b\s*"[^"]*""#).unwrap()
        .replace_all(seeds_str, "");

    for pattern in var_patterns {
        // Check if the pattern appears as a word (variable reference)
        let word_regex = Regex::new(&format!(r"\b{}\b", pattern)).unwrap();
        if word_regex.is_match(&outside_strings) {
            analysis.is_static_only = false;
            analysis.has_user_seed = true;
            analysis.dynamic_seeds.push(pattern.to_string());
        }
    }

    // Check for global config patterns (intentionally static)
    // Handle both b"prefix" and b "prefix" (syn tokenizes with space)
    for prefix in GLOBAL_SEED_PREFIXES {
        let patterns = [
            format!("b\"{}\"", prefix),
            format!("b\"{}\"", prefix.to_uppercase()),
            format!("b \"{}\"", prefix),  // With space after b
            format!("b \"{}\"", prefix.to_uppercase()),
        ];
        for p in patterns {
            if seeds_str.contains(&p) {
                analysis.is_global_config = true;
                analysis.evidence.push(format!("Contains global prefix: {}", prefix));
            }
        }
    }

    // Also check if any static seed starts with a global prefix
    let static_seed_regex = Regex::new(r#"b\s*"([^"]+)""#).unwrap();
    for cap in static_seed_regex.captures_iter(seeds_str) {
        if let Some(seed) = cap.get(1) {
            let seed_str = seed.as_str();
            analysis.static_seeds.push(seed_str.to_string());

            // Check if this seed starts with a global prefix
            let seed_lower = seed_str.to_lowercase();
            for prefix in GLOBAL_SEED_PREFIXES {
                if seed_lower.starts_with(prefix) {
                    analysis.is_global_config = true;
                    analysis.evidence.push(format!("Seed '{}' starts with global prefix: {}", seed_str, prefix));
                }
            }
        }
    }

    // Build evidence
    if analysis.is_static_only {
        analysis.evidence.push("Seeds contain only static values".to_string());
        if !analysis.static_seeds.is_empty() {
            analysis.evidence.push(format!("Static seeds: {:?}", analysis.static_seeds));
        }
    }

    if analysis.has_user_seed {
        analysis.evidence.push(format!("Dynamic seeds found: {:?}", analysis.dynamic_seeds));
    }

    analysis
}

/// Calculate confidence for PDA enumeration finding
fn calculate_pda_confidence(analysis: &SeedAnalysis, field_name: &str, struct_name: &str) -> u8 {
    let mut confidence: i32 = 70;

    // Increase confidence
    if analysis.static_seeds.len() <= 1 {
        confidence += 10; // Very simple seed = more enumerable
    }

    // Field/struct name suggests user data
    let name_lower = field_name.to_lowercase();
    let struct_lower = struct_name.to_lowercase();
    if name_lower.contains("user") || struct_lower.contains("user") ||
       name_lower.contains("profile") || struct_lower.contains("profile") {
        confidence += 15;
    }

    // Decrease confidence
    if analysis.is_global_config {
        confidence -= 30; // Global configs are meant to be static
    }

    // Some DeFi/bridge patterns are intentionally enumerable
    let defi_patterns = ["pool", "vault", "reserve", "market", "oracle", "tick",
                         "bridge", "guardian", "wormhole", "custody", "emitter"];
    if defi_patterns.iter().any(|p| name_lower.contains(p) || struct_lower.contains(p)) {
        confidence -= 20;
    }

    confidence.clamp(20, 95) as u8
}

/// Check emit! events for sensitive data
fn check_emit_events(content: &str, file: &str, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = content.lines().collect();

    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;

        if EMIT_REGEX.is_match(line) {
            let end_idx = (line_idx + 10).min(lines.len());
            let event_body: String = lines[line_idx..end_idx].join("\n");
            let event_lower = event_body.to_lowercase();

            for sensitive in EVENT_SENSITIVE_FIELDS {
                if event_lower.contains(sensitive) {
                    let confidence = calculate_event_confidence(sensitive, &event_lower);

                    let mut finding = Finding::new(
                        "PRIV-006",
                        &format!("Event Emits Sensitive Data: '{}'", sensitive),
                        Severity::Medium,
                        file,
                        line_num,
                        &extract_code_snippet(content, line_num),
                        "Anchor events are publicly indexed. Consider emitting hashed values or minimal identifiers.",
                    );

                    finding.confidence = confidence;
                    finding.evidence.push(format!("Event contains '{}' field", sensitive));
                    finding.evidence.push("Events are indexed by services like Helius".to_string());

                    findings.push(finding);
                    break;
                }
            }
        }
    }
}

/// Calculate confidence for event emission finding
fn calculate_event_confidence(sensitive_field: &str, event_body: &str) -> u8 {
    let mut confidence: i32 = 65;

    // Higher confidence for user-identifying fields
    let high_risk = ["user", "owner", "authority", "recipient", "sender"];
    if high_risk.contains(&sensitive_field) {
        confidence += 15;
    }

    // Lower confidence for DeFi-standard fields
    let standard_defi = ["amount", "fee", "price", "balance"];
    if standard_defi.contains(&sensitive_field) {
        confidence -= 10; // These are often intentionally public
    }

    // If it's combined with identifying info, higher risk
    if event_body.contains("pubkey") || event_body.contains("key()") {
        confidence += 10;
    }

    confidence.clamp(30, 90) as u8
}

/// Check for authority accounts that should be signers but aren't
fn check_missing_signer(content: &str, file: &str, findings: &mut Vec<Finding>) {
    for cap in AUTHORITY_WITHOUT_SIGNER.captures_iter(content) {
        let field_name = cap.get(1).map(|m| m.as_str()).unwrap_or("authority");
        let byte_pos = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let line = find_line_number(content, byte_pos);

        // Check if there's a Signer constraint or has_one nearby
        let context_start = byte_pos.saturating_sub(200);
        let context_end = (byte_pos + 200).min(content.len());
        let context = &content[context_start..context_end];

        // Skip if there's proper validation
        if context.contains("Signer<") || context.contains("has_one") || context.contains("constraint") {
            continue;
        }

        let mut finding = Finding::new(
            "PRIV-011",
            &format!("Authority '{}' May Need Signer Check", field_name),
            Severity::High,
            file,
            line,
            &extract_code_snippet(content, line),
            "Authority accounts should typically be Signer<'info> to ensure they authorized the transaction. If this is intentional, add a comment explaining why.",
        );

        finding.confidence = 65;
        finding.evidence = vec![
            format!("Field '{}' looks like an authority but isn't a Signer", field_name),
            "Missing Signer constraint could allow unauthorized access".to_string(),
        ];

        findings.push(finding);
    }
}

// ============================================================================
// PRIV-008: Uninitialized Account State
// ============================================================================

/// Check for accounts used without proper initialization validation
fn check_uninitialized_state(content: &str, file: &str, findings: &mut Vec<Finding>) {
    // Pattern 1: #[account(mut)] without init or proper constraints
    for mat in MUT_ACCOUNT.find_iter(content) {
        let line = find_line_number(content, mat.start());

        // Get the full account attribute and field declaration (include next 2 lines)
        let context_start = mat.start();
        let mut context_end = mat.end();
        let mut newlines_found = 0;
        for (i, ch) in content[mat.end()..].char_indices() {
            if ch == '\n' {
                newlines_found += 1;
                if newlines_found >= 2 {
                    context_end = mat.end() + i;
                    break;
                }
            }
            if ch == ';' || ch == '}' {
                context_end = mat.end() + i;
                break;
            }
        }
        context_end = context_end.min(content.len());
        let context = &content[context_start..context_end];

        // Skip if it has proper initialization or validation constraints
        let has_init = context.contains("init") || context.contains("init_if_needed");
        let has_validation = context.contains("constraint")
            || context.contains("has_one")
            || context.contains("seeds")
            || context.contains("close");

        // Skip known safe patterns
        let is_signer = context.contains("Signer<");
        let is_program = context.contains("Program<");
        let is_system = context.contains("system_program") || context.contains("rent");

        if has_init || has_validation || is_signer || is_program || is_system {
            continue;
        }

        // Check if this is an Account<'info, T> (safer) vs AccountInfo/UncheckedAccount
        let is_typed_account = context.contains("Account<");

        let mut finding = Finding::new(
            "PRIV-008",
            "Mutable Account Without Initialization Check",
            Severity::High,
            file,
            line,
            &extract_code_snippet(content, line),
            "Mutable accounts should have initialization checks (init/init_if_needed) or validation constraints (has_one, constraint, seeds) to prevent using uninitialized or incorrect account state. This can lead to reading stale data from previous owners.",
        );

        finding.confidence = if is_typed_account { 70 } else { 85 };
        finding.evidence = vec![
            "Mutable account without initialization constraint".to_string(),
            "No validation constraints (has_one, constraint, seeds) detected".to_string(),
            "Could read/write uninitialized or stale account data".to_string(),
        ];

        // Lower confidence for typed Account (Anchor does some checks automatically)
        if is_typed_account {
            finding.evidence.push(
                "Account<T> provides some safety, but explicit checks are better".to_string()
            );
        }

        findings.push(finding);
    }

    // Pattern 2: Manual deserialization without discriminator check
    let deserialize_patterns = [
        r"try_from_slice\s*\(",
        r"try_deserialize\s*\(",
        r"try_borrow_data\s*\(",
        r"Account::try_from\s*\(",
    ];

    for pattern_str in &deserialize_patterns {
        if let Ok(pattern) = regex::Regex::new(pattern_str) {
            for mat in pattern.find_iter(content) {
                let line = find_line_number(content, mat.start());

                // Check for discriminator validation in surrounding context
                let context_start = mat.start().saturating_sub(300);
                let context_end = (mat.end() + 300).min(content.len());
                let context = &content[context_start..context_end];

                let has_discriminator_check = context.contains("discriminator")
                    || context.contains("DISCRIMINATOR")
                    || context.contains("try_deserialize") // Anchor's method includes check
                    || context.contains("Account::try_from"); // Also includes check

                if has_discriminator_check {
                    continue;
                }

                let mut finding = Finding::new(
                    "PRIV-008",
                    "Manual Deserialization Without Discriminator Check",
                    Severity::Medium,
                    file,
                    line,
                    &extract_code_snippet(content, line),
                    "Manual account deserialization should verify the account's discriminator to ensure it's the expected type. Use Account::try_from() or check discriminator manually.",
                );

                finding.confidence = 75;
                finding.evidence = vec![
                    "Manual deserialization detected".to_string(),
                    "No discriminator validation found in context".to_string(),
                    "Could deserialize wrong account type".to_string(),
                ];

                findings.push(finding);
            }
        }
    }
}

// ============================================================================
// PRIV-012: Unchecked Accounts
// ============================================================================

/// Check for UncheckedAccount and raw AccountInfo usage
fn check_unchecked_accounts(content: &str, file: &str, findings: &mut Vec<Finding>) {
    // Check for UncheckedAccount
    for mat in UNCHECKED_ACCOUNT.find_iter(content) {
        let line = find_line_number(content, mat.start());

        // Check if there's a CHECK comment in the surrounding lines (Anchor safety pattern)
        // Look up to 10 lines above for the CHECK comment (accounts can have multi-line attributes)
        let lines: Vec<&str> = content.lines().collect();
        let start_check = line.saturating_sub(10);
        let end_check = line;

        let mut has_check_comment = false;
        for i in start_check..end_check {
            if let Some(l) = lines.get(i) {
                if l.contains("/// CHECK:") || l.contains("// CHECK:") || l.contains("* CHECK:") {
                    has_check_comment = true;
                    break;
                }
            }
        }

        if has_check_comment {
            continue; // Properly documented
        }

        // Check if this UncheckedAccount has seed/PDA validation (safe pattern)
        // Look at the #[account(...)] attribute above for seeds or seeds::program
        let mut has_seed_validation = false;
        for i in start_check..end_check {
            if let Some(l) = lines.get(i) {
                if l.contains("seeds") || l.contains("seeds::program") {
                    has_seed_validation = true;
                    break;
                }
            }
        }

        if has_seed_validation {
            continue; // PDA validation provides safety
        }

        let mut finding = Finding::new(
            "PRIV-012",
            "UncheckedAccount Without Safety Documentation",
            Severity::Medium,
            file,
            line,
            &extract_code_snippet(content, line),
            "UncheckedAccount bypasses Anchor's account validation. Add a `/// CHECK: <reason>` comment to document why this is safe.",
        );

        finding.confidence = 75;
        finding.evidence = vec![
            "UncheckedAccount found without /// CHECK: documentation".to_string(),
            "This bypasses Anchor's automatic account validation".to_string(),
        ];

        findings.push(finding);
    }

    // Check for raw AccountInfo (less common in Anchor)
    for mat in RAW_ACCOUNT_INFO.find_iter(content) {
        let line = find_line_number(content, mat.start());

        // Check if there's a CHECK comment in the surrounding lines
        let lines: Vec<&str> = content.lines().collect();
        let start_check = line.saturating_sub(10);
        let end_check = line;

        let mut has_check_comment = false;
        for i in start_check..end_check {
            if let Some(l) = lines.get(i) {
                if l.contains("/// CHECK:") || l.contains("// CHECK:") || l.contains("* CHECK:") {
                    has_check_comment = true;
                    break;
                }
            }
        }

        if has_check_comment {
            continue;
        }

        let line_content = content.lines().nth(line.saturating_sub(1)).unwrap_or("");

        // Skip common safe patterns
        if line_content.contains("system_program") || line_content.contains("rent") {
            continue;
        }

        let mut finding = Finding::new(
            "PRIV-012",
            "Raw AccountInfo Requires Manual Validation",
            Severity::Low,
            file,
            line,
            &extract_code_snippet(content, line),
            "Raw AccountInfo<'info> requires manual ownership and validation checks. Consider using typed Account<'info, T> or document with /// CHECK: comment.",
        );

        finding.confidence = 55;
        finding.evidence = vec![
            "Raw AccountInfo found - requires manual validation".to_string(),
        ];

        findings.push(finding);
    }
}

// ============================================================================
// PRIV-013: CPI Validation
// ============================================================================

/// Check for CPI calls without program validation
fn check_cpi_validation(content: &str, file: &str, findings: &mut Vec<Finding>) {
    for mat in CPI_INVOKE.find_iter(content) {
        let line = find_line_number(content, mat.start());

        // Look for program validation in the surrounding context
        let context_start = mat.start().saturating_sub(500);
        let context_end = (mat.start() + 300).min(content.len());
        let context = &content[context_start..context_end];

        // Check for proper program validation
        let has_program_check = PROGRAM_CHECK.is_match(context)
            || context.contains("program.key()")
            || context.contains("program_id")
            || context.contains("token_program")
            || context.contains("system_program")
            || context.contains("cpi::");

        if has_program_check {
            continue;
        }

        let mut finding = Finding::new(
            "PRIV-013",
            "CPI Call May Lack Program Validation",
            Severity::High,
            file,
            line,
            &extract_code_snippet(content, line),
            "CPI calls should validate the target program ID to prevent calling malicious programs. Use Program<'info, T> or verify program.key() matches expected ID.",
        );

        finding.confidence = 60;
        finding.evidence = vec![
            "invoke/invoke_signed call found".to_string(),
            "No obvious program ID validation in nearby context".to_string(),
        ];

        findings.push(finding);
    }
}

// ============================================================================
// PRIV-014: Account Closing Vulnerability
// ============================================================================

/// Check for account closing without proper cleanup
fn check_account_closing(content: &str, file: &str, findings: &mut Vec<Finding>) {
    for cap in ACCOUNT_CLOSE.captures_iter(content) {
        let byte_pos = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let line = find_line_number(content, byte_pos);

        // Look at the account attribute context
        let context_start = byte_pos.saturating_sub(100);
        let context_end = (byte_pos + 200).min(content.len());
        let context = &content[context_start..context_end];

        // Check for potential revival attack vectors
        let has_discriminator_check = context.contains("discriminator")
            || context.contains("is_initialized")
            || context.contains("AccountDiscriminator");

        if has_discriminator_check {
            continue;
        }

        let mut finding = Finding::new(
            "PRIV-014",
            "Account Close May Be Vulnerable to Revival Attack",
            Severity::Medium,
            file,
            line,
            &extract_code_snippet(content, line),
            "Closed accounts can be revived by sending lamports before the transaction completes. Consider zeroing account data or using a discriminator check on account access.",
        );

        finding.confidence = 55;
        finding.evidence = vec![
            "Account close directive found".to_string(),
            "No discriminator/initialization check detected".to_string(),
            "Revival attack: attacker sends lamports to closed account in same transaction".to_string(),
        ];

        findings.push(finding);
    }
}

// ============================================================================
// PRIV-015: Reinitialization Risk
// ============================================================================

/// Check for potential reinitialization vulnerabilities
fn check_reinitialization(content: &str, file: &str, findings: &mut Vec<Finding>) {
    for mat in INIT_PATTERN.find_iter(content) {
        let line = find_line_number(content, mat.start());

        // Get the full account attribute context
        let context_start = mat.start();
        let context_end = content[mat.start()..].find(']')
            .map(|i| mat.start() + i + 1)
            .unwrap_or(mat.end());
        let context = &content[context_start..context_end];

        // init_if_needed is the risky one
        if context.contains("init_if_needed") {
            // Check for proper guards
            let has_guard = context.contains("constraint")
                || context.contains("has_one")
                || context.contains("realloc");

            if !has_guard {
                let mut finding = Finding::new(
                    "PRIV-015",
                    "init_if_needed Without Constraints",
                    Severity::High,
                    file,
                    line,
                    &extract_code_snippet(content, line),
                    "init_if_needed can lead to reinitialization attacks. Add constraints to verify the account state, or use separate init and update instructions.",
                );

                finding.confidence = 75;
                finding.evidence = vec![
                    "init_if_needed allows reinitialization if account exists".to_string(),
                    "No constraint guards detected".to_string(),
                    "Attacker could reinitialize with different data".to_string(),
                ];

                findings.push(finding);
            }
        }
    }
}

// ============================================================================
// PRIV-016: Unsafe Arithmetic
// ============================================================================

/// Check for unsafe arithmetic in sensitive operations
fn check_unsafe_arithmetic(content: &str, file: &str, findings: &mut Vec<Finding>) {
    for mat in UNCHECKED_MATH.find_iter(content) {
        let line = find_line_number(content, mat.start());

        // Get surrounding context
        let context_start = mat.start().saturating_sub(100);
        let context_end = (mat.end() + 100).min(content.len());
        let context = &content[context_start..context_end];

        // Check for safe math patterns
        let has_safe_math = context.contains("checked_")
            || context.contains("saturating_")
            || context.contains("try_")
            || context.contains("unwrap_or")
            || context.contains("?");

        if has_safe_math {
            continue;
        }

        // Skip test code patterns
        let line_content = content.lines().nth(line.saturating_sub(1)).unwrap_or("");
        if line_content.contains("#[test]") || line_content.contains("assert") {
            continue;
        }

        let mut finding = Finding::new(
            "PRIV-016",
            "Potential Unsafe Arithmetic in Token Operation",
            Severity::Medium,
            file,
            line,
            &extract_code_snippet(content, line),
            "Arithmetic on token amounts should use checked_* or saturating_* methods to prevent overflow/underflow. Example: amount.checked_add(fee).ok_or(Error)?",
        );

        finding.confidence = 50;
        finding.evidence = vec![
            "Unchecked arithmetic on amount/balance/lamports".to_string(),
            "Consider using checked_add, checked_sub, etc.".to_string(),
        ];

        findings.push(finding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_static_pda() {
        let content = r#"
            #[derive(Accounts)]
            pub struct CreateUser<'info> {
                #[account(
                    init,
                    seeds = [b"user_data"],
                    bump,
                    payer = payer
                )]
                pub user_data: Account<'info, UserData>,
                #[account(mut)]
                pub payer: Signer<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        assert!(findings.iter().any(|f| f.id == "PRIV-010"));
    }

    #[test]
    fn test_allows_dynamic_pda() {
        let content = r#"
            #[derive(Accounts)]
            pub struct CreateUser<'info> {
                #[account(
                    init,
                    seeds = [b"user", authority.key().as_ref()],
                    bump,
                    payer = authority
                )]
                pub user_data: Account<'info, UserData>,
                pub authority: Signer<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        // Should not flag PDA with user-specific seeds
        let pda_findings: Vec<_> = findings.iter().filter(|f| f.id == "PRIV-010").collect();
        assert!(pda_findings.is_empty());
    }

    #[test]
    fn test_allows_global_config_pda() {
        let content = r#"
            #[derive(Accounts)]
            pub struct Initialize<'info> {
                #[account(
                    init,
                    seeds = [b"global_config"],
                    bump,
                    payer = admin
                )]
                pub config: Account<'info, Config>,
                pub admin: Signer<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        // Global config PDAs should have low confidence or not be flagged
        let pda_findings: Vec<_> = findings.iter().filter(|f| f.id == "PRIV-010").collect();
        assert!(pda_findings.is_empty() || pda_findings.iter().all(|f| f.confidence < 50));
    }

    #[test]
    fn test_detects_sensitive_emit() {
        let content = r#"
            emit!(TransferEvent {
                amount: transfer_amount,
                user: ctx.accounts.user.key(),
            });
        "#;
        let findings = check(content, "src/lib.rs");
        assert!(!findings.is_empty());
    }

    // =========================================================================
    // PRIV-011: Missing Signer Tests
    // =========================================================================

    #[test]
    fn test_detects_authority_without_signer() {
        let content = r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub authority: AccountInfo<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        assert!(findings.iter().any(|f| f.id == "PRIV-011"));
    }

    #[test]
    fn test_allows_authority_with_signer() {
        let content = r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        let signer_findings: Vec<_> = findings.iter().filter(|f| f.id == "PRIV-011").collect();
        assert!(signer_findings.is_empty());
    }

    // =========================================================================
    // PRIV-008: Uninitialized State Tests
    // =========================================================================

    #[test]
    fn test_detects_mut_without_init() {
        let content = r#"
            #[derive(Accounts)]
            pub struct UpdateUser<'info> {
                #[account(mut)]
                pub user_account: Account<'info, UserData>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        assert!(findings.iter().any(|f| f.id == "PRIV-008"));
    }

    #[test]
    fn test_allows_mut_with_init() {
        let content = r#"
            #[derive(Accounts)]
            pub struct CreateUser<'info> {
                #[account(init, payer = payer, space = 8 + 256)]
                pub user_account: Account<'info, UserData>,
                #[account(mut)]
                pub payer: Signer<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        let state_findings: Vec<_> = findings.iter().filter(|f| f.id == "PRIV-008").collect();
        // Should not flag accounts with init
        assert!(state_findings.is_empty());
    }

    #[test]
    fn test_allows_mut_with_constraints() {
        let content = r#"
            #[derive(Accounts)]
            pub struct UpdateUser<'info> {
                #[account(mut, has_one = authority)]
                pub user_account: Account<'info, UserData>,
                pub authority: Signer<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        let state_findings: Vec<_> = findings.iter().filter(|f| f.id == "PRIV-008").collect();
        // Should not flag accounts with validation constraints
        assert!(state_findings.is_empty());
    }

    #[test]
    fn test_allows_signer_accounts() {
        let content = r#"
            #[derive(Accounts)]
            pub struct Process<'info> {
                #[account(mut)]
                pub authority: Signer<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        let state_findings: Vec<_> = findings.iter().filter(|f| f.id == "PRIV-008").collect();
        // Signers are safe by design
        assert!(state_findings.is_empty());
    }

    // =========================================================================
    // PRIV-012: Unchecked Account Tests
    // =========================================================================

    #[test]
    fn test_detects_unchecked_account_without_doc() {
        let content = r#"
            #[derive(Accounts)]
            pub struct Process<'info> {
                pub external: UncheckedAccount<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        assert!(findings.iter().any(|f| f.id == "PRIV-012"));
    }

    #[test]
    fn test_allows_unchecked_with_check_comment() {
        let content = r#"
            #[derive(Accounts)]
            pub struct Process<'info> {
                /// CHECK: This is a PDA owned by our program, validated in instruction
                pub external: UncheckedAccount<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        let unchecked_findings: Vec<_> = findings.iter().filter(|f| f.id == "PRIV-012").collect();
        assert!(unchecked_findings.is_empty());
    }

    // =========================================================================
    // PRIV-015: Reinitialization Tests
    // =========================================================================

    #[test]
    fn test_detects_init_if_needed_without_constraint() {
        let content = r#"
            #[derive(Accounts)]
            pub struct Create<'info> {
                #[account(
                    init_if_needed,
                    payer = payer,
                    space = 100
                )]
                pub data: Account<'info, MyData>,
                #[account(mut)]
                pub payer: Signer<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        assert!(findings.iter().any(|f| f.id == "PRIV-015"));
    }

    #[test]
    fn test_allows_init_if_needed_with_constraint() {
        let content = r#"
            #[derive(Accounts)]
            pub struct Create<'info> {
                #[account(
                    init_if_needed,
                    payer = payer,
                    space = 100,
                    constraint = data.owner == payer.key()
                )]
                pub data: Account<'info, MyData>,
                #[account(mut)]
                pub payer: Signer<'info>,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        let reinit_findings: Vec<_> = findings.iter().filter(|f| f.id == "PRIV-015").collect();
        assert!(reinit_findings.is_empty());
    }

    // =========================================================================
    // PRIV-016: Unsafe Arithmetic Tests
    // =========================================================================

    #[test]
    fn test_detects_unchecked_arithmetic() {
        let content = r#"
            fn transfer(amount: u64, fee: u64) {
                let total = amount + fee;
                let remaining = balance - amount;
            }
        "#;
        let findings = check(content, "src/lib.rs");
        assert!(findings.iter().any(|f| f.id == "PRIV-016"));
    }

    #[test]
    fn test_allows_checked_arithmetic() {
        let content = r#"
            fn transfer(amount: u64, fee: u64) -> Result<u64> {
                let total = amount.checked_add(fee).ok_or(Error::Overflow)?;
                let remaining = balance.checked_sub(amount).ok_or(Error::Underflow)?;
                Ok(remaining)
            }
        "#;
        let findings = check(content, "src/lib.rs");
        let arith_findings: Vec<_> = findings.iter().filter(|f| f.id == "PRIV-016").collect();
        assert!(arith_findings.is_empty());
    }
}
