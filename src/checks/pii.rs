//! PRIV-004, PRIV-005: PII and sensitive data in account structs
//!
//! This module uses lightweight AST parsing for accurate struct analysis
//! combined with safe pattern recognition to minimize false positives.

use super::{extract_code_snippet, Finding};
use crate::parser::{parse_structs, StructInfo};
use crate::report::Severity;
use crate::safe_patterns::{is_pii_field, is_safe_field, is_secret_field};

/// Check content for PII and sensitive data issues
/// This version uses AST parsing for better accuracy
pub fn check(content: &str, file: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Skip test files
    if (file.contains("test") && !file.contains("test_fixtures")) || file.contains("mock") {
        return findings;
    }

    // Skip CLI-only files
    if file.contains("/cli/") || file.contains("\\cli\\") {
        return findings;
    }

    // Parse structs from the file
    let structs = parse_structs(content);

    // Check each struct
    for struct_info in &structs {
        check_struct(struct_info, content, file, &mut findings);
    }

    findings
}

/// Check a single struct for privacy issues
fn check_struct(s: &StructInfo, content: &str, file: &str, findings: &mut Vec<Finding>) {
    // Only check account structs and regular structs with pub fields
    // Skip pure Accounts context structs (they're for account validation, not data storage)
    if s.is_accounts_context && !s.is_account {
        return;
    }

    for field in &s.fields {
        // Skip non-public fields
        if !field.is_pub {
            continue;
        }

        // Check for PII (PRIV-004)
        if let Some(pii_type) = is_pii_field(&field.name, &field.ty, Some(&s.name)) {
            let confidence = calculate_pii_confidence(s, &field.name, &field.ty, pii_type);

            let mut finding = Finding::new(
                "PRIV-004",
                &format!("PII in Account Struct: '{}'", field.name),
                Severity::High,
                file,
                field.line,
                &extract_code_snippet(content, field.line),
                &format!(
                    "Field '{}' appears to contain {} (PII). Hash with SHA-256 + salt, or encrypt with AES-GCM, or store off-chain.",
                    field.name, pii_type
                ),
            );

            // Add evidence
            finding.confidence = confidence;
            finding.evidence = build_evidence(s, &field.name, &field.ty, pii_type);

            findings.push(finding);
        }

        // Check for secrets (PRIV-005)
        if let Some(secret_type) = is_secret_field(&field.name) {
            let confidence = calculate_secret_confidence(&field.name, &field.ty);

            let mut finding = Finding::new(
                "PRIV-005",
                &format!("Sensitive Data Field: '{}'", field.name),
                Severity::High,
                file,
                field.line,
                &extract_code_snippet(content, field.line),
                &format!(
                    "Field '{}' contains {} (sensitive data). Never store credentials on-chain. Use off-chain storage or encryption.",
                    field.name, secret_type
                ),
            );

            finding.confidence = confidence;
            finding.evidence.push(format!("Matched sensitive pattern: {}", secret_type));
            if field.ty.contains("String") || field.ty.contains("Vec<u8>") {
                finding.evidence.push("Field type suggests plaintext storage".to_string());
            }

            findings.push(finding);
        }
    }

    // Additional check: User/Profile/Identity structs with plaintext strings
    let name_lower = s.name.to_lowercase();
    let is_user_struct = name_lower.contains("user") ||
                         name_lower.contains("profile") ||
                         name_lower.contains("identity") ||
                         name_lower.contains("member") ||
                         name_lower.contains("person");

    if is_user_struct && s.is_account {
        let has_plaintext_strings = s.fields.iter().any(|f| {
            f.is_pub && f.ty.contains("String") && !is_safe_field(&f.name, &f.ty, Some(&s.name))
        });

        if has_plaintext_strings {
            let mut finding = Finding::new(
                "PRIV-004",
                &format!("User/Identity Struct with Plaintext Data: '{}'", s.name),
                Severity::High,
                file,
                s.line,
                &format!("#[account]\npub struct {} {{ ... }}", s.name),
                "This struct stores user data with plaintext String fields. Consider: 1) Hash identifiers, 2) Encrypt sensitive fields, 3) Store PII off-chain.",
            );

            finding.confidence = 85;
            finding.evidence.push(format!("Struct name '{}' suggests user data", s.name));
            finding.evidence.push("Contains public String fields in #[account] struct".to_string());

            findings.push(finding);
        }
    }
}

/// Calculate confidence for PII findings based on context
fn calculate_pii_confidence(s: &StructInfo, field_name: &str, field_type: &str, pii_type: &str) -> u8 {
    let mut confidence: i32 = 70; // Base confidence

    // Increase confidence
    if s.is_account {
        confidence += 15; // On-chain storage is high risk
    }
    if field_type.contains("String") {
        confidence += 10; // Plaintext string storage
    }
    if s.name.to_lowercase().contains("user") || s.name.to_lowercase().contains("profile") {
        confidence += 10; // User-related struct
    }

    // Exact match on field name
    if field_name.to_lowercase() == pii_type {
        confidence += 5;
    }

    // Decrease confidence
    if field_name.contains("hash") || field_name.contains("encrypted") {
        confidence -= 30; // Likely protected
    }
    if !s.is_account && !s.name.to_lowercase().contains("state") {
        confidence -= 10; // Might not be on-chain
    }

    confidence.clamp(20, 98) as u8
}

/// Calculate confidence for secret findings
fn calculate_secret_confidence(field_name: &str, field_type: &str) -> u8 {
    let mut confidence: i32 = 75;

    if field_type.contains("String") || field_type.contains("Vec<u8>") {
        confidence += 15;
    }

    // Exact matches are more confident
    let exact_matches = ["password", "secret_key", "private_key", "api_key", "mnemonic"];
    if exact_matches.iter().any(|&m| field_name.to_lowercase() == m) {
        confidence += 10;
    }

    if field_name.contains("hash") {
        confidence -= 40;
    }

    confidence.clamp(20, 98) as u8
}

/// Build evidence list for a finding
fn build_evidence(s: &StructInfo, _field_name: &str, field_type: &str, pii_type: &str) -> Vec<String> {
    let mut evidence = Vec::new();

    evidence.push(format!("Matched PII pattern: {}", pii_type));

    if s.is_account {
        evidence.push("Field is in #[account] struct (stored on-chain)".to_string());
    }

    if field_type.contains("String") {
        evidence.push("Type is String (plaintext, publicly readable)".to_string());
    }

    let name_lower = s.name.to_lowercase();
    if name_lower.contains("user") || name_lower.contains("profile") {
        evidence.push(format!("Struct '{}' appears to store user data", s.name));
    }

    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_email_in_account() {
        let content = r#"
            #[account]
            pub struct UserProfile {
                pub email: String,
                pub verified: bool,
            }
        "#;
        let findings = check(content, "src/state.rs");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "PRIV-004"));
    }

    #[test]
    fn test_detects_password_field() {
        let content = r#"
            pub struct Credentials {
                pub password: String,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "PRIV-005"));
    }

    #[test]
    fn test_ignores_safe_fields() {
        let content = r#"
            pub struct Token {
                pub mint_address: Pubkey,
                pub owner: Pubkey,
                pub amount: u64,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        // Should not flag these as PII
        assert!(findings.iter().all(|f| !f.title.contains("mint_address")));
        assert!(findings.iter().all(|f| !f.title.contains("owner")));
    }

    #[test]
    fn test_name_in_config_is_safe() {
        let content = r#"
            #[account]
            pub struct PoolConfig {
                pub name: String,
                pub fee_rate: u64,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        // "name" in PoolConfig should not be flagged
        assert!(findings.is_empty() || findings.iter().all(|f| !f.title.contains("'name'")));
    }

    #[test]
    fn test_name_in_user_profile_is_flagged() {
        let content = r#"
            #[account]
            pub struct UserProfile {
                pub name: String,
                pub score: u64,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        // "name" in UserProfile should be flagged
        assert!(findings.iter().any(|f| f.title.contains("name") || f.title.contains("UserProfile")));
    }

    #[test]
    fn test_hashed_fields_not_flagged() {
        let content = r#"
            #[account]
            pub struct User {
                pub email_hash: [u8; 32],
                pub password_hash: String,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        // Hashed fields should not be flagged
        assert!(findings.is_empty());
    }

    #[test]
    fn test_pubkey_address_not_flagged() {
        let content = r#"
            pub struct ExtData {
                pub recipient_address: Pubkey,
                pub mint_address: Pubkey,
            }
        "#;
        let findings = check(content, "src/lib.rs");
        // Pubkey addresses should not be flagged
        assert!(findings.is_empty());
    }
}
