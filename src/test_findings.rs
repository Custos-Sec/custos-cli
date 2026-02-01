//! Shared test data and fixtures for privacy finding tests
//!
//! This module provides reusable test findings that can be used across:
//! - Mock tests (with mocked RPC/API responses)
//! - CLI commands (with real RPC/API)
//! - Integration tests
//!
//! All findings use realistic Solana addresses and code patterns.

#![allow(dead_code)]

use crate::checks::Finding;
use crate::report::Severity;

/// Solana Mainnet Addresses (real, used for realistic test data)
pub struct SolanaAddresses;

impl SolanaAddresses {
    /// System Program - always exists
    pub const SYSTEM_PROGRAM: &'static str = "11111111111111111111111111111111";

    /// Token Program - well-known safe program
    pub const TOKEN_PROGRAM: &'static str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    /// Token-2022 Program
    pub const TOKEN_2022_PROGRAM: &'static str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

    /// Associated Token Program
    pub const ASSOCIATED_TOKEN_PROGRAM: &'static str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

    /// Example program ID for tests
    pub const TEST_PROGRAM_ID: &'static str = "GrPC1n1n1n1n1n1n1n1n1n1n1n1n1n1n1n1n1n1n1";

    /// Example user wallet
    pub const TEST_USER_WALLET: &'static str = "5d1bR8D4J7QoJnQ7Xn8cK9mL2pQ4rS5tU6vW7xY8zZa";
}

/// Builder for creating test findings with various configurations
pub struct TestFindingBuilder {
    id: String,
    title: String,
    severity: Severity,
    file: String,
    line: usize,
    code_snippet: String,
    recommendation: String,
    confidence: u8,
    evidence: Vec<String>,
}

impl TestFindingBuilder {
    /// Create a new builder with default values
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            title: format!("Test Finding {}", id),
            severity: Severity::Medium,
            file: "test.rs".to_string(),
            line: 1,
            code_snippet: "let test = true;".to_string(),
            recommendation: "Review and fix".to_string(),
            confidence: 75,
            evidence: vec![],
        }
    }

    pub fn title(mut self, title: &str) -> Self {
        self.title = title.to_string();
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn file(mut self, file: &str) -> Self {
        self.file = file.to_string();
        self
    }

    pub fn line(mut self, line: usize) -> Self {
        self.line = line;
        self
    }

    pub fn code_snippet(mut self, snippet: &str) -> Self {
        self.code_snippet = snippet.to_string();
        self
    }

    pub fn recommendation(mut self, rec: &str) -> Self {
        self.recommendation = rec.to_string();
        self
    }

    pub fn confidence(mut self, conf: u8) -> Self {
        self.confidence = conf.min(100);
        self
    }

    pub fn evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn add_evidence(mut self, ev: &str) -> Self {
        self.evidence.push(ev.to_string());
        self
    }

    pub fn build(self) -> Finding {
        Finding {
            id: self.id,
            title: self.title,
            severity: self.severity,
            file: self.file,
            line: self.line,
            code_snippet: self.code_snippet,
            recommendation: self.recommendation,
            confidence: self.confidence,
            evidence: self.evidence,
        }
    }
}

/// Pre-built sample findings for different PRIV codes
pub struct TestFindings;

impl TestFindings {
    /// PRIV-001: Hardcoded private key
    pub fn priv_001_hardcoded_key() -> Finding {
        TestFindingBuilder::new("PRIV-001")
            .title("Hardcoded Private Key Detected")
            .severity(Severity::Critical)
            .code_snippet(
                "const SECRET_KEY: [u8; 32] = [0x1a, 0x2b, 0x3c, 0x4d, ...];"
            )
            .recommendation("Remove hardcoded key. Use environment variables or secure key management.")
            .confidence(95)
            .add_evidence("Found 32-byte hex literal matching private key format")
            .add_evidence("Hardcoded in constant declaration")
            .build()
    }

    /// PRIV-002: Mnemonic/seed phrase
    pub fn priv_002_mnemonic() -> Finding {
        TestFindingBuilder::new("PRIV-002")
            .title("Mnemonic/Seed Phrase Detected")
            .severity(Severity::Critical)
            .code_snippet(
                "const MNEMONIC: &str = \"abandon ability able about above absent absorb abstract abundance...\""
            )
            .recommendation("Remove mnemonic from code. Use secure key derivation.")
            .confidence(92)
            .add_evidence("Found BIP39 word list pattern")
            .build()
    }

    /// PRIV-003: Hardcoded seed bytes
    pub fn priv_003_seed_bytes() -> Finding {
        TestFindingBuilder::new("PRIV-003")
            .title("Hardcoded Seed Bytes")
            .severity(Severity::Critical)
            .code_snippet(
                "let seed = b\"my_secret_seed_value_12345678901234567890\";"
            )
            .recommendation("Avoid hardcoding seeds. Use secure random generation.")
            .confidence(88)
            .add_evidence("Seed pattern in literal byte string")
            .build()
    }

    /// PRIV-004: PII in account structs
    pub fn priv_004_pii_account() -> Finding {
        TestFindingBuilder::new("PRIV-004")
            .title("PII Detected in Account Struct")
            .severity(Severity::High)
            .code_snippet(
                "#[account]
pub struct UserProfile {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}"
            )
            .recommendation("Remove PII from on-chain structs. Use hash-based identification instead.")
            .confidence(85)
            .add_evidence("Found first_name field")
            .add_evidence("Found email field")
            .build()
    }

    /// PRIV-005: Sensitive fields (passwords, API keys)
    pub fn priv_005_sensitive_fields() -> Finding {
        TestFindingBuilder::new("PRIV-005")
            .title("Sensitive Field Detected")
            .severity(Severity::High)
            .code_snippet(
                "#[account]
pub struct Config {
    pub api_key: String,
    pub password: [u8; 32],
}"
            )
            .recommendation("Store sensitive data off-chain or use encrypted fields.")
            .confidence(82)
            .add_evidence("Found api_key field")
            .add_evidence("Found password field")
            .build()
    }

    /// PRIV-006: Sensitive data in logs/events
    pub fn priv_006_debug_logs() -> Finding {
        TestFindingBuilder::new("PRIV-006")
            .title("Sensitive Data in Debug Logs")
            .severity(Severity::High)
            .code_snippet(
                "msg!(\"User created: email={}, balance={}\", email, balance);"
            )
            .recommendation("Remove sensitive data from logs. Log only non-identifying info.")
            .confidence(78)
            .add_evidence("Email exposed in log statement")
            .build()
    }

    /// PRIV-007: Debug logging in production
    pub fn priv_007_debug_logging() -> Finding {
        TestFindingBuilder::new("PRIV-007")
            .title("Debug Logging in Production Code")
            .severity(Severity::Medium)
            .code_snippet(
                "println!(\"Account owner: {:?}\", owner);
debug!(\"{:?}\", private_data);"
            )
            .recommendation("Remove debug! and println! calls. Use cfg!() for dev-only logging.")
            .confidence(75)
            .add_evidence("Found println! macro call")
            .add_evidence("Found debug! macro call")
            .build()
    }

    /// PRIV-008: Uninitialized account state
    pub fn priv_008_uninitialized_state() -> Finding {
        TestFindingBuilder::new("PRIV-008")
            .title("Account State Not Validated")
            .severity(Severity::High)
            .code_snippet(
                "#[derive(Accounts)]
pub struct UpdateUser<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserData>,  // Missing init check
}"
            )
            .recommendation("Add initialization checks (init/init_if_needed) or validation constraints (has_one, constraint, seeds) to prevent using uninitialized account state.")
            .confidence(80)
            .add_evidence("Mutable account without initialization constraint")
            .add_evidence("No validation constraints detected")
            .add_evidence("Could read stale data from previous owner")
            .build()
    }

    /// PRIV-009: CPI without program validation
    pub fn priv_009_unvalidated_cpi() -> Finding {
        TestFindingBuilder::new("PRIV-009")
            .title("CPI Without Program Validation")
            .severity(Severity::High)
            .code_snippet(&format!(
                "invoke(&ix, &[program.clone()]) // Missing check for known program {}",
                SolanaAddresses::TOKEN_PROGRAM
            ))
            .recommendation("Validate CPI target is a known, safe program before execution.")
            .confidence(80)
            .add_evidence("CPI call without program verification")
            .add_evidence(&format!("Unknown CPI target: {}", SolanaAddresses::TOKEN_PROGRAM))
            .build()
    }

    /// PRIV-010: Predictable PDA seeds
    pub fn priv_010_predictable_pda() -> Finding {
        TestFindingBuilder::new("PRIV-010")
            .title("Predictable PDA Seeds")
            .severity(Severity::High)
            .code_snippet(
                "let (pda, _) = Pubkey::find_program_address(
    &[b\"user_account\", user.key().as_ref()],
    program_id,
);"
            )
            .recommendation("Use high-entropy seeds (timestamps, nonces) to prevent PDA enumeration.")
            .confidence(72)
            .add_evidence("PDA derived from deterministic seed")
            .add_evidence("User pubkey used in seed (enumerable)")
            .build()
    }

    /// PRIV-020: Wallet clustering (chain only)
    pub fn priv_020_wallet_clustering() -> Finding {
        TestFindingBuilder::new("PRIV-020")
            .title("Wallet Clustering Pattern Detected")
            .severity(Severity::Medium)
            .code_snippet("transaction verified on-chain")
            .recommendation("Use multiple wallets or mixing services to break correlation patterns.")
            .confidence(60)
            .add_evidence("10+ transactions from same wallet")
            .add_evidence("Pattern suggests single operator")
            .build()
    }

    /// PRIV-021: Balance correlation (chain only)
    pub fn priv_021_balance_correlation() -> Finding {
        TestFindingBuilder::new("PRIV-021")
            .title("Balance Correlation Detected")
            .severity(Severity::Medium)
            .code_snippet("multiple accounts with identical balance changes")
            .recommendation("Use time delays or randomized amounts to break correlation.")
            .confidence(65)
            .add_evidence("3 accounts with identical +1000 SPL token transfers")
            .add_evidence("All transfers within 2 blocks")
            .build()
    }

    /// Get all sample findings
    pub fn all() -> Vec<Finding> {
        vec![
            Self::priv_001_hardcoded_key(),
            Self::priv_002_mnemonic(),
            Self::priv_003_seed_bytes(),
            Self::priv_004_pii_account(),
            Self::priv_005_sensitive_fields(),
            Self::priv_006_debug_logs(),
            Self::priv_007_debug_logging(),
            Self::priv_008_uninitialized_state(),
            Self::priv_009_unvalidated_cpi(),
            Self::priv_010_predictable_pda(),
            Self::priv_020_wallet_clustering(),
            Self::priv_021_balance_correlation(),
        ]
    }

    /// Get findings for QuickNode verification (PRIV-004, 005, 008, 009, 010)
    pub fn for_quicknode_verification() -> Vec<Finding> {
        vec![
            Self::priv_004_pii_account(),
            Self::priv_005_sensitive_fields(),
            Self::priv_008_uninitialized_state(),
            Self::priv_009_unvalidated_cpi(),
            Self::priv_010_predictable_pda(),
        ]
    }

    /// Get findings for Helius verification (PRIV-006, 007, 008, 009, 010)
    pub fn for_helius_verification() -> Vec<Finding> {
        vec![
            Self::priv_006_debug_logs(),
            Self::priv_007_debug_logging(),
            Self::priv_008_uninitialized_state(),
            Self::priv_009_unvalidated_cpi(),
            Self::priv_010_predictable_pda(),
        ]
    }

    /// Get findings for static analysis (PRIV-001 through 010)
    pub fn for_static_analysis() -> Vec<Finding> {
        vec![
            Self::priv_001_hardcoded_key(),
            Self::priv_002_mnemonic(),
            Self::priv_003_seed_bytes(),
            Self::priv_004_pii_account(),
            Self::priv_005_sensitive_fields(),
            Self::priv_006_debug_logs(),
            Self::priv_007_debug_logging(),
            Self::priv_008_uninitialized_state(),
            Self::priv_009_unvalidated_cpi(),
            Self::priv_010_predictable_pda(),
        ]
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let finding = TestFindingBuilder::new("PRIV-001")
            .title("Test Title")
            .severity(Severity::Critical)
            .build();

        assert_eq!(finding.id, "PRIV-001");
        assert_eq!(finding.title, "Test Title");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.confidence, 75);
    }

    #[test]
    fn test_builder_with_evidence() {
        let finding = TestFindingBuilder::new("PRIV-004")
            .confidence(85)
            .add_evidence("Evidence 1")
            .add_evidence("Evidence 2")
            .build();

        assert_eq!(finding.evidence.len(), 2);
        assert!(finding.evidence.contains(&"Evidence 1".to_string()));
    }

    #[test]
    fn test_sample_findings_exist() {
        assert_eq!(TestFindings::all().len(), 12);
    }

    #[test]
    fn test_quicknode_findings_count() {
        let findings = TestFindings::for_quicknode_verification();
        assert_eq!(findings.len(), 5);
        assert!(findings.iter().any(|f| f.id == "PRIV-004"));
        assert!(findings.iter().any(|f| f.id == "PRIV-008"));
        assert!(findings.iter().any(|f| f.id == "PRIV-010"));
    }

    #[test]
    fn test_helius_findings_count() {
        let findings = TestFindings::for_helius_verification();
        assert_eq!(findings.len(), 5);
        assert!(findings.iter().any(|f| f.id == "PRIV-006"));
        assert!(findings.iter().any(|f| f.id == "PRIV-008"));
        assert!(findings.iter().any(|f| f.id == "PRIV-010"));
    }

    #[test]
    fn test_static_analysis_findings_count() {
        let findings = TestFindings::for_static_analysis();
        assert_eq!(findings.len(), 10);
    }

    #[test]
    fn test_solana_addresses() {
        assert_eq!(
            SolanaAddresses::SYSTEM_PROGRAM,
            "11111111111111111111111111111111"
        );
        assert_eq!(
            SolanaAddresses::TOKEN_PROGRAM,
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        );
    }
}
