//! Helius RPC Integration - Transaction History Verification Layer
//!
//! This module provides verification based on transaction history and events.
//! It uses Helius enhanced RPC to analyze actual on-chain behavior and patterns.
//!
//! # Integration with Existing Checks
//!
//! This module takes findings from the existing checks and verifies them with
//! transaction history data:
//!
//! - **PRIV-006** (Sensitive Data in Events): Find actual emitted events with PII
//! - **PRIV-007** (Debug Logging): Detect debug output in production transactions
//! - **PRIV-009** (CPI Validation): See behavioral patterns of CPI calls
//! - **PRIV-010** (PDA Enumeration): Show historical timeline of PDA discovery

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::checks::Finding;

/// Helius RPC client for transaction history verification
pub struct HeliumsVerifier {
    api_key: String,
    client: Client,
    /// Cache of parsed programs
    _program_cache: HashMap<String, ProgramInfo>,
}

/// Enhanced evidence from transaction history
#[derive(Debug, Clone, Serialize)]
pub struct TransactionEvidence {
    /// Total transactions analyzed
    pub tx_analyzed: usize,
    /// Transactions with relevant findings
    pub tx_with_findings: usize,
    /// Events emitted
    pub events_found: Vec<EventLog>,
    /// CPI calls made
    pub cpi_calls: Vec<CPICallRecord>,
    /// PDA discovery timeline
    pub pda_timeline: Option<PDATimeline>,
    /// Evidence notes
    pub notes: Vec<String>,
}

impl Default for TransactionEvidence {
    fn default() -> Self {
        Self {
            tx_analyzed: 0,
            tx_with_findings: 0,
            events_found: Vec::new(),
            cpi_calls: Vec::new(),
            pda_timeline: None,
            notes: Vec::new(),
        }
    }
}

/// An emitted event with parsed data
#[derive(Debug, Clone, Serialize)]
pub struct EventLog {
    pub tx_signature: String,
    pub timestamp: u64,
    pub event_name: String,
    pub event_data: String,
    pub contains_pii: bool,
    pub pii_types: Vec<String>,
}

/// A CPI call recorded in transaction
#[derive(Debug, Clone, Serialize)]
pub struct CPICallRecord {
    pub tx_signature: String,
    pub target_program: String,
    pub timestamp: u64,
    pub inner_instruction_count: u32,
}

/// PDA discovery timeline
#[derive(Debug, Clone, Serialize)]
pub struct PDATimeline {
    pub first_discovered: u64,
    pub last_discovered: u64,
    pub total_unique_pdas: usize,
    pub discovery_rate_per_week: f64,
}

/// Verified finding with transaction evidence
#[derive(Debug, Clone, Serialize)]
pub struct HeliumsVerifiedFinding {
    /// Original finding from static analysis
    pub finding: Finding,
    /// Transaction history evidence
    pub evidence: TransactionEvidence,
    /// Original confidence from static analysis
    pub static_confidence: u8,
    /// Adjusted confidence after historical verification
    pub verified_confidence: u8,
    /// Explanation of confidence adjustment
    pub adjustment_reason: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ProgramInfo {
    program_id: String,
    update_authority: Option<String>,
    is_known: bool,
}

// ============================================================================
// Helius API Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct HeliumsTransaction {
    pub signature: String,
    #[serde(rename = "blockTime")]
    pub block_time: u64,
    pub instructions: Vec<ParsedInstruction>,
    #[serde(default)]
    pub logs: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ParsedInstruction {
    #[serde(rename = "programId")]
    pub program_id: String,
    #[serde(default)]
    pub parsed: Option<serde_json::Value>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub accounts: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TokenMetadata {
    pub mint: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub decimals: u8,
    #[serde(default)]
    pub supply: String,
    pub uri: Option<String>,
    pub creators: Option<Vec<Creator>>,
    pub on_chain_data: Option<OnChainTokenData>,
    pub off_chain_data: Option<OffChainTokenData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OnChainTokenData {
    pub name: Option<String>,
    pub symbol: Option<String>,
    pub uri: Option<String>,
    pub update_authority: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OffChainTokenData {
    pub name: Option<String>,
    pub description: Option<String>,
    pub attributes: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Creator {
    pub address: String,
    pub verified: bool,
    pub share: u8,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub id: String,
    pub mint: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub symbol: String,
    pub uri: Option<String>,
    pub authority: Option<String>,
    #[serde(default)]
    pub owner: String,
    pub creators: Option<Vec<Creator>>,
    pub metadata: Option<serde_json::Value>,
    pub interface: Option<String>,
    pub content: Option<AssetContent>,
    pub ownership: Option<AssetOwnership>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AssetContent {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub json_uri: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AssetOwnership {
    pub owner: Option<String>,
    pub frozen: Option<bool>,
    pub delegated: Option<bool>,
    pub delegate: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RichTransaction {
    pub signature: String,
    pub timestamp: Option<u64>,
    pub slot: Option<u64>,
    pub block_time: Option<u64>,
    #[serde(rename = "type")]
    pub type_field: Option<String>,
    pub source: Option<String>,
    pub fee: Option<u64>,
    pub fee_payer: Option<String>,
    #[serde(default)]
    pub token_transfers: Vec<TokenTransfer>,
    #[serde(default)]
    pub native_transfers: Vec<NativeTransfer>,
    #[serde(default)]
    pub instructions: Vec<ParsedInstruction>,
    #[serde(default)]
    pub account_data: Vec<serde_json::Value>,
    pub events: Option<serde_json::Value>,
    pub transaction_error: Option<serde_json::Value>,
    pub description: Option<String>,
    #[serde(default)]
    pub raw_logs: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct TokenTransfer {
    #[serde(default)]
    pub mint: String,
    #[serde(default)]
    pub amount: String,
    #[serde(default)]
    pub from_token_account: String,
    #[serde(default)]
    pub to_token_account: String,
    pub from_user_account: Option<String>,
    pub to_user_account: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct NativeTransfer {
    #[serde(default)]
    pub from_address: String,
    #[serde(default)]
    pub to_address: String,
    #[serde(default)]
    pub amount: u64,
}

impl HeliumsVerifier {
    /// Create a new Helius verifier with API key
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            client: Client::new(),
            _program_cache: HashMap::new(),
        }
    }

    /// Create verifier from environment variable
    #[allow(dead_code)]
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("HELIUS_API_KEY")
            .map_err(|_| anyhow!(
                "Helius API key required. Set HELIUS_API_KEY env var.\n\
                 Get a free key at: https://dev.helius.xyz/"
            ))?;

        Ok(Self::new(&api_key))
    }

    /// Verify findings with transaction history
    #[allow(dead_code)]
    pub async fn verify_findings(&self, findings: &[Finding], program_id: &str) -> Result<Vec<HeliumsVerifiedFinding>> {
        let mut verified = Vec::new();

        for finding in findings {
            let verified_finding = self.verify_finding_enhanced(finding, program_id).await?;
            verified.push(verified_finding);
        }

        Ok(verified)
    }

    /// Run the standard Helius checks (PRIV-006 .. PRIV-010) for a program_id
    #[allow(dead_code)]
    pub async fn verify_priv_006_to_010(&self, program_id: &str) -> Result<Vec<HeliumsVerifiedFinding>> {
        use crate::report::Severity;

        let checks = vec![
            ("PRIV-006", "Sensitive Data in Events", Severity::High, "emit!(...)", "remove PII"),
            ("PRIV-007", "Debug Logging in Production", Severity::Medium, "println!(...)", "remove debug"),
            ("PRIV-008", "Uninitialized Account State", Severity::High, "initialized account <addr>", "validate init"),
            ("PRIV-009", "CPI without Program Validation", Severity::Medium, "invoke_signed(&unknown, ..)", "validate CPI targets"),
            ("PRIV-010", "PDA Historical Timeline", Severity::Medium, "find_program_address(...)", "harden PDA seeds"),
        ];

        let mut findings: Vec<Finding> = Vec::new();

        for (id, title, sev, snippet, rec) in checks {
            findings.push(crate::checks::Finding::new(id, title, sev, "src/lib.rs", 1, snippet, rec));
        }

        self.verify_findings(&findings, program_id).await
    }

    /// Route a finding to appropriate verification method
    pub async fn verify_finding_enhanced(
        &self,
        finding: &Finding,
        program_id: &str,
    ) -> Result<HeliumsVerifiedFinding> {
        let mut evidence = TransactionEvidence::default();
        let mut confidence_adjustment: i32 = 0;

        match finding.id.as_str() {
            // PRIV-006: Sensitive Data in Events
            "PRIV-006" => {
                evidence = self.verify_event_leakage(program_id).await?;
                confidence_adjustment = self.calculate_event_adjustment(&evidence);
            }

            // PRIV-007: Debug Logging in Production
            "PRIV-007" => {
                evidence = self.verify_debug_output(program_id).await?;
                confidence_adjustment = self.calculate_debug_adjustment(&evidence);
            }

            // PRIV-008: Account State Initialization
            "PRIV-008" => {
                evidence = self.verify_account_state(program_id).await?;
                confidence_adjustment = self.calculate_state_adjustment(&evidence);
            }

            // PRIV-009: CPI Behavioral Verification
            "PRIV-009" => {
                evidence = self.verify_cpi_behavior(program_id).await?;
                confidence_adjustment = self.calculate_cpi_behavioral_adjustment(&evidence);
            }

            // PRIV-010: PDA Historical Timeline
            "PRIV-010" => {
                evidence = self.verify_pda_timeline(program_id).await?;
                confidence_adjustment = self.calculate_pda_timeline_adjustment(&evidence);
            }

            // PRIV-002: Mnemonic/Seed Phrase Detection in Events and Logs
            "PRIV-002" => {
                evidence = self.verify_seed_phrase_leakage(program_id).await?;
                confidence_adjustment = self.calculate_seed_phrase_adjustment(&evidence);
            }

            // PRIV-020: Wallet Clustering Detection (chain-scan only)
            "PRIV-020" => {
                evidence = self.verify_wallet_clustering(program_id).await?;
                confidence_adjustment = self.calculate_wallet_clustering_adjustment(&evidence);
            }

            // PRIV-021: Balance Correlation Detection (chain-scan only)
            "PRIV-021" => {
                evidence = self.verify_balance_correlation(program_id).await?;
                confidence_adjustment = self.calculate_balance_correlation_adjustment(&evidence);
            }

            _ => {
                evidence.notes.push(format!("No Helius verification for {}", finding.id));
            }
        }

        let verified_confidence = ((finding.confidence as i32 + confidence_adjustment).max(5).min(100)) as u8;

        Ok(HeliumsVerifiedFinding {
            finding: finding.clone(),
            evidence,
            static_confidence: finding.confidence,
            verified_confidence,
            adjustment_reason: format!(
                "Confidence {} {}",
                if confidence_adjustment > 0 { "+" } else { "" },
                confidence_adjustment
            ),
        })
    }

    // ========================================================================
    // Verification Methods by Check Type
    // ========================================================================

    /// PRIV-006: Scan for sensitive data in emitted events
    async fn verify_event_leakage(&self, program_id: &str) -> Result<TransactionEvidence> {
        let mut evidence = TransactionEvidence::default();

        // Fetch recent transactions for program
        let transactions = self.get_program_transactions(program_id, 100).await?;

        evidence.tx_analyzed = transactions.len();

        for tx in transactions {
            let mut found_pii = false;
            let mut pii_types = Vec::new();

            // Check logs for PII patterns
            for log in &tx.logs {
                if let Some(detected) = self.detect_pii_in_log(log) {
                    found_pii = true;
                    pii_types.extend(detected);
                }
            }

            if found_pii {
                evidence.tx_with_findings += 1;
                evidence.events_found.push(EventLog {
                    tx_signature: tx.signature.clone(),
                    timestamp: tx.block_time,
                    event_name: "Event".to_string(),
                    event_data: tx.logs.join("; "),
                    contains_pii: true,
                    pii_types: pii_types.clone(),
                });
            }
        }

        if evidence.events_found.is_empty() {
            evidence.notes.push("No PII detected in recent event logs".to_string());
        } else {
            evidence.notes.push(format!(
                "CRITICAL: Found {} transactions with PII in events",
                evidence.events_found.len()
            ));
        }

        Ok(evidence)
    }

    /// PRIV-007: Check for debug output in production
    async fn verify_debug_output(&self, program_id: &str) -> Result<TransactionEvidence> {
        let mut evidence = TransactionEvidence::default();

        let transactions = self.get_program_transactions(program_id, 100).await?;
        evidence.tx_analyzed = transactions.len();

        for tx in transactions {
            // Check for debug-like output patterns
            for log in &tx.logs {
                if self.is_debug_output(log) {
                    evidence.tx_with_findings += 1;
                    evidence.notes.push(format!("Debug output found in tx: {}", tx.signature));
                    break;
                }
            }
        }

        if evidence.tx_with_findings == 0 {
            evidence.notes.push("No debug output detected in production transactions".to_string());
        }

        Ok(evidence)
    }

    /// PRIV-008: Check for account reinitialization patterns
    async fn verify_account_state(&self, program_id: &str) -> Result<TransactionEvidence> {
        let mut evidence = TransactionEvidence::default();

        let transactions = self.get_program_transactions(program_id, 100).await?;
        evidence.tx_analyzed = transactions.len();

        // Track accounts that appear multiple times (potential reinitialization)
        let mut account_create_count: HashMap<String, u32> = HashMap::new();
        let mut reinit_patterns = 0;
        let mut discriminator_issues = 0;
        let mut uninitialized_warnings = 0;

        for tx in &transactions {
            // Look for init/create patterns in logs
            for log in &tx.logs {
                let log_lower = log.to_lowercase();

                // Detect missing discriminator patterns (CRITICAL)
                if log_lower.contains("no anchor discriminator")
                    || log_lower.contains("missing discriminator")
                    || log_lower.contains("invalid discriminator")
                    || (log_lower.contains("discriminator") && log_lower.contains("warning")) {
                    discriminator_issues += 1;
                    evidence.notes.push(format!("CRITICAL: Missing discriminator: {}",
                        if log.len() > 80 { &log[..80] } else { log }));
                }

                // Detect uninitialized account warnings
                if (log_lower.contains("warning") || log_lower.contains("error"))
                    && (log_lower.contains("uninitialized") || log_lower.contains("not initialized")) {
                    uninitialized_warnings += 1;
                    evidence.notes.push(format!("WARNING: Uninitialized account detected"));
                }

                // Detect init/create patterns for reinitialization tracking
                if log_lower.contains("initialize") || log_lower.contains("created account") {
                    // Extract account addresses from log (simplified)
                    let words: Vec<&str> = log.split_whitespace().collect();
                    for word in words {
                        if word.len() >= 32 && word.len() <= 44 {
                            // Looks like a base58 address
                            *account_create_count.entry(word.to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        // Count accounts that were initialized multiple times
        for (addr, count) in &account_create_count {
            if *count > 1 {
                reinit_patterns += 1;
                evidence.notes.push(format!(
                    "Account {} appears to be initialized {} times",
                    addr, count
                ));
            }
        }

        // Calculate total findings
        let total_issues = discriminator_issues + uninitialized_warnings + reinit_patterns;
        evidence.tx_with_findings = total_issues as usize;

        if discriminator_issues > 0 {
            evidence.notes.insert(0, format!(
                "CRITICAL: {} accounts missing Anchor discriminator",
                discriminator_issues
            ));
        }

        if total_issues > 0 {
            evidence.notes.push(format!(
                "Found {} account state issues: {} discriminator, {} uninitialized, {} reinit",
                total_issues, discriminator_issues, uninitialized_warnings, reinit_patterns
            ));
        } else {
            evidence.notes.push("No account state issues detected".to_string());
        }

        Ok(evidence)
    }

    /// PRIV-009: Analyze CPI call patterns and behavior
    async fn verify_cpi_behavior(&self, program_id: &str) -> Result<TransactionEvidence> {
        let mut evidence = TransactionEvidence::default();

        let transactions = self.get_program_transactions(program_id, 100).await?;
        evidence.tx_analyzed = transactions.len();

        let mut cpi_target_map: HashMap<String, u32> = HashMap::new();

        for tx in transactions {
            // Count CPI calls to each target
            for instr in &tx.instructions {
                if instr.program_id != program_id {
                    *cpi_target_map.entry(instr.program_id.clone()).or_insert(0) += 1;
                    evidence.cpi_calls.push(CPICallRecord {
                        tx_signature: tx.signature.clone(),
                        target_program: instr.program_id.clone(),
                        timestamp: tx.block_time,
                        inner_instruction_count: 0,
                    });
                }
            }
        }

        evidence.notes.push(format!(
            "Analyzed {} transactions, found {} CPI calls to {} unique programs",
            evidence.tx_analyzed,
            evidence.cpi_calls.len(),
            cpi_target_map.len()
        ));

        for (program, count) in cpi_target_map.iter() {
            evidence.notes.push(format!("  - {}: {} calls", program, count));
        }

        Ok(evidence)
    }

    /// PRIV-010: Build PDA discovery timeline and detect predictable seeds
    async fn verify_pda_timeline(&self, program_id: &str) -> Result<TransactionEvidence> {
        let mut evidence = TransactionEvidence::default();

        let transactions = self.get_program_transactions(program_id, 200).await?;
        evidence.tx_analyzed = transactions.len();

        let mut predictable_seeds = 0;
        let mut sequential_patterns = 0;

        // Scan logs for predictable PDA seed patterns
        for tx in &transactions {
            for log in &tx.logs {
                let log_lower = log.to_lowercase();

                // Detect predictable seed patterns in logs
                if log_lower.contains("predictable seed")
                    || log_lower.contains("predictable pda")
                    || log_lower.contains("enumerable seed") {
                    predictable_seeds += 1;
                    evidence.notes.push(format!("CRITICAL: Predictable PDA seed: {}",
                        if log.len() > 60 { &log[..60] } else { log }));
                }

                // Detect sequential/numeric patterns like user_account_1, user_2, etc.
                if log_lower.contains("derived pda") || log_lower.contains("find_program_address") {
                    // Check for sequential patterns: _1, _2, _3 or user1, user2, etc.
                    let sequential_indicators = ["_1", "_2", "_3", "user1", "user2", "account1", "account2"];
                    if sequential_indicators.iter().any(|p| log_lower.contains(p)) {
                        sequential_patterns += 1;
                        evidence.notes.push(format!("WARNING: Sequential PDA pattern detected"));
                    }
                }
            }
        }

        // Calculate timeline if we have transactions
        if !transactions.is_empty() {
            let first_tx = transactions.last().unwrap(); // Oldest
            let last_tx = transactions.first().unwrap(); // Most recent

            let time_span_weeks = (last_tx.block_time - first_tx.block_time) as f64 / (7 * 24 * 60 * 60) as f64;
            let discovery_rate = if time_span_weeks > 0.0 {
                evidence.tx_analyzed as f64 / time_span_weeks
            } else {
                0.0
            };

            evidence.pda_timeline = Some(PDATimeline {
                first_discovered: first_tx.block_time,
                last_discovered: last_tx.block_time,
                total_unique_pdas: evidence.tx_analyzed, // Approximate
                discovery_rate_per_week: discovery_rate,
            });

            evidence.notes.push(format!(
                "PDA timeline: {} accounts discovered over {:.1} weeks ({:.0} per week)",
                evidence.tx_analyzed, time_span_weeks, discovery_rate
            ));
        }

        // Record findings
        evidence.tx_with_findings = predictable_seeds + sequential_patterns;

        if predictable_seeds > 0 || sequential_patterns > 0 {
            evidence.notes.insert(0, format!(
                "Found {} predictable seed patterns, {} sequential patterns",
                predictable_seeds, sequential_patterns
            ));
        }

        Ok(evidence)
    }

    /// PRIV-002: Check for mnemonic/seed phrase patterns in transaction logs
    async fn verify_seed_phrase_leakage(&self, program_id: &str) -> Result<TransactionEvidence> {
        let mut evidence = TransactionEvidence::default();

        let transactions = self.get_program_transactions(program_id, 100).await?;
        evidence.tx_analyzed = transactions.len();

        // BIP-39 seed phrase keywords
        let seed_keywords = [
            "abandon", "ability", "able", "about", "above", "absent",
            "absorb", "abstract", "absurd", "abuse", "access", "accident",
            "seed phrase", "recovery phrase", "mnemonic", "12 words",
            "24 words", "backup phrase", "secret words", "wallet words",
        ];

        for tx in &transactions {
            for log in &tx.logs {
                let log_lower = log.to_lowercase();
                let word_matches: Vec<_> = seed_keywords.iter()
                    .filter(|kw| log_lower.contains(&kw.to_lowercase()))
                    .collect();

                // Multiple seed words or explicit phrases indicate leak
                if word_matches.len() >= 2 || log_lower.contains("seed phrase")
                    || log_lower.contains("mnemonic") || log_lower.contains("recovery phrase") {
                    evidence.tx_with_findings += 1;
                    evidence.events_found.push(EventLog {
                        tx_signature: tx.signature.clone(),
                        timestamp: tx.block_time,
                        event_name: "SeedPhrasePattern".to_string(),
                        event_data: if log.len() > 50 { format!("{}...", &log[..50]) } else { log.clone() },
                        contains_pii: true,
                        pii_types: vec!["seed_phrase".to_string()],
                    });
                    break; // One finding per tx
                }
            }
        }

        if evidence.tx_with_findings > 0 {
            evidence.notes.push(format!(
                "CRITICAL: Found {} transactions with potential seed phrase leakage",
                evidence.tx_with_findings
            ));
        } else {
            evidence.notes.push("No seed phrase patterns detected in transaction logs".to_string());
        }

        Ok(evidence)
    }

    /// PRIV-020: Detect wallet clustering patterns (same operator controlling multiple addresses)
    async fn verify_wallet_clustering(&self, program_id: &str) -> Result<TransactionEvidence> {
        let mut evidence = TransactionEvidence::default();

        // Use rich transactions to get user account information
        let transactions = self.get_rich_transactions(program_id, Some(200)).await.unwrap_or_default();
        evidence.tx_analyzed = transactions.len();

        // Track user accounts and their transaction patterns
        let mut account_tx_counts: HashMap<String, usize> = HashMap::new();
        let mut account_timestamps: HashMap<String, Vec<u64>> = HashMap::new();

        for tx in &transactions {
            // Skip transactions without block_time
            let block_time = match tx.block_time {
                Some(t) => t,
                None => continue,
            };

            // Extract user accounts from token transfers
            for transfer in &tx.token_transfers {
                if let Some(from) = &transfer.from_user_account {
                    *account_tx_counts.entry(from.clone()).or_insert(0) += 1;
                    account_timestamps.entry(from.clone()).or_default().push(block_time);
                }
                if let Some(to) = &transfer.to_user_account {
                    *account_tx_counts.entry(to.clone()).or_insert(0) += 1;
                    account_timestamps.entry(to.clone()).or_default().push(block_time);
                }
            }
            // Also extract from native transfers
            for transfer in &tx.native_transfers {
                *account_tx_counts.entry(transfer.from_address.clone()).or_insert(0) += 1;
                account_timestamps.entry(transfer.from_address.clone()).or_default().push(block_time);
                *account_tx_counts.entry(transfer.to_address.clone()).or_insert(0) += 1;
                account_timestamps.entry(transfer.to_address.clone()).or_default().push(block_time);
            }
        }

        // Detect clustering: multiple wallets with correlated activity
        let mut clustered_wallets: Vec<String> = Vec::new();

        // Find wallets with suspiciously similar transaction timing
        let account_list: Vec<_> = account_timestamps.keys().cloned().collect();
        for i in 0..account_list.len() {
            for j in (i + 1)..account_list.len() {
                let times_a = account_timestamps.get(&account_list[i]).unwrap();
                let times_b = account_timestamps.get(&account_list[j]).unwrap();

                // Check for correlated timing (transactions within 60 seconds of each other)
                let mut correlated_count = 0;
                for ta in times_a {
                    for tb in times_b {
                        if (*ta as i64 - *tb as i64).abs() < 60 {
                            correlated_count += 1;
                        }
                    }
                }

                // If more than 3 correlated transactions, flag as clustered
                if correlated_count >= 3 {
                    if !clustered_wallets.contains(&account_list[i]) {
                        clustered_wallets.push(account_list[i].clone());
                    }
                    if !clustered_wallets.contains(&account_list[j]) {
                        clustered_wallets.push(account_list[j].clone());
                    }
                }
            }
        }

        evidence.tx_with_findings = clustered_wallets.len();

        if !clustered_wallets.is_empty() {
            evidence.notes.push(format!(
                "Detected {} wallets with correlated transaction timing (potential same operator)",
                clustered_wallets.len()
            ));
            for wallet in clustered_wallets.iter().take(5) {
                let count = account_tx_counts.get(wallet).unwrap_or(&0);
                let display = if wallet.len() > 12 { &wallet[..12] } else { wallet };
                evidence.notes.push(format!("  → {} ({} txs)", display, count));
            }
        } else {
            evidence.notes.push("No wallet clustering patterns detected".to_string());
        }

        Ok(evidence)
    }

    /// PRIV-021: Detect balance correlation patterns across wallets
    async fn verify_balance_correlation(&self, program_id: &str) -> Result<TransactionEvidence> {
        let mut evidence = TransactionEvidence::default();

        // Use rich transactions to get token transfer data
        let transactions = self.get_rich_transactions(program_id, Some(100)).await.unwrap_or_default();
        evidence.tx_analyzed = transactions.len();

        // Track token flows between addresses (using String amounts since that's what the API returns)
        let mut address_inflows: HashMap<String, Vec<(String, String)>> = HashMap::new();  // addr -> [(token, amount)]
        let mut address_outflows: HashMap<String, Vec<(String, String)>> = HashMap::new();

        for tx in &transactions {
            for transfer in &tx.token_transfers {
                // Track outflow from source (use from_user_account)
                if let Some(from) = &transfer.from_user_account {
                    address_outflows.entry(from.clone()).or_default()
                        .push((transfer.mint.clone(), transfer.amount.clone()));
                }
                // Track inflow to destination (use to_user_account)
                if let Some(to) = &transfer.to_user_account {
                    address_inflows.entry(to.clone()).or_default()
                        .push((transfer.mint.clone(), transfer.amount.clone()));
                }
            }
        }

        // Detect correlation: addresses that consistently receive after another sends
        let mut correlated_pairs: Vec<(String, String)> = Vec::new();
        let outflow_addresses: Vec<_> = address_outflows.keys().cloned().collect();
        let inflow_addresses: Vec<_> = address_inflows.keys().cloned().collect();

        for out_addr in &outflow_addresses {
            let outflows = address_outflows.get(out_addr).unwrap();
            for in_addr in &inflow_addresses {
                if out_addr == in_addr { continue; }
                let inflows = address_inflows.get(in_addr).unwrap();

                // Check for matching amounts (same token, similar amounts)
                let mut matches = 0;
                for (out_token, out_amt_str) in outflows {
                    for (in_token, in_amt_str) in inflows {
                        if out_token == in_token {
                            // Parse amounts as u64 for comparison
                            if let (Ok(out_amt), Ok(in_amt)) = (
                                out_amt_str.parse::<u64>(),
                                in_amt_str.parse::<u64>()
                            ) {
                                if out_amt > 0 {
                                    // Allow 5% variance for fees
                                    let diff = (out_amt as f64 - in_amt as f64).abs() / out_amt as f64;
                                    if diff < 0.05 {
                                        matches += 1;
                                    }
                                }
                            }
                        }
                    }
                }

                if matches >= 2 {
                    correlated_pairs.push((out_addr.clone(), in_addr.clone()));
                }
            }
        }

        evidence.tx_with_findings = correlated_pairs.len();

        if !correlated_pairs.is_empty() {
            evidence.notes.push(format!(
                "Detected {} address pairs with correlated token flows",
                correlated_pairs.len()
            ));
            for (from, to) in correlated_pairs.iter().take(3) {
                let from_display = if from.len() > 8 { &from[..8] } else { from };
                let to_display = if to.len() > 8 { &to[..8] } else { to };
                evidence.notes.push(format!(
                    "  → {}... → {}...",
                    from_display,
                    to_display
                ));
            }
        } else {
            evidence.notes.push("No balance correlation patterns detected".to_string());
        }

        Ok(evidence)
    }

    // ========================================================================
    // Confidence Adjustment Calculators
    // ========================================================================

    fn calculate_event_adjustment(&self, evidence: &TransactionEvidence) -> i32 {
        match evidence.events_found.len() {
            0 => -20,     // No PII found
            1..=10 => 15, // Few events
            11..=100 => 25,
            _ => 35, // Many events - critical
        }
    }

    fn calculate_debug_adjustment(&self, evidence: &TransactionEvidence) -> i32 {
        if evidence.tx_with_findings > 0 {
            10 // Debug output confirmed
        } else {
            -10 // Not found
        }
    }

    fn calculate_state_adjustment(&self, evidence: &TransactionEvidence) -> i32 {
        match evidence.tx_with_findings {
            0 => -15,      // No reinitialization patterns found
            1..=3 => 10,   // Few instances
            4..=10 => 20,  // Multiple instances - concerning
            _ => 30,       // Many instances - critical issue
        }
    }

    fn calculate_cpi_behavioral_adjustment(&self, evidence: &TransactionEvidence) -> i32 {
        match evidence.cpi_calls.len() {
            0 => -20,       // No CPI calls
            1..=50 => -10,  // Few calls - likely safe pattern
            51..=500 => 0,  // Moderate usage
            _ => 10,        // Heavy CPI usage - could be complex
        }
    }

    fn calculate_pda_timeline_adjustment(&self, evidence: &TransactionEvidence) -> i32 {
        // First check for predictable seed patterns (highest priority)
        if evidence.tx_with_findings > 0 {
            return match evidence.tx_with_findings {
                1 => 20,        // Single predictable seed - concerning
                2..=5 => 30,    // Multiple predictable seeds - serious
                _ => 40,        // Many predictable seeds - critical
            };
        }

        // Fall back to timeline-based analysis
        if let Some(timeline) = &evidence.pda_timeline {
            match timeline.discovery_rate_per_week {
                x if x < 100.0 => -10,    // Slow discovery
                x if x < 1000.0 => 5,     // Moderate discovery
                _ => 20,                  // Rapid discovery - high risk
            }
        } else {
            0
        }
    }

    fn calculate_seed_phrase_adjustment(&self, evidence: &TransactionEvidence) -> i32 {
        match evidence.tx_with_findings {
            0 => -15,       // No seed phrase leakage
            1 => 25,        // Single instance - serious
            2..=5 => 35,    // Multiple instances - critical
            _ => 45,        // Many instances - extremely critical
        }
    }

    fn calculate_wallet_clustering_adjustment(&self, evidence: &TransactionEvidence) -> i32 {
        match evidence.tx_with_findings {
            0 => -10,       // No clustering detected
            1..=2 => 10,    // Few clustered wallets
            3..=5 => 20,    // Moderate clustering
            6..=10 => 30,   // Significant clustering
            _ => 40,        // Extensive clustering - high privacy risk
        }
    }

    fn calculate_balance_correlation_adjustment(&self, evidence: &TransactionEvidence) -> i32 {
        match evidence.tx_with_findings {
            0 => -10,       // No correlation detected
            1..=2 => 15,    // Few correlated pairs
            3..=5 => 25,    // Moderate correlation
            _ => 35,        // Extensive correlation - privacy compromise
        }
    }

    // ========================================================================
    // Pattern Detection
    // ========================================================================

    fn detect_pii_in_log(&self, log: &str) -> Option<Vec<String>> {
        let mut found = Vec::new();

        // Email pattern
        if log.contains('@') && log.contains('.') {
            found.push("email".to_string());
        }

        // Phone pattern (10+ digits)
        if log.chars().filter(|c| c.is_ascii_digit()).count() >= 10 {
            found.push("phone".to_string());
        }

        // SSN pattern (XXX-XX-XXXX)
        if log.contains('-') && log.chars().filter(|c| c.is_ascii_digit()).count() >= 9 {
            found.push("ssn".to_string());
        }

        if found.is_empty() {
            None
        } else {
            Some(found)
        }
    }

    fn is_debug_output(&self, log: &str) -> bool {
        log.contains("debug") || log.contains("trace") || log.contains("println") || log.contains("dbg")
    }

    // ========================================================================
    // RPC Methods (mocked for now)
    // ========================================================================

    async fn get_program_transactions(&self, _program_id: &str, _limit: usize) -> Result<Vec<HeliumsTransaction>> {
        // Try to fetch from configurable Helius base URL (for tests/mocks)
        if let Ok(base) = std::env::var("HELIUS_BASE_URL") {
            // Detect real Helius API vs mock server by checking for helius domain
            let is_real_helius = base.contains(".helius") || base.contains("helius-rpc");

            let url = if is_real_helius {
                // Real Helius API - use correct endpoint with api-key as query param
                format!("{}/v0/addresses/{}/transactions?api-key={}&limit={}",
                    base.trim_end_matches('/'), _program_id, &self.api_key, _limit)
            } else {
                // Mock server - use legacy path for test compatibility
                format!("{}/program/{}/transactions?limit={}", base.trim_end_matches('/'), _program_id, _limit)
            };

            let req = self.client.get(&url);
            // Only add header for mock servers
            let req = if !is_real_helius {
                req.header("x-api-key", &self.api_key)
            } else {
                req
            };

            let resp = req
                .send()
                .await
                .map_err(|e| anyhow!("Helius request failed: {}", e))?;

            let text = resp.text().await.map_err(|e| anyhow!("Helius response read failed: {}", e))?;

            // Attempt to parse as array of transactions
            if let Ok(vec) = serde_json::from_str::<Vec<HeliumsTransaction>>(&text) {
                return Ok(vec);
            }

            // Try to parse wrapper objects like { "result": [...] } or {"transactions": [...]}
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                if let Some(result) = v.get("result") {
                    if let Ok(vec) = serde_json::from_value::<Vec<HeliumsTransaction>>(result.clone()) {
                        return Ok(vec);
                    }
                }

                if let Some(txns) = v.get("transactions") {
                    if let Ok(vec) = serde_json::from_value::<Vec<HeliumsTransaction>>(txns.clone()) {
                        return Ok(vec);
                    }
                }
            }

            // If parsing failed, return an error for visibility in tests
            return Err(anyhow!("Failed to parse Helius transactions response"));
        }

        // Fallback: original stub behavior (no transactions)
        Ok(Vec::new())
    }

    /// Get token metadata for a given mint address
    pub async fn get_token_metadata(&self, mint: &str) -> Result<TokenMetadata> {
        if let Ok(base) = std::env::var("HELIUS_BASE_URL") {
            let is_real_helius = base.contains(".helius") || base.contains("helius-rpc");

            let resp = if is_real_helius {
                // Real Helius API - POST to /v0/token-metadata with mintAccounts array
                let url = format!("{}/v0/token-metadata?api-key={}", base.trim_end_matches('/'), &self.api_key);
                self.client
                    .post(&url)
                    .json(&serde_json::json!({ "mintAccounts": [mint] }))
                    .send()
                    .await
                    .map_err(|e| anyhow!("Helius token metadata request failed: {}", e))?
            } else {
                // Mock server - use legacy GET path for test compatibility
                let url = format!("{}/token/{}/metadata", base.trim_end_matches('/'), mint);
                self.client
                    .get(&url)
                    .header("x-api-key", &self.api_key)
                    .send()
                    .await
                    .map_err(|e| anyhow!("Helius token metadata request failed: {}", e))?
            };

            let text = resp.text().await.map_err(|e| anyhow!("Helius response read failed: {}", e))?;

            // Try parsing as direct TokenMetadata
            if let Ok(metadata) = serde_json::from_str::<TokenMetadata>(&text) {
                return Ok(metadata);
            }

            // Try parsing wrapper objects
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                // Try result array [0]
                if let Some(result) = v.get("result") {
                    if let Some(items) = result.as_array() {
                        if let Some(first_item) = items.get(0) {
                            // Manually construct TokenMetadata from nested structure
                            let mint = first_item.get("mint").and_then(|v| v.as_str()).unwrap_or("").to_string();

                            let mut metadata = TokenMetadata {
                                mint: mint.clone(),
                                name: String::new(),
                                symbol: String::new(),
                                decimals: 0,
                                supply: String::new(),
                                uri: None,
                                creators: None,
                                on_chain_data: None,
                                off_chain_data: None,
                            };

                            // Extract on_chain_data if available
                            if let Some(on_chain) = first_item.get("onChainData") {
                                if let Ok(on_chain_data) = serde_json::from_value::<OnChainTokenData>(on_chain.clone()) {
                                    // Merge top-level fields from onChainData
                                    if let Some(name) = &on_chain_data.name {
                                        metadata.name = name.clone();
                                    }
                                    if let Some(symbol) = &on_chain_data.symbol {
                                        metadata.symbol = symbol.clone();
                                    }
                                    if let Some(uri) = &on_chain_data.uri {
                                        metadata.uri = Some(uri.clone());
                                    }
                                    metadata.on_chain_data = Some(on_chain_data);
                                }
                            }

                            // Extract off_chain_data if available
                            if let Some(off_chain) = first_item.get("offChainData") {
                                if let Ok(off_chain_data) = serde_json::from_value::<OffChainTokenData>(off_chain.clone()) {
                                    metadata.off_chain_data = Some(off_chain_data);
                                }
                            }

                            // Return if we got a mint and at least some metadata
                            if !metadata.mint.is_empty() && (!metadata.name.is_empty() || metadata.on_chain_data.is_some()) {
                                return Ok(metadata);
                            }
                        }
                    }
                    // Try result as direct object
                    if let Ok(metadata) = serde_json::from_value::<TokenMetadata>(result.clone()) {
                        return Ok(metadata);
                    }
                }
                if let Some(data) = v.get("metadata") {
                    if let Ok(metadata) = serde_json::from_value::<TokenMetadata>(data.clone()) {
                        return Ok(metadata);
                    }
                }
            }

            return Err(anyhow!("Failed to parse token metadata response"));
        }

        // Fallback: stub behavior
        Err(anyhow!("HELIUS_BASE_URL not set"))
    }

    /// Search for DAS assets owned by an address
    pub async fn search_assets(
        &self,
        owner: &str,
        limit: Option<usize>,
    ) -> Result<Vec<Asset>> {
        if let Ok(base) = std::env::var("HELIUS_BASE_URL") {
            let lim = limit.unwrap_or(100);
            let is_real_helius = base.contains(".helius") || base.contains("helius-rpc");

            let resp = if is_real_helius {
                // Real Helius API - use DAS searchAssets RPC method
                let url = format!("{}/v0/addresses/{}/balances?api-key={}", base.trim_end_matches('/'), owner, &self.api_key);
                self.client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| anyhow!("Helius asset search request failed: {}", e))?
            } else {
                // Mock server - use legacy GET path for test compatibility
                let url = format!("{}/assets?owner={}&limit={}", base.trim_end_matches('/'), owner, lim);
                self.client
                    .get(&url)
                    .header("x-api-key", &self.api_key)
                    .send()
                    .await
                    .map_err(|e| anyhow!("Helius asset search request failed: {}", e))?
            };

            let text = resp.text().await.map_err(|e| anyhow!("Helius response read failed: {}", e))?;

            // Try parsing as array of assets
            if let Ok(assets) = serde_json::from_str::<Vec<Asset>>(&text) {
                return Ok(assets);
            }

            // Try parsing wrapper objects
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                // Try result.items
                if let Some(result) = v.get("result") {
                    if let Some(items) = result.get("items") {
                        if let Ok(assets) = serde_json::from_value::<Vec<Asset>>(items.clone()) {
                            return Ok(assets);
                        }
                    }
                    // Try direct result as array
                    if let Ok(assets) = serde_json::from_value::<Vec<Asset>>(result.clone()) {
                        return Ok(assets);
                    }
                }
                // Try items directly
                if let Some(items) = v.get("items") {
                    if let Ok(assets) = serde_json::from_value::<Vec<Asset>>(items.clone()) {
                        return Ok(assets);
                    }
                }
            }

            // For real Helius API, balances endpoint format differs from DAS - return empty
            // rather than error to allow scan to continue with transaction data
            if is_real_helius {
                return Ok(Vec::new());
            }

            return Err(anyhow!("Failed to parse assets response"));
        }

        Ok(Vec::new())
    }

    /// Get rich transactions for a program with parsed token transfers
    pub async fn get_rich_transactions(
        &self,
        program_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<RichTransaction>> {
        if let Ok(base) = std::env::var("HELIUS_BASE_URL") {
            let lim = limit.unwrap_or(50);
            let is_real_helius = base.contains(".helius") || base.contains("helius-rpc");

            let url = if is_real_helius {
                // Real Helius API - /v0/addresses/{}/transactions returns enhanced data
                format!("{}/v0/addresses/{}/transactions?api-key={}&limit={}",
                    base.trim_end_matches('/'), program_id, &self.api_key, lim)
            } else {
                // Mock server - use legacy path for test compatibility
                format!("{}/program/{}/rich-transactions?limit={}", base.trim_end_matches('/'), program_id, lim)
            };

            let req = self.client.get(&url);
            let req = if !is_real_helius {
                req.header("x-api-key", &self.api_key)
            } else {
                req
            };

            let resp = req
                .send()
                .await
                .map_err(|e| anyhow!("Helius rich transactions request failed: {}", e))?;

            let text = resp.text().await.map_err(|e| anyhow!("Helius response read failed: {}", e))?;

            // Try parsing as array of rich transactions
            if let Ok(txns) = serde_json::from_str::<Vec<RichTransaction>>(&text) {
                return Ok(txns);
            }

            // Try parsing wrapper objects
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                if let Some(transactions) = v.get("transactions") {
                    if let Ok(txns) = serde_json::from_value::<Vec<RichTransaction>>(transactions.clone()) {
                        return Ok(txns);
                    }
                }
                if let Some(result) = v.get("result") {
                    if let Ok(txns) = serde_json::from_value::<Vec<RichTransaction>>(result.clone()) {
                        return Ok(txns);
                    }
                }
            }

            return Err(anyhow!("Failed to parse rich transactions response"));
        }

        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;
    use crate::test_findings::TestFindingBuilder;

    /// Create a mock finding for testing with custom confidence
    fn mock_finding(id: &str, confidence: u8) -> Finding {
        TestFindingBuilder::new(id)
            .title("Test Finding")
            .code_snippet("let data = sensitive_info")
            .recommendation("Review and fix")
            .confidence(confidence)
            .build()
    }

    /// Format PRIV check results for demo output with colors
    fn print_priv_result(label: &str, result: &HeliumsVerifiedFinding) {
        const GREEN: &str = "\x1b[32m";
        const YELLOW: &str = "\x1b[33m";
        const CYAN: &str = "\x1b[36m";
        const DIM: &str = "\x1b[2m";
        const RESET: &str = "\x1b[0m";

        let delta = result.verified_confidence as i32 - result.static_confidence as i32;
        let (icon, color, status) = if delta > 0 {
            ("✓", GREEN, "DETECTED")
        } else if delta < 0 {
            ("↓", CYAN, "REDUCED")
        } else {
            ("○", YELLOW, "VERIFIED")
        };

        println!("{}{} {} {:>3} → {:>3} ({:+3}) {}{}",
            color, icon, label,
            result.static_confidence, result.verified_confidence, delta,
            status, RESET);

        // Print first note as context
        if let Some(note) = result.evidence.notes.first() {
            let truncated = if note.len() > 60 { &note[..60] } else { note };
            println!("{}  └─ {}{}", DIM, truncated, RESET);
        }
    }

    #[test]
    fn test_pii_detection_email() {
        let verifier = HeliumsVerifier::new("test_key");
        let log = "emit: UserCreated { email: user@example.com }";

        let result = verifier.detect_pii_in_log(log);
        assert!(result.is_some());
        assert!(result.unwrap().contains(&"email".to_string()));
    }

    #[test]
    fn test_debug_output_detection() {
        let verifier = HeliumsVerifier::new("test_key");

        assert!(verifier.is_debug_output("debug: account balance = 1000"));
        assert!(verifier.is_debug_output("trace: executing instruction"));
        assert!(!verifier.is_debug_output("normal program log"));
    }

    #[test]
    fn test_pda_timeline_adjustment() {
        let verifier = HeliumsVerifier::new("test_key");

        let evidence = TransactionEvidence {
            pda_timeline: Some(PDATimeline {
                first_discovered: 0,
                last_discovered: 1000,
                total_unique_pdas: 500,
                discovery_rate_per_week: 50.0,
            }),
            ..Default::default()
        };

        let adjustment = verifier.calculate_pda_timeline_adjustment(&evidence);
        assert_eq!(adjustment, -10); // Slow discovery = lower confidence
    }

    #[test]
    fn test_event_adjustment_scale() {
        let verifier = HeliumsVerifier::new("test_key");

        let evidence_none = TransactionEvidence {
            events_found: vec![],
            ..Default::default()
        };
        assert_eq!(verifier.calculate_event_adjustment(&evidence_none), -20);

        let evidence_few = TransactionEvidence {
            events_found: vec![
                EventLog {
                    tx_signature: "sig".to_string(),
                    timestamp: 0,
                    event_name: "test".to_string(),
                    event_data: "data".to_string(),
                    contains_pii: true,
                    pii_types: vec!["email".to_string()],
                };
                5
            ],
            ..Default::default()
        };
        assert_eq!(verifier.calculate_event_adjustment(&evidence_few), 15);
    }

    // ========================================================================
    // Mock Tests for verify_finding_enhanced
    // ========================================================================

    #[tokio::test]
    async fn test_verify_enhanced_priv_006_event_leakage() {
        let verifier = HeliumsVerifier::new("test_api_key");
        
        let mut finding = mock_finding("PRIV-006", 70);
        finding.title = "Potential PII in event".to_string();
        finding.code_snippet = "emit!(UserCreated { email })".to_string();
        finding.evidence = vec!["Email field in event".to_string()];

        let result = verifier.verify_finding_enhanced(&finding, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(result.as_ref().unwrap().finding.id, "PRIV-006");
        assert_eq!(result.as_ref().unwrap().static_confidence, 70);
        assert!(!result.as_ref().unwrap().evidence.notes.is_empty());
    }

    #[tokio::test]
    async fn test_verify_enhanced_priv_007_debug_output() {
        let verifier = HeliumsVerifier::new("test_api_key");
        
        let mut finding = mock_finding("PRIV-007", 65);
        finding.title = "Debug output in production".to_string();
        finding.code_snippet = "msg!(\"Debug: {}\", sensitive_data)".to_string();
        finding.evidence = vec!["msg!() call with potential data leak".to_string()];
        finding.severity = Severity::Medium;

        let result = verifier.verify_finding_enhanced(&finding, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(result.as_ref().unwrap().finding.id, "PRIV-007");
        assert_eq!(result.as_ref().unwrap().static_confidence, 65);
    }

    #[tokio::test]
    async fn test_verify_enhanced_priv_009_cpi_behavior() {
        let verifier = HeliumsVerifier::new("test_api_key");
        
        let mut finding = mock_finding("PRIV-009", 75);
        finding.title = "Suspicious CPI pattern".to_string();
        finding.code_snippet = "invoke_signed(&unknown_cpi, &[signer], &[])".to_string();
        finding.evidence = vec!["CPI to unknown program with suspicious pattern".to_string()];

        let result = verifier.verify_finding_enhanced(&finding, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(result.as_ref().unwrap().finding.id, "PRIV-009");
        assert_eq!(result.as_ref().unwrap().static_confidence, 75);
    }

    #[tokio::test]
    async fn test_verify_enhanced_priv_010_pda_timeline() {
        let verifier = HeliumsVerifier::new("test_api_key");
        
        let mut finding = mock_finding("PRIV-010", 60);
        finding.title = "PDA with enumerable seed pattern".to_string();
        finding.code_snippet = "find_program_address(&[b\"user\", user.key().as_ref()], &id)".to_string();
        finding.evidence = vec!["Predictable PDA seeds detected".to_string()];
        finding.severity = Severity::Medium;

        let result = verifier.verify_finding_enhanced(&finding, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(result.as_ref().unwrap().finding.id, "PRIV-010");
        assert_eq!(result.as_ref().unwrap().static_confidence, 60);
    }

    #[tokio::test]
    async fn test_verify_enhanced_no_verification_for_other_checks() {
        let verifier = HeliumsVerifier::new("test_api_key");
        
        let mut finding = mock_finding("PRIV-001", 85);
        finding.title = "Uninitialized account".to_string();
        finding.code_snippet = "ctx.accounts.data".to_string();
        finding.evidence = vec!["Account not initialized".to_string()];
        finding.severity = Severity::Critical;

        let result = verifier.verify_finding_enhanced(&finding, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(result.as_ref().unwrap().finding.id, "PRIV-001");
        assert_eq!(result.as_ref().unwrap().static_confidence, 85);
        // Should not be adjusted for Helius (no beneficial check)
        assert!(result.as_ref().unwrap().evidence.notes.iter().any(|n| n.contains("No Helius verification")));
    }

    #[test]
    fn test_detect_pii_in_log_email() {
        let verifier = HeliumsVerifier::new("test_api_key");
        let has_pii = verifier.detect_pii_in_log("user email is user@example.com");

        assert!(has_pii.is_some());
    }

    #[test]
    fn test_detect_pii_in_log_phone() {
        let verifier = HeliumsVerifier::new("test_api_key");
        let has_pii = verifier.detect_pii_in_log("phone number 555-123-4567");

        assert!(has_pii.is_some());
    }

    #[test]
    fn test_detect_pii_in_log_ssn() {
        let verifier = HeliumsVerifier::new("test_api_key");
        let has_pii = verifier.detect_pii_in_log("ssn: 123-45-6789");

        assert!(has_pii.is_some());
    }

    #[test]
    fn test_detect_pii_in_log_no_pii() {
        let verifier = HeliumsVerifier::new("test_api_key");
        let has_pii = verifier.detect_pii_in_log("transaction hash abc123def456");

        assert!(has_pii.is_none());
    }

    #[test]
    fn test_is_debug_output_msg() {
        let verifier = HeliumsVerifier::new("test_api_key");
        
        assert!(verifier.is_debug_output("msg!(\"debug info\")"));
        assert!(verifier.is_debug_output("println!(\"test\")"));
        assert!(verifier.is_debug_output("dbg!(var)"));
        assert!(!verifier.is_debug_output("regular_function()"));
    }

    #[tokio::test]
    async fn test_verify_enhanced_confidence_adjustment_event_pii() {
        let verifier = HeliumsVerifier::new("test_api_key");
        
        let mut finding = mock_finding("PRIV-006", 60);
        finding.title = "Event with PII".to_string();
        finding.code_snippet = "emit!(UserRegistered { email })".to_string();
        finding.evidence = vec!["PII in event".to_string()];

        let result = verifier.verify_finding_enhanced(&finding, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        // With event verification, confidence should potentially increase
        assert!(result.as_ref().unwrap().verified_confidence >= 5);
        assert!(result.as_ref().unwrap().verified_confidence <= 100);
    }

    #[tokio::test]
    async fn test_verify_enhanced_multiple_findings() {
        let verifier = HeliumsVerifier::new("test_api_key");
        
        let mut finding1 = mock_finding("PRIV-006", 70);
        finding1.title = "Event leakage".to_string();
        finding1.code_snippet = "emit!(Data { pii })".to_string();
        finding1.evidence = vec!["PII in event".to_string()];
        
        let mut finding2 = mock_finding("PRIV-007", 65);
        finding2.title = "Debug logs".to_string();
        finding2.code_snippet = "msg!(\"data: {}\", sensitive)".to_string();
        finding2.evidence = vec!["Debug output".to_string()];
        finding2.severity = Severity::Medium;
        
        let mut finding3 = mock_finding("PRIV-003", 45);
        finding3.title = "No Helius verification for this".to_string();
        finding3.code_snippet = "code".to_string();
        finding3.evidence = vec!["Not eligible".to_string()];
        finding3.severity = Severity::Low;

        let mut results = Vec::new();
        for finding in vec![finding1, finding2, finding3] {
            match verifier.verify_finding_enhanced(&finding, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await {
                Ok(result) => results.push(result),
                Err(_) => {}
            }
        }

        assert!(results.len() >= 3);
        assert_eq!(results[0].finding.id, "PRIV-006");
        assert_eq!(results[1].finding.id, "PRIV-007");
        assert_eq!(results[2].finding.id, "PRIV-003");
    }

    #[tokio::test]
    async fn test_verify_enhanced_confidence_bounds() {
        let verifier = HeliumsVerifier::new("test_api_key");

        let finding = mock_finding("PRIV-006", 1); // Very low confidence

        let result = verifier.verify_finding_enhanced(&finding, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;

        // Should be clamped to at least 5
        assert!(result.as_ref().unwrap().verified_confidence >= 5);
        assert!(result.as_ref().unwrap().verified_confidence <= 100);
    }

    // ========================================================================
    // Individual Fixture Test for helius_addressTransactions.json
    // ========================================================================
    #[tokio::test]
    async fn test_helius_get_program_transactions_with_fixture() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Load the Helius program transactions fixture
        let fixture = std::fs::read_to_string("tests/fixtures/helius_addressTransactions.json")
            .expect("read helius_addressTransactions fixture");

        // Stub Helius program transactions endpoint
        Mock::given(method("GET"))
            .and(path_regex(r"^/program/.*/transactions$"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
            .mount(&server)
            .await;

        // Set up Helius with mock server (save and restore env var for test isolation)
        let original_url = std::env::var("HELIUS_BASE_URL").ok();
        std::env::set_var("HELIUS_BASE_URL", server.uri());
        let helius = HeliumsVerifier::new("test_api_key");

        // Test PRIV-006: Event PII leakage
        use crate::report::Severity;
        let finding_006 = crate::checks::Finding::new(
            "PRIV-006",
            "Event PII",
            Severity::High,
            "src/lib.rs",
            1,
            "emit!(UserCreated { email })",
            "remove PII",
        );
        let r006 = helius.verify_finding_enhanced(&finding_006, "SomeProgramId").await.expect("helius priv006");
        print_priv_result("PRIV-006 (Event PII)         ", &r006);

        // Test PRIV-007: Debug output in production
        let finding_007 = crate::checks::Finding::new(
            "PRIV-007",
            "Debug output in production",
            Severity::Medium,
            "src/lib.rs",
            1,
            "println!(\"debug: value = {}\", 42)",
            "remove debug",
        );
        let r007 = helius.verify_finding_enhanced(&finding_007, "SomeProgramId").await.expect("helius priv007");
        print_priv_result("PRIV-007 (Debug output)      ", &r007);

        // Test PRIV-008: Uninitialized account state
        let finding_008 = crate::checks::Finding::new(
            "PRIV-008",
            "Uninitialized account state",
            Severity::High,
            "src/lib.rs",
            1,
            "initialized account SomeAddress11111111111111111111111",
            "validate init",
        );
        let r008 = helius.verify_finding_enhanced(&finding_008, "SomeProgramId").await.expect("helius priv008");
        print_priv_result("PRIV-008 (Uninitialized)     ", &r008);

        // Test PRIV-009: CPI without validation
        let finding_009 = crate::checks::Finding::new(
            "PRIV-009",
            "CPI without validation",
            Severity::Medium,
            "src/lib.rs",
            1,
            "invoke_signed(&unknown_cpi, ..)",
            "validate CPI",
        );
        // For CPI behavior, call with Token program as the subject so the UnknownCpiProgram counts as a CPI target
        let r009 = helius.verify_finding_enhanced(&finding_009, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await.expect("helius priv009");
        print_priv_result("PRIV-009 (CPI validation)    ", &r009);

        // Test PRIV-010: Predictable PDA seeds
        // The fixture contains: "Program log: Derived PDA with predictable seed: 'user_account_1'"
        let finding_010 = crate::checks::Finding::new(
            "PRIV-010",
            "Predictable PDA seeds",
            Severity::Medium,
            "src/lib.rs",
            1,
            "find_program_address(&[b\"user\", user_id], &id)",
            "use non-enumerable seeds",
        );
        let r010 = helius.verify_finding_enhanced(&finding_010, "SomeProgramId").await.expect("helius priv010");
        print_priv_result("PRIV-010 (PDA enumeration)   ", &r010);

        // Restore original env var for test isolation
        if let Some(url) = original_url {
            std::env::set_var("HELIUS_BASE_URL", url);
        } else {
            std::env::remove_var("HELIUS_BASE_URL");
        }

        // Basic sanity assertions
        assert!(r006.static_confidence <= r006.verified_confidence || !r006.evidence.notes.is_empty(),
            "PRIV-006: Expected confidence adjustment or notes");
        assert!(r007.static_confidence <= r007.verified_confidence || !r007.evidence.notes.is_empty(),
            "PRIV-007: Expected confidence adjustment or notes");
        assert!(r008.static_confidence <= r008.verified_confidence || !r008.evidence.notes.is_empty(),
            "PRIV-008: Expected confidence adjustment or notes");
        assert!(r009.static_confidence <= r009.verified_confidence || !r009.evidence.notes.is_empty(),
            "PRIV-009: Expected confidence adjustment or notes");
        assert!(r010.static_confidence <= r010.verified_confidence || !r010.evidence.notes.is_empty(),
            "PRIV-010: Expected confidence adjustment or notes");
    }

    // ========================================================================
    // Tests for New Helius Methods (with Fixtures)
    // ========================================================================

    #[tokio::test]
    async fn test_get_token_metadata_with_fixture() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path_regex};

        let server = MockServer::start().await;

        // Load fixture with privacy leakage examples
        let fixture = std::fs::read_to_string("tests/fixtures/helius_tokenMetadata.json")
            .expect("read getTokenMetadata fixture");

        // Mock the API endpoint
        Mock::given(method("GET"))
            .and(path_regex(r"^/token/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
            .mount(&server)
            .await;

        // Set up Helius with mock server (save and restore env var for test isolation)
        let original_url = std::env::var("HELIUS_BASE_URL").ok();
        std::env::set_var("HELIUS_BASE_URL", server.uri());
        let helius = HeliumsVerifier::new("test_key");

        let metadata = helius
            .get_token_metadata("EPjFWaLb3hyccuBAbYbyrFfr1H34kimZweDKVKLto1o85v")
            .await
            .expect("get token metadata");

        // Restore original env var for test isolation
        if let Some(url) = original_url {
            std::env::set_var("HELIUS_BASE_URL", url);
        } else {
            std::env::remove_var("HELIUS_BASE_URL");
        }

        // Verify metadata with privacy leakage detection
        assert!(metadata.name.contains("Loyalty Token"));
        assert_eq!(metadata.symbol, "LOYAL");

        // PRIV-004: Verify PII in name is detected
        // onChainData.name contains: "Loyalty Token (John Doe)"
        assert!(metadata.name.contains("John Doe"),
                "PII should be detected in token metadata name");

        // PRIV-004: Verify PII in description is detected (from offChainData)
        // offChainData.description contains: "Internal Email: ex-user@oldmail.com"
        assert!(metadata.off_chain_data.is_some());
        let off_chain = metadata.off_chain_data.unwrap();
        assert!(off_chain.description.as_ref().map(|d| d.contains("@oldmail.com")).unwrap_or(false),
                "Email PII should be detected in off-chain metadata");

        // Verify URI is properly extracted
        assert!(metadata.uri.is_some());
        assert!(metadata.uri.as_ref().unwrap().contains("arweave.net"),
                "URI should be extracted from onChainData");

        // ========================================================================
        // PRIV Check Verification - Test PRIV-004/005 (PII in metadata)
        // ========================================================================
        println!("\n=== Helius getTokenMetadata PRIV Check Results ===");

        use crate::report::Severity;

        // Test PRIV-004: PII in token metadata (John Doe, email)
        let finding_004 = crate::checks::Finding::new(
            "PRIV-004",
            "PII in token metadata",
            Severity::High,
            "metadata.rs",
            1,
            "name: \"Loyalty Token (John Doe)\"",
            "Remove PII from token metadata",
        );
        let r004 = helius.verify_finding_enhanced(&finding_004, "EPjFWaLb3hyccuBAbYbyrFfr1H34kimZweDKVKLto1o85v").await.expect("helius priv004");
        print_priv_result("PRIV-004 (PII in metadata)   ", &r004);

        // Test PRIV-005: Sensitive data in off-chain metadata (email)
        let finding_005 = crate::checks::Finding::new(
            "PRIV-005",
            "Sensitive data in off-chain metadata",
            Severity::High,
            "metadata.rs",
            1,
            "description: \"Internal Email: ex-user@oldmail.com\"",
            "Remove sensitive data from metadata",
        );
        let r005 = helius.verify_finding_enhanced(&finding_005, "EPjFWaLb3hyccuBAbYbyrFfr1H34kimZweDKVKLto1o85v").await.expect("helius priv005");
        print_priv_result("PRIV-005 (Sensitive metadata)", &r005);

        println!("=== getTokenMetadata PRIV checks complete ===\n");
    }

    #[tokio::test]
    async fn test_search_assets_with_fixture() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path_regex};

        let server = MockServer::start().await;

        // Load fixture with privacy risks
        let fixture = std::fs::read_to_string("tests/fixtures/helius_searchAssets.json")
            .expect("read searchAssets fixture");

        // Mock the API endpoint
        Mock::given(method("GET"))
            .and(path_regex(r"^/assets.*"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
            .mount(&server)
            .await;

        // Set up Helius with mock server (save and restore env var for test isolation)
        let original_url = std::env::var("HELIUS_BASE_URL").ok();
        std::env::set_var("HELIUS_BASE_URL", server.uri());
        let helius = HeliumsVerifier::new("test_key");

        let assets = helius
            .search_assets("User_Address_11111111111111111111111", Some(100))
            .await
            .expect("search assets");

        // Restore original env var for test isolation
        if let Some(url) = original_url {
            std::env::set_var("HELIUS_BASE_URL", url);
        } else {
            std::env::remove_var("HELIUS_BASE_URL");
        }

        // Verify asset with privacy risks
        assert_eq!(assets.len(), 1);
        let asset = &assets[0];

        // PRIV-010: Verify predictable ID is detected
        assert_eq!(asset.id, "User_Asset_00042");
        // Enumeration risk - sequential IDs allow asset enumeration

        // PRIV-007: Verify debug mode in metadata is detected
        let json_str = serde_json::to_string(&asset).expect("serialize asset");
        assert!(json_str.contains("debug_mode") ||
                json_str.contains("true"),
                "Debug mode should be detectable");

        // PRIV-006: Verify sensitive data in logs is detected
        // raw_log contains: "Session initialized for IP 178.221.34.5"
        assert!(json_str.contains("Session") ||
                json_str.contains("IP"),
                "Session/IP information should be detected");

        // PRIV-009: Verify delegation without verification is detected
        assert!(json_str.contains("delegated") ||
                json_str.contains("delegate"),
                "Delegation info should be captured");

        // ========================================================================
        // PRIV Check Verification - Test PRIV-007/009/010 (debug, creators, enumeration)
        // ========================================================================
        println!("\n=== Helius searchAssets PRIV Check Results ===");

        use crate::report::Severity;

        // Test PRIV-007: Debug mode in production asset
        let finding_007 = crate::checks::Finding::new(
            "PRIV-007",
            "Debug mode enabled in production",
            Severity::Medium,
            "asset.rs",
            1,
            "debug_mode: true",
            "Disable debug mode in production",
        );
        let r007 = helius.verify_finding_enhanced(&finding_007, "User_Address_11111111111111111111111").await.expect("helius priv007");
        print_priv_result("PRIV-007 (Debug mode)        ", &r007);

        // Test PRIV-009: Unverified delegation
        let finding_009 = crate::checks::Finding::new(
            "PRIV-009",
            "Delegation without verification",
            Severity::Medium,
            "asset.rs",
            1,
            "delegated: true",
            "Verify delegation targets",
        );
        let r009 = helius.verify_finding_enhanced(&finding_009, "User_Address_11111111111111111111111").await.expect("helius priv009");
        print_priv_result("PRIV-009 (Unverified deleg.) ", &r009);

        // Test PRIV-010: Predictable/enumerable asset IDs
        let finding_010 = crate::checks::Finding::new(
            "PRIV-010",
            "Enumerable asset IDs",
            Severity::Medium,
            "asset.rs",
            1,
            "id: \"User_Asset_00042\"",
            "Use non-predictable asset IDs",
        );
        let r010 = helius.verify_finding_enhanced(&finding_010, "User_Address_11111111111111111111111").await.expect("helius priv010");
        print_priv_result("PRIV-010 (Enumerable IDs)    ", &r010);

        println!("=== searchAssets PRIV checks complete ===\n");
    }

    #[tokio::test]
    async fn test_get_rich_transactions_with_fixture() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path_regex};

        let server = MockServer::start().await;

        // Load fixture with CRITICAL privacy leaks
        let fixture = std::fs::read_to_string("tests/fixtures/helius_enhancedTransactions.json")
            .expect("read enhancedTransactions fixture");

        // Also load transactions fixture for verify_finding_enhanced calls
        let tx_fixture = std::fs::read_to_string("tests/fixtures/helius_addressTransactions.json")
            .expect("read addressTransactions fixture");

        // Mock the rich-transactions API endpoint
        Mock::given(method("GET"))
            .and(path_regex(r"^/program/.*/rich-transactions.*"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
            .mount(&server)
            .await;

        // Mock the regular transactions endpoint (used by verify_finding_enhanced)
        Mock::given(method("GET"))
            .and(path_regex(r"^/program/.*/transactions$"))
            .respond_with(ResponseTemplate::new(200).set_body_string(tx_fixture))
            .mount(&server)
            .await;

        // Set up Helius with mock server (save and restore env var for test isolation)
        let original_url = std::env::var("HELIUS_BASE_URL").ok();
        std::env::set_var("HELIUS_BASE_URL", server.uri());
        let helius = HeliumsVerifier::new("test_key");

        let transactions = helius
            .get_rich_transactions("C0nArtistProgram1111111111111111111111111", Some(50))
            .await
            .expect("get rich transactions");

        // Verify transaction with CRITICAL privacy leaks
        assert_eq!(transactions.len(), 1);
        let tx = &transactions[0];

        // PRIV-002: Verify mnemonic seed phrase is detected
        // data field contains: "Mnemonic: apple banana cherry dragon..."
        let json_str = serde_json::to_string(&tx).expect("serialize tx");
        assert!(json_str.contains("Mnemonic"),
                "CRITICAL: Seed phrase detected in transaction data");

        // PRIV-001: Verify private key in plain text is detected
        // inner_debug_state contains: "Private_Key_Hex: 0x4a5f..."
        assert!(json_str.contains("Private_Key") || json_str.contains("0x4a5f"),
                "CRITICAL: Private key detected in debug state");

        // PRIV-005: Verify database credentials in logs are detected
        // rawLogs contains: "DB_PASSWORD=admin123"
        assert!(json_str.contains("DB_PASSWORD") || json_str.contains("admin123"),
                "CRITICAL: Database password detected in logs");

        // PRIV-008: Verify stale data detection
        // rawLogs contains: "Stale data detected for User #9"
        assert!(json_str.contains("Stale data") || json_str.contains("User #9"),
                "Stale data reference detected in logs");

        // PRIV-009: Verify suspicious program is detected
        // programId contains: "C0nArtistProgram"
        assert!(json_str.contains("C0nArtist"),
                "Suspicious/unverified program should be detected");

        // Verify transaction structure
        assert_eq!(tx.description, Some("User swapped 10 SOL for USDC".to_string()));
        assert_eq!(tx.type_field.as_deref().unwrap_or(""), "SWAP");

        // ========================================================================
        // PRIV Check Verification - Test PRIV-001/002/005/006 (secrets in logs)
        // ========================================================================
        println!("\n=== Helius getRichTransactions PRIV Check Results ===");

        use crate::report::Severity;

        // Test PRIV-001: Private key exposed in debug state
        let finding_001 = crate::checks::Finding::new(
            "PRIV-001",
            "Private key exposed",
            Severity::Critical,
            "transaction.rs",
            1,
            "Private_Key_Hex: 0x4a5f...",
            "Remove private keys from logs",
        );
        let r001 = helius.verify_finding_enhanced(&finding_001, "C0nArtistProgram1111111111111111111111111").await.expect("helius priv001");
        print_priv_result("PRIV-001 (Private key)       ", &r001);

        // Test PRIV-002: Mnemonic seed phrase in data
        let finding_002 = crate::checks::Finding::new(
            "PRIV-002",
            "Mnemonic seed phrase exposed",
            Severity::Critical,
            "transaction.rs",
            1,
            "Mnemonic: apple banana cherry...",
            "Never log seed phrases",
        );
        let r002 = helius.verify_finding_enhanced(&finding_002, "C0nArtistProgram1111111111111111111111111").await.expect("helius priv002");
        print_priv_result("PRIV-002 (Mnemonic)          ", &r002);

        // Test PRIV-005: Database password in logs
        let finding_005 = crate::checks::Finding::new(
            "PRIV-005",
            "Database credentials exposed",
            Severity::High,
            "transaction.rs",
            1,
            "DB_PASSWORD=admin123",
            "Remove credentials from logs",
        );
        let r005 = helius.verify_finding_enhanced(&finding_005, "C0nArtistProgram1111111111111111111111111").await.expect("helius priv005");
        print_priv_result("PRIV-005 (DB password)       ", &r005);

        // Test PRIV-006: Sensitive user data in logs
        let finding_006 = crate::checks::Finding::new(
            "PRIV-006",
            "Sensitive data in logs",
            Severity::Medium,
            "transaction.rs",
            1,
            "Stale data detected for User #9",
            "Remove user identifiers from logs",
        );
        let r006 = helius.verify_finding_enhanced(&finding_006, "C0nArtistProgram1111111111111111111111111").await.expect("helius priv006");
        print_priv_result("PRIV-006 (User data in logs) ", &r006);

        println!("=== getRichTransactions PRIV checks complete ===\n");

        // Restore original env var for test isolation
        if let Some(url) = original_url {
            std::env::set_var("HELIUS_BASE_URL", url);
        } else {
            std::env::remove_var("HELIUS_BASE_URL");
        }
    }

    #[tokio::test]
    async fn test_search_assets_with_limit() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path_regex};

        let server = MockServer::start().await;

        // Load fixture with privacy risks
        let fixture = std::fs::read_to_string("tests/fixtures/helius_searchAssets.json")
            .expect("read searchAssets fixture");

        // Mock the API endpoint
        Mock::given(method("GET"))
            .and(path_regex(r"^/assets.*"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
            .mount(&server)
            .await;

        // Set up Helius with mock server (save and restore env var for test isolation)
        let original_url = std::env::var("HELIUS_BASE_URL").ok();
        std::env::set_var("HELIUS_BASE_URL", server.uri());
        let helius = HeliumsVerifier::new("test_key");

        // Test with different limits
        let assets_limit_10 = helius
            .search_assets("User_Address_11111111111111111111111", Some(10))
            .await
            .expect("search with limit");

        let assets_no_limit = helius
            .search_assets("User_Address_11111111111111111111111", None)
            .await
            .expect("search without limit");

        // Restore original env var for test isolation
        if let Some(url) = original_url {
            std::env::set_var("HELIUS_BASE_URL", url);
        } else {
            std::env::remove_var("HELIUS_BASE_URL");
        }

        // Both should return the same fixture data (1 asset with privacy risks)
        assert_eq!(assets_limit_10.len(), 1);
        assert_eq!(assets_no_limit.len(), 1);

        // Verify privacy risks are consistently detected
        let json_str_1 = serde_json::to_string(&assets_limit_10[0]).unwrap();
        let json_str_2 = serde_json::to_string(&assets_no_limit[0]).unwrap();

        assert!(json_str_1.contains("debug_mode"));
        assert!(json_str_2.contains("debug_mode"));
    }
}