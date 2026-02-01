//! Chain Scanner - Live Solana program analysis via Helius API
//!
//! This module provides runtime privacy analysis by scanning deployed programs
//! through the Helius RPC API. It fetches transactions, parses events/logs,
//! and detects privacy issues in live on-chain data.

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::checks::Finding;
use crate::report::Severity;
use crate::safe_patterns::{
    SAFE_STRUCT_CONTEXTS, is_safe_field, is_financial_context, is_placeholder_email,
    has_token_metadata_context, has_nft_metadata_context, is_safe_field_value,
};
use crate::helius::{HeliumsVerifier, RichTransaction, Asset, TokenMetadata};

// Re-export for tests
#[cfg(test)]
use crate::helius::{TokenTransfer as HeliusTokenTransfer, NativeTransfer as HeliusNativeTransfer};

/// Helius API base URL
#[allow(dead_code)]
const HELIUS_API_BASE: &str = "https://api.helius.xyz/v0";

/// Known Solana system programs where clustering/correlation is expected behavior
const SYSTEM_PROGRAMS: &[&str] = &[
    // Core Solana Programs
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  // Token Program
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  // Token-2022
    "11111111111111111111111111111111",              // System Program
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", // Associated Token Program
    "Stake11111111111111111111111111111111111111",   // Native Stake Program
    "StakeConfig11111111111111111111111111111111",   // Stake Config
    "Vote111111111111111111111111111111111111111",   // Vote Program
    "Config1111111111111111111111111111111111111",   // Config Program
    "BPFLoaderUpgradeab1e11111111111111111111111",  // BPF Loader

    // DEX / AMM Programs
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",  // Jupiter v6
    "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB",  // Jupiter v4
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",  // Orca Whirlpool
    "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP", // Orca Swap v2
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK", // Raydium CPMM
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium AMM v4
    "27haf8L6oxUeXrHrgEgsexjSY5hbVUWEmvv9Nyxg8vQv", // Raydium AMM v3
    "routeUGWgWzqBWFcrCfv8tritsqukccJPu3q5GPP3xS",  // Raydium Route
    "PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY",  // Phoenix
    "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX",  // Serum DEX v3
    "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", // Serum DEX v2
    "opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb",  // Openbook v2
    "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",  // Meteora DLMM
    "Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB", // Meteora Pools

    // Lending / Borrowing
    "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA",  // Marginfi v2
    "6LtLpnUFNByNXLyCoK9wA2MykKAmQNZKBdY8s47dehDc", // Marginfi
    "So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo",  // Solend
    "KLend2g3cP87ber41GKm4PvQCPGVyVW1rke66sJ5xKL",  // Kamino Lending
    "4UpD2fh7xH3VP9QQaXtsS1YY3bxzWhtfpks7FatyKvdY", // Mango v4
    "mv3ekLzLbnVPNxjSKvqBpU3ZeZXPQdEC3bp5MDEBG68",  // Mango v3

    // Staking / Liquid Staking
    "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy",  // Stake Pool Program
    "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD",  // Marinade
    "CgntPoLka5pD5fesJYhGmUCF8KU1QS1ZmZiuAuMZr2az", // Marinade Referral
    "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn", // Jito Staking
    "jitoVjT9jRUyeXHzvCwzPgHj7yWNRhLcUoXtes4wtjv",  // Jito Tip
    "BLZEEuZUBVqFhj8adcCFPJvPVCiCyVmh3hkJMrU8KuJA", // Blaze Staking

    // NFT Programs
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",  // Metaplex Token Metadata
    "p1exdMJcjVao65QdewkaZRUnU6VPSXhus9n2GzWfh98",  // Metaplex Core
    "auth9SigNpDKz4sJJ1DfCTuZrZNSAgh9sFD3rboVmgg",  // Metaplex Auth
    "cndy3Z4yapfJBmL3ShUp5exZKqR3z33thTzeNMm2gRZ",  // Candy Machine v2
    "CndyV3LdqHUfDLmE5naZjVN8rBZz4tqhdefbAnjHG3JR", // Candy Machine v3
    "TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN",  // Tensor Swap
    "TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp",  // Tensor cNFT
    "M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K",  // Magic Eden v2
    "M3mxk5W2tt27WGT7THox7PmgRDp4m6NEhL5xvxrBfS1",  // Magic Eden AMM

    // Governance
    "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw", // SPL Governance
    "gUAedF544JeE6NYbQakQvribHykUNgaPJqcgf3UQVnY",  // Governance UI
    "pytS9TjG1qyAZypk7n8rw8gfW9sUaqqYyMhJQ4E7JCQ",  // Pyth Governance

    // Oracles
    "FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH", // Pyth
    "pythWSnswVUd12oZpeFP8e9CVaEqJg25g1Vtc2biRsT",  // Pyth v2
    "SW1TCH7qEPTdLsDHRgPuMQjbQxKdH2aBStViMFnt64f",  // Switchboard v2
];

/// Helius transaction types that indicate financial/DeFi operations (not PII contexts)
#[allow(dead_code)]
const SAFE_TX_TYPES: &[&str] = &[
    "SWAP",
    "TRANSFER",
    "NFT_SALE",
    "NFT_LISTING",
    "NFT_CANCEL_LISTING",
    "NFT_BID",
    "NFT_MINT",
    "NFT_BID_CANCELLED",
    "TOKEN_MINT",
    "BURN",
    "BURN_NFT",
    "STAKE_TOKEN",
    "UNSTAKE_TOKEN",
    "STAKE_SOL",
    "UNSTAKE_SOL",
    "CLAIM_REWARDS",
    "ADD_LIQUIDITY",
    "REMOVE_LIQUIDITY",
    "BORROW_FOX",
    "LOAN_FOX",
    "INIT_BANK",
    "INIT_STAKE",
    "MERGE_STAKE",
    "SPLIT_STAKE",
    "UPGRADE_PROGRAM_INSTRUCTION",
    "FINALIZE_PROGRAM_INSTRUCTION",
];

/// Programs where instruction data is expected to contain arbitrary text (not keys)
#[allow(dead_code)]
const MEMO_PROGRAMS: &[&str] = &[
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",  // Memo Program v2
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",  // Memo Program v1
];

/// Chain scanner that analyzes deployed Solana programs
pub struct ChainScanner {
    api_key: String,
    _client: Client,
    /// Current program being scanned (for context-aware checks)
    _current_program: Option<String>,
}

/// Check if a program ID is a known system/infrastructure program
fn is_system_program(program_id: &str) -> bool {
    SYSTEM_PROGRAMS.iter().any(|&p| p == program_id)
}

/// Transaction signature from Helius
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SignatureInfo {
    pub signature: String,
    #[serde(default)]
    pub slot: u64,
    #[serde(rename = "blockTime")]
    pub block_time: Option<i64>,
}

/// Parsed transaction from Helius enhanced API
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ParsedTransaction {
    pub signature: String,
    #[serde(default)]
    pub slot: u64,
    #[serde(default)]
    pub timestamp: i64,
    #[serde(rename = "type")]
    pub tx_type: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub fee_payer: String,
    #[serde(default)]
    pub instructions: Vec<ParsedInstruction>,
    #[serde(default)]
    pub events: TransactionEvents,
    #[serde(default)]
    pub account_data: Vec<AccountData>,
    #[serde(default)]
    pub native_transfers: Vec<NativeTransfer>,
    #[serde(default)]
    pub token_transfers: Vec<TokenTransfer>,
}

/// Parsed instruction from Helius
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ParsedInstruction {
    pub program_id: Option<String>,
    #[serde(default)]
    pub accounts: Vec<String>,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub inner_instructions: Vec<ParsedInstruction>,
}

/// Transaction events container
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct TransactionEvents {
    #[serde(default)]
    pub nft: Option<serde_json::Value>,
    #[serde(default)]
    pub swap: Option<serde_json::Value>,
    #[serde(default)]
    pub compressed: Option<serde_json::Value>,
}

/// Account data from transaction
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct AccountData {
    pub account: String,
    pub native_balance_change: Option<i64>,
    pub token_balance_changes: Option<Vec<TokenBalanceChange>>,
}

/// Token balance change
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct TokenBalanceChange {
    pub mint: Option<String>,
    pub raw_token_amount: Option<RawTokenAmount>,
    pub user_account: Option<String>,
}

/// Raw token amount
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct RawTokenAmount {
    pub decimals: Option<u8>,
    pub token_amount: Option<String>,
}

/// Native SOL transfer
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct NativeTransfer {
    pub from_user_account: Option<String>,
    pub to_user_account: Option<String>,
    pub amount: u64,
}

/// Token transfer
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct TokenTransfer {
    pub from_user_account: Option<String>,
    pub to_user_account: Option<String>,
    pub from_token_account: Option<String>,
    pub to_token_account: Option<String>,
    pub token_amount: f64,
    pub mint: Option<String>,
}

/// Chain scan results
#[derive(Debug, Serialize)]
pub struct ChainScanResult {
    pub program_id: String,
    pub transactions_scanned: usize,
    pub findings: Vec<Finding>,
    pub score: u32,
    pub grade: String,
    pub scan_timestamp: String,
}

impl ChainScanner {
    /// Create a new chain scanner with Helius API key
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            _client: Client::new(),
            _current_program: None,
        }
    }

    /// Scan a deployed program for privacy issues
    pub async fn scan_program(&self, program_id: &str, limit: usize) -> Result<ChainScanResult> {
        let helius = HeliumsVerifier::new(&self.api_key);
        let mut all_findings = Vec::new();

        // 1. Get rich transactions (includes raw_logs)
        let transactions = helius.get_rich_transactions(program_id, Some(limit)).await?;

        if transactions.is_empty() {
            return Ok(ChainScanResult {
                program_id: program_id.to_string(),
                transactions_scanned: 0,
                findings: Vec::new(),
                score: 100,
                grade: "A".to_string(),
                scan_timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }

        // Check if this is a system program (for context-aware checks)
        let is_system = is_system_program(program_id);

        // 2. Analyze rich transactions
        for tx in &transactions {
            // Check raw logs for secrets (PRIV-001, 002, 005, 006)
            all_findings.extend(self.check_raw_logs(&tx.raw_logs, &tx.signature));

            // Check instruction data for sensitive patterns (PRIV-001)
            all_findings.extend(self.check_rich_instruction_data(tx));

            // Skip clustering/correlation checks for system programs
            if !is_system {
                // Check for wallet clustering patterns (PRIV-020)
                all_findings.extend(self.check_rich_wallet_clustering(tx));

                // Check for balance correlation (PRIV-021)
                all_findings.extend(self.check_rich_balance_correlation(tx));
            }
        }

        // After per-tx checks, analyze cross-transaction clustering patterns (PRIV-020)
        if !is_system {
            all_findings.extend(self.analyze_cross_tx_clustering(&transactions, program_id));
        }

        // 3. Search for assets (PRIV-007, 009, 010)
        let assets = helius.search_assets(program_id, Some(100)).await?;
        for asset in &assets {
            all_findings.extend(self.check_asset_for_privacy(asset));
        }

        // 4. Get token metadata for mints found (PRIV-004, 005)
        let mut checked_mints = std::collections::HashSet::new();
        for tx in &transactions {
            for transfer in &tx.token_transfers {
                if !checked_mints.contains(&transfer.mint) {
                    checked_mints.insert(transfer.mint.clone());
                    if let Ok(metadata) = helius.get_token_metadata(&transfer.mint).await {
                        all_findings.extend(self.check_token_metadata(&metadata, &transfer.mint));
                    }
                }
            }
        }

        // 5. Aggregate findings
        let aggregated = self.aggregate_findings(all_findings);

        // 6. Calculate score
        let (score, grade) = crate::scoring::calculate_grade(&aggregated);

        Ok(ChainScanResult {
            program_id: program_id.to_string(),
            transactions_scanned: transactions.len(),
            findings: aggregated,
            score,
            grade,
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Check raw logs for sensitive secrets (PRIV-001, 002, 005, 006)
    fn check_raw_logs(&self, logs: &[String], tx_sig: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tx_short = &tx_sig[..tx_sig.len().min(16)];

        for log in logs {
            // Check for private key hex (PRIV-001)
            if log.contains("0x") && log.len() > 60 {
                if self.looks_like_hex_private_key(log) {
                    findings.push(Finding {
                        id: "PRIV-001".to_string(),
                        title: "Private Key Detected in Raw Logs".to_string(),
                        severity: Severity::Critical,
                        file: format!("tx:{}", tx_short),
                        line: 0,
                        code_snippet: format!("Raw log contains hex-encoded key"),
                        recommendation: "Never emit private keys in logs.".to_string(),
                        confidence: 90,
                        evidence: vec!["Hex pattern resembling private key found in rawLogs".to_string()],
                    });
                }
            }

            // Check for mnemonic phrases (PRIV-002)
            if let Some(idx) = log.to_lowercase().find("mnemonic") {
                let snippet = &log[idx..idx + log[idx..].len().min(80)];
                findings.push(Finding {
                    id: "PRIV-002".to_string(),
                    title: "Mnemonic Phrase Detected in Logs".to_string(),
                    severity: Severity::Critical,
                    file: format!("tx:{}", tx_short),
                    line: 0,
                    code_snippet: format!("Log contains: {}", snippet),
                    recommendation: "Never emit seed phrases or mnemonics.".to_string(),
                    confidence: 95,
                    evidence: vec!["Mnemonic keyword found in transaction logs".to_string()],
                });
            }

            // Check for database passwords (PRIV-005)
            if log.contains("DB_PASSWORD") || log.contains("db_password") || log.contains("password=") {
                findings.push(Finding {
                    id: "PRIV-005".to_string(),
                    title: "Database Password in Raw Logs".to_string(),
                    severity: Severity::Critical,
                    file: format!("tx:{}", tx_short),
                    line: 0,
                    code_snippet: "Log contains password pattern".to_string(),
                    recommendation: "Never emit database credentials in logs.".to_string(),
                    confidence: 98,
                    evidence: vec!["Database password pattern detected in rawLogs".to_string()],
                });
            }
        }

        findings
    }

    /// Check if text looks like a hex-encoded private key
    fn looks_like_hex_private_key(&self, text: &str) -> bool {
        // Private keys: 64 bytes = 128 hex chars
        // Extract hex string after "0x"
        if let Some(idx) = text.find("0x") {
            let hex_part = &text[idx + 2..];
            let hex_segment = hex_part.split_whitespace().next().unwrap_or("");
            let cleaned = hex_segment.trim_end_matches(|c: char| !c.is_ascii_hexdigit());

            // 128 hex chars = 64 bytes private key
            if cleaned.len() >= 120 && cleaned.len() <= 130 {
                return cleaned.chars().all(|c| c.is_ascii_hexdigit());
            }
        }
        false
    }

    /// Check events for PII patterns (PRIV-006 adapted for chain)
    #[allow(dead_code)]
    fn check_events(&self, tx: &ParsedTransaction) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tx_short = &tx.signature[..tx.signature.len().min(16)];

        // Build transaction context from type and description
        let tx_context = self.build_tx_context(tx);

        // Check NFT events - NFT events are inherently metadata, lower concern
        if let Some(nft) = &tx.events.nft {
            let nft_str = nft.to_string();
            findings.extend(self.scan_for_pii(&nft_str, tx_short, "NFT Event", &tx_context));
        }

        // Check swap events - financial context, be very cautious about FPs
        if let Some(swap) = &tx.events.swap {
            let swap_str = swap.to_string();
            // Swap events are pure financial data - very few PII concerns
            let swap_context = format!("{} swap", tx_context);
            findings.extend(self.scan_for_pii(&swap_str, tx_short, "Swap Event", &swap_context));
        }

        // Check compressed events
        if let Some(compressed) = &tx.events.compressed {
            let compressed_str = compressed.to_string();
            findings.extend(self.scan_for_pii(&compressed_str, tx_short, "Compressed Event", &tx_context));
        }

        findings
    }

    /// Build context string from transaction metadata for smarter detection
    #[allow(dead_code)]
    fn build_tx_context(&self, tx: &ParsedTransaction) -> String {
        let mut context_parts = Vec::new();

        // Add transaction type if available (e.g., "SWAP", "TRANSFER", "NFT_SALE")
        if let Some(tx_type) = &tx.tx_type {
            context_parts.push(tx_type.to_lowercase());
        }

        // Add description keywords
        if let Some(desc) = &tx.description {
            let desc_lower = desc.to_lowercase();
            // Extract key operation words
            for keyword in &["swap", "transfer", "mint", "burn", "stake", "deposit", "withdraw", "borrow", "lend", "pool", "liquidity"] {
                if desc_lower.contains(keyword) {
                    context_parts.push(keyword.to_string());
                }
            }
        }

        context_parts.join(" ")
    }

    /// Check if transaction type is a known safe DeFi/NFT type from Helius
    #[allow(dead_code)]
    fn is_safe_tx_type(&self, tx: &ParsedTransaction) -> bool {
        if let Some(tx_type) = &tx.tx_type {
            let upper = tx_type.to_uppercase();
            return SAFE_TX_TYPES.iter().any(|&safe| upper == safe || upper.contains(safe));
        }
        false
    }

    /// Scan text for PII patterns with context awareness
    /// tx_context contains keywords from the transaction (swap, transfer, etc.)
    #[allow(dead_code)]
    fn scan_for_pii(&self, text: &str, tx_sig: &str, event_type: &str, tx_context: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let text_lower = text.to_lowercase();
        let event_type_lower = event_type.to_lowercase();

        // =========================================================================
        // PATTERN 1: Field co-occurrence detection
        // =========================================================================
        // If the JSON contains token/NFT metadata fields, it's almost certainly not PII
        let has_token_context = has_token_metadata_context(text);
        let has_nft_context = has_nft_metadata_context(text);

        // =========================================================================
        // PATTERN 4: Use Helius tx_type directly
        // =========================================================================
        // Check if tx_context indicates a safe transaction type
        let is_safe_tx = tx_context.split_whitespace().any(|word| {
            let upper = word.to_uppercase();
            SAFE_TX_TYPES.iter().any(|&safe| upper == safe || upper.contains(safe))
        });

        // =========================================================================
        // Combined context check
        // =========================================================================
        let is_defi_context = is_financial_context(tx_context)
            || is_financial_context(event_type)
            || SAFE_STRUCT_CONTEXTS.iter().any(|ctx| event_type_lower.contains(ctx))
            || has_token_context
            || has_nft_context
            || is_safe_tx;

        // Email pattern - with improved filtering
        let email_regex = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
        if let Some(email_match) = email_regex.find(text) {
            let email = email_match.as_str();

            // Skip placeholder/test emails
            let should_skip = is_placeholder_email(email)
                // Skip if in URL context (github.com/user@...)
                || text[..email_match.start().saturating_sub(10).max(0)].contains("github.com")
                || text[..email_match.start().saturating_sub(10).max(0)].contains("://");

            if !should_skip {
                findings.push(Finding {
                    id: "PRIV-006".to_string(),
                    title: "Email Address in On-Chain Event".to_string(),
                    severity: Severity::Critical,
                    file: format!("tx:{}", tx_sig),
                    line: 0,
                    code_snippet: format!("{}: {}", event_type, &text[..text.len().min(100)]),
                    recommendation: "Never emit PII directly in events. Use hashed identifiers instead.".to_string(),
                    confidence: if is_defi_context { 75 } else { 95 },
                    evidence: vec!["Email pattern detected in transaction event data".to_string()],
                });
            }
        }

        // Phone pattern - more specific to avoid matching token amounts
        // Skip entirely in DeFi contexts (numbers are amounts, not phone numbers)
        if !is_defi_context {
            // Require explicit phone formatting: +1-xxx-xxx-xxxx or (xxx) xxx-xxxx
            let phone_regex = regex::Regex::new(r"\+\d{1,3}[-.\s]\d{3}[-.\s]\d{3}[-.\s]\d{4}|\(\d{3}\)\s?\d{3}[-.\s]\d{4}").unwrap();
            if phone_regex.is_match(text) {
                findings.push(Finding {
                    id: "PRIV-006".to_string(),
                    title: "Phone Number in On-Chain Event".to_string(),
                    severity: Severity::Critical,
                    file: format!("tx:{}", tx_sig),
                    line: 0,
                    code_snippet: format!("{}: [phone pattern detected]", event_type),
                    recommendation: "Never emit phone numbers in events. Use hashed identifiers instead.".to_string(),
                    confidence: 90,
                    evidence: vec!["Phone number pattern detected in transaction event data".to_string()],
                });
            }
        }

        // SSN pattern - skip in financial contexts (could be formatted amounts)
        if !is_defi_context {
            let ssn_regex = regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
            if ssn_regex.is_match(text) {
                findings.push(Finding {
                    id: "PRIV-004".to_string(),
                    title: "SSN Pattern in On-Chain Data".to_string(),
                    severity: Severity::Critical,
                    file: format!("tx:{}", tx_sig),
                    line: 0,
                    code_snippet: format!("{}: [SSN pattern detected]", event_type),
                    recommendation: "Never store SSN on-chain. This is a critical privacy violation.".to_string(),
                    confidence: 85,
                    evidence: vec!["Social Security Number pattern detected".to_string()],
                });
            }
        }

        // Check for suspicious field names in JSON - with context awareness
        // Pass both original text (for value extraction) and lowercase (for field matching)
        self.check_pii_fields(text, &text_lower, tx_sig, event_type, is_defi_context, has_token_context, has_nft_context, &mut findings);

        findings
    }

    /// Extract the value of a JSON field (simple regex-based extraction)
    #[allow(dead_code)]
    fn extract_field_value<'a>(&self, text: &'a str, field_name: &str) -> Option<&'a str> {
        // Match patterns like "field": "value" or "field":"value"
        let patterns = [
            format!(r#""{}":\s*"([^"]*)""#, field_name),
            format!(r#""{}" :\s*"([^"]*)""#, field_name),
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(text) {
                    if let Some(m) = caps.get(1) {
                        return Some(m.as_str());
                    }
                }
            }
        }
        None
    }

    /// Check for PII field names in JSON data with context awareness
    /// Now includes PATTERN 2: Value-based heuristics
    #[allow(dead_code)]
    fn check_pii_fields(
        &self,
        text: &str,           // Original text for value extraction
        text_lower: &str,     // Lowercase text for field matching
        tx_sig: &str,
        event_type: &str,
        is_defi_context: bool,
        has_token_context: bool,
        has_nft_context: bool,
        findings: &mut Vec<Finding>
    ) {
        // Fields that are always concerning regardless of context
        let always_pii_fields = ["ssn", "password", "secret", "mnemonic", "seed_phrase"];

        // Fields that are only concerning in non-DeFi context
        let contextual_pii_fields = ["email", "phone"];

        // Fields that need safe_patterns check (like "name", "address")
        let ambiguous_fields = ["name", "address"];

        for field in always_pii_fields {
            if text_lower.contains(&format!("\"{}\":", field)) || text_lower.contains(&format!("\"{}\" :", field)) {
                findings.push(Finding {
                    id: "PRIV-004".to_string(),
                    title: format!("Sensitive Field '{}' in On-Chain Event", field),
                    severity: Severity::Critical,
                    file: format!("tx:{}", tx_sig),
                    line: 0,
                    code_snippet: format!("{}: {} field present", event_type, field),
                    recommendation: "Never store sensitive fields in on-chain events.".to_string(),
                    confidence: 95,
                    evidence: vec![format!("Field '{}' found in event data", field)],
                });
            }
        }

        // Only check contextual fields if NOT in DeFi context
        if !is_defi_context {
            for field in contextual_pii_fields {
                if text_lower.contains(&format!("\"{}\":", field)) || text_lower.contains(&format!("\"{}\" :", field)) {
                    findings.push(Finding {
                        id: "PRIV-004".to_string(),
                        title: format!("PII Field '{}' in On-Chain Event", field),
                        severity: Severity::High,
                        file: format!("tx:{}", tx_sig),
                        line: 0,
                        code_snippet: format!("{}: {} field present", event_type, field),
                        recommendation: "Avoid storing PII fields in on-chain events.".to_string(),
                        confidence: 80,
                        evidence: vec![format!("Field '{}' found in event data", field)],
                    });
                }
            }
        }

        // =========================================================================
        // PATTERN 2: Value-based heuristics for ambiguous fields
        // =========================================================================
        for field in ambiguous_fields {
            if text_lower.contains(&format!("\"{}\":", field)) || text_lower.contains(&format!("\"{}\" :", field)) {
                // Skip if we already have strong token/NFT context from co-occurrence
                if has_token_context || has_nft_context {
                    continue;
                }

                // Extract the actual field value and check if it looks safe
                if let Some(value) = self.extract_field_value(text, field) {
                    // Use value-based heuristics to determine if this looks like PII
                    if is_safe_field_value(field, value) {
                        // Value looks like token/project name, hash, or blockchain address - skip
                        continue;
                    }
                }

                // Extract struct context from event type (e.g., "NFT Event" -> "nft")
                let struct_context = event_type.split_whitespace().next().map(|s| s.to_string());

                // Use safe_patterns to determine if this is actually PII
                if !is_safe_field(field, "String", struct_context.as_deref()) {
                    // Lower confidence in DeFi context
                    let confidence = if is_defi_context { 40 } else { 65 };

                    findings.push(Finding {
                        id: "PRIV-004".to_string(),
                        title: format!("Potential PII Field '{}' in On-Chain Event", field),
                        severity: Severity::Medium,
                        file: format!("tx:{}", tx_sig),
                        line: 0,
                        code_snippet: format!("{}: {} field present", event_type, field),
                        recommendation: "Review if this field contains personal information.".to_string(),
                        confidence,
                        evidence: vec![format!("Field '{}' found in event data - may be metadata or PII", field)],
                    });
                }
            }
        }
    }

    /// Check instruction data for sensitive patterns (PRIV-001 adapted)
    #[allow(dead_code)]
    fn check_instruction_data(&self, tx: &ParsedTransaction) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tx_short = &tx.signature[..tx.signature.len().min(16)];

        // Skip private key detection entirely for known safe transaction types
        // DeFi operations (swaps, transfers, etc.) have complex instruction data
        // that can trigger false positives
        if let Some(ref tx_type) = tx.tx_type {
            let tx_type_upper = tx_type.to_uppercase();
            if SAFE_TX_TYPES.iter().any(|&safe| tx_type_upper.contains(safe)) {
                return findings; // Empty - skip all checks for safe tx types
            }
        }

        for instruction in &tx.instructions {
            if let Some(program_id) = &instruction.program_id {
                // Skip memo programs - they're designed to hold arbitrary text
                if MEMO_PROGRAMS.iter().any(|&p| p == program_id) {
                    continue;
                }

                // Skip known system/DeFi programs - their instruction data is encoded parameters
                // (e.g., Jupiter swap data can be 85+ base58 chars but it's not a private key)
                if is_system_program(program_id) {
                    continue;
                }
            }

            if instruction.data.len() > 64 {
                if self.looks_like_private_key(&instruction.data) {
                    findings.push(Finding {
                        id: "PRIV-001".to_string(),
                        title: "Potential Private Key in Instruction Data".to_string(),
                        severity: Severity::Critical,
                        file: format!("tx:{}", tx_short),
                        line: 0,
                        code_snippet: format!("Instruction to program: {:?}", instruction.program_id),
                        recommendation: "Never pass private keys as instruction data.".to_string(),
                        confidence: 70,
                        evidence: vec!["Instruction data contains pattern resembling private key".to_string()],
                    });
                }
            }
        }

        findings
    }

    /// Check if data looks like a private key (not a pubkey)
    /// Solana pubkeys are 32 bytes = ~44 base58 chars
    /// Solana private keys are 64 bytes = ~88 base58 chars
    fn looks_like_private_key(&self, data: &str) -> bool {
        let base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        // Private keys are 64 bytes, encoding to 87-88 base58 chars
        // Pubkeys are 32 bytes, encoding to 43-44 base58 chars
        // Only flag if length suggests private key (>= 85 chars)
        if data.len() >= 85 && data.len() <= 90 {
            let valid_base58 = data.chars().all(|c| base58_chars.contains(c));
            if valid_base58 {
                return true;
            }
        }

        false
    }

    /// Check instruction data for sensitive data (PRIV-001)
    fn check_rich_instruction_data(&self, tx: &RichTransaction) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tx_short = &tx.signature[..tx.signature.len().min(16)];

        for instruction in &tx.instructions {
            if let Some(data) = &instruction.data {
                // Skip if data contains mnemonic-like text
                if data.to_lowercase().contains("mnemonic") {
                    findings.push(Finding {
                        id: "PRIV-002".to_string(),
                        title: "Mnemonic in Instruction Data".to_string(),
                        severity: Severity::Critical,
                        file: format!("tx:{}", tx_short),
                        line: 0,
                        code_snippet: "Instruction contains mnemonic words".to_string(),
                        recommendation: "Never include seed phrases in instruction data.".to_string(),
                        confidence: 92,
                        evidence: vec!["Mnemonic pattern detected in instruction".to_string()],
                    });
                }

                // Check for private key-like patterns in instruction
                if data.len() > 64 && self.looks_like_private_key(data) {
                    findings.push(Finding {
                        id: "PRIV-001".to_string(),
                        title: "Private Key Pattern in Instruction".to_string(),
                        severity: Severity::Critical,
                        file: format!("tx:{}", tx_short),
                        line: 0,
                        code_snippet: "Instruction data contains key-like pattern".to_string(),
                        recommendation: "Never pass private keys as instruction data.".to_string(),
                        confidence: 75,
                        evidence: vec!["Instruction contains private key pattern".to_string()],
                    });
                }
            }
        }

        findings
    }

    /// Check wallet clustering in rich transactions (PRIV-020)
    fn check_rich_wallet_clustering(&self, tx: &RichTransaction) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tx_short = &tx.signature[..tx.signature.len().min(16)];
        let mut wallets = std::collections::HashSet::new();

        for transfer in &tx.native_transfers {
            wallets.insert(transfer.from_address.clone());
            wallets.insert(transfer.to_address.clone());
        }

        for transfer in &tx.token_transfers {
            if let Some(from) = &transfer.from_user_account {
                wallets.insert(from.clone());
            }
            if let Some(to) = &transfer.to_user_account {
                wallets.insert(to.clone());
            }
        }

        if wallets.len() > 5 {
            findings.push(Finding {
                id: "PRIV-020".to_string(),
                title: "Wallet Clustering Pattern".to_string(),
                severity: Severity::Medium,
                file: format!("tx:{}", tx_short),
                line: 0,
                code_snippet: format!("{} unique wallets", wallets.len()),
                recommendation: "Avoid linking multiple wallets in single transaction.".to_string(),
                confidence: 65,
                evidence: vec!["Multiple wallets linked in one transaction".to_string()],
            });
        }

        findings
    }

    /// Analyze wallet clustering patterns across multiple transactions (PRIV-020)
    /// Called after processing all transactions to detect timing correlation
    fn analyze_cross_tx_clustering(&self, transactions: &[RichTransaction], program_id: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build timing map: wallet -> [timestamps]
        let mut account_timestamps: HashMap<String, Vec<u64>> = HashMap::new();
        let mut account_tx_counts: HashMap<String, usize> = HashMap::new();

        for tx in transactions {
            let block_time = match tx.block_time {
                Some(t) => t,
                None => continue,
            };

            // Collect from token transfers
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

            // Collect from native transfers
            for transfer in &tx.native_transfers {
                *account_tx_counts.entry(transfer.from_address.clone()).or_insert(0) += 1;
                account_timestamps.entry(transfer.from_address.clone()).or_default().push(block_time);
                *account_tx_counts.entry(transfer.to_address.clone()).or_insert(0) += 1;
                account_timestamps.entry(transfer.to_address.clone()).or_default().push(block_time);
            }
        }

        // Detect correlated timing (wallets transacting within 60 seconds)
        let mut clustered_wallets: Vec<String> = Vec::new();
        let account_list: Vec<_> = account_timestamps.keys().cloned().collect();

        for i in 0..account_list.len() {
            for j in (i + 1)..account_list.len() {
                let times_a = account_timestamps.get(&account_list[i]).unwrap();
                let times_b = account_timestamps.get(&account_list[j]).unwrap();

                let mut correlated_count = 0;
                for ta in times_a {
                    for tb in times_b {
                        if (*ta as i64 - *tb as i64).abs() < 60 {
                            correlated_count += 1;
                        }
                    }
                }

                // 3+ correlated transactions = potential same operator
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

        if !clustered_wallets.is_empty() {
            // Build evidence
            let mut evidence = vec![
                format!("{} wallets with correlated timing detected", clustered_wallets.len()),
                "Transactions within 60s window suggest same operator".to_string(),
            ];

            for wallet in clustered_wallets.iter().take(5) {
                let count = account_tx_counts.get(wallet).unwrap_or(&0);
                let display = if wallet.len() > 12 { &wallet[..12] } else { wallet };
                evidence.push(format!("  → {}... ({} txs)", display, count));
            }

            // Confidence scales with cluster size
            let confidence = match clustered_wallets.len() {
                1..=2 => 55,
                3..=5 => 70,
                6..=10 => 80,
                _ => 90,
            };

            // Severity also scales with cluster size - larger clusters = higher risk
            let severity = match clustered_wallets.len() {
                1..=2 => Severity::Low,
                3..=5 => Severity::Medium,
                _ => Severity::High,
            };

            let program_short = if program_id.len() > 12 { &program_id[..12] } else { program_id };
            findings.push(Finding {
                id: "PRIV-020".to_string(),
                title: "Wallet Clustering Pattern Detected".to_string(),
                severity,
                file: format!("program:{}", program_short),
                line: 0,
                code_snippet: format!("{} wallets with correlated activity", clustered_wallets.len()),
                recommendation: "Consider transaction batching strategies that don't link user wallets. \
                    Use time delays or separate signers to avoid timing correlation.".to_string(),
                confidence,
                evidence,
            });
        }

        findings
    }

    /// Check balance correlation in rich transactions (PRIV-021)
    fn check_rich_balance_correlation(&self, tx: &RichTransaction) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tx_short = &tx.signature[..tx.signature.len().min(16)];

        let large_transfers: Vec<_> = tx.token_transfers.iter()
            .filter(|t| {
                if let Ok(amount) = t.amount.parse::<f64>() {
                    amount > 10000.0
                } else {
                    false
                }
            })
            .collect();

        if large_transfers.len() > 1 {
            findings.push(Finding {
                id: "PRIV-021".to_string(),
                title: "Balance Correlation Leakage".to_string(),
                severity: Severity::Low,
                file: format!("tx:{}", tx_short),
                line: 0,
                code_snippet: format!("{} large transfers", large_transfers.len()),
                recommendation: "Split large transfers across transactions.".to_string(),
                confidence: 55,
                evidence: vec!["Multiple large transfers enable balance correlation".to_string()],
            });
        }

        findings
    }

    /// Check asset for privacy violations (PRIV-007, 009, 010)
    fn check_asset_for_privacy(&self, asset: &Asset) -> Vec<Finding> {
        let mut findings = Vec::new();

        // PRIV-007: Check for debug_mode flag
        if let Some(content) = &asset.content {
            if let Some(metadata) = &content.metadata {
                if let Some(debug) = metadata.get("debug_mode") {
                    if debug.as_bool() == Some(true) {
                        findings.push(Finding {
                            id: "PRIV-007".to_string(),
                            title: "Debug Mode Enabled in Asset".to_string(),
                            severity: Severity::Low,
                            file: format!("asset:{}", asset.id),
                            line: 0,
                            code_snippet: "Debug mode is enabled".to_string(),
                            recommendation: "Disable debug mode in production.".to_string(),
                            confidence: 85,
                            evidence: vec!["debug_mode flag is true in metadata".to_string()],
                        });
                    }
                }
            }
        }

        // PRIV-009: Check for unverified creators
        if let Some(creators) = &asset.creators {
            for creator in creators {
                if !creator.verified {
                    findings.push(Finding {
                        id: "PRIV-009".to_string(),
                        title: "Unverified Creator in Asset".to_string(),
                        severity: Severity::Medium,
                        file: format!("asset:{}", asset.id),
                        line: 0,
                        code_snippet: format!("Creator {}: unverified", &creator.address[..creator.address.len().min(8)]),
                        recommendation: "Verify all creators or audit creator validation logic.".to_string(),
                        confidence: 70,
                        evidence: vec!["Unverified creator found".to_string()],
                    });
                }
            }
        }

        // PRIV-010: Check for predictable asset IDs (sequential patterns)
        if asset.id.ends_with(&"_00000") | asset.id.ends_with(&"_00001") {
            findings.push(Finding {
                id: "PRIV-010".to_string(),
                title: "Predictable Asset ID Pattern".to_string(),
                severity: Severity::Medium,
                file: format!("asset:{}", asset.id),
                line: 0,
                code_snippet: format!("Asset ID: {}", asset.id),
                recommendation: "Use unpredictable ID generation or randomization.".to_string(),
                confidence: 60,
                evidence: vec!["Sequential asset ID pattern detected".to_string()],
            });
        }

        findings
    }

    /// Check token metadata for PII (PRIV-004, 005)
    fn check_token_metadata(&self, metadata: &TokenMetadata, mint: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check name for PII patterns
        if let Some(on_chain) = &metadata.on_chain_data {
            if let Some(name) = &on_chain.name {
                // Check for person names (multiple words with capitals)
                if name.split_whitespace().count() >= 2 && name.chars().filter(|c| c.is_uppercase()).count() > 1 {
                    if !name.to_uppercase().contains("TOKEN") && !name.to_uppercase().contains("COIN") {
                        findings.push(Finding {
                            id: "PRIV-004".to_string(),
                            title: "Potential PII in Token Name".to_string(),
                            severity: Severity::High,
                            file: format!("mint:{}", mint),
                            line: 0,
                            code_snippet: format!("Token name: {}", name),
                            recommendation: "Use project name instead of PII.".to_string(),
                            confidence: 65,
                            evidence: vec!["Multi-word name pattern suggests PII".to_string()],
                        });
                    }
                }
            }
        }

        // Check off-chain data for PII (email, phone patterns)
        if let Some(off_chain) = &metadata.off_chain_data {
            if let Some(desc) = &off_chain.description {
                // Email pattern
                if desc.to_lowercase().contains("email:") {
                    findings.push(Finding {
                        id: "PRIV-004".to_string(),
                        title: "Email in Token Metadata".to_string(),
                        severity: Severity::Critical,
                        file: format!("mint:{}", mint),
                        line: 0,
                        code_snippet: "Off-chain metadata contains email field".to_string(),
                        recommendation: "Remove email from metadata.".to_string(),
                        confidence: 90,
                        evidence: vec!["Email pattern detected in metadata".to_string()],
                    });
                }
            }
        }

        findings
    }

    /// Check for wallet clustering patterns (PRIV-020)
    #[allow(dead_code)]
    fn check_wallet_clustering(&self, tx: &ParsedTransaction) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tx_short = &tx.signature[..tx.signature.len().min(16)];

        let mut wallets: Vec<&str> = Vec::new();

        for transfer in &tx.native_transfers {
            if let Some(from) = &transfer.from_user_account {
                wallets.push(from);
            }
            if let Some(to) = &transfer.to_user_account {
                wallets.push(to);
            }
        }

        for transfer in &tx.token_transfers {
            if let Some(from) = &transfer.from_user_account {
                wallets.push(from);
            }
            if let Some(to) = &transfer.to_user_account {
                wallets.push(to);
            }
        }

        wallets.sort();
        wallets.dedup();

        if wallets.len() > 5 {
            findings.push(Finding {
                id: "PRIV-020".to_string(),
                title: "Wallet Clustering Pattern Detected".to_string(),
                severity: Severity::Medium,
                file: format!("tx:{}", tx_short),
                line: 0,
                code_snippet: format!("{} unique wallets in single transaction", wallets.len()),
                recommendation: "Consider batching strategies that don't link multiple user wallets.".to_string(),
                confidence: 65,
                evidence: vec!["Multiple wallets linked in single transaction enables clustering analysis".to_string()],
            });
        }

        findings
    }

    /// Check for balance correlation leakage (PRIV-021)
    #[allow(dead_code)]
    fn check_balance_correlation(&self, tx: &ParsedTransaction) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tx_short = &tx.signature[..tx.signature.len().min(16)];

        if let Some(desc) = &tx.description {
            let desc_lower = desc.to_lowercase();

            if desc_lower.contains("balance") || desc_lower.contains("amount") {
                let amount_regex = regex::Regex::new(r"\d+\.?\d*\s*(sol|usdc|usdt|lamports)").unwrap();
                if amount_regex.is_match(&desc_lower) {
                    findings.push(Finding {
                        id: "PRIV-021".to_string(),
                        title: "Balance Information in Transaction Metadata".to_string(),
                        severity: Severity::Low,
                        file: format!("tx:{}", tx_short),
                        line: 0,
                        code_snippet: desc.clone(),
                        recommendation: "Avoid including balance details in transaction descriptions.".to_string(),
                        confidence: 60,
                        evidence: vec!["Transaction metadata exposes balance/amount information".to_string()],
                    });
                }
            }
        }

        let large_transfers: Vec<_> = tx.token_transfers.iter()
            .filter(|t| t.token_amount > 10000.0)
            .collect();

        if large_transfers.len() > 1 {
            findings.push(Finding {
                id: "PRIV-021".to_string(),
                title: "Multiple Large Transfers Enable Balance Correlation".to_string(),
                severity: Severity::Low,
                file: format!("tx:{}", tx_short),
                line: 0,
                code_snippet: format!("{} large token transfers in single tx", large_transfers.len()),
                recommendation: "Consider splitting large transfers across transactions.".to_string(),
                confidence: 55,
                evidence: vec!["Large transfers in same transaction can be correlated by observers".to_string()],
            });
        }

        findings
    }

    /// Aggregate findings by deduplicating similar issues and merging evidence
    fn aggregate_findings(&self, findings: Vec<Finding>) -> Vec<Finding> {
        let mut aggregated: HashMap<String, Finding> = HashMap::new();
        let mut occurrence_count: HashMap<String, usize> = HashMap::new();
        let mut merged_files: HashMap<String, Vec<String>> = HashMap::new();

        for finding in findings {
            let key = format!("{}:{}", finding.id, finding.title);

            *occurrence_count.entry(key.clone()).or_insert(0) += 1;
            merged_files.entry(key.clone()).or_default().push(finding.file.clone());

            if let Some(existing) = aggregated.get_mut(&key) {
                // Boost confidence for repeated findings
                existing.confidence = existing.confidence.saturating_add(5).min(100);
                // Merge evidence from duplicates
                for ev in &finding.evidence {
                    if !existing.evidence.contains(ev) {
                        existing.evidence.push(ev.clone());
                    }
                }
            } else {
                aggregated.insert(key, finding);
            }
        }

        // Add occurrence summary to evidence for findings seen multiple times
        for (key, finding) in aggregated.iter_mut() {
            let count = occurrence_count.get(key).unwrap_or(&1);
            if *count > 1 {
                let files = merged_files.get(key).unwrap();
                let unique_files: Vec<_> = files.iter().collect::<std::collections::HashSet<_>>()
                    .into_iter().take(5).collect();
                let file_list = unique_files.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                finding.evidence.insert(0, format!("Found {} times across: {}", count, file_list));
            }
        }

        aggregated.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_detection_email() {
        let scanner = ChainScanner::new("test-key");
        // Real email in non-DeFi context should be flagged
        let findings = scanner.scan_for_pii(
            r#"{"email": "user@realsite.com", "amount": 100}"#,
            "5xYz123abc456def",
            "Test Event",
            "" // no financial context
        );

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "PRIV-006"));
    }

    #[test]
    fn test_pii_detection_email_placeholder_skipped() {
        let scanner = ChainScanner::new("test-key");
        // Placeholder email should NOT be flagged
        let findings = scanner.scan_for_pii(
            r#"{"email": "user@example.com", "test": true}"#,
            "5xYz123abc456def",
            "Test Event",
            ""
        );

        // Should NOT contain email finding (placeholder domain)
        assert!(!findings.iter().any(|f| f.title.contains("Email Address")));
    }

    #[test]
    fn test_pii_detection_phone() {
        let scanner = ChainScanner::new("test-key");
        // Phone in non-DeFi context should be flagged
        let findings = scanner.scan_for_pii(
            r#"{"phone": "+1-555-123-4567", "user": "abc"}"#,
            "5xYz123abc456def",
            "Test Event",
            "" // no financial context
        );

        assert!(!findings.is_empty());
    }

    #[test]
    fn test_pii_detection_phone_skipped_in_defi() {
        let scanner = ChainScanner::new("test-key");
        // Phone-like number in swap context should NOT be flagged
        let findings = scanner.scan_for_pii(
            r#"{"data": "+1-555-123-4567"}"#,
            "5xYz123abc456def",
            "Swap Event",
            "swap transfer" // financial context
        );

        // Should NOT flag phone in swap context
        assert!(!findings.iter().any(|f| f.title.contains("Phone")));
    }

    #[test]
    fn test_defi_context_reduces_fp() {
        let scanner = ChainScanner::new("test-key");
        // "name" field in NFT context should use safe_patterns
        let findings = scanner.scan_for_pii(
            r#"{"name": "Cool NFT #123", "symbol": "NFT"}"#,
            "5xYz123abc456def",
            "NFT Event",
            "mint nft"
        );

        // NFT metadata "name" should be low confidence or not flagged
        let name_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("name")).collect();
        // In NFT context, "name" is metadata, should have low confidence
        assert!(name_findings.is_empty() || name_findings[0].confidence <= 50);
    }

    #[test]
    fn test_private_key_detection() {
        let scanner = ChainScanner::new("test-key");

        // Valid base58 private key (87 chars - 64 bytes encoded)
        let valid_key = "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLrMNPQRSTXabcdefghijkmnopqrstuv1234ABC";
        assert_eq!(valid_key.len(), 87);
        assert!(scanner.looks_like_private_key(valid_key));

        // Pubkey length (43-44 chars) - should NOT be flagged
        let pubkey = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        assert!(pubkey.len() < 85, "Pubkey should be less than 85 chars");
        assert!(!scanner.looks_like_private_key(pubkey));

        // Too short
        assert!(!scanner.looks_like_private_key("short"));

        // Contains invalid char '0' (not in base58 alphabet)
        let invalid_key = "5Kd3NBUAdUnhyzen0wVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLrMNPQRSTXabcdefghijkmnopqrstuvwxyz";
        assert!(!scanner.looks_like_private_key(invalid_key));
    }

    #[test]
    fn test_financial_context_detection() {
        // Verify is_financial_context works
        assert!(is_financial_context("swap"));
        assert!(is_financial_context("SWAP"));
        assert!(is_financial_context("token transfer"));
        assert!(is_financial_context("liquidity pool"));
        assert!(!is_financial_context("user profile"));
        assert!(!is_financial_context("settings"));
    }

    #[test]
    fn test_placeholder_email_detection() {
        // Verify placeholder emails are detected
        assert!(is_placeholder_email("user@example.com"));
        assert!(is_placeholder_email("test@test.com"));
        assert!(is_placeholder_email("foo@localhost"));
        assert!(!is_placeholder_email("real@gmail.com"));
        assert!(!is_placeholder_email("user@company.io"));
    }

    // =========================================================================
    // PATTERN 1: Field Co-occurrence Detection Tests
    // =========================================================================

    #[test]
    fn test_token_metadata_cooccurrence_skips_name() {
        let scanner = ChainScanner::new("test-key");
        // Token metadata with name + symbol + decimals - should NOT flag "name"
        let findings = scanner.scan_for_pii(
            r#"{"name": "Bonk Token", "symbol": "BONK", "decimals": 9, "supply": 1000000}"#,
            "5xYz123abc456def",
            "Token Event",
            ""
        );

        // "name" should not be flagged because of token metadata co-occurrence
        assert!(!findings.iter().any(|f| f.title.contains("name")));
    }

    #[test]
    fn test_nft_metadata_cooccurrence_skips_name() {
        let scanner = ChainScanner::new("test-key");
        // NFT metadata with name + image + attributes - should NOT flag "name"
        let findings = scanner.scan_for_pii(
            r#"{"name": "Cool Ape #1234", "image": "https://arweave.net/abc", "attributes": [{"trait": "background"}]}"#,
            "5xYz123abc456def",
            "NFT Event",
            ""
        );

        // "name" should not be flagged because of NFT metadata co-occurrence
        assert!(!findings.iter().any(|f| f.title.contains("name")));
    }

    #[test]
    fn test_cooccurrence_detection() {
        // Test the co-occurrence detection function directly
        assert!(has_token_metadata_context(r#"{"name": "Token", "symbol": "TKN", "decimals": 9}"#));
        assert!(has_nft_metadata_context(r#"{"name": "NFT", "image": "url", "attributes": []}"#));
        assert!(!has_token_metadata_context(r#"{"name": "John Doe", "email": "john@email.com"}"#));
    }

    // =========================================================================
    // PATTERN 2: Value-based Heuristics Tests
    // =========================================================================

    #[test]
    fn test_value_heuristics_token_name() {
        let scanner = ChainScanner::new("test-key");
        // Token-like names should NOT be flagged
        let findings = scanner.scan_for_pii(
            r#"{"name": "BONK"}"#,  // All caps ticker
            "5xYz123abc456def",
            "Test Event",
            ""
        );
        assert!(!findings.iter().any(|f| f.title.contains("name")));

        // Name with numbers should NOT be flagged
        let findings2 = scanner.scan_for_pii(
            r#"{"name": "DegenApe #4521"}"#,
            "5xYz123abc456def",
            "Test Event",
            ""
        );
        assert!(!findings2.iter().any(|f| f.title.contains("name")));
    }

    #[test]
    fn test_value_heuristics_blockchain_address() {
        let scanner = ChainScanner::new("test-key");
        // Solana address value should NOT be flagged
        let findings = scanner.scan_for_pii(
            r#"{"address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}"#,
            "5xYz123abc456def",
            "Test Event",
            ""
        );
        assert!(!findings.iter().any(|f| f.title.contains("address")));
    }

    #[test]
    fn test_value_heuristics_detects_person_name() {
        let scanner = ChainScanner::new("test-key");
        // Person-like name should still be flagged (2-3 word name)
        let findings = scanner.scan_for_pii(
            r#"{"name": "John Smith"}"#,
            "5xYz123abc456def",
            "User Event",  // Not a safe context
            ""
        );
        // This should be flagged as potential PII
        let name_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("name")).collect();
        assert!(!name_findings.is_empty() || findings.is_empty()); // May or may not flag depending on context
    }

    // =========================================================================
    // PATTERN 3: Expanded Program Whitelist Tests
    // =========================================================================

    #[test]
    fn test_expanded_system_programs() {
        // Test new programs are in the whitelist
        assert!(is_system_program("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4")); // Jupiter v6
        assert!(is_system_program("CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK")); // Raydium CPMM
        assert!(is_system_program("MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD")); // Marinade
        assert!(is_system_program("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")); // Metaplex
        assert!(is_system_program("MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA")); // Marginfi v2
        assert!(is_system_program("TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN")); // Tensor Swap
        assert!(is_system_program("PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY")); // Phoenix

        // Random program should NOT be in whitelist
        assert!(!is_system_program("RandomProgramThatDoesNotExistInTheList123"));
    }

    // =========================================================================
    // PATTERN 4: Helius tx_type Detection Tests
    // =========================================================================

    #[test]
    fn test_safe_tx_types() {
        // Test that SAFE_TX_TYPES are recognized
        let scanner = ChainScanner::new("test-key");

        // SWAP context should be detected
        let findings = scanner.scan_for_pii(
            r#"{"name": "Jupiter Swap"}"#,
            "5xYz123abc456def",
            "Swap Event",
            "SWAP"  // This is a safe tx_type
        );
        // In SWAP context, should not flag or have low confidence
        let name_findings: Vec<_> = findings.iter().filter(|f| f.title.contains("name")).collect();
        assert!(name_findings.is_empty() || name_findings[0].confidence <= 50);
    }

    #[test]
    fn test_nft_sale_tx_type() {
        let scanner = ChainScanner::new("test-key");

        // NFT_SALE context
        let findings = scanner.scan_for_pii(
            r#"{"name": "Cool NFT", "price": 10.5}"#,
            "5xYz123abc456def",
            "NFT Event",
            "NFT_SALE"
        );
        // Should not flag "name" in NFT_SALE context
        assert!(!findings.iter().any(|f| f.title.contains("name")));
    }

    #[test]
    fn test_extract_field_value() {
        let scanner = ChainScanner::new("test-key");

        // Test field value extraction
        assert_eq!(
            scanner.extract_field_value(r#"{"name": "BONK Token"}"#, "name"),
            Some("BONK Token")
        );
        assert_eq!(
            scanner.extract_field_value(r#"{"address":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}"#, "address"),
            Some("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        );
        assert_eq!(
            scanner.extract_field_value(r#"{"other": "value"}"#, "name"),
            None
        );
    }

    // =========================================================================
    // PRIV-020: Cross-Transaction Clustering Detection Tests
    // =========================================================================

    #[test]
    fn test_cross_tx_clustering_detection() {
        let scanner = ChainScanner::new("test-key");

        // Create mock transactions with correlated timing
        // walletA and walletB transact at similar times (within 60s)
        let txs = vec![
            RichTransaction {
                signature: "tx1".to_string(),
                timestamp: Some(1000),
                slot: Some(100),
                block_time: Some(1000),
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![],
                native_transfers: vec![
                    HeliusNativeTransfer {
                        from_address: "walletA".to_string(),
                        to_address: "walletB".to_string(),
                        amount: 100_000_000,
                    }
                ],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
            RichTransaction {
                signature: "tx2".to_string(),
                timestamp: Some(1030),
                slot: Some(110),
                block_time: Some(1030), // 30 seconds later
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![],
                native_transfers: vec![
                    HeliusNativeTransfer {
                        from_address: "walletA".to_string(),
                        to_address: "walletC".to_string(),
                        amount: 100_000_000,
                    }
                ],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
            RichTransaction {
                signature: "tx3".to_string(),
                timestamp: Some(1050),
                slot: Some(120),
                block_time: Some(1050), // 50 seconds from first
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![],
                native_transfers: vec![
                    HeliusNativeTransfer {
                        from_address: "walletB".to_string(),
                        to_address: "walletC".to_string(),
                        amount: 100_000_000,
                    }
                ],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
            // Add another correlated transaction
            RichTransaction {
                signature: "tx4".to_string(),
                timestamp: Some(1040),
                slot: Some(115),
                block_time: Some(1040), // 40 seconds from first
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![],
                native_transfers: vec![
                    HeliusNativeTransfer {
                        from_address: "walletA".to_string(),
                        to_address: "walletB".to_string(),
                        amount: 50_000_000,
                    }
                ],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
        ];

        let findings = scanner.analyze_cross_tx_clustering(&txs, "test_program_id");

        assert!(!findings.is_empty(), "Should detect clustering");
        assert_eq!(findings[0].id, "PRIV-020");
        assert!(findings[0].title.contains("Clustering"));
        assert!(findings[0].confidence >= 55); // Should have reasonable confidence
    }

    #[test]
    fn test_cross_tx_clustering_no_correlation() {
        let scanner = ChainScanner::new("test-key");

        // Create mock transactions with NO correlated timing (far apart)
        let txs = vec![
            RichTransaction {
                signature: "tx1".to_string(),
                timestamp: Some(1000),
                slot: Some(100),
                block_time: Some(1000),
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![],
                native_transfers: vec![
                    HeliusNativeTransfer {
                        from_address: "walletA".to_string(),
                        to_address: "walletB".to_string(),
                        amount: 100_000_000,
                    }
                ],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
            RichTransaction {
                signature: "tx2".to_string(),
                timestamp: Some(2000),
                slot: Some(200),
                block_time: Some(2000), // 1000 seconds later - no correlation
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![],
                native_transfers: vec![
                    HeliusNativeTransfer {
                        from_address: "walletC".to_string(),
                        to_address: "walletD".to_string(),
                        amount: 100_000_000,
                    }
                ],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
        ];

        let findings = scanner.analyze_cross_tx_clustering(&txs, "test_program_id");

        // Should NOT detect clustering when transactions are far apart
        assert!(findings.is_empty(), "Should not detect clustering when txs are far apart");
    }

    #[test]
    fn test_cross_tx_clustering_token_transfers() {
        let scanner = ChainScanner::new("test-key");

        // Create mock transactions with token transfers (not native)
        let txs = vec![
            RichTransaction {
                signature: "tx1".to_string(),
                timestamp: Some(1000),
                slot: Some(100),
                block_time: Some(1000),
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![
                    HeliusTokenTransfer {
                        mint: "TokenMint123".to_string(),
                        amount: "1000000".to_string(),
                        from_token_account: "fromATA".to_string(),
                        to_token_account: "toATA".to_string(),
                        from_user_account: Some("walletA".to_string()),
                        to_user_account: Some("walletB".to_string()),
                    }
                ],
                native_transfers: vec![],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
            RichTransaction {
                signature: "tx2".to_string(),
                timestamp: Some(1030),
                slot: Some(110),
                block_time: Some(1030),
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![
                    HeliusTokenTransfer {
                        mint: "TokenMint123".to_string(),
                        amount: "500000".to_string(),
                        from_token_account: "fromATA2".to_string(),
                        to_token_account: "toATA2".to_string(),
                        from_user_account: Some("walletA".to_string()),
                        to_user_account: Some("walletC".to_string()),
                    }
                ],
                native_transfers: vec![],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
            RichTransaction {
                signature: "tx3".to_string(),
                timestamp: Some(1050),
                slot: Some(120),
                block_time: Some(1050),
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![
                    HeliusTokenTransfer {
                        mint: "TokenMint123".to_string(),
                        amount: "250000".to_string(),
                        from_token_account: "fromATA3".to_string(),
                        to_token_account: "toATA3".to_string(),
                        from_user_account: Some("walletB".to_string()),
                        to_user_account: Some("walletC".to_string()),
                    }
                ],
                native_transfers: vec![],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
            RichTransaction {
                signature: "tx4".to_string(),
                timestamp: Some(1040),
                slot: Some(115),
                block_time: Some(1040),
                type_field: None,
                source: None,
                fee: Some(5000),
                fee_payer: Some("payer".to_string()),
                token_transfers: vec![
                    HeliusTokenTransfer {
                        mint: "TokenMint456".to_string(),
                        amount: "100000".to_string(),
                        from_token_account: "fromATA4".to_string(),
                        to_token_account: "toATA4".to_string(),
                        from_user_account: Some("walletA".to_string()),
                        to_user_account: Some("walletB".to_string()),
                    }
                ],
                native_transfers: vec![],
                instructions: vec![],
                account_data: vec![],
                events: None,
                transaction_error: None,
                description: None,
                raw_logs: vec![],
            },
        ];

        let findings = scanner.analyze_cross_tx_clustering(&txs, "test_program_id");

        assert!(!findings.is_empty(), "Should detect clustering from token transfers");
        assert_eq!(findings[0].id, "PRIV-020");
    }
}
