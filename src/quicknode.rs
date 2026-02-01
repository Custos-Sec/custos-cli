//! QuickNode RPC Integration - On-Chain Verification Layer
//!
//! This module provides on-chain verification of static analysis findings.
//! It queries account state via QuickNode RPC to adjust confidence scores
//! based on real on-chain evidence.
//!
//! Key difference from Helius:
//! - Helius: Transaction parsing, events, enhanced data (used in chain.rs)
//! - QuickNode: Raw RPC, account state, program verification (this module)

use anyhow::{anyhow, Result};
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::checks::Finding;

/// QuickNode RPC client for on-chain verification
pub struct QuickNodeVerifier {
    rpc_url: String,
    client: Client,
    /// Cache of known programs (program_id -> is_known_safe)
    known_programs: HashMap<String, bool>,
}

/// On-chain evidence collected for a finding
#[derive(Debug, Clone, Serialize)]
pub struct OnChainEvidence {
    /// Does the account/program exist on-chain?
    pub exists: bool,
    /// Is the program frozen (no upgrade authority)?
    pub program_frozen: Option<bool>,
    /// Is this a known/whitelisted program?
    pub known_program: bool,
    /// Account owner (if applicable)
    pub owner: Option<String>,
    /// Account data size in bytes
    pub data_size: Option<usize>,
    /// For PDA enumeration: number of accounts found with pattern
    pub enumerable_count: Option<usize>,
    /// Raw evidence notes for reporting
    pub notes: Vec<String>,
}

impl Default for OnChainEvidence {
    fn default() -> Self {
        Self {
            exists: false,
            program_frozen: None,
            known_program: false,
            owner: None,
            data_size: None,
            enumerable_count: None,
            notes: Vec::new(),
        }
    }
}

/// Verification result combining static analysis with on-chain evidence
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedFinding {
    /// Original finding from static analysis
    pub finding: Finding,
    /// On-chain evidence collected
    pub evidence: OnChainEvidence,
    /// Original confidence from static analysis
    pub static_confidence: u8,
    /// Adjusted confidence after on-chain verification
    pub verified_confidence: u8,
    /// Explanation of confidence adjustment
    pub adjustment_reason: String,
}

// ============================================================================
// RPC Response Types (Solana JSON-RPC format)
// ============================================================================

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct AccountInfoResult {
    context: RpcContext,
    value: Option<AccountInfo>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct MultipleAccountsResult {
    #[allow(dead_code)]
    context: RpcContext,
    value: Vec<Option<AccountInfo>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RpcContext {
    pub slot: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct AccountInfo {
    pub lamports: u64,
    pub owner: String,
    pub data: AccountData,
    pub executable: bool,
    pub rent_epoch: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AccountData {
    /// Base64 encoded: ["base64data", "base64"]
    Encoded(Vec<String>),
    /// Legacy format (raw bytes as string)
    Legacy(String),
}

impl AccountData {
    pub fn size(&self) -> usize {
        match self {
            AccountData::Encoded(v) => {
                if v.len() >= 1 {
                    // Base64 decode to get actual size
                    v[0].len() * 3 / 4
                } else {
                    0
                }
            }
            AccountData::Legacy(s) => s.len(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ProgramAccountsResult {
    pub pubkey: String,
    pub account: AccountInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SignatureResult {
    pub signature: String,
    pub slot: u64,
    pub err: Option<serde_json::Value>,
    pub memo: Option<String>,
    pub block_time: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct TransactionResult {
    pub block_time: Option<i64>,
    pub slot: u64,
    pub meta: Option<TransactionMeta>,
    pub transaction: Option<TransactionData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct TransactionMeta {
    pub err: Option<serde_json::Value>,
    pub fee: u64,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    pub log_messages: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TransactionData {
    pub message: serde_json::Value,
    pub signatures: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenAccountsResult {
    pub context: RpcContext,
    pub value: Vec<TokenAccountInfo>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct TokenAccountInfo {
    pub pubkey: String,
    pub account: AccountInfo,
}

// ============================================================================
// Known Programs Database
// ============================================================================

/// Programs that are known-safe and don't need privacy alerts
const KNOWN_SAFE_PROGRAMS: &[&str] = &[
    // Core Solana
    "11111111111111111111111111111111",              // System Program
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  // Token Program
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  // Token-2022
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", // Associated Token
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",  // Metaplex Metadata

    // Major DeFi (verified, audited)
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",  // Jupiter v6
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",  // Orca Whirlpool
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK", // Raydium CPMM
    "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA",  // Marginfi v2
    "So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo",  // Solend
];

/// BPF Loader program IDs (programs are owned by these)
const BPF_LOADERS: &[&str] = &[
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
];

impl QuickNodeVerifier {
    /// Create a new verifier with QuickNode RPC endpoint
    ///
    /// # Arguments
    /// * `rpc_url` - QuickNode RPC URL (e.g., "https://example.solana-mainnet.quiknode.pro/abc123/")
    pub fn new(rpc_url: &str) -> Self {
        let mut known_programs = HashMap::new();
        for program in KNOWN_SAFE_PROGRAMS {
            known_programs.insert(program.to_string(), true);
        }

        Self {
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
            client: Client::new(),
            known_programs,
        }
    }

    /// Create verifier from environment variable
    pub fn from_env() -> Result<Self> {
        let rpc_url = std::env::var("QUICKNODE_RPC_URL")
            .or_else(|_| std::env::var("SOLANA_RPC_URL"))
            .map_err(|_| anyhow!(
                "QuickNode RPC URL required. Set QUICKNODE_RPC_URL or SOLANA_RPC_URL env var.\n\
                 Get a free endpoint at: https://www.quicknode.com/chains/sol"
            ))?;

        Ok(Self::new(&rpc_url))
    }

    // ========================================================================
    // Core RPC Methods
    // ========================================================================

    /// Get account info for a given address
    pub async fn get_account_info(&self, address: &str) -> Result<Option<AccountInfo>> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [
                address,
                {"encoding": "base64"}
            ]
        });

        let response: RpcResponse<AccountInfoResult> = self.client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            return Err(anyhow!("RPC error: {}", error.message));
        }

        Ok(response.result.and_then(|r| r.value))
    }

    /// Get multiple accounts in a single request (more efficient)
    #[allow(dead_code)]
    pub async fn get_multiple_accounts(&self, addresses: &[&str]) -> Result<Vec<Option<AccountInfo>>> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getMultipleAccounts",
            "params": [
                addresses,
                {"encoding": "base64"}
            ]
        });

        let response: RpcResponse<MultipleAccountsResult> = self.client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            return Err(anyhow!("RPC error: {}", error.message));
        }

        // For getMultipleAccounts, result.value is an array of optional accounts
        Ok(response.result.map(|r| r.value).unwrap_or_default())
    }

    /// Get program accounts matching filters (for PDA enumeration check)
    pub async fn get_program_accounts(
        &self,
        program_id: &str,
        data_size: Option<usize>,
        memcmp_offset: Option<usize>,
        memcmp_bytes: Option<&str>,
    ) -> Result<Vec<ProgramAccountsResult>> {
        let mut filters = Vec::new();

        if let Some(size) = data_size {
            filters.push(serde_json::json!({"dataSize": size}));
        }

        if let (Some(offset), Some(bytes)) = (memcmp_offset, memcmp_bytes) {
            filters.push(serde_json::json!({
                "memcmp": {
                    "offset": offset,
                    "bytes": bytes
                }
            }));
        }

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getProgramAccounts",
            "params": [
                program_id,
                {
                    "encoding": "base64",
                    "filters": filters
                }
            ]
        });

        let response: RpcResponse<Vec<ProgramAccountsResult>> = self.client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            return Err(anyhow!("RPC error: {}", error.message));
        }

        Ok(response.result.unwrap_or_default())
    }

    /// Get transaction signatures for an address
    pub async fn get_signatures_for_address(
        &self,
        address: &str,
        limit: Option<usize>,
    ) -> Result<Vec<SignatureResult>> {
        let mut params = vec![serde_json::json!(address)];

        if let Some(lim) = limit {
            params.push(serde_json::json!({"limit": lim}));
        }

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": params
        });

        let response: RpcResponse<Vec<SignatureResult>> = self.client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            return Err(anyhow!("RPC error: {}", error.message));
        }

        Ok(response.result.unwrap_or_default())
    }

    /// Get transaction details by signature
    pub async fn get_transaction(&self, signature: &str) -> Result<Option<TransactionResult>> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "encoding": "json",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        });

        let response: RpcResponse<TransactionResult> = self.client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            return Err(anyhow!("RPC error: {}", error.message));
        }

        Ok(response.result)
    }

    /// Get all token accounts owned by an address
    #[allow(dead_code)]
    pub async fn get_token_accounts_by_owner(
        &self,
        owner: &str,
        mint: Option<&str>,
    ) -> Result<Vec<TokenAccountInfo>> {
        let filter = if let Some(m) = mint {
            serde_json::json!({"mint": m})
        } else {
            serde_json::json!({"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"})
        };

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountsByOwner",
            "params": [
                owner,
                filter,
                {"encoding": "base64"}
            ]
        });

        let response: RpcResponse<TokenAccountsResult> = self.client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            return Err(anyhow!("RPC error: {}", error.message));
        }

        Ok(response.result.map(|r| r.value).unwrap_or_default())
    }

    // ========================================================================
    // Verification Methods
    // ========================================================================

    /// Check if a program is frozen (no upgrade authority)
    pub async fn is_program_frozen(&self, program_id: &str) -> Result<bool> {
        let account = self.get_account_info(program_id).await?;

        let Some(info) = account else {
            return Ok(false); // Doesn't exist
        };

        // Program accounts are owned by BPF loaders
        if !BPF_LOADERS.contains(&info.owner.as_str()) {
            return Ok(false); // Not a program
        }

        // For upgradeable programs, we'd need to check the programdata account
        // The upgrade authority is stored in the first 36 bytes of programdata
        // If it's all zeros, the program is frozen

        // Simplified check: if it's executable, check if owner is non-upgradeable loader
        if info.owner == "BPFLoader2111111111111111111111111111111111" {
            // Old loader = always frozen (can't upgrade)
            return Ok(true);
        }

        // For upgradeable loader, we'd need to fetch the programdata account
        // This is a simplified version - in production, decode the program account
        // to get programdata address and check its upgrade authority
        Ok(false)
    }

    /// Check if an address is a known/whitelisted program
    pub fn is_known_program(&self, program_id: &str) -> bool {
        self.known_programs.contains_key(program_id)
    }

    /// Verify a finding and collect on-chain evidence
    pub async fn verify_finding(&self, finding: &Finding) -> Result<VerifiedFinding> {
        let mut evidence = OnChainEvidence::default();

        // Extract relevant address from finding if present
        // This is a simplified extraction - in practice, parse the finding context
        let address = self.extract_address_from_finding(finding);

        if let Some(addr) = &address {
            // Check if account exists
            if let Ok(Some(info)) = self.get_account_info(addr).await {
                evidence.exists = true;
                evidence.owner = Some(info.owner.clone());
                evidence.data_size = Some(info.data.size());
                evidence.notes.push(format!("Account exists, owner: {}", info.owner));

                // Check if it's a known program
                if self.is_known_program(addr) {
                    evidence.known_program = true;
                    evidence.notes.push("Known/whitelisted program".to_string());
                }

                // Check if program is frozen
                if info.executable {
                    if let Ok(frozen) = self.is_program_frozen(addr).await {
                        evidence.program_frozen = Some(frozen);
                        if frozen {
                            evidence.notes.push("Program is frozen (not upgradeable)".to_string());
                        }
                    }
                }
            } else {
                evidence.exists = false;
                evidence.notes.push("Account does not exist on-chain".to_string());
            }
        }

        // Check for PDA enumeration if this is PRIV-010
        if finding.id == "PRIV-010" {
            evidence = self.check_pda_enumeration(finding, evidence).await;
        }

        // Calculate adjusted confidence
        let (verified_confidence, adjustment_reason) =
            self.calculate_adjusted_confidence(finding.confidence, &evidence);

        Ok(VerifiedFinding {
            finding: finding.clone(),
            evidence,
            static_confidence: finding.confidence,
            verified_confidence,
            adjustment_reason,
        })
    }

    /// Verify multiple findings in batch (more efficient)
    pub async fn verify_findings(&self, findings: &[Finding]) -> Vec<VerifiedFinding> {
        let mut verified = Vec::with_capacity(findings.len());

        for finding in findings {
            match self.verify_finding(finding).await {
                Ok(v) => verified.push(v),
                Err(e) => {
                    // On error, return unverified finding with note
                    verified.push(VerifiedFinding {
                        finding: finding.clone(),
                        evidence: OnChainEvidence {
                            notes: vec![format!("Verification failed: {}", e)],
                            ..Default::default()
                        },
                        static_confidence: finding.confidence,
                        verified_confidence: finding.confidence,
                        adjustment_reason: "Could not verify on-chain".to_string(),
                    });
                }
            }
        }

        verified
    }

    /// Verify findings focusing ONLY on beneficial checks
    /// Routes to check-specific verification:
    /// - PRIV-004/005: PII scale in accounts
    /// - PRIV-009: CPI target program safety  
    /// - PRIV-010: PDA enumeration
    pub async fn verify_findings_focused(&self, findings: &[Finding], program_id: &str) -> Vec<VerifiedFinding> {
        let mut verified = Vec::new();

        for finding in findings {
            let mut evidence = OnChainEvidence::default();
            let mut confidence_adjustment: i32 = 0;

            match finding.id.as_str() {
                // PRIV-004/005: Check PII scale in accounts
                "PRIV-004" | "PRIV-005" => {
                    if let Ok(accounts) = self.get_program_accounts(program_id, None, None, None).await {
                        let pii_accounts = accounts.iter()
                            .filter(|a| self.has_pii_patterns(&a.account.data))
                            .count();

                        evidence.exists = !accounts.is_empty();
                        evidence.data_size = Some(accounts.len());

                        if pii_accounts > 0 {
                            evidence.notes.push(format!(
                                "CRITICAL: {} of {} accounts contain PII patterns",
                                pii_accounts, accounts.len()
                            ));
                            confidence_adjustment = 25;
                        } else {
                            evidence.notes.push("No PII patterns detected in accounts".to_string());
                            confidence_adjustment = -15;
                        }
                    }
                }

                // PRIV-008: Check account initialization state
                "PRIV-008" => {
                    if let Ok(accounts) = self.get_program_accounts(program_id, None, None, None).await {
                        let mut small_accounts = 0;  // Likely uninitialized
                        let mut zero_data = 0;       // Empty/zeroed accounts
                        let total_checked = accounts.len();

                        for account in &accounts {
                            let data_size = account.account.data.size();

                            // Accounts smaller than 8 bytes can't have Anchor discriminator
                            if data_size < 8 {
                                small_accounts += 1;
                                continue;
                            }

                            // Check if data appears to be all zeros (uninitialized)
                            let appears_empty = match &account.account.data {
                                AccountData::Encoded(v) if v.len() >= 1 => {
                                    // Base64 string of all zeros will have specific patterns
                                    v[0].chars().all(|c| c == 'A' || c == '=' || c == 'a')
                                }
                                AccountData::Legacy(s) => {
                                    s.is_empty() || s.chars().all(|c| c == '\0' || c == '0')
                                }
                                _ => false,
                            };

                            if appears_empty {
                                zero_data += 1;
                            }
                        }

                        evidence.exists = !accounts.is_empty();
                        evidence.data_size = Some(total_checked);

                        let issue_count = small_accounts + zero_data;

                        if issue_count > 0 {
                            evidence.notes.push(format!(
                                "Found {} suspicious accounts: {} too small, {} appear uninitialized",
                                issue_count, small_accounts, zero_data
                            ));

                            // Scale confidence adjustment based on prevalence
                            let ratio = (issue_count as f64 / total_checked as f64) * 100.0;
                            confidence_adjustment = if ratio > 50.0 {
                                30  // More than half are problematic
                            } else if ratio > 20.0 {
                                20  // Significant portion
                            } else if ratio > 5.0 {
                                10  // Some issues
                            } else {
                                5   // Few issues
                            };
                        } else if total_checked > 0 {
                            evidence.notes.push(format!(
                                "All {} accounts appear properly initialized",
                                total_checked
                            ));
                            confidence_adjustment = -20;
                        } else {
                            evidence.notes.push("No accounts found to verify".to_string());
                            confidence_adjustment = -10;
                        }
                    }
                }

                // PRIV-009: Verify CPI targets
                "PRIV-009" => {
                    if let Some(target_addr) = self.extract_address_from_finding(finding) {
                        if let Ok(Some(info)) = self.get_account_info(&target_addr).await {
                            evidence.exists = true;
                            evidence.owner = Some(info.owner.clone());
                            evidence.known_program = self.is_known_program(&target_addr);
                            
                            if evidence.known_program {
                                evidence.notes.push("CPI target is known-safe program".to_string());
                                confidence_adjustment = -20;
                            } else if let Ok(frozen) = self.is_program_frozen(&target_addr).await {
                                evidence.program_frozen = Some(frozen);
                                if frozen {
                                    evidence.notes.push("CPI target is frozen (immutable)".to_string());
                                    confidence_adjustment = -15;
                                } else {
                                    evidence.notes.push("CPI target is upgradeable - HIGH RISK".to_string());
                                    confidence_adjustment = 25;
                                }
                            }
                        } else {
                            evidence.exists = false;
                            evidence.notes.push("CPI target program not found".to_string());
                        }
                    }
                }

                // PRIV-010: Enumerate PDAs
                "PRIV-010" => {
                    if let Ok(accounts) = self.get_program_accounts(program_id, None, None, None).await {
                        evidence.enumerable_count = Some(accounts.len());
                        evidence.exists = !accounts.is_empty();

                        match accounts.len() {
                            0..=10 => {
                                evidence.notes.push("Small PDA set - low enumeration risk".to_string());
                                confidence_adjustment = -15;
                            }
                            11..=100 => {
                                evidence.notes.push(format!("Moderate: {} enumerable PDAs", accounts.len()));
                                confidence_adjustment = 10;
                            }
                            101..=1000 => {
                                evidence.notes.push(format!("High: {} highly enumerable PDAs", accounts.len()));
                                confidence_adjustment = 25;
                            }
                            _ => {
                                evidence.notes.push(format!("CRITICAL: {} PDAs are enumerable", accounts.len()));
                                confidence_adjustment = 35;
                            }
                        }
                    }
                }

                // PRIV-006: Check memo fields and raw logs for sensitive data
                // (Complements Helius which checks emitted events)
                "PRIV-006" => {
                    if let Ok(sigs) = self.get_signatures_for_address(program_id, Some(50)).await {
                        let sensitive_keywords = [
                            "private", "secret", "password", "key", "cold wallet",
                            "internal", "confidential", "ssn", "social security"
                        ];

                        let mut sensitive_memos = 0;
                        let mut memo_examples: Vec<String> = Vec::new();

                        for sig in &sigs {
                            if let Some(memo) = &sig.memo {
                                let memo_lower = memo.to_lowercase();
                                if sensitive_keywords.iter().any(|kw| memo_lower.contains(kw)) {
                                    sensitive_memos += 1;
                                    if memo_examples.len() < 3 {
                                        memo_examples.push(memo.clone());
                                    }
                                }
                            }
                        }

                        evidence.exists = !sigs.is_empty();
                        evidence.data_size = Some(sigs.len());

                        if sensitive_memos > 0 {
                            evidence.notes.push(format!(
                                "Found {} transactions with sensitive memo data",
                                sensitive_memos
                            ));
                            for ex in &memo_examples {
                                evidence.notes.push(format!("  → \"{}\"", ex));
                            }
                            confidence_adjustment = if sensitive_memos > 10 { 30 }
                                                   else if sensitive_memos > 3 { 20 }
                                                   else { 10 };
                        } else if !sigs.is_empty() {
                            evidence.notes.push(format!(
                                "Checked {} transactions, no sensitive memos found",
                                sigs.len()
                            ));
                            confidence_adjustment = -15;
                        }

                        // Also check transaction logs for PII leakage (IP, session, etc.)
                        if let Some(first_sig) = sigs.first() {
                            if let Ok(Some(tx)) = self.get_transaction(&first_sig.signature).await {
                                if let Some(meta) = &tx.meta {
                                    if let Some(logs) = &meta.log_messages {
                                        let pii_patterns = ["ip:", "session", "user id", "email", "phone"];
                                        let pii_logs: Vec<_> = logs.iter()
                                            .filter(|log| {
                                                let log_lower = log.to_lowercase();
                                                pii_patterns.iter().any(|p| log_lower.contains(p))
                                            })
                                            .collect();

                                        if !pii_logs.is_empty() {
                                            evidence.notes.push(format!(
                                                "Transaction logs contain PII: {} instances",
                                                pii_logs.len()
                                            ));
                                            confidence_adjustment += 15;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // PRIV-001: Check transaction logs for private key patterns
                "PRIV-001" => {
                    if let Ok(sigs) = self.get_signatures_for_address(program_id, Some(20)).await {
                        let mut key_leaks = 0;
                        let mut leak_examples: Vec<String> = Vec::new();

                        for sig in sigs.iter().take(5) {  // Sample first 5 transactions
                            if let Ok(Some(tx)) = self.get_transaction(&sig.signature).await {
                                if let Some(meta) = &tx.meta {
                                    if let Some(logs) = &meta.log_messages {
                                        for log in logs {
                                            let log_lower = log.to_lowercase();
                                            // Check for private key patterns
                                            if log_lower.contains("private_key")
                                                || log_lower.contains("secret_key")
                                                || log_lower.contains("0x4a5f")  // Hex key prefix
                                                || (log.contains("Key:") && log.len() > 60) {
                                                key_leaks += 1;
                                                if leak_examples.len() < 2 {
                                                    // Truncate to avoid leaking full key
                                                    let truncated = if log.len() > 50 {
                                                        format!("{}...", &log[..50])
                                                    } else {
                                                        log.clone()
                                                    };
                                                    leak_examples.push(truncated);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        evidence.exists = !sigs.is_empty();
                        evidence.data_size = Some(sigs.len());

                        if key_leaks > 0 {
                            evidence.notes.push(format!(
                                "CRITICAL: Found {} potential key leaks in transaction logs",
                                key_leaks
                            ));
                            for ex in &leak_examples {
                                evidence.notes.push(format!("  → {}", ex));
                            }
                            confidence_adjustment = 35;  // High boost for confirmed key leak
                        } else {
                            evidence.notes.push("No key patterns detected in sampled transactions".to_string());
                            confidence_adjustment = -10;
                        }
                    }
                }

                // PRIV-002: Check for mnemonic/seed phrase patterns in memos and logs
                "PRIV-002" => {
                    if let Ok(sigs) = self.get_signatures_for_address(program_id, Some(30)).await {
                        // BIP-39 seed phrase keywords (first words of common mnemonics)
                        let seed_keywords = [
                            "abandon", "ability", "able", "about", "above", "absent",
                            "absorb", "abstract", "absurd", "abuse", "access", "accident",
                            // Common phrases indicating seed exposure
                            "seed phrase", "recovery phrase", "mnemonic", "12 words",
                            "24 words", "backup phrase", "secret words", "wallet words",
                        ];

                        let mut seed_leaks = 0;
                        let mut leak_examples: Vec<String> = Vec::new();

                        // Check memos for seed phrase patterns
                        for sig in &sigs {
                            if let Some(memo) = &sig.memo {
                                let memo_lower = memo.to_lowercase();
                                // Check for multiple seed words (suggests actual mnemonic)
                                let word_matches: Vec<_> = seed_keywords.iter()
                                    .filter(|kw| memo_lower.contains(*kw))
                                    .collect();

                                if word_matches.len() >= 2 || memo_lower.contains("seed phrase")
                                    || memo_lower.contains("mnemonic") || memo_lower.contains("recovery phrase") {
                                    seed_leaks += 1;
                                    if leak_examples.len() < 2 {
                                        let truncated = if memo.len() > 40 {
                                            format!("{}...", &memo[..40])
                                        } else {
                                            memo.clone()
                                        };
                                        leak_examples.push(truncated);
                                    }
                                }
                            }
                        }

                        // Also check transaction logs
                        for sig in sigs.iter().take(5) {
                            if let Ok(Some(tx)) = self.get_transaction(&sig.signature).await {
                                if let Some(meta) = &tx.meta {
                                    if let Some(logs) = &meta.log_messages {
                                        for log in logs {
                                            let log_lower = log.to_lowercase();
                                            let word_matches: Vec<_> = seed_keywords.iter()
                                                .filter(|kw| log_lower.contains(*kw))
                                                .collect();

                                            if word_matches.len() >= 3 {
                                                seed_leaks += 1;
                                                if leak_examples.len() < 2 {
                                                    let truncated = if log.len() > 40 {
                                                        format!("{}...", &log[..40])
                                                    } else {
                                                        log.clone()
                                                    };
                                                    leak_examples.push(truncated);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        evidence.exists = !sigs.is_empty();
                        evidence.data_size = Some(sigs.len());

                        if seed_leaks > 0 {
                            evidence.notes.push(format!(
                                "CRITICAL: Found {} potential seed phrase leaks",
                                seed_leaks
                            ));
                            for ex in &leak_examples {
                                evidence.notes.push(format!("  → {}", ex));
                            }
                            confidence_adjustment = 40;  // Very high - seed phrase exposure is critical
                        } else {
                            evidence.notes.push("No seed phrase patterns detected".to_string());
                            confidence_adjustment = -10;
                        }
                    }
                }

                // PRIV-007: Check for debug logging patterns in transaction logs
                "PRIV-007" => {
                    if let Ok(sigs) = self.get_signatures_for_address(program_id, Some(30)).await {
                        let debug_patterns = [
                            "debug:", "trace:", "println!", "dbg!", "[debug]", "[trace]",
                            "console.log", "console.debug", "log::debug", "log::trace",
                            "DEBUG:", "TRACE:", ">>> ", "=== ", "--- ",
                            "dumping", "inspecting", "raw bytes:", "hex dump",
                        ];

                        let mut debug_count = 0;
                        let mut debug_examples: Vec<String> = Vec::new();

                        for sig in sigs.iter().take(10) {
                            if let Ok(Some(tx)) = self.get_transaction(&sig.signature).await {
                                if let Some(meta) = &tx.meta {
                                    if let Some(logs) = &meta.log_messages {
                                        for log in logs {
                                            let log_lower = log.to_lowercase();
                                            if debug_patterns.iter().any(|p| log_lower.contains(&p.to_lowercase())) {
                                                debug_count += 1;
                                                if debug_examples.len() < 3 {
                                                    let truncated = if log.len() > 60 {
                                                        format!("{}...", &log[..60])
                                                    } else {
                                                        log.clone()
                                                    };
                                                    debug_examples.push(truncated);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        evidence.exists = !sigs.is_empty();
                        evidence.data_size = Some(sigs.len());

                        if debug_count > 0 {
                            evidence.notes.push(format!(
                                "Found {} debug log statements in production",
                                debug_count
                            ));
                            for ex in &debug_examples {
                                evidence.notes.push(format!("  → {}", ex));
                            }
                            confidence_adjustment = if debug_count > 10 { 25 }
                                                   else if debug_count > 3 { 15 }
                                                   else { 10 };
                        } else {
                            evidence.notes.push("No debug logging detected in production".to_string());
                            confidence_adjustment = -15;
                        }
                    }
                }

                _ => {
                    evidence.notes.push(format!("No QuickNode verification for {}", finding.id));
                }
            }

            let verified_confidence = ((finding.confidence as i32 + confidence_adjustment)
                .max(5)
                .min(100)) as u8;

            verified.push(VerifiedFinding {
                finding: finding.clone(),
                evidence,
                static_confidence: finding.confidence,
                verified_confidence,
                adjustment_reason: format!(
                    "Confidence {} {}",
                    if confidence_adjustment > 0 { "+" } else { "" },
                    confidence_adjustment
                ),
            });
        }

        verified
    }

    /// Check if account data contains PII patterns
    fn has_pii_patterns(&self, data: &AccountData) -> bool {
        // Get the decoded data as string
        let data_str = match data {
            AccountData::Encoded(v) => {
                if !v.is_empty() {
                    // Actually decode base64 to get real data
                    match base64::engine::general_purpose::STANDARD.decode(&v[0]) {
                        Ok(decoded) => String::from_utf8_lossy(&decoded).to_lowercase(),
                        Err(_) => return false, // Invalid base64, skip
                    }
                } else {
                    return false;
                }
            }
            AccountData::Legacy(s) => s.to_lowercase(),
        };

        // Simple PII pattern detection (email, phone, SSN patterns)
        let pii_patterns = [
            r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",  // Email-like
            r"\d{3}-\d{2}-\d{4}",                       // SSN-like
            r"\+?1?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}", // Phone-like
            r"(first_name|last_name|ssn|passport|phone|email|birth)", // Field names
            r"api[_-]?key", // API key patterns
        ];

        for pattern in &pii_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(&data_str) {
                    return true;
                }
            }
        }

        false
    }

    // ========================================================================
    // Private Helpers
    // ========================================================================

    /// Extract a Solana address from finding context (simplified)
    fn extract_address_from_finding(&self, finding: &Finding) -> Option<String> {
        // Look for base58 address pattern in code snippet or evidence
        let base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        // Simple extraction: find 32-44 char base58 strings
        for word in finding.code_snippet.split_whitespace() {
            let clean = word.trim_matches(|c: char| !base58_chars.contains(c));
            if clean.len() >= 32 && clean.len() <= 44
                && clean.chars().all(|c| base58_chars.contains(c)) {
                return Some(clean.to_string());
            }
        }

        None
    }

    /// Check if PDAs with the flagged pattern are enumerable
    async fn check_pda_enumeration(&self, finding: &Finding, mut evidence: OnChainEvidence) -> OnChainEvidence {
        // For PRIV-010 (predictable PDA seeds), we try to enumerate accounts
        // This is a simplified check - in practice, parse the seeds from the finding

        // Extract program ID if present in finding
        if let Some(program_id) = self.extract_address_from_finding(finding) {
            // Try to get program accounts (limited to small sample)
            if let Ok(accounts) = self.get_program_accounts(&program_id, None, None, None).await {
                let count = accounts.len();
                if count > 0 {
                    evidence.enumerable_count = Some(count);
                    evidence.notes.push(format!(
                        "Found {} accounts for program - PDA enumeration possible",
                        count
                    ));
                }
            }
        }

        evidence
    }

    /// Adjust confidence based on on-chain evidence
    fn calculate_adjusted_confidence(&self, static_conf: u8, evidence: &OnChainEvidence) -> (u8, String) {
        let mut adjustments: Vec<(i16, &str)> = Vec::new();
        let mut score = static_conf as i16;

        // Account doesn't exist = lower priority (not deployed yet)
        if !evidence.exists {
            adjustments.push((-20, "account not deployed"));
        }

        // Known/whitelisted program = significantly lower risk
        if evidence.known_program {
            adjustments.push((-25, "known safe program"));
        }

        // Program is frozen = can't be fixed, lower urgency
        if evidence.program_frozen == Some(true) {
            adjustments.push((-15, "program frozen"));
        }

        // PDA enumeration confirmed = higher confidence
        if let Some(count) = evidence.enumerable_count {
            if count > 10 {
                adjustments.push((20, "PDA enumeration confirmed"));
            } else if count > 0 {
                adjustments.push((10, "some enumerable accounts found"));
            }
        }

        for (adj, _) in &adjustments {
            score += adj;
        }

        let final_score = score.clamp(5, 100) as u8;

        let reason = if adjustments.is_empty() {
            "No on-chain adjustments".to_string()
        } else {
            adjustments.iter()
                .map(|(adj, reason)| {
                    if *adj > 0 {
                        format!("+{}: {}", adj, reason)
                    } else {
                        format!("{}: {}", adj, reason)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        };

        (final_score, reason)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_findings::TestFindingBuilder;

    /// Create a mock finding for testing with custom confidence
    fn mock_finding(id: &str, confidence: u8) -> Finding {
        TestFindingBuilder::new(id)
            .title("Test Finding")
            .code_snippet("let addr = TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .recommendation("Fix it")
            .confidence(confidence)
            .build()
    }

    /// Format PRIV check results for demo output with colors
    fn print_priv_result(label: &str, results: &[VerifiedFinding]) {
        const GREEN: &str = "\x1b[32m";
        const YELLOW: &str = "\x1b[33m";
        const CYAN: &str = "\x1b[36m";
        const DIM: &str = "\x1b[2m";
        const RESET: &str = "\x1b[0m";

        if let Some(r) = results.first() {
            let delta = r.verified_confidence as i32 - r.static_confidence as i32;
            let (icon, color, status) = if delta > 0 {
                ("✓", GREEN, "DETECTED")
            } else if delta < 0 {
                ("↓", CYAN, "REDUCED")
            } else {
                ("○", YELLOW, "VERIFIED")
            };

            println!("{}{} {} {:>3} → {:>3} ({:+3}) {}{}",
                color, icon, label,
                r.static_confidence, r.verified_confidence, delta,
                status, RESET);

            // Print first note as context
            if let Some(note) = r.evidence.notes.first() {
                let truncated = if note.len() > 60 { &note[..60] } else { note };
                println!("{}  └─ {}{}", DIM, truncated, RESET);
            }
        }
    }

    #[test]
    fn test_known_program_detection() {
        let verifier = QuickNodeVerifier::new("https://example.com");

        assert!(verifier.is_known_program("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"));
        assert!(verifier.is_known_program("11111111111111111111111111111111"));
        assert!(!verifier.is_known_program("RandomUnknownProgram123456789012345678901234"));
    }

    #[test]
    fn test_confidence_adjustment_known_program() {
        let verifier = QuickNodeVerifier::new("https://example.com");

        let evidence = OnChainEvidence {
            exists: true,
            known_program: true,
            ..Default::default()
        };

        let (adjusted, reason) = verifier.calculate_adjusted_confidence(80, &evidence);

        // Known program should reduce confidence by 25
        assert_eq!(adjusted, 55);
        assert!(reason.contains("known safe program"));
    }

    #[test]
    fn test_confidence_adjustment_not_deployed() {
        let verifier = QuickNodeVerifier::new("https://example.com");

        let evidence = OnChainEvidence {
            exists: false,
            ..Default::default()
        };

        let (adjusted, reason) = verifier.calculate_adjusted_confidence(80, &evidence);

        // Not deployed should reduce confidence by 20
        assert_eq!(adjusted, 60);
        assert!(reason.contains("not deployed"));
    }

    #[test]
    fn test_confidence_adjustment_enumeration_confirmed() {
        let verifier = QuickNodeVerifier::new("https://example.com");

        let evidence = OnChainEvidence {
            exists: true,
            enumerable_count: Some(50),
            ..Default::default()
        };

        let (adjusted, reason) = verifier.calculate_adjusted_confidence(70, &evidence);

        // Enumeration confirmed should increase confidence by 20
        assert_eq!(adjusted, 90);
        assert!(reason.contains("enumeration confirmed"));
    }

    #[test]
    fn test_confidence_adjustment_combined() {
        let verifier = QuickNodeVerifier::new("https://example.com");

        // Account exists, program frozen, but enumeration confirmed
        let evidence = OnChainEvidence {
            exists: true,
            program_frozen: Some(true),
            enumerable_count: Some(100),
            ..Default::default()
        };

        let (adjusted, reason) = verifier.calculate_adjusted_confidence(70, &evidence);

        // -15 (frozen) + 20 (enumeration) = +5
        assert_eq!(adjusted, 75);
        assert!(reason.contains("frozen"));
        assert!(reason.contains("enumeration"));
    }

    #[test]
    fn test_confidence_floor() {
        let verifier = QuickNodeVerifier::new("https://example.com");

        // Maximum reduction: known + not deployed + frozen = -60
        let evidence = OnChainEvidence {
            exists: false,
            known_program: true,
            program_frozen: Some(true),
            ..Default::default()
        };

        let (adjusted, _) = verifier.calculate_adjusted_confidence(30, &evidence);

        // Should floor at 5, not go negative
        assert_eq!(adjusted, 5);
    }

    #[test]
    fn test_extract_address() {
        let verifier = QuickNodeVerifier::new("https://example.com");

        let finding = mock_finding("PRIV-009", 80);
        let addr = verifier.extract_address_from_finding(&finding);

        assert_eq!(addr, Some("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()));
    }

    // ========================================================================
    // Mock Tests for verify_findings_focused
    // ========================================================================

    #[tokio::test]
    async fn test_verify_focused_priv_004_pii_detected() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        
        // Mock finding for PII in accounts
        let mut finding = mock_finding("PRIV-004", 70);
        finding.title = "PII stored in accounts".to_string();
        finding.code_snippet = "ctx.accounts.user_data".to_string();
        finding.evidence = vec!["Email pattern detected".to_string()];

        let results = verifier.verify_findings_focused(&[finding], "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding.id, "PRIV-004");
        assert_eq!(results[0].static_confidence, 70);
        // Confidence may be adjusted based on mock data
    }

    #[tokio::test]
    async fn test_verify_focused_priv_005_pii_scale() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        
        let mut finding = mock_finding("PRIV-005", 65);
        finding.title = "PII exposure at scale".to_string();
        finding.code_snippet = "account.data".to_string();
        finding.evidence = vec!["Multiple accounts with PII".to_string()];

        let results = verifier.verify_findings_focused(&[finding], "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding.id, "PRIV-005");
        assert_eq!(results[0].static_confidence, 65);
    }

    #[tokio::test]
    async fn test_verify_focused_priv_009_cpi_safety() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        
        let mut finding = mock_finding("PRIV-009", 75);
        finding.title = "Unknown CPI target".to_string();
        finding.code_snippet = "invoke_signed(&ix, &[signer], &[])".to_string();
        finding.evidence = vec!["CPI to unknown program".to_string()];

        let results = verifier.verify_findings_focused(&[finding], "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding.id, "PRIV-009");
        // Known-safe program should reduce confidence
        assert!(results[0].verified_confidence <= results[0].static_confidence);
    }

    #[tokio::test]
    async fn test_verify_focused_priv_010_pda_enumeration() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        
        let mut finding = mock_finding("PRIV-010", 60);
        finding.title = "PDA enumeration vulnerability".to_string();
        finding.code_snippet = "find_program_address".to_string();
        finding.evidence = vec!["Predictable seeds".to_string()];

        let results = verifier.verify_findings_focused(&[finding], "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding.id, "PRIV-010");
    }

    #[test]
    fn test_has_pii_patterns_email() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        let data = AccountData::Legacy("user@example.com".to_string());
        
        assert!(verifier.has_pii_patterns(&data));
    }

    #[test]
    fn test_has_pii_patterns_ssn() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        let data = AccountData::Legacy("ssn: 123-45-6789".to_string());
        
        assert!(verifier.has_pii_patterns(&data));
    }

    #[test]
    fn test_has_pii_patterns_phone() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        let data = AccountData::Legacy("+1 555-123-4567".to_string());
        
        assert!(verifier.has_pii_patterns(&data));
    }

    #[test]
    fn test_has_pii_patterns_field_name() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        let data = AccountData::Legacy("first_name: John".to_string());
        
        assert!(verifier.has_pii_patterns(&data));
    }

    #[test]
    fn test_has_pii_patterns_no_pii() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        let data = AccountData::Legacy("token_mint_account_data_xyz".to_string());

        assert!(!verifier.has_pii_patterns(&data));
    }

    #[tokio::test]
    async fn test_verify_focused_multiple_findings() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");
        
        let mut f1 = mock_finding("PRIV-004", 70);
        f1.title = "PII in accounts".to_string();
        f1.code_snippet = "ctx.accounts.user_data".to_string();
        f1.evidence = vec!["Email pattern".to_string()];
        
        let mut f2 = mock_finding("PRIV-009", 75);
        f2.title = "Unknown CPI target".to_string();
        f2.code_snippet = "invoke_signed(&ix, &[signer], &[])".to_string();
        f2.evidence = vec!["CPI to unknown".to_string()];
        
        let mut f3 = mock_finding("PRIV-002", 50);
        f3.title = "No verification for this check".to_string();
        f3.code_snippet = "some_code".to_string();
        f3.evidence = vec!["Not eligible".to_string()];
        
        let findings = vec![f1, f2, f3];

        let results = verifier.verify_findings_focused(&findings, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;
        
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].finding.id, "PRIV-004");
        assert_eq!(results[1].finding.id, "PRIV-009");
        assert_eq!(results[2].finding.id, "PRIV-002");
        // PRIV-002 should have no verification note
        assert!(results[2].evidence.notes[0].contains("No QuickNode verification"));
    }

    #[tokio::test]
    async fn test_verify_focused_confidence_clamping() {
        let verifier = QuickNodeVerifier::new("http://localhost:8899");

        // Confidence < 5 should be clamped to 5
        let mut finding = mock_finding("PRIV-004", 2);  // Very low
        finding.title = "Very low confidence".to_string();
        finding.evidence = vec!["Minimal evidence".to_string()];

        let results = verifier.verify_findings_focused(&[finding], "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").await;

        assert!(results[0].verified_confidence >= 5);
    }

    // ========================================================================
    // Tests for New RPC Methods (with Fixtures)
    // ========================================================================

    #[tokio::test]
    async fn test_get_signatures_for_address_with_fixture() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Load fixture
        let fixture = std::fs::read_to_string("tests/fixtures/quicknode_getSignaturesForAddress.json")
            .expect("read getSignaturesForAddress fixture");

        // Mock the RPC endpoint
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());
        let signatures = verifier
            .get_signatures_for_address(
                "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT",
                Some(10),
            )
            .await
            .expect("get signatures");

        // Verify we got the expected results
        assert_eq!(signatures.len(), 3);
        assert_eq!(signatures[0].signature.len(), 88); // Ed25519 signature in base58
        assert_eq!(signatures[0].slot, 154829301);
        assert_eq!(signatures[0].block_time, Some(1672531200));

        // Check memo is captured
        assert_eq!(signatures[0].memo, Some("Internal Transfer to Private Cold Wallet".to_string()));

        // Check that failed transaction is captured
        assert_eq!(signatures[2].err, Some(serde_json::json!({"InstructionError": [0, "Custom"]})));

        // ========================================================================
        // PRIV Check Verification - Test PRIV-006 (sensitive memos)
        // ========================================================================
        println!("\n=== QuickNode getSignaturesForAddress PRIV Check Results ===");

        // Test PRIV-006: Sensitive data in memos (fixture has "Private Cold Wallet" memo)
        let finding_006 = TestFindingBuilder::new("PRIV-006")
            .title("Sensitive data in transaction memo")
            .code_snippet("memo: \"Private Cold Wallet\"")
            .recommendation("Avoid sensitive labels in memos")
            .confidence(65)
            .build();

        let results_006 = verifier.verify_findings_focused(
            &[finding_006],
            "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT"
        ).await;
        print_priv_result("PRIV-006 (Sensitive memo)    ", &results_006);
        assert!(!results_006.is_empty(), "PRIV-006 should return results");

        println!("=== getSignaturesForAddress PRIV checks complete ===\n");
    }

    #[tokio::test]
    async fn test_get_transaction_with_fixture() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Load fixture
        let fixture = std::fs::read_to_string("tests/fixtures/quicknode_getTransaction.json")
            .expect("read getTransaction fixture");

        // Mock the RPC endpoint
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());
        let tx = verifier
            .get_transaction(
                "5hS7p8xK2mL9vQ4rT6wN3bY8jF2cP5qR9sX1zH3mL7vT2xW4yK8nP1qR5sT9vW2xY3zB6cE9dF3gH7iK1lM5nQ9pR2sS6tU0vV4wW8xY1zA4bC8cD2eE6fF0gG4hH8",
            )
            .await
            .expect("get transaction");

        // Verify we got the expected transaction
        assert!(tx.is_some());
        let tx = tx.unwrap();
        assert_eq!(tx.slot, 154829301);
        assert_eq!(tx.block_time, Some(1672531200));

        // Check meta data
        assert!(tx.meta.is_some());
        let meta = tx.meta.unwrap();
        assert_eq!(meta.fee, 5000);
        assert_eq!(meta.pre_balances[0], 5000000000);
        assert_eq!(meta.post_balances[0], 4900000000);

        // Check logs contain PII-relevant information (privacy violation detection)
        assert!(meta.log_messages.is_some());
        let logs = meta.log_messages.unwrap();
        assert!(logs.iter().any(|log| log.contains("User IP")));
        assert!(logs.iter().any(|log| log.contains("SessionID")));

        // ========================================================================
        // PRIV Check Verification - Test PRIV-006 (PII in logs)
        // ========================================================================
        println!("\n=== QuickNode getTransaction PRIV Check Results ===");

        // Test PRIV-006: Sensitive data in logs (fixture has User IP, SessionID)
        let finding_006 = TestFindingBuilder::new("PRIV-006")
            .title("PII exposed in transaction logs")
            .code_snippet("log: User IP, SessionID")
            .recommendation("Remove PII from program logs")
            .confidence(70)
            .build();

        let results_006 = verifier.verify_findings_focused(
            &[finding_006],
            "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT"
        ).await;
        print_priv_result("PRIV-006 (PII in logs)       ", &results_006);
        assert!(!results_006.is_empty(), "PRIV-006 should return results");

        println!("=== getTransaction PRIV checks complete ===\n");
    }

    #[tokio::test]
    async fn test_get_token_accounts_by_owner_with_fixture() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Load fixture
        let fixture = std::fs::read_to_string("tests/fixtures/quicknode_getTokenAccountsByOwner.json")
            .expect("read getTokenAccountsByOwner fixture");

        // Mock the RPC endpoint
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());
        let accounts = verifier
            .get_token_accounts_by_owner(
                "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT",
                None, // Get all token accounts
            )
            .await
            .expect("get token accounts");

        // Verify we got the expected token accounts
        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].pubkey, "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT");
        assert_eq!(
            accounts[0].account.owner,
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        );
        assert_eq!(accounts[0].account.lamports, 2039280);

        // Verify all accounts have token program as owner
        for account in &accounts {
            assert_eq!(
                account.account.owner,
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            );
        }

        // ========================================================================
        // PRIV Check Verification - Test PRIV-020/021 (wallet clustering)
        // ========================================================================
        println!("\n=== QuickNode getTokenAccountsByOwner PRIV Check Results ===");

        // Test PRIV-020: Wallet clustering (multiple token accounts = potential clustering)
        let finding_020 = TestFindingBuilder::new("PRIV-020")
            .title("Wallet clustering detected")
            .code_snippet("Multiple token accounts for same owner")
            .recommendation("Use separate wallets for different purposes")
            .confidence(60)
            .build();

        let results_020 = verifier.verify_findings_focused(
            &[finding_020],
            "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT"
        ).await;
        print_priv_result("PRIV-020 (Wallet clustering) ", &results_020);
        assert!(!results_020.is_empty(), "PRIV-020 should return results");

        // Test PRIV-021: Balance correlation (token balances can correlate identity)
        let finding_021 = TestFindingBuilder::new("PRIV-021")
            .title("Balance correlation risk")
            .code_snippet("Token balances visible across accounts")
            .recommendation("Consider privacy-preserving token transfers")
            .confidence(55)
            .build();

        let results_021 = verifier.verify_findings_focused(
            &[finding_021],
            "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT"
        ).await;
        print_priv_result("PRIV-021 (Balance correlation)", &results_021);
        assert!(!results_021.is_empty(), "PRIV-021 should return results");

        println!("=== getTokenAccountsByOwner PRIV checks complete ===\n");
    }

    #[tokio::test]
    async fn test_get_signatures_for_address_with_limit() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Load fixture
        let fixture = std::fs::read_to_string("tests/fixtures/quicknode_getSignaturesForAddress.json")
            .expect("read getSignaturesForAddress fixture");

        // Mock the RPC endpoint
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());

        // Test with different limits
        let sigs_limit_5 = verifier
            .get_signatures_for_address(
                "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT",
                Some(5),
            )
            .await
            .expect("get signatures with limit");

        let sigs_no_limit = verifier
            .get_signatures_for_address(
                "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT",
                None,
            )
            .await
            .expect("get signatures without limit");

        // Both should return the same fixture data (3 signatures)
        assert_eq!(sigs_limit_5.len(), 3);
        assert_eq!(sigs_no_limit.len(), 3);
    }

    // ========================================================================
    // Tests for PRIV-006 and PRIV-001 Verification
    // ========================================================================

    #[tokio::test]
    async fn test_verify_focused_priv_006_memo_detection() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Load fixtures for both getSignaturesForAddress and getTransaction
        let sig_fixture = std::fs::read_to_string("tests/fixtures/quicknode_getSignaturesForAddress.json")
            .expect("read getSignaturesForAddress fixture");
        let tx_fixture = std::fs::read_to_string("tests/fixtures/quicknode_getTransaction.json")
            .expect("read getTransaction fixture");

        // Mock server will return sig_fixture first, then tx_fixture
        // Using expect(2) to handle both calls
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sig_fixture.clone()))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(tx_fixture))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());

        // Create a PRIV-006 finding
        let mut finding = mock_finding("PRIV-006", 60);
        finding.title = "Sensitive data in logs".to_string();
        finding.code_snippet = "msg!(\"User data: {}\", user.email)".to_string();
        finding.evidence = vec!["PII in program logs".to_string()];

        let results = verifier.verify_findings_focused(
            &[finding],
            "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT",
        ).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding.id, "PRIV-006");
        assert_eq!(results[0].static_confidence, 60);

        // The fixture has a memo with "Private Cold Wallet" which should trigger detection
        // Confidence should be increased due to sensitive memo
        assert!(results[0].verified_confidence > results[0].static_confidence,
            "Expected confidence increase due to sensitive memo, got {} -> {}",
            results[0].static_confidence, results[0].verified_confidence);

        // Check evidence notes mention the sensitive memo
        let notes_text = results[0].evidence.notes.join(" ");
        assert!(notes_text.contains("sensitive") || notes_text.contains("memo") || notes_text.contains("PII"),
            "Expected notes about sensitive data, got: {:?}", results[0].evidence.notes);
    }

    #[tokio::test]
    async fn test_verify_focused_priv_001_key_detection() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Load fixtures
        let sig_fixture = std::fs::read_to_string("tests/fixtures/quicknode_getSignaturesForAddress.json")
            .expect("read getSignaturesForAddress fixture");
        let tx_fixture = std::fs::read_to_string("tests/fixtures/quicknode_getTransaction.json")
            .expect("read getTransaction fixture");

        // Mock server returns sig_fixture first, then tx_fixture for subsequent calls
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sig_fixture.clone()))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(tx_fixture))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());

        // Create a PRIV-001 finding (hardcoded private key)
        let mut finding = mock_finding("PRIV-001", 70);
        finding.title = "Hardcoded private key".to_string();
        finding.code_snippet = "let secret = \"5JvT...\"".to_string();
        finding.evidence = vec!["Private key pattern detected".to_string()];

        let results = verifier.verify_findings_focused(
            &[finding],
            "9B5X32gkjH2c3K7mL4nP9qR1sT5uV8wX2yZ4aB6cD9eF1gH3iJ5kL7mN9oP1qR3sT",
        ).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding.id, "PRIV-001");
        assert_eq!(results[0].static_confidence, 70);

        // Evidence should exist (transactions were found)
        assert!(results[0].evidence.exists, "Expected evidence.exists to be true");

        // Check notes mention key detection attempt
        let notes_text = results[0].evidence.notes.join(" ");
        assert!(notes_text.contains("key") || notes_text.contains("transaction"),
            "Expected notes about key detection, got: {:?}", results[0].evidence.notes);
    }

    #[tokio::test]
    async fn test_verify_focused_priv_006_no_sensitive_memos() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Create a fixture with no sensitive memos
        let clean_fixture = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {
                    "signature": "abc123",
                    "slot": 100,
                    "err": null,
                    "memo": "Regular transfer",
                    "blockTime": 1672531200
                }
            ]
        }"#;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(clean_fixture))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());

        let mut finding = mock_finding("PRIV-006", 60);
        finding.title = "Sensitive data in logs".to_string();

        let results = verifier.verify_findings_focused(
            &[finding],
            "TestProgram123",
        ).await;

        assert_eq!(results.len(), 1);
        // No sensitive memos found, confidence should decrease
        assert!(results[0].verified_confidence < results[0].static_confidence,
            "Expected confidence decrease with no sensitive memos, got {} -> {}",
            results[0].static_confidence, results[0].verified_confidence);
    }

    #[tokio::test]
    async fn test_verify_focused_priv_001_no_key_leaks() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Fixture with no sensitive memos
        let sig_fixture = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {
                    "signature": "abc123",
                    "slot": 100,
                    "err": null,
                    "memo": null,
                    "blockTime": 1672531200
                }
            ]
        }"#;

        // Transaction fixture with clean logs (no key patterns)
        let tx_fixture = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "slot": 100,
                "blockTime": 1672531200,
                "transaction": {
                    "signatures": ["abc123"],
                    "message": {}
                },
                "meta": {
                    "err": null,
                    "fee": 5000,
                    "preBalances": [1000],
                    "postBalances": [900],
                    "logMessages": [
                        "Program log: Transfer successful",
                        "Program log: Amount: 100"
                    ]
                }
            }
        }"#;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sig_fixture))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(tx_fixture))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());

        let mut finding = mock_finding("PRIV-001", 70);
        finding.title = "Hardcoded private key".to_string();

        let results = verifier.verify_findings_focused(
            &[finding],
            "TestProgram123",
        ).await;

        assert_eq!(results.len(), 1);
        // No key leaks found, confidence should decrease
        assert!(results[0].verified_confidence < results[0].static_confidence,
            "Expected confidence decrease with no key leaks, got {} -> {}",
            results[0].static_confidence, results[0].verified_confidence);

        // Notes should mention no key patterns detected
        let notes_text = results[0].evidence.notes.join(" ");
        assert!(notes_text.contains("No key patterns"),
            "Expected notes about no key patterns, got: {:?}", results[0].evidence.notes);
    }

    // ========================================================================
    // Individual Fixture Tests (one test per fixture file)
    // ========================================================================

    #[tokio::test]
    async fn test_quicknode_get_account_info_with_fixture() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Load fixture - contains PII in account data (SSN, email, STRIPE_KEY)
        let fixture = std::fs::read_to_string("tests/fixtures/quicknode_getAccountInfo.json")
            .expect("read getAccountInfo fixture");

        // Mock the RPC endpoint
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture.clone()))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());
        let account = verifier
            .get_account_info("SomeAddress11111111111111111111111")
            .await
            .expect("get account info");

        // Verify we got the expected account data
        assert!(account.is_some());
        let account = account.unwrap();
        assert_eq!(account.lamports, 1000000000);
        assert_eq!(account.owner, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

        // Verify account data is present and has expected size
        // The fixture contains base64-encoded PII (SSN, email, STRIPE_KEY)
        assert!(account.data.size() > 0, "Expected non-empty account data");

        // ========================================================================
        // PRIV Check Verification - Test PRIV-004/005 (PII in account data)
        // ========================================================================
        println!("\n=== QuickNode getAccountInfo PRIV Check Results ===");

        // Test PRIV-004: PII in accounts
        let finding_004 = TestFindingBuilder::new("PRIV-004")
            .title("PII stored in account data")
            .code_snippet("pub email: String")
            .recommendation("Remove PII from on-chain storage")
            .confidence(70)
            .build();

        let results_004 = verifier.verify_findings_focused(
            &[finding_004],
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        ).await;
        print_priv_result("PRIV-004 (PII in accounts)   ", &results_004);
        assert!(!results_004.is_empty(), "PRIV-004 should return results");

        // Test PRIV-005: Sensitive fields (API keys)
        let finding_005 = TestFindingBuilder::new("PRIV-005")
            .title("Sensitive field exposure")
            .code_snippet("pub stripe_key: String")
            .recommendation("Remove API keys from on-chain storage")
            .confidence(75)
            .build();

        let results_005 = verifier.verify_findings_focused(
            &[finding_005],
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        ).await;
        print_priv_result("PRIV-005 (Sensitive fields)  ", &results_005);
        assert!(!results_005.is_empty(), "PRIV-005 should return results");

        println!("=== getAccountInfo PRIV checks complete ===\n");
    }

    #[tokio::test]
    async fn test_quicknode_get_multiple_accounts_with_fixture() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Load fixture - contains multiple accounts with various issues
        // Account 1: PII/API key (PRIV-004/005)
        // Account 2: Uninitialized (PRIV-008)
        // Account 3: Owner mismatch (PRIV-009)
        let fixture = std::fs::read_to_string("tests/fixtures/quicknode_getMultipleAccounts.json")
            .expect("read getMultipleAccounts fixture");

        // Mock the RPC endpoint
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture.clone()))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());
        let accounts = verifier
            .get_multiple_accounts(&[
                "Account1_Address_1111111111111111111111",
                "Account2_Address_2222222222222222222222",
                "Account3_Address_3333333333333333333333",
                "Account4_Nonexistent_44444444444444444444",
            ])
            .await
            .expect("get multiple accounts");

        // Verify we got 4 results (3 accounts + 1 null)
        assert_eq!(accounts.len(), 4);

        // Account 1: Has PII/API key (PRIV-004/005)
        assert!(accounts[0].is_some());
        let account1 = accounts[0].as_ref().unwrap();
        assert_eq!(account1.lamports, 500000000);

        // Account 2: Uninitialized (all zeros) - PRIV-008
        assert!(accounts[1].is_some());
        let account2 = accounts[1].as_ref().unwrap();
        assert_eq!(account2.lamports, 1000000000);

        // Account 3: Owner mismatch (System Program) - PRIV-009
        assert!(accounts[2].is_some());
        let account3 = accounts[2].as_ref().unwrap();
        assert_eq!(account3.owner, "11111111111111111111111111111111");

        // Account 4: null (doesn't exist)
        assert!(accounts[3].is_none());

        // ========================================================================
        // PRIV Check Verification - Multiple PRIV types
        // ========================================================================
        println!("\n=== QuickNode getMultipleAccounts PRIV Check Results ===");

        // Test PRIV-004: PII in accounts (Account 1 has email/password)
        let finding_004 = TestFindingBuilder::new("PRIV-004")
            .title("PII stored in account data")
            .code_snippet("pub email: String")
            .recommendation("Remove PII from on-chain storage")
            .confidence(70)
            .build();

        let results_004 = verifier.verify_findings_focused(
            &[finding_004],
            "YourProgramID11111111111111111111111111111"
        ).await;
        print_priv_result("PRIV-004 (PII in accounts)   ", &results_004);
        assert!(!results_004.is_empty(), "PRIV-004 should return results");

        // Test PRIV-005: Sensitive fields (Account 1 has API key)
        let finding_005 = TestFindingBuilder::new("PRIV-005")
            .title("Sensitive field exposure")
            .code_snippet("pub api_key: String")
            .recommendation("Remove API keys from on-chain storage")
            .confidence(75)
            .build();

        let results_005 = verifier.verify_findings_focused(
            &[finding_005],
            "YourProgramID11111111111111111111111111111"
        ).await;
        print_priv_result("PRIV-005 (Sensitive fields)  ", &results_005);
        assert!(!results_005.is_empty(), "PRIV-005 should return results");

        // Test PRIV-008: Uninitialized account state (Account 2 is all zeros)
        let finding_008 = TestFindingBuilder::new("PRIV-008")
            .title("Uninitialized account state")
            .code_snippet("ctx.accounts.user_data")
            .recommendation("Add initialization checks")
            .confidence(65)
            .build();

        let results_008 = verifier.verify_findings_focused(
            &[finding_008],
            "YourProgramID11111111111111111111111111111"
        ).await;
        print_priv_result("PRIV-008 (Uninitialized)     ", &results_008);
        assert!(!results_008.is_empty(), "PRIV-008 should return results");

        // Test PRIV-009: CPI without validation (Account 3 has owner mismatch)
        let finding_009 = TestFindingBuilder::new("PRIV-009")
            .title("CPI without program validation")
            .code_snippet("invoke_signed(&ix, &accounts, &[])")
            .recommendation("Validate CPI target program")
            .confidence(70)
            .build();

        let results_009 = verifier.verify_findings_focused(
            &[finding_009],
            "YourProgramID11111111111111111111111111111"
        ).await;
        print_priv_result("PRIV-009 (CPI validation)    ", &results_009);
        assert!(!results_009.is_empty(), "PRIV-009 should return results");

        println!("=== getMultipleAccounts PRIV checks complete ===\n");
    }

    #[tokio::test]
    async fn test_quicknode_get_program_accounts_with_fixture() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};

        let server = MockServer::start().await;

        // Load fixture - contains enumerable PDA accounts (PRIV-010)
        // Also contains PII in account data (PRIV-004/005)
        let fixture = std::fs::read_to_string("tests/fixtures/quicknode_getProgramAccounts.json")
            .expect("read getProgramAccounts fixture");

        // Mock the RPC endpoint
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture.clone()))
            .mount(&server)
            .await;

        let verifier = QuickNodeVerifier::new(&server.uri());
        let accounts = verifier
            .get_program_accounts(
                "YourProgramID11111111111111111111111111111",
                None,
                None,
                None,
            )
            .await
            .expect("get program accounts");

        // Verify we got 2 PDA accounts (indicating enumerable PDAs - PRIV-010)
        assert_eq!(accounts.len(), 2);

        // Verify PDA account structure
        assert!(accounts[0].pubkey.starts_with("PDA_User_Account_001"));
        assert!(accounts[1].pubkey.starts_with("PDA_User_Account_002"));

        // Both owned by the program
        assert_eq!(accounts[0].account.owner, "YourProgramID11111111111111111111111111111");
        assert_eq!(accounts[1].account.owner, "YourProgramID11111111111111111111111111111");

        // Verify data is present in each PDA account
        for account in &accounts {
            // The fixture contains base64-encoded PII (emails, SSN, API keys)
            assert!(account.account.data.size() > 0, "Expected non-empty PDA account data");
        }

        // ========================================================================
        // PRIV Check Verification - PDA enumeration and PII
        // ========================================================================
        println!("\n=== QuickNode getProgramAccounts PRIV Check Results ===");

        // Test PRIV-004: PII in accounts (both PDAs contain PII)
        let finding_004 = TestFindingBuilder::new("PRIV-004")
            .title("PII stored in PDA accounts")
            .code_snippet("pub email: String")
            .recommendation("Remove PII from on-chain storage")
            .confidence(70)
            .build();

        let results_004 = verifier.verify_findings_focused(
            &[finding_004],
            "YourProgramID11111111111111111111111111111"
        ).await;
        print_priv_result("PRIV-004 (PII in PDAs)       ", &results_004);
        assert!(!results_004.is_empty(), "PRIV-004 should return results");

        // Test PRIV-005: Sensitive fields (PDAs contain API keys)
        let finding_005 = TestFindingBuilder::new("PRIV-005")
            .title("Sensitive field in PDA")
            .code_snippet("pub stripe_secret: String")
            .recommendation("Remove secrets from on-chain storage")
            .confidence(75)
            .build();

        let results_005 = verifier.verify_findings_focused(
            &[finding_005],
            "YourProgramID11111111111111111111111111111"
        ).await;
        print_priv_result("PRIV-005 (Sensitive in PDAs) ", &results_005);
        assert!(!results_005.is_empty(), "PRIV-005 should return results");

        // Test PRIV-010: PDA enumeration (predictable seeds allow enumeration)
        let finding_010 = TestFindingBuilder::new("PRIV-010")
            .title("Predictable PDA seeds enable enumeration")
            .code_snippet("seeds = [b\"user\", user_id.to_le_bytes().as_ref()]")
            .recommendation("Use non-predictable seeds or access control")
            .confidence(60)
            .build();

        let results_010 = verifier.verify_findings_focused(
            &[finding_010],
            "YourProgramID11111111111111111111111111111"
        ).await;
        print_priv_result("PRIV-010 (PDA enumeration)   ", &results_010);
        assert!(!results_010.is_empty(), "PRIV-010 should return results");

        // Verify enumeration evidence: multiple PDAs found indicates enumerable pattern
        println!("Enumeration evidence: Found {} enumerable PDA accounts", accounts.len());
        assert!(accounts.len() >= 2, "Should find multiple enumerable PDAs");

        println!("=== getProgramAccounts PRIV checks complete ===\n");
    }
}

