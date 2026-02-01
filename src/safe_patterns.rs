//! Safe patterns module - reduces false positives by recognizing
//! Solana-specific naming conventions and types.

/// Field names that are safe in Solana/Anchor context
pub const SAFE_FIELD_NAMES: &[&str] = &[
    // Solana account types
    "mint",
    "authority",
    "owner",
    "payer",
    "recipient",
    "sender",
    "signer",
    "delegate",

    // Token-related
    "token_account",
    "token_mint",
    "token_program",
    "associated_token",
    "vault",
    "treasury",

    // Program accounts
    "program_id",
    "system_program",
    "rent",
    "clock",

    // DeFi patterns
    "pool",
    "reserve",
    "liquidity",
    "collateral",
    "oracle",
    "fee_account",

    // Common safe fields
    "bump",
    "nonce",
    "seed",
    "seeds",
    "discriminator",
];

/// Field name patterns (substrings) that indicate safe Solana usage
pub const SAFE_FIELD_PATTERNS: &[&str] = &[
    "_mint",
    "_authority",
    "_account",
    "_program",
    "_pubkey",
    "_key",      // in context of public keys
    "_bump",
    "_seed",
    "_vault",
    "_pool",
    "_oracle",
    "_signer",
    "program_",
    "token_",
    "mint_",
];

/// Struct name patterns that indicate non-PII context
/// When a struct contains these patterns, certain fields like "name" are likely metadata, not PII
pub const SAFE_STRUCT_CONTEXTS: &[&str] = &[
    // Configuration
    "config",
    "settings",
    "params",
    "parameters",

    // Metadata
    "metadata",
    "info",
    "data",

    // Token/DeFi
    "token",
    "mint",
    "pool",
    "vault",
    "reserve",
    "market",
    "oracle",

    // Program state
    "state",
    "account",
    "program",

    // Governance
    "proposal",
    "vote",
    "governance",

    // System
    "system",
    "global",
    "protocol",
];

/// Types that are inherently safe (not PII)
pub const SAFE_TYPES: &[&str] = &[
    "Pubkey",
    "u8", "u16", "u32", "u64", "u128",
    "i8", "i16", "i32", "i64", "i128",
    "bool",
    "UnixTimestamp",
    "Slot",
    "Epoch",
];

/// Check if a field name is a known safe Solana pattern
pub fn is_safe_field_name(name: &str) -> bool {
    let lower = name.to_lowercase();

    // Exact match
    if SAFE_FIELD_NAMES.iter().any(|&safe| lower == safe) {
        return true;
    }

    // Pattern match (contains)
    if SAFE_FIELD_PATTERNS.iter().any(|&pattern| lower.contains(pattern)) {
        return true;
    }

    false
}

/// Check if a type is a safe Solana primitive
pub fn is_safe_type(ty: &str) -> bool {
    SAFE_TYPES.iter().any(|&safe| {
        ty.starts_with(safe) || ty.contains(&format!("<{}", safe))
    })
}

/// Check if a struct name indicates a safe (non-PII) context
pub fn is_safe_struct_context(struct_name: &str) -> bool {
    let lower = struct_name.to_lowercase();
    SAFE_STRUCT_CONTEXTS.iter().any(|&ctx| lower.contains(ctx))
}

/// Check if a field (name + type combo) should be considered safe
pub fn is_safe_field(name: &str, ty: &str, struct_name: Option<&str>) -> bool {
    let lower_name = name.to_lowercase();

    // Pubkey types are almost always blockchain addresses, not PII
    if ty.contains("Pubkey") {
        // Only flag if explicitly personal-looking
        let personal_indicators = ["home_", "mailing_", "billing_", "shipping_", "street_", "postal_"];
        if !personal_indicators.iter().any(|&p| lower_name.contains(p)) {
            return true;
        }
    }

    // Safe field name
    if is_safe_field_name(name) {
        return true;
    }

    // Safe type (numeric, bool, etc.) - but not if it's a String
    if is_safe_type(ty) && !ty.contains("String") {
        return true;
    }

    // Context-aware: "name" in Config/Metadata structs is usually not PII
    if lower_name == "name" || lower_name == "title" || lower_name == "label" {
        if let Some(struct_name) = struct_name {
            if is_safe_struct_context(struct_name) {
                return true;
            }
        }
    }

    // Hash/encrypted fields are safe
    let safe_suffixes = ["_hash", "_hashed", "_encrypted", "_cipher", "_digest", "_commitment"];
    if safe_suffixes.iter().any(|&s| lower_name.ends_with(s)) {
        return true;
    }

    false
}

/// Sensitive field patterns that indicate potential PII
pub const PII_PATTERNS: &[&str] = &[
    "email",
    "e_mail",
    "phone",
    "telephone",
    "mobile",
    "ssn",
    "social_security",
    "tax_id",
    "national_id",
    "passport",
    "driver_license",
    "date_of_birth",
    "dob",
    "birthdate",
    "birthday",
    "first_name",
    "last_name",
    "full_name",
    "street",
    "city",
    "zip",
    "postal",
    "ip_address",
    "ip_addr",
];

/// Sensitive field patterns that indicate secrets/credentials
pub const SECRET_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "private_key",
    "secret_key",
    "api_key",
    "apikey",
    "auth_token",
    "access_token",
    "refresh_token",
    "bearer",
    "credential",
    "mnemonic",
    "seed_phrase",
    "recovery_phrase",
];

/// Check if a field name matches PII patterns (but respects safe context)
pub fn is_pii_field(name: &str, ty: &str, struct_name: Option<&str>) -> Option<&'static str> {
    // First check if it's safe
    if is_safe_field(name, ty, struct_name) {
        return None;
    }

    let lower = name.to_lowercase();

    // Special case: "name" alone is only PII in user-like contexts
    if lower == "name" || lower == "username" || lower == "user_name" {
        if let Some(sn) = struct_name {
            let sn_lower = sn.to_lowercase();
            // Only flag if struct looks user-related
            if sn_lower.contains("user") || sn_lower.contains("profile") ||
               sn_lower.contains("member") || sn_lower.contains("person") ||
               sn_lower.contains("customer") || sn_lower.contains("identity") {
                return Some("name");
            }
        }
        // Without struct context and String type, be cautious
        if ty.contains("String") {
            return Some("name");
        }
        return None;
    }

    // Special case: "address" - only PII if it's a String (not Pubkey)
    if lower.contains("address") {
        if ty.contains("Pubkey") || lower.contains("wallet") || lower.contains("token") {
            return None;
        }
        if ty.contains("String") && !lower.contains("program") && !lower.contains("mint") {
            return Some("address");
        }
        return None;
    }

    // Check other PII patterns
    for pattern in PII_PATTERNS {
        if lower.contains(pattern) {
            return Some(pattern);
        }
    }

    None
}

/// Financial/DeFi context patterns - these indicate blockchain financial operations
/// where numeric data or addresses are expected, not PII
#[allow(dead_code)]
pub const FINANCIAL_CONTEXTS: &[&str] = &[
    // Transaction types
    "swap",
    "transfer",
    "deposit",
    "withdraw",
    "withdrawal",
    "stake",
    "unstake",

    // DeFi operations
    "liquidity",
    "pool",
    "mint",
    "burn",
    "borrow",
    "repay",
    "lend",

    // Amount/value related
    "amount",
    "balance",
    "price",
    "fee",
    "reward",

    // Token operations
    "token",
    "nft",
    "collection",
];

/// Check if text contains financial/DeFi context indicators
pub fn is_financial_context(text: &str) -> bool {
    let lower = text.to_lowercase();
    FINANCIAL_CONTEXTS.iter().any(|&ctx| lower.contains(ctx))
}

/// Common placeholder/test email domains that shouldn't be flagged
#[allow(dead_code)]
pub const PLACEHOLDER_EMAIL_DOMAINS: &[&str] = &[
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.org",
    "localhost",
    "placeholder.com",
    "fake.com",
    "dummy.com",
    "sample.com",
    "foo.com",
    "bar.com",
];

/// Check if an email address appears to be a placeholder/test email
pub fn is_placeholder_email(email: &str) -> bool {
    let lower = email.to_lowercase();
    PLACEHOLDER_EMAIL_DOMAINS.iter().any(|&domain| lower.ends_with(domain))
}

// ============================================================================
// Field Co-occurrence Detection
// ============================================================================

/// Field combinations that indicate token/NFT metadata (not PII)
/// If these fields appear together, "name" is almost certainly not a person's name
#[allow(dead_code)]
pub const TOKEN_METADATA_FIELDS: &[&str] = &[
    "symbol",
    "decimals",
    "supply",
    "total_supply",
    "mint",
    "uri",
    "image",
    "description",
    "seller_fee_basis_points",
    "creators",
    "collection",
    "attributes",
    "properties",
];

/// Field combinations that indicate NFT metadata specifically
#[allow(dead_code)]
pub const NFT_METADATA_FIELDS: &[&str] = &[
    "image",
    "animation_url",
    "external_url",
    "attributes",
    "collection",
    "seller_fee_basis_points",
    "creators",
    "properties",
    "edition",
    "token_id",
];

/// Check if JSON contains token/NFT metadata field patterns
/// Returns true if the data looks like token metadata (name is not PII)
pub fn has_token_metadata_context(json_text: &str) -> bool {
    let lower = json_text.to_lowercase();

    // Count how many token metadata fields are present
    let token_field_count = TOKEN_METADATA_FIELDS.iter()
        .filter(|&field| lower.contains(&format!("\"{}\"", field)))
        .count();

    // If 2+ token metadata fields present alongside "name", it's token data
    token_field_count >= 2
}

/// Check if JSON contains NFT metadata field patterns
pub fn has_nft_metadata_context(json_text: &str) -> bool {
    let lower = json_text.to_lowercase();

    let nft_field_count = NFT_METADATA_FIELDS.iter()
        .filter(|&field| lower.contains(&format!("\"{}\"", field)))
        .count();

    // NFT metadata typically has image + at least one other field
    nft_field_count >= 2 || (lower.contains("\"image\"") && nft_field_count >= 1)
}

// ============================================================================
// Value-based Heuristics
// ============================================================================

/// Check if a "name" value looks like a person's name vs token/project name
/// Returns true if it looks like a SAFE (non-person) name
#[allow(dead_code)]
pub fn is_safe_name_value(value: &str) -> bool {
    let trimmed = value.trim();

    // Empty or very short - probably not a real name
    if trimmed.len() < 2 {
        return true;
    }

    // Very long strings are usually not person names
    if trimmed.len() > 50 {
        return true;
    }

    // All uppercase - likely a ticker/symbol, not a person (e.g., "BONK", "SOL")
    if trimmed.chars().all(|c| c.is_uppercase() || c.is_numeric() || c == ' ') && trimmed.len() <= 10 {
        return true;
    }

    // Contains numbers - likely not a person name (e.g., "CoolNFT #1234", "Token2022")
    if trimmed.chars().any(|c| c.is_numeric()) {
        return true;
    }

    // Contains special characters common in tokens/NFTs but not names
    let token_chars = ['#', '@', '$', '_', '/', '\\', '{', '}', '[', ']', '|'];
    if trimmed.chars().any(|c| token_chars.contains(&c)) {
        return true;
    }

    // Starts with common token/project prefixes
    let token_prefixes = ["0x", "sol", "token", "nft", "dao", "defi", "meta", "ape", "punk", "degen"];
    let lower = trimmed.to_lowercase();
    if token_prefixes.iter().any(|&prefix| lower.starts_with(prefix)) {
        return true;
    }

    // Contains common token/NFT keywords
    let token_keywords = ["token", "coin", "nft", "dao", "protocol", "finance", "swap", "pool",
                          "vault", "staking", "yield", "farm", "dex", "amm", "edition", "collection"];
    if token_keywords.iter().any(|&kw| lower.contains(kw)) {
        return true;
    }

    // Single word with no spaces and > 10 chars - likely a project name
    if !trimmed.contains(' ') && trimmed.len() > 10 {
        return true;
    }

    // Looks like a typical person name pattern (2-3 words, capitalized)
    // This is UNSAFE - could be a real person
    false
}

/// Check if a value looks like a hash or encoded data (not PII)
#[allow(dead_code)]
pub fn is_hash_or_encoded(value: &str) -> bool {
    let trimmed = value.trim();

    // Check for hex hash patterns (32, 64, 128 chars of hex)
    if trimmed.len() >= 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // Check for base58 patterns (Solana addresses/signatures are 32-88 chars)
    let base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if trimmed.len() >= 32 && trimmed.len() <= 90 && trimmed.chars().all(|c| base58_chars.contains(c)) {
        return true;
    }

    // Check for base64 patterns
    if trimmed.len() >= 20 && trimmed.ends_with("==") || trimmed.ends_with("=") {
        let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        if trimmed.chars().all(|c| base64_chars.contains(c)) {
            return true;
        }
    }

    // Check for UUID pattern
    if trimmed.len() == 36 && trimmed.chars().filter(|&c| c == '-').count() == 4 {
        return true;
    }

    false
}

/// Check if an "address" value looks like a blockchain address vs physical address
/// Returns true if it looks like a SAFE (blockchain) address
#[allow(dead_code)]
pub fn is_blockchain_address_value(value: &str) -> bool {
    let trimmed = value.trim();

    // Solana address (32-44 base58 chars)
    let base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if trimmed.len() >= 32 && trimmed.len() <= 44 && trimmed.chars().all(|c| base58_chars.contains(c)) {
        return true;
    }

    // Ethereum address (0x + 40 hex chars)
    if trimmed.starts_with("0x") && trimmed.len() == 42 {
        return true;
    }

    // Bitcoin address patterns
    if (trimmed.starts_with("1") || trimmed.starts_with("3") || trimmed.starts_with("bc1"))
        && trimmed.len() >= 26 && trimmed.len() <= 62 {
        return true;
    }

    false
}

/// Combined check for whether a field value is safe (not PII)
#[allow(dead_code)]
pub fn is_safe_field_value(field_name: &str, value: &str) -> bool {
    let field_lower = field_name.to_lowercase();

    // Always check for hash/encoded values first
    if is_hash_or_encoded(value) {
        return true;
    }

    // Field-specific checks
    if field_lower == "name" || field_lower.ends_with("_name") {
        return is_safe_name_value(value);
    }

    if field_lower.contains("address") {
        return is_blockchain_address_value(value);
    }

    false
}

/// Check if a field name matches secret patterns
pub fn is_secret_field(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();

    // Skip if it looks hashed/safe
    if lower.contains("hash") || lower.contains("encrypted") {
        return None;
    }

    for pattern in SECRET_PATTERNS {
        if lower.contains(pattern) {
            return Some(pattern);
        }
    }

    None
}

// ============================================================================
// Context-Aware Confidence Scoring
// ============================================================================

/// Confidence adjustment factors based on code context
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ConfidenceAdjustment {
    /// Base adjustment (positive = increase, negative = decrease)
    pub delta: i32,
    /// Reasons for the adjustment
    pub reasons: Vec<String>,
}

#[allow(dead_code)]
impl ConfidenceAdjustment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn adjust(&mut self, delta: i32, reason: &str) {
        self.delta += delta;
        self.reasons.push(reason.to_string());
    }

    /// Apply to a base confidence score, clamping to valid range
    pub fn apply(&self, base: u8) -> u8 {
        let result = (base as i32 + self.delta).clamp(10, 98);
        result as u8
    }
}

/// Context signals extracted from code for confidence calibration
#[allow(dead_code)]
pub struct CodeContext<'a> {
    /// Full file content
    pub content: &'a str,
    /// Line number of the finding
    pub line: usize,
    /// Struct name if inside one
    pub struct_name: Option<&'a str>,
    /// Function name if inside one
    pub function_name: Option<&'a str>,
}

#[allow(dead_code)]
impl<'a> CodeContext<'a> {
    pub fn new(content: &'a str, line: usize) -> Self {
        Self {
            content,
            line,
            struct_name: None,
            function_name: None,
        }
    }

    pub fn with_struct(mut self, name: &'a str) -> Self {
        self.struct_name = Some(name);
        self
    }

    pub fn with_function(mut self, name: &'a str) -> Self {
        self.function_name = Some(name);
        self
    }
}

/// Calculate confidence adjustments based on code context
#[allow(dead_code)]
pub fn calculate_context_adjustment(ctx: &CodeContext) -> ConfidenceAdjustment {
    let mut adj = ConfidenceAdjustment::new();
    let content_lower = ctx.content.to_lowercase();

    // Get surrounding context (50 lines around the finding)
    let lines: Vec<&str> = ctx.content.lines().collect();
    let start = ctx.line.saturating_sub(25);
    let end = (ctx.line + 25).min(lines.len());
    let surrounding = lines.get(start..end)
        .map(|l| l.join("\n"))
        .unwrap_or_default()
        .to_lowercase();

    // ========== Increase Confidence Signals ==========

    // 1. Found in #[account] or instruction context
    if surrounding.contains("#[account") || surrounding.contains("#[instruction") {
        adj.adjust(10, "Inside Anchor account/instruction context");
    }

    // 2. Found in event/emit context (publicly indexed)
    if surrounding.contains("emit!") || surrounding.contains("#[event]") {
        adj.adjust(15, "Inside event emission context");
    }

    // 3. User-related struct/function names
    if let Some(name) = ctx.struct_name {
        let lower = name.to_lowercase();
        if lower.contains("user") || lower.contains("profile") || lower.contains("member") {
            adj.adjust(15, "Inside user-related struct");
        }
    }
    if let Some(name) = ctx.function_name {
        let lower = name.to_lowercase();
        if lower.contains("user") || lower.contains("register") || lower.contains("profile") {
            adj.adjust(10, "Inside user-related function");
        }
    }

    // 4. Multiple PII fields in same struct (indicates real user data)
    let pii_count = PII_PATTERNS.iter()
        .filter(|p| surrounding.contains(*p))
        .count();
    if pii_count >= 3 {
        adj.adjust(20, "Multiple PII fields detected");
    } else if pii_count >= 2 {
        adj.adjust(10, "Multiple PII fields detected");
    }

    // 5. String/Vec<u8> types (can contain arbitrary data)
    if surrounding.contains("string") || surrounding.contains("vec<u8>") {
        adj.adjust(5, "Uses String/Vec types");
    }

    // ========== Decrease Confidence Signals ==========

    // 1. Test file or test function
    if content_lower.contains("#[cfg(test)]") || content_lower.contains("#[test]") {
        adj.adjust(-30, "Inside test code");
    }

    // 2. Token/DeFi context
    if is_financial_context(&surrounding) {
        adj.adjust(-15, "Financial/DeFi context");
    }

    // 3. Token metadata context (symbol, decimals, etc. present)
    if has_token_metadata_context(&surrounding) {
        adj.adjust(-20, "Token metadata context");
    }

    // 4. NFT metadata context
    if has_nft_metadata_context(&surrounding) {
        adj.adjust(-15, "NFT metadata context");
    }

    // 5. Config/Settings struct
    if let Some(name) = ctx.struct_name {
        if is_safe_struct_context(name) {
            adj.adjust(-15, "Safe struct context (config/metadata)");
        }
    }

    // 6. Hashing/encryption nearby (data is being protected)
    let protection_patterns = ["hash(", "sha256", "encrypt", "cipher", "commitment"];
    if protection_patterns.iter().any(|p| surrounding.contains(p)) {
        adj.adjust(-10, "Data protection (hash/encrypt) nearby");
    }

    // 7. Validation/constraint nearby (proper checks in place)
    let validation_patterns = ["require!", "assert!", "constraint", "has_one", "verify"];
    if validation_patterns.iter().any(|p| surrounding.contains(p)) {
        adj.adjust(-5, "Validation/constraints in context");
    }

    // 8. Mock/fixture/example patterns
    let mock_patterns = ["mock", "fixture", "example", "sample", "test_", "_test", "dummy"];
    if mock_patterns.iter().any(|p| content_lower.contains(p)) {
        adj.adjust(-20, "Mock/fixture/example code");
    }

    // 9. Placeholder values detected
    if surrounding.contains("example.com") || surrounding.contains("placeholder")
        || surrounding.contains("xxx") || surrounding.contains("todo") {
        adj.adjust(-25, "Placeholder/example values");
    }

    // 10. Documentation comments (not actual code)
    if surrounding.contains("///") || surrounding.contains("//!") {
        let doc_lines = surrounding.lines()
            .filter(|l| l.trim().starts_with("///") || l.trim().starts_with("//!"))
            .count();
        if doc_lines > 3 {
            adj.adjust(-10, "Likely documentation context");
        }
    }

    adj
}

/// Apply context-aware confidence adjustment to a finding's base score
#[allow(dead_code)]
pub fn adjust_confidence_for_context(
    base_confidence: u8,
    content: &str,
    line: usize,
    struct_name: Option<&str>,
    function_name: Option<&str>,
) -> (u8, Vec<String>) {
    let mut ctx = CodeContext::new(content, line);
    if let Some(s) = struct_name {
        ctx = ctx.with_struct(s);
    }
    if let Some(f) = function_name {
        ctx = ctx.with_function(f);
    }

    let adj = calculate_context_adjustment(&ctx);
    let new_confidence = adj.apply(base_confidence);

    (new_confidence, adj.reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_field_names() {
        assert!(is_safe_field_name("mint"));
        assert!(is_safe_field_name("authority"));
        assert!(is_safe_field_name("token_account"));
        assert!(!is_safe_field_name("email"));
        assert!(!is_safe_field_name("password"));
    }

    #[test]
    fn test_pubkey_is_safe() {
        assert!(is_safe_field("address", "Pubkey", None));
        assert!(is_safe_field("mint_address", "Pubkey", None));
        assert!(is_safe_field("recipient", "Pubkey", None));
    }

    #[test]
    fn test_name_context_aware() {
        // "name" in Config struct is safe
        assert!(is_safe_field("name", "String", Some("PoolConfig")));
        assert!(is_safe_field("name", "String", Some("TokenMetadata")));

        // "name" in User struct is not safe
        assert!(!is_safe_field("name", "String", Some("UserProfile")));
    }

    #[test]
    fn test_pii_detection() {
        assert!(is_pii_field("email", "String", None).is_some());
        assert!(is_pii_field("phone_number", "String", None).is_some());

        // Safe patterns not flagged
        assert!(is_pii_field("mint_address", "Pubkey", None).is_none());
        assert!(is_pii_field("token_account", "Pubkey", None).is_none());
    }

    #[test]
    fn test_secret_detection() {
        assert!(is_secret_field("password").is_some());
        assert!(is_secret_field("api_key").is_some());
        assert!(is_secret_field("password_hash").is_none()); // hashed is safe
    }

    #[test]
    fn test_financial_context() {
        // DeFi operations
        assert!(is_financial_context("swap"));
        assert!(is_financial_context("SWAP")); // case insensitive
        assert!(is_financial_context("token transfer"));
        assert!(is_financial_context("liquidity pool"));
        assert!(is_financial_context("stake"));
        assert!(is_financial_context("withdraw deposit"));
        assert!(is_financial_context("mint"));
        assert!(is_financial_context("burn"));
        assert!(is_financial_context("NFT collection"));

        // Non-financial contexts
        assert!(!is_financial_context("user profile"));
        assert!(!is_financial_context("settings page"));
        assert!(!is_financial_context("login form"));
        assert!(!is_financial_context(""));
    }

    #[test]
    fn test_placeholder_email() {
        // Common placeholders
        assert!(is_placeholder_email("user@example.com"));
        assert!(is_placeholder_email("test@example.org"));
        assert!(is_placeholder_email("foo@test.com"));
        assert!(is_placeholder_email("admin@localhost"));
        assert!(is_placeholder_email("test@placeholder.com"));
        assert!(is_placeholder_email("UPPER@EXAMPLE.COM")); // case insensitive

        // Real email domains
        assert!(!is_placeholder_email("user@gmail.com"));
        assert!(!is_placeholder_email("user@company.io"));
        assert!(!is_placeholder_email("support@myservice.com"));
        assert!(!is_placeholder_email("real@protonmail.com"));
    }

    // =========================================================================
    // Field Co-occurrence Tests
    // =========================================================================

    #[test]
    fn test_token_metadata_context() {
        // Token metadata with symbol + decimals
        assert!(has_token_metadata_context(r#"{"name": "Bonk", "symbol": "BONK", "decimals": 9}"#));
        // Token with supply
        assert!(has_token_metadata_context(r#"{"name": "Token", "supply": 1000000, "mint": "abc123"}"#));
        // Not token metadata - just a name
        assert!(!has_token_metadata_context(r#"{"name": "John Doe"}"#));
        // Not enough fields
        assert!(!has_token_metadata_context(r#"{"name": "Token", "symbol": "TKN"}"#));
    }

    #[test]
    fn test_nft_metadata_context() {
        // NFT with image + attributes
        assert!(has_nft_metadata_context(r#"{"name": "NFT", "image": "url", "attributes": []}"#));
        // NFT with collection + creators
        assert!(has_nft_metadata_context(r#"{"name": "NFT", "collection": "xyz", "creators": []}"#));
        // Image alone is detected (image + nft_field_count >= 1)
        assert!(has_nft_metadata_context(r#"{"name": "NFT", "image": "url"}"#));
        // Just name alone is not NFT context
        assert!(!has_nft_metadata_context(r#"{"name": "NFT"}"#));
    }

    // =========================================================================
    // Value-based Heuristics Tests
    // =========================================================================

    #[test]
    fn test_safe_name_value() {
        // Token-like names (safe)
        assert!(is_safe_name_value("BONK"));  // All caps ticker
        assert!(is_safe_name_value("SOL"));
        assert!(is_safe_name_value("DegenApe #1234"));  // Has number
        assert!(is_safe_name_value("Cool_NFT_123"));  // Has underscore and number
        assert!(is_safe_name_value("SolanaToken"));  // Starts with "sol"
        assert!(is_safe_name_value("NFTCollection"));  // Contains "nft"
        assert!(is_safe_name_value("DeFiProtocol"));  // Contains "defi"
        assert!(is_safe_name_value("LongProjectNameWithoutSpaces"));  // Long single word

        // Person-like names (not safe)
        assert!(!is_safe_name_value("John"));
        assert!(!is_safe_name_value("John Smith"));
        assert!(!is_safe_name_value("Alice"));
    }

    #[test]
    fn test_hash_or_encoded() {
        // Hex hashes
        assert!(is_hash_or_encoded("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));  // 32 hex chars
        assert!(is_hash_or_encoded("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));  // 64 hex chars

        // Base58 (Solana-like)
        assert!(is_hash_or_encoded("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"));

        // UUID
        assert!(is_hash_or_encoded("550e8400-e29b-41d4-a716-446655440000"));

        // Not hashes
        assert!(!is_hash_or_encoded("hello world"));
        assert!(!is_hash_or_encoded("short"));
    }

    #[test]
    fn test_blockchain_address_value() {
        // Solana addresses
        assert!(is_blockchain_address_value("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"));
        assert!(is_blockchain_address_value("11111111111111111111111111111111"));

        // Ethereum addresses
        assert!(is_blockchain_address_value("0x742d35Cc6634C0532925a3b844Bc9e7595f9DdE6"));

        // Not blockchain addresses (physical addresses)
        assert!(!is_blockchain_address_value("123 Main Street"));
        assert!(!is_blockchain_address_value("New York, NY 10001"));
    }

    #[test]
    fn test_safe_field_value_combined() {
        // Name field with safe value
        assert!(is_safe_field_value("name", "BONK"));
        assert!(is_safe_field_value("name", "CoolNFT #123"));

        // Address field with blockchain address
        assert!(is_safe_field_value("address", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"));
        assert!(is_safe_field_value("wallet_address", "11111111111111111111111111111111"));

        // Hash value in any field
        assert!(is_safe_field_value("data", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));

        // Unsafe values
        assert!(!is_safe_field_value("name", "John Smith"));
        assert!(!is_safe_field_value("address", "123 Main Street"));
    }
}
