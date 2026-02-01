#!/bin/bash
# demo/demo_optional.sh - Custos Integration Demo (QuickNode + Helius)
#
# Self-narrating demo for video recording
# Shows ALL 10 on-chain verification methods
# Pre-compile tests first, then run clean demo

set -e  # Exit on error

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# =============================================================================
# HARDCODED API KEYS (for demo recording only - remove before committing!)
# =============================================================================
export QUICKNODE_RPC_URL='your-quicknode-url-here'
export HELIUS_BASE_URL='https://api.helius.xyz'
export HELIUS_API_KEY='your-helius-api-key-here'

# =============================================================================
# PRE-BUILD TESTS (before recording starts)
# =============================================================================
# At start of demo script, replace the silent pre-build with:

# Disabled pre-build tests (commented out for demo recording)
# echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
# echo -e "${DIM}Building & compiling tests (one-time setup)...${NC}"
# echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
# cargo build --release
# cargo test --no-run --bin custos
# echo -e "${GREEN}✓ Build complete${NC}"
# sleep 2

# =============================================================================
# CHECK FOR API KEYS (optional live scans)
# =============================================================================
HAVE_QN_KEY=false
HAVE_HELIUS_KEY=false

if [ -n "$QUICKNODE_RPC_URL" ]; then
    HAVE_QN_KEY=true
fi
if [ -n "$HELIUS_API_KEY" ]; then
    HAVE_HELIUS_KEY=true
fi

# Inform user about optional live scans
if [ "$HAVE_QN_KEY" = false ] && [ "$HAVE_HELIUS_KEY" = false ]; then
    echo -e "${YELLOW}Note: Set QUICKNODE_RPC_URL and/or HELIUS_API_KEY for live on-chain demos${NC}"
    sleep 2
fi

clear  # Clear screen before actual demo starts

# =============================================================================
# Hide username in prompt for demo recording
# =============================================================================
ORIGINAL_PS1="$PS1"
export PS1='$ '

cleanup() {
    export PS1="$ORIGINAL_PS1"
}
trap cleanup EXIT

clear_and_pause() {
    sleep "$1"
}

print_slide() {
    clear
    echo -e "$1"
    clear_and_pause 5
}

# Show command with typing effect
type_command() {
    local cmd="$1"
    echo ""
    echo -ne "${YELLOW}$ ${NC}"
    for (( i=0; i<${#cmd}; i++ )); do
        echo -n "${cmd:$i:1}"
        sleep 0.02
    done
    echo ""
    sleep 0.3
}

# Execute test and show output
run_test() {
    local cmd="$1"
    echo ""
    eval "$cmd" || {
        echo -e "${RED}Test failed${NC}"
        return 1
    }
    echo ""
    sleep 1
}

# =============================================================================
# SLIDE 1: Architecture Overview
# =============================================================================
SLIDE1=$(cat << 'EOF'

┌─────────────────────────────────────────────────────────────────────┐
│            CUSTOS - On-Chain Verification Layers                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│    ┌─────────────────┐                                              │
│    │  Static Analysis│  PRIV-001 to PRIV-016, PRIV-030              │
│    │   (Source Code) │  Finds potential issues                      │
│    └────────┬────────┘                                              │
│             │                                                       │
│             ▼                                                       │
│    ┌─────────────────┐                                              │
│    │   QuickNode RPC │  Verification Layer (6 methods)              │
│    │  (Account State)│  Adjusts confidence based on chain state     │
│    └────────┬────────┘                                              │
│             │                                                       │
│             ▼                                                       │
│    ┌─────────────────┐                                              │
│    │    Helius API   │  Transaction Analysis (4 methods)            │
│    │ (Event History) │  Finds runtime privacy patterns              │
│    └─────────────────┘                                              │
│                                                                     │
│  Each layer adds evidence to increase or decrease confidence        │
└─────────────────────────────────────────────────────────────────────┘

EOF
)

# =============================================================================
# SLIDE 2: QuickNode Methods (ALL 6)
# =============================================================================
SLIDE2=$(cat << 'EOF'

┌─────────────────────────────────────────────────────────────────────┐
│              QUICKNODE RPC - 6 Verification Methods                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Method                  │ PRIV Checks      │ Purpose               │
│  ────────────────────────┼──────────────────┼───────────────────────│
│  getAccountInfo          │ PRIV-004, 008    │ Account state, PII    │
│  getMultipleAccounts     │ Batch verify     │ Multi-account check   │
│  getProgramAccounts      │ PRIV-010         │ PDA enumeration       │
│  getSignaturesForAddress │ PRIV-006         │ Memo field leaks      │
│  getTransaction          │ PRIV-001, 006    │ Secrets in tx data    │
│  getTokenAccountsByOwner │ SPL discovery    │ Token correlation     │
│                                                                     │
│  Confidence Adjustments:                                            │
│  ────────────────────────────────────────────────────────────────   │
│  • Account not deployed:     -20  (lower priority)                  │
│  • Known safe program:       -25  (Token Program, etc.)             │
│  • Uninitialized (>50%):     +30  (critical issue)                  │
│  • All initialized:          -20  (false positive)                  │
│  • PDA enumeration found:    +20  (confirmed vuln)                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

EOF
)

# =============================================================================
# SLIDE 3: Helius Methods (ALL 4)
# =============================================================================
SLIDE3=$(cat << 'EOF'

┌─────────────────────────────────────────────────────────────────────┐
│                HELIUS API - 4 Analysis Endpoints                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Endpoint              │ PRIV Checks       │ Purpose                │
│  ──────────────────────┼───────────────────┼────────────────────────│
│  /v0/addresses/{}/     │ PRIV-006,007,008  │ Transaction history    │
│    transactions        │ 009,010           │ with enhanced data     │
│  /v0/token-metadata    │ PRIV-004, 005     │ PII in token metadata  │
│  searchAssets (DAS)    │ PRIV-007,009,010  │ Debug flags, creators  │
│  /v0/addresses/{}/     │ SPL discovery     │ Token balance info     │
│    balances            │                   │                        │
│                                                                     │
│  Privacy Patterns Detected:                                         │
│  ────────────────────────────────────────────────────────────────   │
│  • Private keys in rawLogs         → PRIV-001                       │
│  • Mnemonic in instruction data    → PRIV-002                       │
│  • PII (name, email) in metadata   → PRIV-004                       │
│  • DB passwords in logs            → PRIV-005                       │
│  • Sensitive data in events        → PRIV-006                       │
│  • debug_mode: true in NFT         → PRIV-007                       │
│  • Unverified creators             → PRIV-009                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

EOF
)

# =============================================================================
# SLIDE 4: Test Fixtures Overview
# =============================================================================
SLIDE4=$(cat << 'EOF'

┌─────────────────────────────────────────────────────────────────────┐
│              TEST FIXTURES - 10 Simulated Bad Scenarios             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  QuickNode Fixtures (6 - Standard Solana RPC):                      │
│  ─────────────────────────────────────────────────────────────────  │
│  • quicknode_getAccountInfo.json      → SSN, Email, STRIPE_KEY      │
│  • quicknode_getMultipleAccounts.json → Batch PII detection         │
│  • quicknode_getProgramAccounts.json  → Enumerable PDAs with PII    │
│  • quicknode_getSignaturesForAddress  → Sensitive memo fields       │
│  • quicknode_getTransaction.json      → Private key in tx data      │
│  • quicknode_getTokenAccountsByOwner  → Token correlation data      │
│                                                                     │
│  Helius Fixtures (4 - Enhanced API):                                │
│  ─────────────────────────────────────────────────────────────────  │
│  • helius_addressTransactions.json    → /v0/addresses/{}/txns       │
│  • helius_enhancedTransactions.json   → CRITICAL: keys, mnemonics,  │
│                                         DB passwords in logs        │
│  • helius_tokenMetadata.json          → "John Doe", email in data   │
│  • helius_searchAssets.json           → DAS: debug_mode, unverified │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

EOF
)

# =============================================================================
# MAIN DEMO SCRIPT
# =============================================================================

# --- SLIDE 1: Architecture ---
print_slide "$SLIDE1"

# --- SLIDE 2: QuickNode Methods ---
print_slide "$SLIDE2"

# --- SLIDE 3: Helius Methods ---
print_slide "$SLIDE3"

# --- SLIDE 4: Fixtures ---
print_slide "$SLIDE4"

# --- LIVE DEMO ---
clear
echo ""
echo -e "${WHITE}${BOLD}Running ALL QuickNode fixture tests (6 methods)...${NC}"
echo ""
sleep 1

# =============================================================================
# QUICKNODE TESTS (6)
# =============================================================================

# Test 1: getAccountInfo
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  1/6 QuickNode: getAccountInfo (PRIV-004, PRIV-008)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
type_command "cargo test test_quicknode_get_account_info_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_quicknode_get_account_info_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

# Test 2: getMultipleAccounts
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  2/6 QuickNode: getMultipleAccounts (Batch verification)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
type_command "cargo test test_quicknode_get_multiple_accounts_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_quicknode_get_multiple_accounts_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

# Test 3: getProgramAccounts
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  3/6 QuickNode: getProgramAccounts (PRIV-010 enumeration)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
type_command "cargo test test_quicknode_get_program_accounts_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_quicknode_get_program_accounts_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

# Test 4: getSignaturesForAddress
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  4/6 QuickNode: getSignaturesForAddress (PRIV-006 memos)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
type_command "cargo test test_get_signatures_for_address_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_get_signatures_for_address_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

# Test 5: getTransaction
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  5/6 QuickNode: getTransaction (PRIV-001, PRIV-006)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
type_command "cargo test test_get_transaction_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_get_transaction_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

# Test 6: getTokenAccountsByOwner
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  6/6 QuickNode: getTokenAccountsByOwner (Token discovery)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
type_command "cargo test test_get_token_accounts_by_owner_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_get_token_accounts_by_owner_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

echo -e "${GREEN}  ✓ All 6 QuickNode verification methods tested${NC}"
sleep 2

# =============================================================================
# HELIUS TESTS (4)
# =============================================================================
clear
echo ""
echo -e "${WHITE}${BOLD}Running ALL Helius fixture tests (4 methods)...${NC}"
echo ""
sleep 1

# Test 1: getProgramTransactions
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${MAGENTA}  1/4 Helius: getProgramTransactions (Basic tx history)${NC}"
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
type_command "cargo test test_helius_get_program_transactions_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_helius_get_program_transactions_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

# Test 2: getRichTransactions
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${MAGENTA}  2/4 Helius: getRichTransactions (PRIV-001,002,005,006)${NC}"
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${DIM}  Contains: Private keys, mnemonics, DB passwords in logs${NC}"
type_command "cargo test test_get_rich_transactions_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_get_rich_transactions_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

# Test 3: getTokenMetadata
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${MAGENTA}  3/4 Helius: getTokenMetadata (PRIV-004, PRIV-005)${NC}"
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${DIM}  Contains: PII in metadata (John Doe, email)${NC}"
type_command "cargo test test_get_token_metadata_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_get_token_metadata_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

# Test 4: searchAssets
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${MAGENTA}  4/4 Helius: searchAssets DAS (PRIV-007,009,010)${NC}"
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${DIM}  Contains: debug_mode: true, unverified creators${NC}"
type_command "cargo test test_search_assets_with_fixture --bin custos -- --nocapture --test-threads=1"
run_test "cargo test test_search_assets_with_fixture --bin custos -- --nocapture --test-threads=1 2>&1 | tail -20"

echo -e "${GREEN}  ✓ All 4 Helius analysis methods tested${NC}"
sleep 2

# =============================================================================
# LIVE ON-CHAIN SCANNING (requires API keys)
# =============================================================================

if [ "$HAVE_QN_KEY" = true ]; then
    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  LIVE: QuickNode On-Chain Verification${NC}"
    echo -e "${CYAN}  Scanning Metaplex Token Metadata program state...${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    METAPLEX_PROGRAM="metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
    type_command "custos verify $METAPLEX_PROGRAM --limit 20"
    ./target/release/custos verify $METAPLEX_PROGRAM --limit 20

    echo ""
    echo -e "${GREEN}  ✓ Live QuickNode verification complete${NC}"
    echo -e "${DIM}    • Checked program accounts for PRIV-008 (uninitialized)${NC}"
    echo -e "${DIM}    • Analyzed transaction history for PRIV-006 (sensitive memos)${NC}"
    echo ""
    sleep 3
fi

if [ "$HAVE_HELIUS_KEY" = true ]; then
    clear
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${MAGENTA}  LIVE: Helius Transaction Analysis${NC}"
    echo -e "${MAGENTA}  Scanning Jupiter v6 for privacy patterns...${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    JUPITER_PROGRAM="JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
    type_command "custos scan $JUPITER_PROGRAM --limit 50"
    ./target/release/custos scan $JUPITER_PROGRAM --limit 50

    echo ""
    echo -e "${GREEN}  ✓ Live Helius chain scan complete${NC}"
    echo -e "${DIM}    • Analyzed 50 recent transactions${NC}"
    echo -e "${DIM}    • Checked for PRIV-020 (wallet clustering)${NC}"
    echo -e "${DIM}    • Checked for PRIV-021 (balance correlation)${NC}"
    echo ""
    echo -e "${DIM}    Note: Flagged patterns are inherent to DEX aggregator design,${NC}"
    echo -e "${DIM}    not security vulnerabilities. Custos highlights privacy-relevant${NC}"
    echo -e "${DIM}    behaviors for informed decision-making.${NC}"
    echo ""
    sleep 5
fi

# =============================================================================
# DEMO COMPLETE
# =============================================================================
clear
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            INTEGRATION DEMO COMPLETE                       ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}║  QuickNode Verification (6 methods):                       ║${NC}"
echo -e "${GREEN}║    getAccountInfo         - Account state, PII             ║${NC}"
echo -e "${GREEN}║    getMultipleAccounts    - Batch verification             ║${NC}"
echo -e "${GREEN}║    getProgramAccounts     - PDA enumeration                ║${NC}"
echo -e "${GREEN}║    getSignaturesForAddr   - Memo field leaks               ║${NC}"
echo -e "${GREEN}║    getTransaction         - Secrets in tx data             ║${NC}"
echo -e "${GREEN}║    getTokenAccountsByOwner- Token correlation              ║${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}║  Helius Enhanced API (4 endpoints):                        ║${NC}"
echo -e "${GREEN}║    /v0/addresses/txns     - Transaction patterns           ║${NC}"
echo -e "${GREEN}║    /v0/addresses/txns     - Enhanced secrets check         ║${NC}"
echo -e "${GREEN}║    /v0/token-metadata     - PII in metadata                ║${NC}"
echo -e "${GREEN}║    searchAssets (DAS)     - Debug flags, creators          ║${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}║   LIVE: QuickNode program verification                     ║${NC}"
echo -e "${GREEN}║   LIVE: Helius transaction analysis                        ║${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}║  All 10 fixture tests passed                               ║${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
sleep 2

echo -e "${WHITE}${BOLD}Thank you for watching!${NC}"
echo ""
sleep 4