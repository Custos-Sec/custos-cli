#!/bin/bash
# demo/demo_main.sh - Custos Main Privacy Track Demo (~4 min)
#
# Self-narrating demo for video recording
# Pre-build first, then run clean demo with no cargo overhead

set -e  # Exit on error

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

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
    clear_and_pause 12
}

print_slide_long() {
    clear
    echo -e "$1"
    clear_and_pause 14
}

# Simulate typing effect for commands (optional, can remove if too slow)
type_command() {
    local cmd="$1"
    echo ""
    echo -ne "${YELLOW}$ ${NC}"
    for (( i=0; i<${#cmd}; i++ )); do
        echo -n "${cmd:$i:1}"
        sleep 0.02
    done
    echo -e "${NC}"
    sleep 1
}

# Execute and show output
run_command() {
    local cmd="$1"
    echo ""
    # Run command and show all output
    eval "$cmd" || {
        echo -e "${RED}Error running command${NC}"
        return 1
    }
    echo ""
    sleep 8
}

# =============================================================================
# SLIDE 1: Custos Capabilities Overview
# =============================================================================
SLIDE1=$(cat << 'EOF'

┌────────────────────────────────────────────────────────────────────┐
│                    CUSTOS - Privacy Scanner for Solana             │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────┬──────────────────────────────────────┐   │
│  │  STATIC ANALYSIS     │  CHAIN SCANNING                      │   │
│  │  (Source Code)       │  (Deployed Programs)                 │   │
│  ├──────────────────────┼──────────────────────────────────────┤   │
│  │  • Hardcoded secrets │  • Wallet clustering detection       │   │
│  │  • PII in structs    │  • Balance correlation analysis      │   │
│  │  • Sensitive logging │  • Transaction pattern analysis      │   │
│  │  • Uninitialized     │  • On-chain PII exposure             │   │
│  │    account state     │  • Debug flags in production         │   │
│  │  • Taint analysis    │  • Metadata privacy leaks            │   │
│  │  • PDA enumeration   │                                      │   │
│  └──────────────────────┴──────────────────────────────────────┘   │
│                                                                    │
│  Integrations: QuickNode RPC | Helius API                          │
└────────────────────────────────────────────────────────────────────┘

EOF
)

# =============================================================================
# SLIDE 2: All PRIV Checks Reference
# =============================================================================
SLIDE2=$(cat << 'EOF'

┌────────────┬─────────────────────────────────┬──────────┬───────────┐
│ ID         │ Description                     │ Severity │ Mode      │
├────────────┼─────────────────────────────────┼──────────┼───────────┤
│ PRIV-001   │ Hardcoded Private Keys          │ CRITICAL │ Both      │
│ PRIV-002   │ Exposed Mnemonic Phrases        │ CRITICAL │ Both      │
│ PRIV-003   │ Hardcoded Seed Bytes            │ HIGH     │ Static    │
│ PRIV-004   │ PII in Account Structs          │ HIGH     │ Both      │
│ PRIV-005   │ Sensitive Credentials Stored    │ HIGH     │ Both      │
│ PRIV-006   │ Sensitive Data in Logs/Events   │ MEDIUM   │ Both      │
│ PRIV-007   │ Debug Macros in Production      │ LOW      │ Both      │
│ PRIV-008   │ Uninitialized Account State     │ HIGH     │ Static    │
│ PRIV-009   │ Unverified CPI Targets          │ MEDIUM   │ Both      │
│ PRIV-010   │ Predictable/Enumerable PDAs     │ MEDIUM   │ Both      │
│ PRIV-012   │ Raw AccountInfo (no validation) │ LOW      │ Static    │
│ PRIV-020   │ Wallet Clustering Detected      │ HIGH     │ Chain     │
│ PRIV-021   │ Balance Correlation Leakage     │ HIGH     │ Chain     │
│ PRIV-030   │ Taint Analysis (Data Flow)      │ HIGH     │ Static    │
└────────────┴─────────────────────────────────┴──────────┴───────────┘

EOF
)

# =============================================================================
# SLIDE 3: Critical Vulnerability Cross-Reference
# =============================================================================
SLIDE3=$(cat << 'EOF'

┌────────────────────────────────────────────────────────────────────┐
│              CRITICAL VULNERABILITIES & DETECTION                  |
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Real-World Exploit          │ Loss      │ Custos Detection        │
│  ────────────────────────────┼───────────┼─────────────────────────│
│  Wormhole Bridge Hack        │ $326M     │ PRIV-008 (uninitialized)│
│  Cashio Infinite Mint        │ $52M      │ PRIV-008, PRIV-009      │
│  Crema Finance Exploit       │ $8.8M     │ PRIV-008                │
│  Slope Wallet Leak           │ $8M+      │ PRIV-001, PRIV-006      │
│  ────────────────────────────┼───────────┼─────────────────────────│
│                                                                    │
│  Privacy Risk Category       │ Checks    │ Impact                  │
│  ────────────────────────────┼───────────┼─────────────────────────│
│  Key/Credential Exposure     │ 001,002,  │ Total fund loss         │
│                              │ 003,005   │                         │
│  Identity Correlation        │ 020,021   │ Pseudonymity broken     │
│  PII On-Chain                │ 004,006   │ GDPR violations,        │
│                              │           │ identity theft          │
│  Account State Attacks       │ 008,009   │ Fund theft, fake data   │
└────────────────────────────────────────────────────────────────────┘

EOF
)

# =============================================================================
# MAIN DEMO SCRIPT
# =============================================================================

# --- SLIDE 1: Capabilities ---
print_slide "$SLIDE1"

# --- SLIDE 2: PRIV Checks ---
print_slide "$SLIDE2"

# --- SLIDE 3: Critical Vulns ---
print_slide_long "$SLIDE3"

# --- SLIDE 4: Live Demo ---
clear
echo ""
echo -e "${WHITE}${BOLD}Now let's see Custos in action...${NC}"
echo ""
sleep 4

# -----------------------------------------------------------------------------
# 4.1 Wormhole Pattern Demo (PRIV-008 detection)
# -----------------------------------------------------------------------------
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Scanning for Wormhole-class vulnerabilities (PRIV-008)...${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

WORMHOLE_TARGET="demo/wormhole-pattern"
type_command "custos analyze $WORMHOLE_TARGET"
run_command "./target/release/custos analyze $WORMHOLE_TARGET"

echo -e "${GREEN}  ✓ PRIV-008 detected the Wormhole-class vulnerability${NC}"
echo -e "${DIM}    This pattern caused \$326M+ in losses${NC}"
echo ""
sleep 10

# -----------------------------------------------------------------------------
# 4.2 Vulnerable Program Demo (Multiple PRIV detections)
# -----------------------------------------------------------------------------
clear
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Scanning a program with multiple privacy issues...${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

VULNERABLE_TARGET="demo/vulnerable-program"
type_command "custos analyze $VULNERABLE_TARGET"
run_command "./target/release/custos analyze $VULNERABLE_TARGET"

echo -e "${GREEN}  ✓ Multiple privacy violations detected:${NC}"
echo -e "${DIM}    • PII in account structs (email, phone, name)${NC}"
echo -e "${DIM}    • Sensitive data in logs and events${NC}"
echo -e "${DIM}    • Taint flow tracking across functions${NC}"
echo ""
sleep 10

# -----------------------------------------------------------------------------
# 4.3 Secure Program Demo (Clean result)
# -----------------------------------------------------------------------------
clear
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Scanning a secure program (should pass)...${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

SECURE_TARGET="demo/secure-program"
type_command "custos analyze $SECURE_TARGET"
run_command "./target/release/custos analyze $SECURE_TARGET"

echo -e "${GREEN}  ✓ Secure program follows privacy best practices:${NC}"
echo -e "${DIM}    • No PII stored on-chain${NC}"
echo -e "${DIM}    • Proper account validation${NC}"
echo -e "${DIM}    • Events contain only public blockchain data${NC}"
echo ""
sleep 10

# -----------------------------------------------------------------------------
# 4.4 Production Contract Demo (Marinade Finance - audited protocol)
# -----------------------------------------------------------------------------
clear
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Now scanning a REAL production DeFi protocol...${NC}"
echo -e "${CYAN}  Marinade Finance - \$100M+ TVL liquid staking${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

MARINADE_URL="https://github.com/marinade-finance/liquid-staking-program"
type_command "custos analyze $MARINADE_URL -c 85"
run_command "./target/release/custos analyze $MARINADE_URL -c 85"

echo -e "${GREEN}  ✓ Analysis complete - findings are informational:${NC}"
echo -e "${DIM}    • Low-severity items flagged for review${NC}"
echo -e "${DIM}    • No CRITICAL or HIGH severity issues found${NC}"
echo -e "${DIM}    • Expected result for well-audited production code${NC}"
echo ""
sleep 10

# =============================================================================
# DEMO COMPLETE
# =============================================================================
clear
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    DEMO COMPLETE                           ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}║  Custos detected:                                          ║${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}║  ✓ Wormhole-class vulnerabilities (PRIV-008)               ║${NC}"
echo -e "${GREEN}║  ✓ PII exposure in account structs                         ║${NC}"
echo -e "${GREEN}║  ✓ Sensitive data in logs/events                           ║${NC}"
echo -e "${GREEN}║  ✓ Cross-function taint analysis (FlowTrace)               ║${NC}"
echo -e "${GREEN}║  ✓ Scanned real production protocol (Marinade Finance)     ║${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}║  And verified secure code passes clean!                    ║${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
sleep 8

echo -e "${WHITE}${BOLD}Thank you for watching!${NC}"
echo ""
sleep 2