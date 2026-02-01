# Custos

**Static analyzer + on-chain monitor that catches $500M+ exploit patterns**

Prevent Wormhole-class bugs before deployment and monitor for privacy leaks after...

## The $500M Problem We Solve

The Solana ecosystem has lost over **$500 million** to a single class of vulnerability: **unvalidated account state**.

| Exploit | Loss | Root Cause |
|---------|------|------------|
| **Wormhole** (Feb 2022) | $326M | Missing discriminator check on guardian accounts |
| **Mango Markets** (Oct 2022) | $114M | Unvalidated oracle accounts manipulated |
| **Cashio** (Mar 2022) | $52M | Fake collateral accounts accepted without validation |
| **Crema Finance** (Jul 2022) | $8.8M | Uninitialized tick accounts exploited |

**Custos detects these patterns before you deploy.**

## Quick Start

```bash
# Install from GitHub
cargo install --git https://github.com/Custos-Sec/custos-cli.git

# Run on your Solana program
custos analyze ./your_solana_program
```

## Demo

```bash
# Clone and build
git clone https://github.com/Custos-Sec/custos-cli.git && cd custos-cli
cargo build --release

# See Custos catch the Wormhole vulnerability pattern
cargo run -- analyze demo/wormhole-pattern
```

## Why Custos?

| Tool | Solana-Native | Catches PRIV-008 | FlowTrace Taint Analysis | On-Chain Verification |
|------|---------------|------------------|--------------------------|----------------------|
| **Custos** | Yes | Yes | Yes (4-level depth) | Yes |
| Anchor Verify | Yes | No | No | No |
| cargo-audit | No | No | No | No |
| Semgrep | Generic rules | Custom only | No | No |

Custos is **purpose-built** for Solana's account model and Anchor patterns.

## What Custos Detects

### Security Checks (Exploit Prevention)
- **PRIV-008**: Uninitialized account state (the Wormhole/Cashio bug class)
- **PRIV-009**: CPI without program validation
- **PRIV-010**: Predictable/enumerable PDA seeds
- **PRIV-011**: Missing signer validation on authority accounts
- **PRIV-012**: UncheckedAccount without safety documentation
- **PRIV-013**: CPI calls without program ID validation
- **PRIV-014**: Account close without discriminator zeroing (revival attacks)
- **PRIV-015**: init_if_needed without ownership constraints (reinitialization)
- **PRIV-016**: Unsafe arithmetic in token operations

### Privacy Checks (Data Protection)
- **PRIV-001**: Hardcoded private keys (base58, base64, hex, byte arrays)
- **PRIV-002**: Exposed mnemonic/seed phrases
- **PRIV-003**: Hardcoded seed bytes
- **PRIV-004**: PII in on-chain account structs (email, phone, SSN)
- **PRIV-005**: Sensitive data fields (passwords, API keys)
- **PRIV-006**: Sensitive data in logs/events
- **PRIV-007**: Debug logging in production

### FlowTrace: Data-Flow Analysis
- **PRIV-030**: Tracks sensitive data across functions (4-level depth)

### Chain Scanning Checks (Helius API)
These checks are only available when scanning deployed programs with `custos scan`:
- **PRIV-020**: Wallet clustering detection (multiple wallets linked in single transaction)
- **PRIV-021**: Balance correlation leakage (detects correlated balance patterns)

## FlowTrace Visualization

Custos includes **FlowTrace**, a taint analysis engine that shows exactly how sensitive data travels through your code:

```
+---------------------------------------------------------+
|  PRIV-030: Privacy Leak Path Detected (Confidence: 94%) |
+---------------------------------------------------------+

  SOURCE: parameter 'email' (String)
          src/lib.rs:14
                   |
                   v
  FLOW:   via email -> emit!(UserEvent)
                   |
                   v
  SINK:   emit!(UserRegistered) event (publicly indexed)
          src/lib.rs:67

  Warning: Personal data flows directly to publicly-indexed event
```

## Installation

```bash
# Clone the repository
git clone https://github.com/Custos-Sec/custos-cli.git
cd custos-cli

# Build
cargo build --release

# Install globally (optional)
cargo install --path .
```

## Usage

### Static Analysis

```bash
# Analyze a local project
custos analyze ./my-solana-program

# Analyze a GitHub repository
custos analyze https://github.com/coral-xyz/anchor

# JSON output for CI/CD
custos analyze ./program --output json

# Filter by severity
custos analyze ./program --severity high

# CI mode - fail if score below threshold
custos analyze ./program --ci --threshold 60
```

### On-Chain Verification

Custos can verify static findings against live chain state to adjust confidence scores:

```bash
# Set RPC URL
export QUICKNODE_RPC_URL=https://your-rpc.solana.com

# Analyze with on-chain verification
custos analyze ./program --verify

# Or with explicit RPC URL
custos analyze ./program --verify --rpc-url https://api.mainnet-beta.solana.com
```

Verification adjusts confidence based on:
- Account deployment status and initialization state
- Known safe programs (Token Program, Jupiter, etc.)
- PDA enumeration feasibility on-chain

### Live Chain Scanning

Scan deployed programs for runtime privacy issues (PRIV-020, PRIV-021):

```bash
# Set your Helius API key
export HELIUS_API_KEY=your_key_here

# Scan a deployed program
custos scan <PROGRAM_ID>

# Scan with options
custos scan <PROGRAM_ID> --limit 100 --output json -v
```

Chain scanning detects:
- **Wallet clustering** - Multiple wallets controlled by same operator
- **Balance correlation** - Patterns that link anonymous wallets

Get a free Helius API key at: https://dev.helius.xyz/

## Example Findings

### Wormhole-Pattern Detection (PRIV-008)

**Vulnerable Code:**
```rust
#[derive(Accounts)]
pub struct MintWithCollateral<'info> {
    // VULNERABLE: mut without init, seeds, has_one, or constraint
    #[account(mut)]
    pub collateral: Account<'info, Collateral>,
}
```

**Custos Output:**
```
[!!] [HIGH] PRIV-008: Mutable Account Without Initialization Check (70%)
   Evidence:
      - Mutable account without initialization constraint
      - No validation constraints (has_one, constraint, seeds) detected
      - Could read/write uninitialized or stale account data

   Fix: Add validation constraints:
        #[account(mut, has_one = authority, seeds = [...], bump)]
```

### PII Detection (PRIV-004)

**Vulnerable Code:**
```rust
#[account]
pub struct UserProfile {
    pub email: String,     // PII on-chain!
    pub phone: String,     // PII on-chain!
}
```

**Custos Output:**
```
[!!] [HIGH] PRIV-004: PII in Account Struct: 'email' (98%)
   Evidence:
      - Field is in #[account] struct (stored on-chain)
      - Type is String (plaintext, publicly readable)

   Fix: Hash with SHA-256 + salt, or encrypt with AES-GCM, or store off-chain.
```

## Why Privacy Matters on Solana

**Blockchain data is permanent.** Once deployed, privacy bugs can never be fully fixed - the data is already public, forever.

1. **On-chain PII**: Storing email, phone, or names in account structs makes them globally accessible
2. **Event indexing**: Anchor events are indexed by Helius - any data emitted is searchable
3. **Transaction logs**: `msg!()` output is visible to anyone inspecting transactions
4. **Account enumeration**: Predictable PDA seeds allow attackers to scan all user accounts
5. **Regulatory risk**: GDPR violations can result in fines up to 4% of global revenue

Custos catches these issues **before deployment**, when they can still be fixed.

## Architecture

```
custos/
├── src/
│   ├── main.rs           # CLI entry point
│   ├── scanner.rs        # Static analysis orchestrator
│   ├── chain.rs          # Live chain scanning via Helius API
│   ├── checks/
│   │   ├── secrets.rs    # PRIV-001/002/003 (keys, mnemonics)
│   │   ├── pii.rs        # PRIV-004/005 (PII, sensitive fields)
│   │   ├── logging.rs    # PRIV-006/007 (log/debug leaks)
│   │   ├── access.rs     # PRIV-009 (CPI validation)
│   │   └── anchor.rs     # PRIV-008/010+ (state validation, PDA enumeration)
│   ├── taint.rs          # FlowTrace data-flow analysis (PRIV-030)
│   ├── parser.rs         # Lightweight Rust AST parsing
│   ├── safe_patterns.rs  # False positive reduction (65+ patterns)
│   ├── quicknode.rs      # On-chain verification via RPC
│   └── helius.rs         # Helius API integration
├── demo/
│   ├── wormhole-pattern/ # Demonstrates PRIV-008 (the $326M bug class)
│   ├── vulnerable-program/ # 22 privacy issues for testing
│   └── secure-program/   # Best practices example
└── tests/
    └── fixtures/         # Mock RPC/API responses for testing
```

## Suppression Comments

Suppress false positives with inline comments:

```rust
let key = "not-a-secret";  // custos-ignore
// custos-ignore-next-line
let data = "safe";
let x = "ok";              // custos-ignore[PRIV-001]
// custos-ignore-file      (at top of file)
// custos-ignore-file[PRIV-001, PRIV-002]
```

## Testing

```bash
# Run all tests
cargo test

# Run fixture-driven verification tests
cargo test test_verify_with_fixtures_inproc --bin custos -- --nocapture

# Run Helius API tests
cargo test helius --bin custos -- --test-threads=1 --nocapture

# Run QuickNode RPC tests
cargo test quicknode --bin custos -- --test-threads=1 --nocapture
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for our vision of becoming the default security and privacy layer on Solana.

For the technical refactor plan, see [REFACTOR.md](REFACTOR.md).

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Thoughts and musings

Custos started as a challenge for the Privacy Hack, but it quickly evolved into something that has actual real world merit. This is what we are set out to explore and build as it seems like there's an opportunity somewhere in the intersection of privacy and security onchain. Building Custos and exploring different paths to achieveing our goal has been extremely fun! We encourage everyone to try it out for themselves and see what they can build... meanwhile, we will be working on the improvements outlined in our roadmap so we can fulfill that vision.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built for the Solana Privacy Hackathon, January 2026**

## Demo folder

We've added the demo scripts from the submission video to the `demo/` folder.
To run them yourself, just set your API keys within the scripts and then run the demo to quickly see Custos in action.