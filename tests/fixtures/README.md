# Test Fixtures

## Purpose

These fixture files mock real RPC/API responses from Helius and QuickNode for **offline integration testing**. They allow us to:

1. **Test without live API keys** - No need for `HELIUS_API_KEY` or `QUICKNODE_RPC_URL` during CI/CD
2. **Deterministic tests** - Same fixture data every run, no network flakiness
3. **Verify PRIV detection logic** - Each fixture contains intentional privacy violations to ensure our scanners catch them
4. **Fast execution** - No network calls, tests run in milliseconds

All tests use [`wiremock`](https://docs.rs/wiremock) to spin up mock HTTP servers that serve these JSON responses.

---

## Fixture Files

### QuickNode RPC Fixtures (JSON-RPC 2.0)
- `quicknode_getAccountInfo.json`: Account info response (PRIV-004, PRIV-008 detection)
- `quicknode_getMultipleAccounts.json`: Batch account info response
- `quicknode_getProgramAccounts.json`: Program accounts enumeration (PRIV-010 detection)
- `quicknode_getSignaturesForAddress.json`: Transaction signature history (3 signatures with memos)
- `quicknode_getTransaction.json`: Detailed transaction data (PRIV-001, PRIV-006 detection)
- `quicknode_getTokenAccountsByOwner.json`: SPL token account discovery

### Helius RPC Fixtures (Enhanced API)
Fixtures named after Helius API endpoints:
- `helius_addressTransactions.json`: `/v0/addresses/{addr}/transactions` - Basic transaction history
- `helius_tokenMetadata.json`: `/v0/token-metadata` - Token metadata with PII (PRIV-004: "John Doe", email in offChainData)
- `helius_searchAssets.json`: DAS `searchAssets` RPC method - Asset search (PRIV-007: debug_mode, PRIV-009: unverified creators)
- `helius_enhancedTransactions.json`: `/v0/addresses/{addr}/transactions` - Rich transaction data with **CRITICAL** privacy leaks:
  - PRIV-001: Private key hex in `rawLogs`
  - PRIV-002: Mnemonic seed phrase in instruction `data`
  - PRIV-005: Database password in `rawLogs` ("DB_PASSWORD=admin123superSecret")
  - PRIV-006: Stale data references in logs

## Privacy Violations in Fixtures

Each fixture demonstrates specific PRIV-XXX violations:

| Fixture | PRIV Checks | Example Leak |
|---------|-------------|--------------|
| `helius_enhancedTransactions.json` | PRIV-001, 002, 005, 006 | Private keys, mnemonics, DB passwords in logs |
| `helius_tokenMetadata.json` | PRIV-004, 005 | PII in metadata (names, emails) |
| `helius_searchAssets.json` | PRIV-007, 009, 010 | Debug flags, unverified creators, predictable IDs |
| `quicknode_getSignaturesForAddress.json` | PRIV-006 | Sensitive memo fields ("Internal Transfer to Private Cold Wallet") |

## Running Tests

**Important**: Use `--test-threads=1` to prevent environment variable race conditions when mocking.

### Run All Tests at Once

```bash
# All fixture-based tests (Helius + QuickNode)
cargo test fixture --bin custos -- --test-threads=1 --nocapture

# Only Helius API tests
cargo test helius --bin custos -- --test-threads=1 --nocapture

# Only QuickNode RPC tests
cargo test quicknode --bin custos -- --test-threads=1 --nocapture
```

### Fixture → Test Mapping

| Fixture File | Test Command |
|-------------|--------------|
| `helius_addressTransactions.json` | `cargo test test_helius_get_program_transactions_with_fixture --bin custos -- --nocapture` |
| `helius_tokenMetadata.json` | `cargo test test_get_token_metadata_with_fixture --bin custos -- --nocapture` |
| `helius_searchAssets.json` | `cargo test test_search_assets_with_fixture --bin custos -- --nocapture` |
| `helius_enhancedTransactions.json` | `cargo test test_get_rich_transactions_with_fixture --bin custos -- --nocapture` |
| `quicknode_getAccountInfo.json` | `cargo test test_quicknode_get_account_info_with_fixture --bin custos -- --nocapture` |
| `quicknode_getMultipleAccounts.json` | `cargo test test_quicknode_get_multiple_accounts_with_fixture --bin custos -- --nocapture` |
| `quicknode_getProgramAccounts.json` | `cargo test test_quicknode_get_program_accounts_with_fixture --bin custos -- --nocapture` |
| `quicknode_getSignaturesForAddress.json` | `cargo test test_get_signatures_for_address_with_fixture --bin custos -- --nocapture` |
| `quicknode_getTransaction.json` | `cargo test test_get_transaction_with_fixture --bin custos -- --nocapture` |
| `quicknode_getTokenAccountsByOwner.json` | `cargo test test_get_token_accounts_by_owner_with_fixture --bin custos -- --nocapture` |

### Run Individual Tests

#### Helius Tests (one by one)

```bash
cargo test test_helius_get_program_transactions_with_fixture --bin custos -- --nocapture
cargo test test_get_token_metadata_with_fixture --bin custos -- --nocapture
cargo test test_search_assets_with_fixture --bin custos -- --nocapture
cargo test test_get_rich_transactions_with_fixture --bin custos -- --nocapture
```

#### QuickNode Tests (one by one)

```bash
cargo test test_quicknode_get_account_info_with_fixture --bin custos -- --nocapture
cargo test test_quicknode_get_multiple_accounts_with_fixture --bin custos -- --nocapture
cargo test test_quicknode_get_program_accounts_with_fixture --bin custos -- --nocapture
cargo test test_get_signatures_for_address_with_fixture --bin custos -- --nocapture
cargo test test_get_transaction_with_fixture --bin custos -- --nocapture
cargo test test_get_token_accounts_by_owner_with_fixture --bin custos -- --nocapture
```

#### PRIV Verification Tests (cross-check with on-chain data)

```bash
cargo test test_verify_focused_priv_006 --bin custos -- --nocapture
cargo test test_verify_focused_priv_001 --bin custos -- --nocapture
```

---

## Testing with Live APIs

The above tests use **mock data** (fixtures). To test with **real Helius/QuickNode APIs**, use the CLI commands:

### Helius Live API Testing

```bash
# Set your API key (get free key at: https://dev.helius.xyz/)
export HELIUS_API_KEY=your_api_key_here

# Scan a deployed program (e.g., Token Program)
custos scan TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA

# Or pass API key directly
custos scan <PROGRAM_ID> --api-key your_api_key_here --limit 50 --output json
```

**What it does:** Fetches real transaction data from Helius API and runs PRIV-001, 002, 004, 005, 007, 009, 010, 020, 021 checks.

### QuickNode Live RPC Testing

```bash
# Set your RPC URL (get free endpoint at: https://www.quicknode.com/chains/sol)
export QUICKNODE_RPC_URL=https://your-endpoint.solana-mainnet.quiknode.pro/your_token/

# Verify a deployed program
custos verify <PROGRAM_ID>

# Or pass URL directly
custos verify <PROGRAM_ID> --rpc-url https://your-endpoint.solana-mainnet.quiknode.pro/your_token/
```

**What it does:** Queries on-chain account state via QuickNode RPC and runs PRIV-004, 006, 008, 010 verification checks.

**Note:** You need a **full RPC URL** for QuickNode (not just a project ID).

---

## Editing Fixtures

Edit these JSON files to test different privacy violation scenarios. Tests use `wiremock` to mock HTTP endpoints with fixture data.
