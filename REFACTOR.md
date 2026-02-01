# Custos Full Refactor Plan — Production-Grade Idiomatic Rust

## Overview

Refactor Custos to idiomatic Rust with production-grade Solana tooling conventions. Each chunk is self-contained, testable, and can be merged independently.

**Total Estimated Time: 18-24 hours**

---

## Chunk 0 — Prep & Safety 

**Goal:** Establish baseline, create safe refactoring environment.

### Tasks
- [ ] Run `cargo check` and `cargo test` — capture current state
- [ ] Run `cargo clippy` — note all lints
- [ ] Document all `#[allow(dead_code)]` locations (70+ occurrences)
- [ ] Create `refactor/full-cleanup` branch
- [ ] **Quick win:** Minimize tokio features in `Cargo.toml`:
  ```toml
  # Before
  tokio = { version = "1.35", features = ["full"] }
  # After
  tokio = { version = "1.35", features = ["rt-multi-thread", "macros", "time", "sync"] }
  ```

### Outcome
- Clean git state
- Baseline metrics captured
- Immediate binary size reduction (~30MB → ~15MB)

---

## Chunk 1 — Code Organization + Dead Code Audit

**Goal:** Reduce file sizes, improve navigation, understand what's actually used.

### Tasks

#### 1.1 Split main.rs (1022 LOC)
- [ ] Extract `src/cli.rs` — Clap structs and argument parsing
- [ ] Create `src/commands/` directory:
  - `src/commands/mod.rs`
  - `src/commands/analyze.rs`
  - `src/commands/scan.rs`
  - `src/commands/verify.rs`
  - `src/commands/report.rs`
- [ ] `main.rs` becomes thin dispatcher (~50 LOC)

#### 1.2 Split large modules
- [ ] `quicknode.rs` (2200 LOC) → `src/quicknode/mod.rs`, `src/quicknode/client.rs`, `src/quicknode/verifier.rs`
- [ ] `chain.rs` (1867 LOC) → `src/chain/mod.rs`, `src/chain/scanner.rs`, `src/chain/clustering.rs`

#### 1.3 Dead code audit
- [ ] Audit all 70+ `#[allow(dead_code)]` occurrences
- [ ] Remove truly unused code
- [ ] Document justified `#[allow(dead_code)]` with `// Used by: X feature`
- [ ] Target: <20 justified allows remaining

### Files Changed
| Before | After |
|--------|-------|
| `src/main.rs` (1022 LOC) | `src/main.rs` + `src/cli.rs` + `src/commands/*.rs` |
| `src/quicknode.rs` (2200 LOC) | `src/quicknode/*.rs`|
| `src/chain.rs` (1867 LOC) | `src/chain/*.rs` 

### Outcome
- No file >800 LOC
- Dead code removed or justified
- Easy navigation

---

## Chunk 2 — Error Handling 

**Goal:** Replace ad-hoc errors with typed, domain-specific errors.

### Tasks
- [ ] Create `src/error.rs` with thiserror:
  ```rust
  use thiserror::Error;

  #[derive(Error, Debug)]
  pub enum CustosError {
      #[error("Analysis failed: {0}")]
      Analysis(String),

      #[error("RPC error: {0}")]
      Rpc(#[from] reqwest::Error),

      #[error("Configuration error: {0}")]
      Config(String),

      #[error("File not found: {0}")]
      FileNotFound(std::path::PathBuf),

      #[error("Parse error in {file}: {message}")]
      Parse { file: String, message: String },
  }

  pub type Result<T> = std::result::Result<T, CustosError>;
  ```
- [ ] Add `thiserror = "1.0"` to Cargo.toml
- [ ] Replace `anyhow::Result` with `crate::error::Result` in all modules
- [ ] Remove `std::process::exit(1)` calls — return `Err()` instead
- [ ] Add `.context()` or custom error variants for meaningful messages

### Files Changed
- New: `src/error.rs`
- Modified: All `src/*.rs` files (import changes, Result type changes)

### Outcome
- Type-safe, categorized errors
- No silent failures
- Better error messages for users

---

## Chunk 3 — Naming & Domain Types 

**Goal:** Replace generic names with domain-specific names, add newtypes.

### Tasks

#### 3.1 Newtypes for domain concepts
- [ ] Create `src/types.rs`:
  ```rust
  use std::path::PathBuf;

  #[derive(Debug, Clone, PartialEq, Eq, Hash)]
  pub struct ProgramId(pub String);

  #[derive(Debug, Clone)]
  pub struct FilePath(pub PathBuf);

  #[derive(Debug, Clone, Copy)]
  pub struct Confidence(u8);

  impl Confidence {
      pub fn new(value: u8) -> Self {
          Self(value.min(100))
      }
      pub fn value(&self) -> u8 { self.0 }
  }
  ```

#### 3.2 Rename generic functions
| Before | After |
|--------|-------|
| `process_data()` | `analyze_account_struct()` |
| `handle()` | `execute_command()` |
| `check()` | `detect_pii_fields()` |
| `utils.rs` | Split: `fs.rs`, `git.rs` |

#### 3.3 Add trait for verifiers (they share interface)
- [ ] Create `src/verifier.rs`:
  ```rust
  pub trait FindingVerifier {
      async fn verify(&self, finding: &Finding, program_id: &ProgramId) -> Result<VerifiedFinding>;
  }
  ```
- [ ] Implement for `QuickNodeVerifier` and `HeliusVerifier`

### Outcome
- Domain-oriented, self-documenting code
- Type safety for IDs and scores
- Polymorphic verifier interface

---

## Chunk 4 — CLI & Enums 

**Goal:** Make CLI robust, type-safe, and minimal.

### Tasks

#### 4.1 Consolidate commands (7 → 4)
| Before | After |
|--------|-------|
| `analyze`, `verify`, `verify-quicknode`, `verify-helius` | `analyze --verify [quicknode\|helius\|both]` |
| `scan` | `scan` (unchanged) |
| `check` | `check` (unchanged) |
| `report` | `report` (unchanged) |

#### 4.2 Convert string enums to clap::ValueEnum
```rust
#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, ValueEnum)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, ValueEnum)]
pub enum VerifyBackend {
    Quicknode,
    Helius,
    Both,
}
```

#### 4.3 Add validation
- [ ] `min_confidence: u8` — clap range validator 0-100
- [ ] `limit: usize` — cap at 1000 (Helius API limit)

### Files Changed
- `src/cli.rs` — New enums, consolidated commands
- `src/commands/*.rs` — Updated handlers

### Outcome
- 4 clear commands instead of 7
- Type-safe enums, no string matching
- Input validation at parse time

---

## Chunk 5 — Async & Runtime 

**Goal:** Fix async correctness issues.

### Tasks
- [ ] Fix blocking git command in `utils.rs`:
  ```rust
  // Before (blocks tokio thread)
  Command::new("git").args(&["..."]).output()

  // After (proper async)
  tokio::process::Command::new("git").args(&["..."]).output().await
  ```
- [ ] Share single `reqwest::Client` across modules:
  ```rust
  // In main.rs or app state
  let client = reqwest::Client::builder()
      .timeout(Duration::from_secs(30))
      .build()?;
  ```
- [ ] Add timeout configuration for RPC calls (10s) and API calls (30s)
- [ ] Verify no other `std::process::Command` or blocking I/O in async context

### Files Changed
- `src/utils.rs` → `src/git.rs` (async)
- `src/quicknode/client.rs` — shared client
- `src/chain/scanner.rs` — shared client

### Outcome
- No blocking in async context
- Connection pooling via shared client
- Configurable timeouts

---

## Chunk 6 — Logging & Observability 

**Goal:** Replace println with structured logging.

### Tasks
- [ ] Add dependencies:
  ```toml
  tracing = "0.1"
  tracing-subscriber = { version = "0.3", features = ["env-filter"] }
  ```
- [ ] Initialize in main:
  ```rust
  tracing_subscriber::fmt()
      .with_env_filter(EnvFilter::from_default_env())
      .init();
  ```
- [ ] Replace `println!` / `eprintln!` with tracing macros:
  | Before | After |
  |--------|-------|
  | `println!("Analyzing...")` | `info!("Analyzing {}", path)` |
  | `eprintln!("Error: {}", e)` | `error!(%e, "Analysis failed")` |
  | `if verbose { println!(...) }` | `debug!(...)` |
- [ ] Add spans for commands:
  ```rust
  #[tracing::instrument(skip(self))]
  async fn analyze(&self, target: &str) -> Result<()> { ... }
  ```

### Outcome
- Structured logs (JSON available via env)
- Debug output controlled by `RUST_LOG=debug`
- Performance spans for profiling

---

## Chunk 7 — Tests & Verification 

**Goal:** Comprehensive test coverage.

### Tasks

#### 7.1 Unit tests per check module
- [ ] `src/checks/secrets.rs` — Test all key patterns
- [ ] `src/checks/pii.rs` — Test PII detection, false positive handling
- [ ] `src/checks/logging.rs` — Test log pattern detection
- [ ] `src/checks/anchor.rs` — Test PRIV-008 through PRIV-016
- [ ] `src/checks/access.rs` — Test CPI validation

#### 7.2 CLI integration tests
- [ ] Test `analyze` command with demo programs
- [ ] Test `scan` command with mocked Helius
- [ ] Test error cases (missing file, invalid args)

#### 7.3 Error path coverage
- [ ] Test all `CustosError` variants
- [ ] Test graceful handling of API failures

### Outcome
- >80% code coverage on check modules
- CLI behavior verified
- Error handling tested

---

## Chunk 8 — Cleanup & Polish 

**Goal:** Final human-readable polish.

### Tasks
- [ ] Run `cargo fmt` — consistent formatting
- [ ] Run `cargo clippy` — fix all warnings
- [ ] Add API documentation:
  ```rust
  /// Analyzes a Solana program for privacy vulnerabilities.
  ///
  /// # Arguments
  /// * `target` - Path to program or GitHub URL
  ///
  /// # Returns
  /// Analysis results with findings and score
  ///
  /// # Errors
  /// Returns `CustosError::FileNotFound` if target doesn't exist
  pub fn analyze(target: &str) -> Result<AnalysisResult> { ... }
  ```
- [ ] Remove verbose/redundant comments
- [ ] Verify all public types have doc comments

### Outcome
- Clean, consistent code style
- Self-documenting public API
- Zero clippy warnings

---

## Chunk 9 — Optional Advanced 

**Goal:** Further optimization 

### Tasks
- [ ] Consolidate duplicated regex patterns across modules
- [ ] Inline trivial single-use helper functions
- [ ] Optimize module visibility (`pub(crate)` vs `pub`)
- [ ] Consider adding benchmarks for taint analysis
- [ ] Profile and optimize hot paths

### Outcome
- Minimal, highly optimized code
- Clear module boundaries

## Key Principles

1. **One improvement per chunk** — Don't mix organizational changes with behavioral changes
2. **Test after each chunk** — `cargo test` must pass before moving on
3. **Commit after each chunk** — Clean git history, easy to revert
4. **Document reasoning** — Replace AI-like over-commenting with domain reasoning
