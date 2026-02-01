# Roadmap

## Immediate: Production-Grade Refactor (4-6 Weeks)

The hackathon version works but the code is still quite messy. Cleaning it up:

**Weeks 1-3: Core Cleanup**
- Split 1000+ line files into proper modules
- Replace ad-hoc error handling with typed errors (thiserror)
- Fix async correctness issues (blocking git calls in tokio context)
- Consolidate CLI commands (7 → 4 with proper flags)
- Add structured logging (replace println spam)

**Weeks 3-6: Quality & Testing**
- Unit tests for all check modules (target >80% coverage)
- CLI integration tests
- Documentation for public APIs
- Zero clippy warnings
- Benchmark taint analysis performance

See [REFACTOR.md](REFACTOR.md) for the detailed technical plan.

---

## Short Term (1-3 Months): Developer Integration

**GitHub Action**
```yaml
- uses: custos-sec/custos-action@v1
  with:
    severity: high
    fail-on-findings: true
```

**VS Code Extension**
- Inline squiggles for PRIV-008, PRIV-030 findings
- Quick fixes for common patterns
- Security score in status bar

**Anchor Integration**
```bash
anchor build
# Automatically runs: custos analyze --ci
```

Make Custos the default security check, not an afterthought.

---

## Medium Term (3-6 Months): Beyond Static Analysis

**Custos Runtime** - Monitor deployed programs
- Continuous scanning of production programs
- Alert on new privacy leaks in events/logs
- Historical analysis (did this program ever leak PII?)
- Webhook integration for real-time alerts

**Custos Audit** - Generate reports
- PDF audit reports with severity breakdown
- Remediation steps for each finding
- Compliance checklists (GDPR, SOC2)
- Diff reports (show what changed between versions)

**SDK for Tool Builders**
```rust
use custos_sdk::{Analyzer, Check};

let analyzer = Analyzer::new()
    .add_check(CustomCheck::new())
    .run("./program")?;
```

Let others build domain-specific checks on top of our engine.

---

## Long Term (6-12 Months): Platform & Scale

**Deeper Analysis Capabilities**
- Enhanced flow analysis for complex multi-function scenarios
- Support for multi-crate projects and dependency trees
- Configurable analysis depth and precision tradeoffs
- Extensibility framework for custom security policies

**Custos Score API**
```rust
// DeFi protocols query before integration
let score = custos_api::score("ProgramId...").await?;
if score < 70 { return Err("Security threshold not met") }
```

**Ecosystem Expansion**
- Sui (Move/Rust-based, similar account patterns)
- Aptos (Move VM, transaction model)
- NEAR (Rust contracts, different execution model)

**Platform Features**
- Marketplace for community-contributed checks
- White-label options for audit firms
- Integration APIs for insurance/DeFi protocols
- Security badge system for verified programs

---

## Vision

Custos is the security infrastructure layer for Solana.

**Product Trajectory:**
1. **Developer Tool** — The default pre-audit check for every Anchor project
2. **Platform** — SDK, APIs, and integrations that let others build on our analysis engine
3. **Ecosystem Standard** — Scoring, verification, and compliance infrastructure for DeFi

**Focus:**
- Solana-native, not chain-agnostic
- Product-first, not services-first
- Developer adoption, then enterprise

$500M+ has been lost to preventable exploits. Better tooling changes that.

---

## How to Contribute


Add Solana-specific vulnerability patterns you've seen
Submit bugs
Use the tool
Build integrations
Experiment

File issues for bugs Custos missed. PRs welcome for new checks.

The codebase is messy right now (hackathon code). It'll  hopefully be much cleaner in a few weeks.
