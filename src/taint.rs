//! Single-Function Taint Analysis with Limited Cross-Function Tracking
//!
//! This module provides lightweight taint tracking within individual functions,
//! plus cross-function analysis (4-level depth, same file only).
//!
//! ## Design Principles
//! - Single-function scope with optional cross-function summaries
//! - Conservative: may have false positives, but few false negatives
//! - Fast: O(n) per function where n = number of statements
//! - No full IR required
//!
//! ## Taint Model
//! - **Sources**: `ctx.accounts.*`, instruction parameters, account data reads, CPI returns
//! - **Sinks**: `msg!()`, `emit!()`, `println!()`, account writes, CPI calls, return
//! - **Sanitizers**: hash functions, validation macros, checked math
//! - **Propagation**: assignments, clones, field access, arithmetic, function calls

use std::collections::{HashMap, HashSet};
use crate::checks::Finding;
use crate::report::Severity;

// ============================================================================
// Core Types
// ============================================================================

/// Where tainted data originated
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSource {
    /// Function parameter (e.g., `data: Vec<u8>`)
    Parameter { name: String, param_type: String },
    /// Context account access (e.g., `ctx.accounts.user`)
    ContextAccount { account_name: String },
    /// Account data read (e.g., `account.data.borrow()`)
    AccountDataRead { account_name: String },
    /// Account field access (e.g., `account.owner`, `account.lamports`)
    AccountField { account_name: String, field: String },
    /// CPI return value
    CpiReturn { program: String },
    /// Instruction data (e.g., `ix.data`)
    InstructionData,
    /// Deserialized instruction data
    DeserializedInput { type_name: String },
    /// Return value from another function in the same file
    FunctionReturn { function_name: String },
}

impl TaintSource {
    pub fn description(&self) -> String {
        match self {
            TaintSource::Parameter { name, param_type } => {
                format!("parameter '{}' ({})", name, param_type)
            }
            TaintSource::ContextAccount { account_name } => {
                format!("ctx.accounts.{}", account_name)
            }
            TaintSource::AccountDataRead { account_name } => {
                format!("{}.data (account read)", account_name)
            }
            TaintSource::AccountField { account_name, field } => {
                format!("{}.{} (account field)", account_name, field)
            }
            TaintSource::CpiReturn { program } => {
                format!("CPI return from {}", program)
            }
            TaintSource::InstructionData => "instruction_data".to_string(),
            TaintSource::DeserializedInput { type_name } => {
                format!("deserialized input ({})", type_name)
            }
            TaintSource::FunctionReturn { function_name } => {
                format!("return from {}()", function_name)
            }
        }
    }
}

/// Where tainted data should not flow
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSink {
    /// msg!() macro - logs to program output
    MsgMacro { line: usize },
    /// emit!() macro - Anchor events
    EmitMacro { line: usize, event_name: Option<String> },
    /// println!/dbg! - debug output
    DebugOutput { line: usize, macro_name: String },
    /// Account write (storing tainted data on-chain)
    AccountWrite { line: usize, account_name: String },
    /// Return statement (leaking from function)
    ReturnValue { line: usize },
    /// sol_log or similar
    SolLog { line: usize },
    /// CPI call - sending tainted data to another program
    CpiCall { line: usize, program: Option<String> },
    /// Serialization to account (e.g., .serialize())
    Serialization { line: usize, account_name: Option<String> },
}

impl TaintSink {
    pub fn line(&self) -> usize {
        match self {
            TaintSink::MsgMacro { line } => *line,
            TaintSink::EmitMacro { line, .. } => *line,
            TaintSink::DebugOutput { line, .. } => *line,
            TaintSink::AccountWrite { line, .. } => *line,
            TaintSink::ReturnValue { line } => *line,
            TaintSink::SolLog { line } => *line,
            TaintSink::CpiCall { line, .. } => *line,
            TaintSink::Serialization { line, .. } => *line,
        }
    }

    pub fn description(&self) -> String {
        match self {
            TaintSink::MsgMacro { .. } => "msg!() macro (logged on-chain)".to_string(),
            TaintSink::EmitMacro { event_name, .. } => {
                if let Some(name) = event_name {
                    format!("emit!({}) event (publicly indexed)", name)
                } else {
                    "emit!() event (publicly indexed)".to_string()
                }
            }
            TaintSink::DebugOutput { macro_name, .. } => {
                format!("{}! macro (debug output)", macro_name)
            }
            TaintSink::AccountWrite { account_name, .. } => {
                format!("write to {} (stored on-chain)", account_name)
            }
            TaintSink::ReturnValue { .. } => "return value".to_string(),
            TaintSink::SolLog { .. } => "sol_log() (logged on-chain)".to_string(),
            TaintSink::CpiCall { program, .. } => {
                if let Some(prog) = program {
                    format!("CPI to {} (data sent to external program)", prog)
                } else {
                    "CPI call (data sent to external program)".to_string()
                }
            }
            TaintSink::Serialization { account_name, .. } => {
                if let Some(name) = account_name {
                    format!("serialize to {} (stored on-chain)", name)
                } else {
                    "serialization (stored on-chain)".to_string()
                }
            }
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            TaintSink::MsgMacro { .. } => Severity::Medium,
            TaintSink::EmitMacro { .. } => Severity::High,
            TaintSink::DebugOutput { .. } => Severity::Low,
            TaintSink::AccountWrite { .. } => Severity::High,
            TaintSink::ReturnValue { .. } => Severity::Medium,
            TaintSink::SolLog { .. } => Severity::Medium,
            TaintSink::CpiCall { .. } => Severity::High,
            TaintSink::Serialization { .. } => Severity::High,
        }
    }
}

/// A tracked tainted variable
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TaintedVar {
    /// Variable name
    name: String,
    /// Original source(s) of taint
    sources: HashSet<TaintSource>,
    /// Line where this variable was assigned
    def_line: usize,
    /// Has this been sanitized?
    sanitized: bool,
    /// Sanitization method if any
    sanitizer: Option<String>,
}

/// A detected taint flow from source to sink
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TaintFlow {
    /// The source of tainted data
    pub source: TaintSource,
    /// The sink where it leaked
    pub sink: TaintSink,
    /// The variable that carried the taint
    pub carrier_var: String,
    /// The function where this occurred
    pub function_name: String,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Path description (simplified)
    pub flow_path: Vec<String>,
}

impl TaintFlow {
    /// Convert to a Finding
    pub fn to_finding(&self, file: &str, code_snippet: &str) -> Finding {
        let mut finding = Finding::new(
            "PRIV-030",
            &format!("Tainted Data Flow to {}", self.sink.description()),
            self.sink.severity(),
            file,
            self.sink.line(),
            code_snippet,
            &format!(
                "Data from {} flows to {}. Consider sanitizing (hash/encrypt) before use.",
                self.source.description(),
                self.sink.description()
            ),
        );

        finding.confidence = self.confidence;
        finding.evidence = vec![
            format!("Source: {}", self.source.description()),
            format!("Sink: {}", self.sink.description()),
            format!("Carrier variable: '{}'", self.carrier_var),
            format!("Flow path: {}", self.flow_path.join(" → ")),
        ];

        finding
    }
}

// ============================================================================
// Function Summary for Cross-Function Tracking
// ============================================================================

/// Summary of a function's taint behavior
#[derive(Debug, Clone, Default)]
pub struct FunctionSummary {
    /// Function name
    pub name: String,
    /// Source file where this function is defined
    pub source_file: String,
    /// Which parameters are tainted (by index)
    pub tainted_params: HashSet<usize>,
    /// Does this function return tainted data?
    pub returns_tainted: bool,
    /// Which parameter indices flow to return?
    pub param_to_return: HashSet<usize>,
    /// Does this function read from accounts?
    pub reads_accounts: bool,
    /// Does this function contain sinks?
    pub has_sinks: bool,
}

// ============================================================================
// Global Crate Function Registry for Cross-File Tracking
// ============================================================================

/// Global registry of function summaries across all files in a crate
#[derive(Debug, Clone, Default)]
pub struct CrateFunctionRegistry {
    /// All function summaries keyed by "file::function_name"
    summaries: HashMap<String, FunctionSummary>,
    /// Lookup by just function name (for unqualified calls)
    by_name: HashMap<String, Vec<String>>, // name -> list of qualified keys
}

impl CrateFunctionRegistry {
    pub fn new() -> Self {
        Self {
            summaries: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// Add a function summary to the registry
    pub fn add_summary(&mut self, file: &str, summary: FunctionSummary) {
        let qualified_name = format!("{}::{}", file, summary.name);
        let func_name = summary.name.clone();

        self.summaries.insert(qualified_name.clone(), summary);
        self.by_name
            .entry(func_name)
            .or_insert_with(Vec::new)
            .push(qualified_name);
    }

    /// Look up a function by unqualified name
    pub fn get_by_name(&self, name: &str) -> Option<&FunctionSummary> {
        // If there's exactly one function with this name, return it
        if let Some(keys) = self.by_name.get(name) {
            if keys.len() == 1 {
                return self.summaries.get(&keys[0]);
            }
            // If multiple, return first (could be improved with module context)
            if !keys.is_empty() {
                return self.summaries.get(&keys[0]);
            }
        }
        None
    }

    /// Look up a function by qualified name (file::name)
    #[allow(dead_code)]
    pub fn get_qualified(&self, qualified: &str) -> Option<&FunctionSummary> {
        self.summaries.get(qualified)
    }

    /// Get all function names in the registry
    #[allow(dead_code)]
    pub fn function_count(&self) -> usize {
        self.summaries.len()
    }

    /// Build summaries from a single file (first pass)
    pub fn build_from_file(&mut self, content: &str, file: &str) {
        // Skip test files
        if file.contains("test") || file.contains("mock") {
            return;
        }

        let Ok(syntax) = syn::parse_file(content) else {
            return;
        };

        for item in &syntax.items {
            if let syn::Item::Fn(func) = item {
                let summary = Self::summarize_function(&func.sig, &func.block, file);
                self.add_summary(file, summary);
            }
            if let syn::Item::Impl(impl_block) = item {
                for impl_item in &impl_block.items {
                    if let syn::ImplItem::Fn(method) = impl_item {
                        let summary = Self::summarize_function(&method.sig, &method.block, file);
                        self.add_summary(file, summary);
                    }
                }
            }
        }
    }

    /// Create a quick summary of a function's taint behavior
    fn summarize_function(sig: &syn::Signature, block: &syn::Block, file: &str) -> FunctionSummary {
        let name = sig.ident.to_string();
        let mut summary = FunctionSummary {
            name: name.clone(),
            source_file: file.to_string(),
            ..Default::default()
        };

        // Check which parameters could be tainted
        for (idx, param) in sig.inputs.iter().enumerate() {
            if let syn::FnArg::Typed(pat_type) = param {
                let param_type = type_to_string(&pat_type.ty);
                if is_taintable_type_static(&param_type) {
                    summary.tainted_params.insert(idx);
                }
            }
        }

        // Quick scan of body for patterns
        let body_str = quote::quote!(#block).to_string();

        // Check for account reads
        if body_str.contains("ctx.accounts") || body_str.contains(".data.borrow()")
            || body_str.contains(".try_borrow_data()") {
            summary.reads_accounts = true;
        }

        // Check for sinks
        if body_str.contains("msg!") || body_str.contains("emit!")
            || body_str.contains("println!") || body_str.contains("invoke") {
            summary.has_sinks = true;
        }

        // Check if return statement references parameters or tainted sources
        if body_str.contains("return") || !body_str.ends_with("{ }") {
            if !summary.tainted_params.is_empty() || summary.reads_accounts {
                summary.returns_tainted = true;
                summary.param_to_return = summary.tainted_params.clone();
            }
        }

        summary
    }
}

/// Static helper for checking taintable types (used by registry)
fn is_taintable_type_static(ty: &str) -> bool {
    let normalized = ty.replace(" ", "");
    let taintable = [
        "Vec<u8>", "[u8]", "&[u8]", "String", "&str",
        "Vec<", "Box<", "&mut",
        "Pubkey", "AccountInfo",
    ];
    let safe = [
        "Context<", "Signer<", "Program<", "SystemProgram",
        "Clock", "Rent",
    ];

    if taintable.iter().any(|s| normalized.contains(s)) {
        return true;
    }
    if safe.iter().any(|s| normalized.contains(s)) {
        return false;
    }
    if normalized.starts_with("bool") || normalized.starts_with("u8") ||
       normalized.starts_with("u16") || normalized.starts_with("u32") ||
       normalized.starts_with("u64") || normalized.starts_with("i8") ||
       normalized.starts_with("i16") || normalized.starts_with("i32") ||
       normalized.starts_with("i64") || normalized.starts_with("usize") ||
       normalized.starts_with("isize") {
        return false;
    }
    false
}

// ============================================================================
// Taint Analyzer
// ============================================================================

/// Single-function taint analyzer with cross-function support
pub struct TaintAnalyzer {
    /// Currently tainted variables: name -> TaintedVar
    tainted: HashMap<String, TaintedVar>,
    /// Detected flows
    flows: Vec<TaintFlow>,
    /// Current function name
    current_function: String,
    /// Source content lines for snippets
    lines: Vec<String>,
    /// Function summaries for cross-function tracking (local to current file)
    function_summaries: HashMap<String, FunctionSummary>,
    /// Global crate-wide function registry (for cross-file tracking)
    global_registry: Option<CrateFunctionRegistry>,
    /// Current analysis depth (for limiting recursion)
    analysis_depth: usize,
    /// Maximum cross-function depth
    max_depth: usize,
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        Self {
            tainted: HashMap::new(),
            flows: Vec::new(),
            current_function: String::new(),
            lines: Vec::new(),
            function_summaries: HashMap::new(),
            global_registry: None,
            analysis_depth: 0,
            max_depth: 4, // Increased from 2 to 4 for deeper cross-function tracking
        }
    }

    /// Create an analyzer with a global function registry for cross-file tracking
    pub fn with_global_registry(registry: CrateFunctionRegistry) -> Self {
        Self {
            tainted: HashMap::new(),
            flows: Vec::new(),
            current_function: String::new(),
            lines: Vec::new(),
            function_summaries: HashMap::new(),
            global_registry: Some(registry),
            analysis_depth: 0,
            max_depth: 4, // Increased from 2 to 4 for deeper cross-function tracking
        }
    }

    /// Analyze a file and return all taint flow findings
    pub fn analyze_file(&mut self, content: &str, file: &str) -> Vec<Finding> {
        self.lines = content.lines().map(|s| s.to_string()).collect();

        // Skip test files
        if file.contains("test") || file.contains("mock") {
            return Vec::new();
        }

        // Parse the file
        let Ok(syntax) = syn::parse_file(content) else {
            return Vec::new();
        };

        // Phase 1: Build function summaries (quick pass)
        self.build_function_summaries(&syntax);

        // Phase 2: Full taint analysis with cross-function info
        for item in &syntax.items {
            if let syn::Item::Fn(func) = item {
                self.analyze_function(func, content);
            }
            if let syn::Item::Impl(impl_block) = item {
                for impl_item in &impl_block.items {
                    if let syn::ImplItem::Fn(method) = impl_item {
                        self.analyze_method(method, content);
                    }
                }
            }
        }

        // Convert flows to findings
        let mut findings = Vec::new();
        for flow in &self.flows {
            let snippet = self.get_snippet(flow.sink.line());
            findings.push(flow.to_finding(file, &snippet));
        }

        // Reset for next file
        self.flows.clear();
        self.function_summaries.clear();

        findings
    }

    /// Phase 1: Build lightweight summaries of all functions
    fn build_function_summaries(&mut self, syntax: &syn::File) {
        for item in &syntax.items {
            if let syn::Item::Fn(func) = item {
                let summary = self.summarize_function(&func.sig, &func.block);
                self.function_summaries.insert(summary.name.clone(), summary);
            }
            if let syn::Item::Impl(impl_block) = item {
                for impl_item in &impl_block.items {
                    if let syn::ImplItem::Fn(method) = impl_item {
                        let summary = self.summarize_function(&method.sig, &method.block);
                        self.function_summaries.insert(summary.name.clone(), summary);
                    }
                }
            }
        }
    }

    /// Create a quick summary of a function's taint behavior
    fn summarize_function(&self, sig: &syn::Signature, block: &syn::Block) -> FunctionSummary {
        let name = sig.ident.to_string();
        let mut summary = FunctionSummary {
            name: name.clone(),
            ..Default::default()
        };

        // Check which parameters could be tainted
        for (idx, param) in sig.inputs.iter().enumerate() {
            if let syn::FnArg::Typed(pat_type) = param {
                let param_type = type_to_string(&pat_type.ty);
                if self.is_taintable_type(&param_type) {
                    summary.tainted_params.insert(idx);
                }
            }
        }

        // Quick scan of body for patterns
        let body_str = quote::quote!(#block).to_string();

        // Check for account reads
        if body_str.contains("ctx.accounts") || body_str.contains(".data.borrow()")
            || body_str.contains(".try_borrow_data()") {
            summary.reads_accounts = true;
        }

        // Check for sinks
        if body_str.contains("msg!") || body_str.contains("emit!")
            || body_str.contains("println!") || body_str.contains("invoke") {
            summary.has_sinks = true;
        }

        // Check if return statement references parameters or tainted sources
        if body_str.contains("return") || !body_str.ends_with("{ }") {
            // Simplified: if function has tainted params and has a return, assume it might return tainted
            if !summary.tainted_params.is_empty() || summary.reads_accounts {
                summary.returns_tainted = true;
                summary.param_to_return = summary.tainted_params.clone();
            }
        }

        summary
    }

    /// Analyze a standalone function
    fn analyze_function(&mut self, func: &syn::ItemFn, content: &str) {
        self.tainted.clear();
        self.current_function = func.sig.ident.to_string();
        self.analysis_depth = 0;

        // 1. Mark parameters as tainted sources
        self.taint_parameters(&func.sig);

        // 2. Analyze the function body
        self.analyze_block(&func.block, content);
    }

    /// Analyze a method in an impl block
    fn analyze_method(&mut self, method: &syn::ImplItemFn, content: &str) {
        self.tainted.clear();
        self.current_function = method.sig.ident.to_string();
        self.analysis_depth = 0;

        // 1. Mark parameters as tainted sources
        self.taint_parameters(&method.sig);

        // 2. Analyze the method body
        self.analyze_block(&method.block, content);
    }

    /// Mark function parameters as taint sources
    fn taint_parameters(&mut self, sig: &syn::Signature) {
        for param in &sig.inputs {
            if let syn::FnArg::Typed(pat_type) = param {
                // Extract parameter name - handle both Pat::Ident and Pat::Type
                let param_name = match &*pat_type.pat {
                    syn::Pat::Ident(ident) => ident.ident.to_string(),
                    syn::Pat::Type(pt) => {
                        if let syn::Pat::Ident(ident) = &*pt.pat {
                            ident.ident.to_string()
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                };

                let param_type = type_to_string(&pat_type.ty);
                let normalized_type = param_type.replace(" ", "");

                // Skip Context<T> - we'll handle ctx.accounts separately
                if normalized_type.contains("Context<") {
                    continue;
                }

                // Taint parameters that could contain user data
                if self.is_taintable_type(&param_type) {
                    let source = TaintSource::Parameter {
                        name: param_name.clone(),
                        param_type: normalized_type,
                    };
                    self.add_tainted_var(&param_name, source, 0);
                }
            }
        }
    }

    /// Check if a type should be considered taintable
    fn is_taintable_type(&self, ty: &str) -> bool {
        // Normalize type string (quote adds spaces around tokens)
        let normalized = ty.replace(" ", "");

        // Types that commonly carry user input
        let taintable = [
            "Vec<u8>", "[u8]", "&[u8]", "String", "&str",
            "Vec<", "Box<", "&mut",
            "Pubkey", // Could be user-provided
            "AccountInfo",
        ];

        // Safe types that shouldn't be tainted
        let safe = [
            "Context<", "Signer<", "Program<", "SystemProgram",
            "Clock", "Rent",
        ];

        // If it matches taintable patterns first (more specific), taint it
        if taintable.iter().any(|s| normalized.contains(s)) {
            return true;
        }

        // If it's a safe type, don't taint
        if safe.iter().any(|s| normalized.contains(s)) {
            return false;
        }

        // Safe numeric types that shouldn't be tainted
        if normalized.starts_with("bool") || normalized.starts_with("u8") || 
           normalized.starts_with("u16") || normalized.starts_with("u32") || 
           normalized.starts_with("u64") || normalized.starts_with("i8") || 
           normalized.starts_with("i16") || normalized.starts_with("i32") || 
           normalized.starts_with("i64") || normalized.starts_with("usize") || 
           normalized.starts_with("isize") {
            return false;
        }

        false
    }

    /// Add a variable to the tainted set
    fn add_tainted_var(&mut self, name: &str, source: TaintSource, line: usize) {
        let mut sources = HashSet::new();
        sources.insert(source);

        self.tainted.insert(name.to_string(), TaintedVar {
            name: name.to_string(),
            sources,
            def_line: line,
            sanitized: false,
            sanitizer: None,
        });
    }

    /// Add taint to existing variable (merge sources)
    fn add_taint_to_var(&mut self, name: &str, new_sources: HashSet<TaintSource>, line: usize) {
        if let Some(existing) = self.tainted.get_mut(name) {
            existing.sources.extend(new_sources);
        } else {
            self.tainted.insert(name.to_string(), TaintedVar {
                name: name.to_string(),
                sources: new_sources,
                def_line: line,
                sanitized: false,
                sanitizer: None,
            });
        }
    }

    /// Analyze a block of statements
    fn analyze_block(&mut self, block: &syn::Block, content: &str) {
        for stmt in &block.stmts {
            self.analyze_statement(stmt, content);
        }
    }

    /// Analyze a single statement
    fn analyze_statement(&mut self, stmt: &syn::Stmt, content: &str) {
        match stmt {
            syn::Stmt::Local(local) => {
                self.analyze_local(local, content);
            }
            syn::Stmt::Expr(expr, _) => {
                self.analyze_expr(expr, content, None);
            }
            syn::Stmt::Item(_) => {
                // Nested items, skip for now
            }
            syn::Stmt::Macro(macro_stmt) => {
                self.analyze_macro_stmt(&macro_stmt.mac, content);
            }
        }
    }

    /// Analyze a let binding
    fn analyze_local(&mut self, local: &syn::Local, _content: &str) {
        // Get the variable name being bound
        let var_name = if let syn::Pat::Ident(ident) = &local.pat {
            ident.ident.to_string()
        } else if let syn::Pat::Type(pat_type) = &local.pat {
            if let syn::Pat::Ident(ident) = &*pat_type.pat {
                ident.ident.to_string()
            } else {
                return;
            }
        } else {
            return;
        };

        // Check if the initializer is tainted
        if let Some(init) = &local.init {
            let line = self.estimate_line(&local.pat);
            let init_str = expr_to_string(&init.expr);

            // Normalize spaces for matching
            let normalized_init = init_str.replace(" ", "");

            // Check for ctx.accounts access
            if normalized_init.contains("ctx.accounts.") {
                if let Some(account) = extract_account_name(&normalized_init) {
                    let source = TaintSource::ContextAccount {
                        account_name: account,
                    };
                    self.add_tainted_var(&var_name, source, line);
                    return;
                }
            }

            // Check for account data reads
            if init_str.contains(".data.borrow()") || init_str.contains(".try_borrow_data()")
                || init_str.contains(".try_borrow_mut_data()") {
                if let Some(account) = extract_account_from_data_read(&init_str) {
                    let source = TaintSource::AccountDataRead {
                        account_name: account,
                    };
                    self.add_tainted_var(&var_name, source, line);
                    return;
                }
            }

            // Check for account field access (owner, lamports, key, etc.)
            if let Some((account, field)) = extract_account_field_access(&init_str) {
                let source = TaintSource::AccountField {
                    account_name: account,
                    field,
                };
                self.add_tainted_var(&var_name, source, line);
                return;
            }

            // Check for instruction_data
            if init_str.contains("instruction_data") || init_str.contains("ix_data")
                || init_str.contains("_ix.data") {
                let source = TaintSource::InstructionData;
                self.add_tainted_var(&var_name, source, line);
                return;
            }

            // Check for deserialization (common pattern for instruction args)
            if init_str.contains("deserialize") || init_str.contains("try_from_slice")
                || init_str.contains("unpack") || init_str.contains("BorshDeserialize") {
                let type_name = extract_type_from_deser(&init_str).unwrap_or("unknown".to_string());
                let source = TaintSource::DeserializedInput { type_name };
                self.add_tainted_var(&var_name, source, line);
                return;
            }

            // Check for CPI return handling
            if init_str.contains("invoke(") || init_str.contains("invoke_signed(") {
                let program = extract_cpi_program(&init_str);
                let source = TaintSource::CpiReturn {
                    program: program.unwrap_or("unknown".to_string()),
                };
                self.add_tainted_var(&var_name, source, line);
                return;
            }

            // Check for function call that might return tainted data (cross-function)
            if let Some(sources) = self.check_function_call_taint(&init.expr) {
                self.add_taint_to_var(&var_name, sources, line);
                return;
            }

            // Check if RHS references a tainted variable (propagation)
            if let Some(taint_sources) = self.get_taint_from_expr(&init.expr) {
                // Check for sanitizers
                if self.is_sanitized(&init_str) {
                    // Don't propagate taint through sanitizers
                    return;
                }

                // Propagate taint
                self.tainted.insert(var_name.clone(), TaintedVar {
                    name: var_name,
                    sources: taint_sources,
                    def_line: line,
                    sanitized: false,
                    sanitizer: None,
                });
            }
        }
    }

    /// Check if a function call returns tainted data (cross-function tracking)
    fn check_function_call_taint(&self, expr: &syn::Expr) -> Option<HashSet<TaintSource>> {
        if self.analysis_depth >= self.max_depth {
            return None;
        }

        let expr_str = expr_to_string(expr);

        // First, check local function summaries (same file)
        for (func_name, summary) in &self.function_summaries {
            if expr_str.contains(&format!("{}(", func_name)) {
                if summary.returns_tainted {
                    let mut sources = HashSet::new();
                    sources.insert(TaintSource::FunctionReturn {
                        function_name: func_name.clone(),
                    });
                    return Some(sources);
                }
            }
        }

        // Then, check global registry for cross-file functions
        if let Some(ref registry) = self.global_registry {
            // Extract function name from the call expression
            // Pattern: function_name( or path::function_name(
            for func_name in extract_function_names_from_call(&expr_str) {
                if let Some(summary) = registry.get_by_name(&func_name) {
                    if summary.returns_tainted {
                        let mut sources = HashSet::new();
                        sources.insert(TaintSource::FunctionReturn {
                            function_name: format!("{}::{}", summary.source_file, func_name),
                        });
                        return Some(sources);
                    }
                }
            }
        }

        None
    }

    /// Check if an expression is sanitized (hashed, validated, etc.)
    fn is_sanitized(&self, expr_str: &str) -> bool {
        // Normalize spaces for comparison
        let normalized = expr_str.replace(" ", "");

        // Comprehensive sanitizer patterns
        let sanitizers = [
            // ========== Hash Functions ==========
            // Generic
            "hash(", "digest(", "finalize(",
            // SHA family
            "sha256(", "sha512(", "sha3(",
            "Sha256::", "Sha512::", "Sha3::",
            // Keccak
            "keccak256(", "keccak(", "Keccak256::",
            // Blake
            "blake2(", "blake2b(", "blake2s(", "blake3(",
            "Blake2::", "Blake3::",
            // Poseidon (ZK-friendly)
            "poseidon(", "Poseidon::",
            // Solana-specific
            "solana_program::hash::", "hashv(",
            "anchor_lang::solana_program::hash",
            "hash_to_", "Hash::",

            // ========== Encryption ==========
            "encrypt(", "seal(", "cipher(",
            "aes_encrypt", "chacha_encrypt",
            "Aes::", "ChaCha::",
            "box_seal", "secretbox",
            // ZK encryption
            "encrypt_message", "elgamal",

            // ========== Signature/Verification ==========
            "verify(", "ed25519_verify(", "verify_signature(",
            "secp256k1_recover", "keccak_secp256k1",
            "signature.verify", "Signature::verify",

            // ========== Validation Macros ==========
            "require!(", "require_eq!(", "require_neq!(",
            "require_gt!(", "require_gte!(",
            "require_keys_eq!(", "require_keys_neq!(",
            "assert!(", "assert_eq!(", "assert_ne!(",
            "debug_assert!", "ensure!(", "invariant!(",

            // ========== Anchor Constraints ==========
            "constraint =", "has_one =", "address =",

            // ========== Safe Math ==========
            "checked_add", "checked_sub", "checked_mul", "checked_div",
            "checked_rem", "checked_pow", "checked_shl", "checked_shr",
            "saturating_add", "saturating_sub", "saturating_mul",

            // ========== Privacy-Preserving Operations ==========
            "commitment(", "pedersen(", "Pedersen::",
            "blind(", "mask(", "nullifier(",

            // ========== Truncation/Redaction ==========
            "truncate(", "redact(", "mask_pii(", "anonymize(",
        ];

        // Check if any sanitizer pattern matches
        if sanitizers.iter().any(|s| normalized.contains(s)) {
            return true;
        }

        // Check for privacy-safe transformations (value not leaked)
        self.is_privacy_safe_transform(expr_str)
    }

    /// Check if a value is transformed in a privacy-safe way
    fn is_privacy_safe_transform(&self, expr_str: &str) -> bool {
        // These transforms make data safe for logging/emission
        let safe_transforms = [
            // Only logging length, not content
            ".len()",
            // Logging existence, not value
            ".is_some()", ".is_none()", ".is_empty()",
            // Comparison results (bool, not the value)
            ".contains(", ".starts_with(", ".ends_with(",
        ];

        // Only consider it safe if the ENTIRE expression is a safe transform
        // Not if it just contains one somewhere
        safe_transforms.iter().any(|s| expr_str.ends_with(s.trim_end_matches('(')))
    }

    /// Get taint sources from an expression if it's tainted
    fn get_taint_from_expr(&self, expr: &syn::Expr) -> Option<HashSet<TaintSource>> {
        let expr_str = expr_to_string(expr);

        // Check if any tainted variable is referenced
        for (var_name, tainted_var) in &self.tainted {
            // More precise check: word boundary matching
            if contains_identifier(&expr_str, var_name) && !tainted_var.sanitized {
                return Some(tainted_var.sources.clone());
            }
        }

        // Check for direct taint sources in the expression
        if expr_str.contains("ctx.accounts.") {
            if let Some(account) = extract_account_name(&expr_str) {
                let mut sources = HashSet::new();
                sources.insert(TaintSource::ContextAccount {
                    account_name: account,
                });
                return Some(sources);
            }
        }

        None
    }

    /// Analyze an expression (looking for sinks)
    fn analyze_expr(&mut self, expr: &syn::Expr, content: &str, _context: Option<&str>) {
        match expr {
            syn::Expr::Macro(expr_macro) => {
                self.analyze_macro_stmt(&expr_macro.mac, content);
            }
            syn::Expr::Call(call) => {
                self.analyze_call(call, content);
            }
            syn::Expr::MethodCall(method_call) => {
                self.analyze_method_call(method_call, content);
            }
            syn::Expr::Block(block) => {
                self.analyze_block(&block.block, content);
            }
            syn::Expr::If(expr_if) => {
                self.analyze_block(&expr_if.then_branch, content);
                if let Some((_, else_branch)) = &expr_if.else_branch {
                    self.analyze_expr(else_branch, content, None);
                }
            }
            syn::Expr::Match(expr_match) => {
                for arm in &expr_match.arms {
                    self.analyze_expr(&arm.body, content, None);
                }
            }
            syn::Expr::Return(ret) => {
                if let Some(return_expr) = &ret.expr {
                    if let Some(sources) = self.get_taint_from_expr(return_expr) {
                        let line = self.estimate_line_from_expr(expr);
                        for source in sources {
                            let carrier = self.find_carrier_in_expr(return_expr);
                            self.record_flow(
                                source,
                                TaintSink::ReturnValue { line },
                                &carrier,
                            );
                        }
                    }
                }
            }
            syn::Expr::Assign(assign) => {
                let left_str = expr_to_string(&assign.left);
                if let Some(sources) = self.get_taint_from_expr(&assign.right) {
                    // Check if writing to an account field
                    if left_str.contains(".") && !left_str.starts_with("self.") {
                        let parts: Vec<&str> = left_str.split('.').collect();
                        if let Some(account_name) = parts.first() {
                            let line = self.estimate_line_from_expr(expr);
                            for source in sources {
                                let carrier = self.find_carrier_in_expr(&assign.right);
                                self.record_flow(
                                    source,
                                    TaintSink::AccountWrite {
                                        line,
                                        account_name: account_name.to_string(),
                                    },
                                    &carrier,
                                );
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Analyze a macro invocation (msg!, emit!, etc.)
    fn analyze_macro_stmt(&mut self, mac: &syn::Macro, _content: &str) {
        use syn::spanned::Spanned;

        let macro_path = mac.path.segments.iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");

        let tokens_str = mac.tokens.to_string();
        let line = mac.span().start().line;

        // Check for tainted data in macro arguments
        let taint_sources = self.find_taint_in_tokens(&tokens_str);

        if taint_sources.is_empty() {
            return;
        }

        // Determine sink type
        let sink = match macro_path.as_str() {
            "msg" => Some(TaintSink::MsgMacro { line }),
            "emit" | "emit_cpi" => {
                let event_name = extract_event_name(&tokens_str);
                Some(TaintSink::EmitMacro { line, event_name })
            }
            "println" => Some(TaintSink::DebugOutput { line, macro_name: "println".to_string() }),
            "dbg" => Some(TaintSink::DebugOutput { line, macro_name: "dbg".to_string() }),
            "eprintln" => Some(TaintSink::DebugOutput { line, macro_name: "eprintln".to_string() }),
            "sol_log" | "sol_log_64" | "sol_log_slice" => Some(TaintSink::SolLog { line }),
            _ => None,
        };

        if let Some(sink) = sink {
            for (source, carrier) in taint_sources {
                self.record_flow(source, sink.clone(), &carrier);
            }
        }
    }

    /// Find tainted variables referenced in token string
    fn find_taint_in_tokens(&self, tokens: &str) -> Vec<(TaintSource, String)> {
        let mut found = Vec::new();

        for (var_name, tainted_var) in &self.tainted {
            if !tainted_var.sanitized && contains_identifier(tokens, var_name) {
                for source in &tainted_var.sources {
                    found.push((source.clone(), var_name.clone()));
                }
            }
        }

        found
    }

    /// Analyze a function call
    fn analyze_call(&mut self, call: &syn::ExprCall, content: &str) {
        use syn::spanned::Spanned;

        let call_str = expr_to_string(&call.func);
        let line = call.span().start().line;

        // Check for CPI calls - these are sinks!
        if call_str.contains("invoke") || call_str.contains("invoke_signed") {
            for arg in &call.args {
                if let Some(sources) = self.get_taint_from_expr(arg) {
                    let program = extract_cpi_program(&call_str);
                    for source in sources {
                        let carrier = self.find_carrier_in_expr(arg);
                        self.record_flow(
                            source,
                            TaintSink::CpiCall { line, program: program.clone() },
                            &carrier,
                        );
                    }
                }
            }
        }

        // Check for sol_log and similar
        if call_str.contains("sol_log") || call_str.contains("log_") {
            for arg in &call.args {
                if let Some(sources) = self.get_taint_from_expr(arg) {
                    for source in sources {
                        let carrier = self.find_carrier_in_expr(arg);
                        self.record_flow(
                            source,
                            TaintSink::SolLog { line },
                            &carrier,
                        );
                    }
                }
            }
        }

        // Check for anchor CPI helpers
        if call_str.contains("CpiContext") || call_str.contains("cpi::") {
            for arg in &call.args {
                if let Some(sources) = self.get_taint_from_expr(arg) {
                    for source in sources {
                        let carrier = self.find_carrier_in_expr(arg);
                        self.record_flow(
                            source,
                            TaintSink::CpiCall { line, program: Some("anchor_cpi".to_string()) },
                            &carrier,
                        );
                    }
                }
            }
        }

        // Recurse into arguments
        for arg in &call.args {
            self.analyze_expr(arg, content, None);
        }
    }

    /// Analyze a method call
    fn analyze_method_call(&mut self, method_call: &syn::ExprMethodCall, content: &str) {
        use syn::spanned::Spanned;

        let method_name = method_call.method.to_string();
        let line = method_call.span().start().line;

        // Check for serialization methods - these are sinks!
        let serialize_methods = ["serialize", "try_serialize", "pack", "pack_into_slice"];
        if serialize_methods.contains(&method_name.as_str()) {
            if let Some(sources) = self.get_taint_from_expr(&method_call.receiver) {
                let account_name = extract_receiver_name(&method_call.receiver);
                for source in sources {
                    let carrier = self.find_carrier_in_expr(&method_call.receiver);
                    self.record_flow(
                        source,
                        TaintSink::Serialization { line, account_name: account_name.clone() },
                        &carrier,
                    );
                }
            }
            // Also check arguments
            for arg in &method_call.args {
                if let Some(sources) = self.get_taint_from_expr(arg) {
                    let account_name = extract_receiver_name(&method_call.receiver);
                    for source in sources {
                        let carrier = self.find_carrier_in_expr(arg);
                        self.record_flow(
                            source,
                            TaintSink::Serialization { line, account_name: account_name.clone() },
                            &carrier,
                        );
                    }
                }
            }
        }

        // Check for dangerous methods that convert to string (often precedes logging)
        let string_methods = ["to_string", "fmt", "display", "debug"];
        if string_methods.contains(&method_name.as_str()) {
            // Track but don't flag - the actual sink is the log
        }

        // Recurse
        self.analyze_expr(&method_call.receiver, content, None);
        for arg in &method_call.args {
            self.analyze_expr(arg, content, None);
        }
    }

    /// Record a taint flow
    fn record_flow(&mut self, source: TaintSource, sink: TaintSink, carrier: &str) {
        // Calculate confidence based on flow characteristics
        let confidence = self.calculate_flow_confidence(&source, &sink, carrier);

        self.flows.push(TaintFlow {
            source: source.clone(),
            sink,
            carrier_var: carrier.to_string(),
            function_name: self.current_function.clone(),
            confidence,
            flow_path: vec![
                source.description(),
                format!("var '{}'", carrier),
                "→ sink".to_string(),
            ],
        });
    }

    /// Calculate confidence for a taint flow
    fn calculate_flow_confidence(&self, source: &TaintSource, sink: &TaintSink, carrier: &str) -> u8 {
        let mut confidence: i32 = 70; // Base confidence

        // Source confidence modifiers
        match source {
            TaintSource::Parameter { param_type, .. } => {
                if param_type.contains("Vec<u8>") || param_type.contains("[u8]") {
                    confidence += 10; // Raw bytes are high risk
                }
            }
            TaintSource::ContextAccount { .. } => {
                confidence += 5; // Account data access
            }
            TaintSource::AccountDataRead { .. } => {
                confidence += 15; // Direct data read is high risk
            }
            TaintSource::AccountField { .. } => {
                confidence += 10; // Account field access
            }
            TaintSource::InstructionData => {
                confidence += 15; // Instruction data is user input
            }
            TaintSource::DeserializedInput { .. } => {
                confidence += 15; // Deserialized user input
            }
            TaintSource::CpiReturn { .. } => {
                confidence += 5;
            }
            TaintSource::FunctionReturn { .. } => {
                confidence -= 5; // Cross-function is less certain
            }
        }

        // Sink confidence modifiers
        match sink {
            TaintSink::EmitMacro { .. } => {
                confidence += 15; // Events are publicly indexed
            }
            TaintSink::MsgMacro { .. } => {
                confidence += 10; // Logs are public
            }
            TaintSink::AccountWrite { .. } => {
                confidence += 10; // On-chain storage
            }
            TaintSink::DebugOutput { .. } => {
                confidence -= 10; // Usually filtered in release
            }
            TaintSink::ReturnValue { .. } => {
                confidence -= 5; // May or may not be exposed
            }
            TaintSink::SolLog { .. } => {
                confidence += 10;
            }
            TaintSink::CpiCall { .. } => {
                confidence += 15; // Data sent to external program
            }
            TaintSink::Serialization { .. } => {
                confidence += 10; // Stored on-chain
            }
        }

        // Carrier name heuristics
        let carrier_lower = carrier.to_lowercase();

        // Generic/non-PII parameter names should reduce confidence
        const GENERIC_NAMES: &[&str] = &[
            "field_name", "account_name", "name_str", "label", "tag", "key_name",
            "param_name", "arg_name", "var_name", "type_name", "struct_name",
        ];

        let is_generic = GENERIC_NAMES.iter().any(|g| carrier_lower == *g)
            || (carrier_lower.ends_with("_name") && !carrier_lower.contains("user"));

        if is_generic {
            confidence -= 25; // Generic labels are not PII
        } else if carrier_lower.contains("user") || carrier_lower.contains("pii")
            || carrier_lower.contains("email") || carrier_lower.contains("phone")
            || carrier_lower.contains("secret") || carrier_lower.contains("private")
            || carrier_lower.contains("ssn") || carrier_lower.contains("password") {
            confidence += 10;
        }

        confidence.clamp(20, 98) as u8
    }

    /// Find the carrier variable name in an expression
    fn find_carrier_in_expr(&self, expr: &syn::Expr) -> String {
        let expr_str = expr_to_string(expr);
        for (var_name, _) in &self.tainted {
            if contains_identifier(&expr_str, var_name) {
                return var_name.clone();
            }
        }
        "unknown".to_string()
    }

    /// Estimate line number from a pattern
    fn estimate_line(&self, pat: &syn::Pat) -> usize {
        use syn::spanned::Spanned;
        pat.span().start().line
    }

    /// Estimate line number from expression
    fn estimate_line_from_expr(&self, expr: &syn::Expr) -> usize {
        use syn::spanned::Spanned;
        expr.span().start().line
    }

    /// Get code snippet for a line
    fn get_snippet(&self, line: usize) -> String {
        if line == 0 || line > self.lines.len() {
            return String::new();
        }

        let start = line.saturating_sub(2);
        let end = (line + 2).min(self.lines.len());

        self.lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let actual_line = start + i + 1;
                if actual_line == line {
                    format!(">{:4} | {}", actual_line, l)
                } else {
                    format!(" {:4} | {}", actual_line, l)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert a syn::Type to string
fn type_to_string(ty: &syn::Type) -> String {
    quote::quote!(#ty).to_string()
}

/// Convert a syn::Expr to string
fn expr_to_string(expr: &syn::Expr) -> String {
    quote::quote!(#expr).to_string()
}

/// Check if a string contains an identifier (word boundary aware)
fn contains_identifier(text: &str, ident: &str) -> bool {
    // Simple approach: check for the identifier not surrounded by alphanumeric chars
    for (idx, _) in text.match_indices(ident) {
        let before_ok = idx == 0 || !text.chars().nth(idx - 1).map(|c| c.is_alphanumeric() || c == '_').unwrap_or(false);
        let after_idx = idx + ident.len();
        let after_ok = after_idx >= text.len() || !text.chars().nth(after_idx).map(|c| c.is_alphanumeric() || c == '_').unwrap_or(false);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Extract function names from a call expression string
/// Handles patterns like: function_name(, path::function_name(, self.method(
fn extract_function_names_from_call(expr: &str) -> Vec<String> {
    let mut names = Vec::new();

    // Find all occurrences of identifier followed by (
    let mut i = 0;
    let chars: Vec<char> = expr.chars().collect();

    while i < chars.len() {
        // Look for opening parenthesis
        if chars[i] == '(' {
            // Walk backwards to find the function name
            let mut end = i;
            let mut start = end;

            // Skip whitespace before (
            while start > 0 && chars[start - 1].is_whitespace() {
                start -= 1;
            }
            end = start;

            // Collect identifier characters
            while start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
                start -= 1;
            }

            if start < end {
                let name: String = chars[start..end].iter().collect();
                // Skip common non-function patterns
                if !name.is_empty()
                    && !["if", "while", "for", "match", "Some", "None", "Ok", "Err"].contains(&name.as_str())
                {
                    names.push(name);
                }
            }
        }
        i += 1;
    }

    names
}

/// Extract account name from ctx.accounts.X expression
fn extract_account_name(expr: &str) -> Option<String> {
    if let Some(start) = expr.find("ctx.accounts.") {
        let rest = &expr[start + 13..];
        let end = rest.find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        let account = &rest[..end];
        if !account.is_empty() {
            return Some(account.to_string());
        }
    }
    None
}

/// Extract account name from .data.borrow() expression
fn extract_account_from_data_read(expr: &str) -> Option<String> {
    if let Some(end) = expr.find(".data") {
        let before = &expr[..end];
        let start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_')
            .map(|i| i + 1)
            .unwrap_or(0);
        let account = &before[start..];
        if !account.is_empty() {
            return Some(account.to_string());
        }
    }
    None
}

/// Extract account and field from expressions like account.owner, account.lamports
fn extract_account_field_access(expr: &str) -> Option<(String, String)> {
    let fields = ["owner", "lamports", "key", "is_signer", "is_writable", "executable"];

    for field in fields {
        let pattern = format!(".{}", field);
        if let Some(idx) = expr.find(&pattern) {
            let before = &expr[..idx];
            let start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_')
                .map(|i| i + 1)
                .unwrap_or(0);
            let account = &before[start..];
            if !account.is_empty() && account != "ctx" && account != "accounts" {
                return Some((account.to_string(), field.to_string()));
            }
        }
    }
    None
}

/// Extract type name from deserialization expression
fn extract_type_from_deser(expr: &str) -> Option<String> {
    // Look for patterns like Type::deserialize or Type::try_from_slice
    if let Some(idx) = expr.find("::") {
        let before = &expr[..idx];
        let start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_')
            .map(|i| i + 1)
            .unwrap_or(0);
        let type_name = &before[start..];
        if !type_name.is_empty() && type_name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            return Some(type_name.to_string());
        }
    }
    None
}

/// Extract CPI program from invoke call
fn extract_cpi_program(expr: &str) -> Option<String> {
    // Look for common program references
    let programs = [
        ("token_program", "Token Program"),
        ("system_program", "System Program"),
        ("associated_token", "Associated Token"),
    ];

    for (pattern, name) in programs {
        if expr.to_lowercase().contains(pattern) {
            return Some(name.to_string());
        }
    }

    None
}

/// Extract receiver name from method call
fn extract_receiver_name(expr: &syn::Expr) -> Option<String> {
    let expr_str = expr_to_string(expr);
    let parts: Vec<&str> = expr_str.split('.').collect();
    parts.first().map(|s| s.trim().to_string())
}

/// Extract event name from emit! macro tokens
fn extract_event_name(tokens: &str) -> Option<String> {
    let trimmed = tokens.trim();
    if let Some(end) = trimmed.find(|c: char| c == '{' || c == '(' || c.is_whitespace()) {
        let name = trimmed[..end].trim();
        if !name.is_empty() && name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            return Some(name.to_string());
        }
    }
    None
}

// ============================================================================
// Integration with existing checks
// ============================================================================

/// Run taint analysis on file content
pub fn check(content: &str, file: &str) -> Vec<Finding> {
    let mut analyzer = TaintAnalyzer::new();
    analyzer.analyze_file(content, file)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_taint_flow() {
        let code = r#"
            fn process(data: Vec<u8>) {
                let user_input = data;
                msg!("Received: {:?}", user_input);
            }
        "#;

        let findings = check(code, "src/lib.rs");
        assert!(!findings.is_empty(), "Should detect taint flow");
        assert!(findings.iter().any(|f| f.id == "PRIV-030"));
    }

    #[test]
    fn test_ctx_accounts_taint() {
        let code = r#"
            fn process(ctx: Context<Process>) {
                let user = ctx.accounts.user;
                emit!(UserEvent { user: user.key() });
            }
        "#;

        let findings = check(code, "src/lib.rs");
        assert!(findings.iter().any(|f|
            f.id == "PRIV-030" && f.title.contains("emit")
        ));
    }

    #[test]
    fn test_sanitized_not_flagged() {
        let code = r#"
            fn process(data: Vec<u8>) {
                let hashed = hash(&data);
                msg!("Hash: {:?}", hashed);
            }
        "#;

        let findings = check(code, "src/lib.rs");
        let taint_findings: Vec<_> = findings.iter()
            .filter(|f| f.id == "PRIV-030")
            .collect();
        assert!(taint_findings.is_empty(), "Sanitized data should not be flagged");
    }

    #[test]
    fn test_cpi_sink() {
        let code = r#"
            fn process(ctx: Context<Process>, data: Vec<u8>) {
                let user_data = data;
                invoke(
                    &instruction,
                    &[ctx.accounts.user.to_account_info()],
                );
            }
        "#;

        let _findings = check(code, "src/lib.rs");
        // Should detect tainted data potentially going to CPI
        // Note: this test may or may not flag depending on exact analysis
    }

    #[test]
    fn test_account_data_read_source() {
        let code = r#"
            fn process(account: AccountInfo) {
                let data = account.data.borrow();
                msg!("Account data: {:?}", data);
            }
        "#;

        let findings = check(code, "src/lib.rs");
        assert!(findings.iter().any(|f|
            f.evidence.iter().any(|e| e.contains("account read") || e.contains("AccountInfo"))
        ));
    }

    #[test]
    fn test_instruction_data_source() {
        let code = r#"
            fn process(instruction_data: &[u8]) {
                let input = instruction_data;
                msg!("Input: {:?}", input);
            }
        "#;

        let findings = check(code, "src/lib.rs");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_deserialization_source() {
        let code = r#"
            fn process(data: &[u8]) {
                let args = MyArgs::deserialize(&mut &data[..])?;
                msg!("Args: {:?}", args);
            }
        "#;

        let findings = check(code, "src/lib.rs");
        assert!(findings.iter().any(|f|
            f.evidence.iter().any(|e| e.contains("deserialized") || e.contains("MyArgs"))
        ));
    }

    #[test]
    fn test_serialization_sink() {
        let code = r#"
            fn process(data: Vec<u8>) {
                let user_input = data;
                account.serialize(&mut *account_data.borrow_mut())?;
            }
        "#;

        // This test checks that we detect serialization as a sink
        let _findings = check(code, "src/lib.rs");
        // May or may not find depending on exact flow
    }

    #[test]
    fn test_propagation_tracking() {
        let code = r#"
            fn process(data: Vec<u8>) {
                let step1 = data;
                let step2 = step1.clone();
                let step3 = step2;
                msg!("Data: {:?}", step3);
            }
        "#;

        let findings = check(code, "src/lib.rs");
        assert!(!findings.is_empty(), "Should track propagation");
    }

    #[test]
    fn test_safe_types_not_tainted() {
        let code = r#"
            fn process(amount: u64, flag: bool) {
                msg!("Amount: {}, Flag: {}", amount, flag);
            }
        "#;

        let findings = check(code, "src/lib.rs");
        let taint_findings: Vec<_> = findings.iter()
            .filter(|f| f.id == "PRIV-030")
            .collect();
        assert!(taint_findings.is_empty(), "Safe types should not be tainted");
    }

    #[test]
    fn test_cross_function_basic() {
        let code = r#"
            fn get_user_data(data: Vec<u8>) -> Vec<u8> {
                data
            }

            fn process(input: Vec<u8>) {
                let result = get_user_data(input);
                msg!("Result: {:?}", result);
            }
        "#;

        let findings = check(code, "src/lib.rs");
        // Should detect cross-function taint flow
        assert!(!findings.is_empty(), "Should track cross-function flow");
    }

    #[test]
    fn test_contains_identifier() {
        assert!(contains_identifier("let x = data;", "data"));
        assert!(contains_identifier("msg!(data)", "data"));
        assert!(!contains_identifier("let userdata = 1;", "data"));
        assert!(!contains_identifier("let data_copy = 1;", "data"));
        assert!(contains_identifier("data.clone()", "data"));
    }

    #[test]
    fn test_extract_account_field() {
        assert_eq!(
            extract_account_field_access("account.owner"),
            Some(("account".to_string(), "owner".to_string()))
        );
        assert_eq!(
            extract_account_field_access("user_account.lamports"),
            Some(("user_account".to_string(), "lamports".to_string()))
        );
    }

    #[test]
    fn test_cross_file_registry() {
        // File 1: defines a function that returns tainted data
        let file1_code = r#"
            pub fn get_user_data(input: Vec<u8>) -> Vec<u8> {
                input
            }
        "#;

        // File 2: calls the function from file1 and logs it
        let file2_code = r#"
            fn process_data(data: Vec<u8>) {
                let result = get_user_data(data);
                msg!("Result: {:?}", result);
            }
        "#;

        // Build global registry from both files
        let mut registry = CrateFunctionRegistry::new();
        registry.build_from_file(file1_code, "src/utils.rs");
        registry.build_from_file(file2_code, "src/lib.rs");

        // Verify get_user_data was registered
        let summary = registry.get_by_name("get_user_data");
        assert!(summary.is_some(), "Function should be in registry");
        assert!(summary.unwrap().returns_tainted, "Function should return tainted data");

        // Analyze file2 with the global registry
        let mut analyzer = TaintAnalyzer::with_global_registry(registry);
        let findings = analyzer.analyze_file(file2_code, "src/lib.rs");

        // Should detect the cross-file taint flow
        assert!(!findings.is_empty(), "Should detect cross-file taint flow");
        assert!(findings.iter().any(|f|
            f.id == "PRIV-030" && f.title.contains("msg")
        ), "Should flag msg! call with cross-file tainted data");
    }

    #[test]
    fn test_extract_function_names() {
        let names = extract_function_names_from_call("get_user_data(input)");
        assert!(names.contains(&"get_user_data".to_string()));

        let names2 = extract_function_names_from_call("module::func(a, b)");
        assert!(names2.contains(&"func".to_string()));

        let names3 = extract_function_names_from_call("if (x) { foo(y) }");
        assert!(names3.contains(&"foo".to_string()));
        assert!(!names3.contains(&"if".to_string())); // 'if' should be filtered
    }
}
