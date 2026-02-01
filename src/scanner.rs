//! Core privacy scanner that orchestrates regex-based checks and taint analysis

use crate::checks::{self, Finding};
use crate::suppression;
use crate::taint::{self, CrateFunctionRegistry, TaintAnalyzer};
use crate::utils;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// The main privacy scanner
pub struct PrivacyScanner {
    findings: Vec<Finding>,
    enabled_patterns: Vec<String>,
    #[allow(dead_code)]
    pub project_path: PathBuf,
    /// Track suppressed finding count for reporting
    suppressed_count: usize,
    /// Global function registry for cross-file taint tracking
    global_registry: Option<CrateFunctionRegistry>,
}

impl PrivacyScanner {
    /// Create a new scanner with all checks enabled
    pub fn new(project_path: &Path) -> Self {
        Self {
            findings: Vec::new(),
            enabled_patterns: vec![
                "secrets".to_string(),
                "pii".to_string(),
                "logs".to_string(),
                "access".to_string(),
                "anchor".to_string(),
                "taint".to_string(),  // Enable taint analysis by default
            ],
            project_path: project_path.to_path_buf(),
            suppressed_count: 0,
            global_registry: None,
        }
    }

    /// Create a scanner with specific patterns enabled
    pub fn with_patterns(patterns: &[&str]) -> Self {
        Self {
            findings: Vec::new(),
            enabled_patterns: patterns.iter().map(|s| s.to_string()).collect(),
            project_path: PathBuf::from("."),
            suppressed_count: 0,
            global_registry: None,
        }
    }

    /// Scan all provided files with two-pass analysis for cross-file taint tracking
    pub fn scan_files(&mut self, files: &[PathBuf], base_path: &Path) -> Result<()> {
        // Phase 1: Build global function registry for cross-file taint tracking
        if self.is_pattern_enabled("taint") {
            let mut registry = CrateFunctionRegistry::new();
            for file in files {
                if let Ok(content) = utils::read_file(file) {
                    let relative_path = utils::get_relative_path(file, base_path);
                    let file_str = relative_path.to_string_lossy().to_string();
                    registry.build_from_file(&content, &file_str);
                }
            }
            self.global_registry = Some(registry);
        }

        // Phase 2: Full analysis with cross-file taint information
        for file in files {
            if let Err(e) = self.scan_file(file, base_path) {
                eprintln!("Warning: Failed to scan {}: {}", file.display(), e);
            }
        }
        Ok(())
    }

    /// Scan a single file
    fn scan_file(&mut self, path: &Path, base_path: &Path) -> Result<()> {
        let content = utils::read_file(path)?;
        let relative_path = utils::get_relative_path(path, base_path);
        let file_str = relative_path.to_string_lossy().to_string();

        // Parse suppression comments for this file
        let suppressions = suppression::parse_suppressions(&content);

        // Collect all findings for this file
        let mut file_findings = Vec::new();

        // Run enabled checks
        if self.is_pattern_enabled("secrets") {
            file_findings.extend(checks::secrets::check(&content, &file_str));
        }

        if self.is_pattern_enabled("pii") {
            file_findings.extend(checks::pii::check(&content, &file_str));
        }

        if self.is_pattern_enabled("logs") {
            file_findings.extend(checks::logging::check(&content, &file_str));
        }

        if self.is_pattern_enabled("access") {
            file_findings.extend(checks::access::check(&content, &file_str));
        }

        if self.is_pattern_enabled("anchor") {
            file_findings.extend(checks::anchor::check(&content, &file_str));
        }

        // Taint analysis (data flow tracking) with cross-file support
        if self.is_pattern_enabled("taint") {
            let taint_findings = if let Some(ref registry) = self.global_registry {
                // Use analyzer with global registry for cross-file tracking
                let mut analyzer = TaintAnalyzer::with_global_registry(registry.clone());
                analyzer.analyze_file(&content, &file_str)
            } else {
                // Fallback to simple single-file analysis
                taint::check(&content, &file_str)
            };
            file_findings.extend(taint_findings);
        }

        // Apply suppressions
        let before_count = file_findings.len();
        let filtered_findings = suppression::filter_with_suppressions(file_findings, &suppressions);
        self.suppressed_count += before_count - filtered_findings.len();

        self.findings.extend(filtered_findings);

        Ok(())
    }

    fn is_pattern_enabled(&self, pattern: &str) -> bool {
        self.enabled_patterns.iter().any(|p| p == pattern)
    }

    /// Get all findings
    pub fn get_findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }

    /// Get count of suppressed findings
    #[allow(dead_code)]
    pub fn get_suppressed_count(&self) -> usize {
        self.suppressed_count
    }
}
