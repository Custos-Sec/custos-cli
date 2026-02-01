//! Privacy checks module

pub mod access;
pub mod anchor;
pub mod logging;
pub mod pii;
pub mod secrets;

use crate::report::Severity;
use serde::Serialize;

/// A privacy finding
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Rule ID (e.g., PRIV-001)
    pub id: String,
    /// Short title
    pub title: String,
    /// Severity level
    pub severity: Severity,
    /// File path (relative)
    pub file: String,
    /// Line number
    pub line: usize,
    /// Code snippet
    pub code_snippet: String,
    /// Fix recommendation
    pub recommendation: String,
    /// Confidence score (0-100)
    #[serde(default = "default_confidence")]
    pub confidence: u8,
    /// Evidence explaining confidence level
    #[serde(default)]
    pub evidence: Vec<String>,
}

fn default_confidence() -> u8 {
    80
}

impl Finding {
    pub fn new(
        id: &str,
        title: &str,
        severity: Severity,
        file: &str,
        line: usize,
        code_snippet: &str,
        recommendation: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            severity,
            file: file.to_string(),
            line,
            code_snippet: code_snippet.to_string(),
            recommendation: recommendation.to_string(),
            confidence: default_confidence(),
            evidence: Vec::new(),
        }
    }

    /// Set confidence score with evidence
    #[allow(dead_code)]
    pub fn with_confidence(mut self, confidence: u8, evidence: Vec<String>) -> Self {
        self.confidence = confidence.min(100);
        self.evidence = evidence;
        self
    }

    /// Get confidence as a descriptive string
    pub fn confidence_label(&self) -> &'static str {
        match self.confidence {
            90..=100 => "Very High",
            70..=89 => "High",
            50..=69 => "Medium",
            25..=49 => "Low",
            _ => "Very Low",
        }
    }
}

/// Helper to find line number from byte position
pub fn find_line_number(content: &str, byte_pos: usize) -> usize {
    content[..byte_pos.min(content.len())]
        .chars()
        .filter(|&c| c == '\n')
        .count()
        + 1
}

/// Helper to extract code snippet around a match
pub fn extract_code_snippet(content: &str, line_number: usize) -> String {
    crate::utils::extract_snippet(content, line_number, 2)
}
