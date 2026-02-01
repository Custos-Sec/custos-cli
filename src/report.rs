//! Report generation and output formatting

use crate::checks::Finding;
use anyhow::Result;
use colored::*;
use serde::Serialize;

/// Output format for reports
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Text,
        }
    }
}

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Severity::Info => "[i]",
            Severity::Low => "[*]",
            Severity::Medium => "[!]",
            Severity::High => "[!!]",
            Severity::Critical => "[!!!]",
        }
    }

    pub fn colorize(&self, text: &str) -> ColoredString {
        match self {
            Severity::Info => text.bright_blue(),
            Severity::Low => text.white(),
            Severity::Medium => text.yellow(),
            Severity::High => text.red(),
            Severity::Critical => text.bright_red().bold(),
        }
    }

    pub fn weight(&self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 5,
            Severity::Medium => 10,
            Severity::High => 25,
            Severity::Critical => 40,
        }
    }
}

/// Parse severity from string
pub fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// JSON report structure
#[derive(Serialize)]
pub struct JsonReport {
    pub version: String,
    pub analyzed_at: String,
    pub target: String,
    pub privacy_score: u32,
    pub grade: String,
    pub summary: Summary,
    pub findings: Vec<JsonFinding>,
}

#[derive(Serialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub files_scanned: usize,
}

#[derive(Serialize)]
pub struct JsonFinding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub code_snippet: String,
    pub recommendation: String,
    pub confidence: u8,
    pub confidence_label: String,
    pub evidence: Vec<String>,
}

/// Print a text-formatted report
pub fn print_text_report(findings: &[Finding], score: u32, grade: &str, files_scanned: usize) {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();

    println!("{}", "=".repeat(60).bright_cyan());

    let score_color = match grade {
        "A" => format!("{}/100", score).green().bold(),
        "B" => format!("{}/100", score).bright_green(),
        "C" => format!("{}/100", score).yellow(),
        "D" => format!("{}/100", score).bright_red(),
        _ => format!("{}/100", score).red().bold(),
    };

    println!(
        "Summary: {} {} (Grade: {})",
        "Privacy Score:".bold(),
        score_color,
        grade.bold()
    );

    println!(
        "   Found {} issues in {} files\n",
        findings.len(),
        files_scanned
    );

    if !findings.is_empty() {
        // Confidence breakdown
        let high_conf = findings.iter().filter(|f| f.confidence >= 90).count();
        let med_conf = findings.iter().filter(|f| f.confidence >= 70 && f.confidence < 90).count();
        let low_conf = findings.iter().filter(|f| f.confidence < 70).count();

        let avg = findings.iter().map(|f| f.confidence as u32).sum::<u32>() as f64 / findings.len() as f64;
        println!("   Average confidence: {}%", format!("{:.0}", avg).bright_white());
        println!(
            "   Confidence breakdown: {} High (90+) | {} Medium (70-89) | {} Low (<70)",
            format!("{}", high_conf).bright_green(),
            format!("{}", med_conf).yellow(),
            format!("{}", low_conf).red()
        );
        println!();
        println!(
            "   [!!!] Critical: {}  [!!] High: {}  [!] Medium: {}  [*] Low: {}",
            critical, high, medium, low
        );
        println!();
    }

    for finding in findings {
        print_finding(finding);
    }

    println!("{}", "=".repeat(60).bright_cyan());

    if findings.is_empty() {
        println!("{} No privacy issues detected!", "[OK]".green());
    } else {
        println!(
            "{} Review the findings above and apply the suggested fixes.",
            "[TIP]".bright_yellow()
        );
    }
    println!();
}

fn print_finding(finding: &Finding) {
    // Use special FlowTrace visualization for taint findings
    if finding.id == "PRIV-030" {
        print_flowtrace(finding);
        return;
    }

    let severity_str = finding.severity.as_str();
    let emoji = finding.severity.emoji();

    let confidence_colored = match finding.confidence {
        90..=100 => format!("{}%", finding.confidence).bright_green(),
        70..=89 => format!("{}%", finding.confidence).green(),
        50..=69 => format!("{}%", finding.confidence).yellow(),
        25..=49 => format!("{}%", finding.confidence).bright_yellow(),
        _ => format!("{}%", finding.confidence).red(),
    };

    println!(
        "{} [{}] {}: {} ({})",
        emoji,
        finding.severity.colorize(severity_str),
        finding.id.bright_white().bold(),
        finding.title.bold(),
        confidence_colored
    );

    println!(
        "   {} {}:{}",
        "[FILE]".bright_blue(),
        finding.file.bright_white(),
        finding.line.to_string().bright_yellow()
    );

    if !finding.code_snippet.is_empty() {
        println!("   +{}", "-".repeat(50));
        for line in finding.code_snippet.lines() {
            println!("   | {}", line.dimmed());
        }
        println!("   +{}", "-".repeat(50));
    }

    if !finding.evidence.is_empty() {
        println!("   {} Evidence:", "[INFO]".bright_cyan());
        for ev in &finding.evidence {
            println!("      - {}", ev.dimmed());
        }
    }

    println!(
        "   {} {}",
        "Fix:".bright_yellow(),
        finding.recommendation
    );
    println!();
}

/// Print a taint flow finding with visual FlowTrace format
fn print_flowtrace(finding: &Finding) {
    let box_width = 63;

    // Parse evidence to extract source, sink, carrier, and flow path
    let mut source_desc = String::new();
    let mut sink_desc = String::new();
    let mut carrier = String::new();
    let mut flow_path = String::new();

    for ev in &finding.evidence {
        if ev.starts_with("Source: ") {
            source_desc = ev.strip_prefix("Source: ").unwrap_or("").to_string();
        } else if ev.starts_with("Sink: ") {
            sink_desc = ev.strip_prefix("Sink: ").unwrap_or("").to_string();
        } else if ev.starts_with("Carrier variable: ") {
            carrier = ev.strip_prefix("Carrier variable: ").unwrap_or("").to_string();
        } else if ev.starts_with("Flow path: ") {
            flow_path = ev.strip_prefix("Flow path: ").unwrap_or("").to_string();
        }
    }

    // Header box with double lines
    println!();
    println!("  {}", format!("╔{}╗", "═".repeat(box_width)).bright_red());
    let header = format!(
        "  PRIV-030: Privacy Leak Path Detected (Confidence: {}%)",
        finding.confidence
    );
    let padding = box_width.saturating_sub(header.len());
    println!(
        "  {}{}{}{}",
        "║".bright_red(),
        header.bright_white().bold(),
        " ".repeat(padding),
        "║".bright_red()
    );
    println!("  {}", format!("╚{}╝", "═".repeat(box_width)).bright_red());
    println!();

    // Source box
    println!("  {}", format!("┌{}┐", "─".repeat(box_width)).cyan());
    let source_header = format!(" SOURCE: {}", truncate_str(&source_desc, box_width - 12));
    let source_padding = box_width.saturating_sub(source_header.len());
    println!(
        "  {}{}{}{}",
        "│".cyan(),
        source_header.bright_cyan().bold(),
        " ".repeat(source_padding),
        "│".cyan()
    );
    let source_loc = format!("         {}:{}", finding.file, finding.line);
    let loc_padding = box_width.saturating_sub(source_loc.len());
    println!(
        "  {}{}{}{}",
        "│".cyan(),
        source_loc.dimmed(),
        " ".repeat(loc_padding),
        "│".cyan()
    );
    println!("  {}", format!("└{}┘", "─".repeat(box_width)).cyan());

    // Flow arrow
    println!("  {}", " ".repeat(box_width / 2) + "│");
    println!("  {}", " ".repeat(box_width / 2) + "▼");

    // Flow path box (if we have flow info)
    if !flow_path.is_empty() && !carrier.is_empty() {
        println!("  {}", format!("┌{}┐", "─".repeat(box_width)).yellow());
        let flow_header = format!(" FLOW: via {} → {}", carrier.trim_matches('\''), truncate_str(&sink_desc, box_width - 20));
        let flow_padding = box_width.saturating_sub(flow_header.len());
        println!(
            "  {}{}{}{}",
            "│".yellow(),
            flow_header.bright_yellow(),
            " ".repeat(flow_padding),
            "│".yellow()
        );
        println!("  {}", format!("└{}┘", "─".repeat(box_width)).yellow());

        // Another flow arrow
        println!("  {}", " ".repeat(box_width / 2) + "│");
        println!("  {}", " ".repeat(box_width / 2) + "▼");
    }

    // Sink box
    println!("  {}", format!("┌{}┐", "─".repeat(box_width)).red());
    let sink_header = format!(" SINK: {}", truncate_str(&sink_desc, box_width - 10));
    let sink_padding = box_width.saturating_sub(sink_header.len());
    println!(
        "  {}{}{}{}",
        "│".red(),
        sink_header.bright_red().bold(),
        " ".repeat(sink_padding),
        "│".red()
    );
    let sink_loc = format!("       {}:{}", finding.file, finding.line);
    let sink_loc_padding = box_width.saturating_sub(sink_loc.len());
    println!(
        "  {}{}{}{}",
        "│".red(),
        sink_loc.dimmed(),
        " ".repeat(sink_loc_padding),
        "│".red()
    );
    println!("  {}", format!("└{}┘", "─".repeat(box_width)).red());
    println!();

    // Warning message based on sink type
    let warning = get_flowtrace_warning(&sink_desc, &source_desc);
    println!("  {} {}", "⚠".bright_yellow(), warning.bright_yellow());

    // Code snippet
    if !finding.code_snippet.is_empty() {
        println!();
        println!("  {}", "Code:".dimmed());
        for line in finding.code_snippet.lines() {
            println!("  {}", line.dimmed());
        }
    }

    // Fix recommendation
    println!();
    println!(
        "  {} {}",
        "Fix:".bright_green(),
        finding.recommendation
    );
    println!();
}

/// Truncate a string to fit within a certain width
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Get a contextual warning message for the FlowTrace visualization
fn get_flowtrace_warning(sink: &str, source: &str) -> String {
    let sink_lower = sink.to_lowercase();
    let source_lower = source.to_lowercase();

    if sink_lower.contains("emit") || sink_lower.contains("event") {
        if source_lower.contains("email") || source_lower.contains("pii") {
            return "Personal data flows directly to publicly-indexed event".to_string();
        }
        return "Sensitive data emitted to publicly-indexed blockchain event".to_string();
    }

    if sink_lower.contains("msg!") || sink_lower.contains("log") {
        return "Data logged on-chain where it can be read by anyone".to_string();
    }

    if sink_lower.contains("cpi") || sink_lower.contains("invoke") {
        return "Sensitive data sent to external program via CPI".to_string();
    }

    if sink_lower.contains("serialize") || sink_lower.contains("account") {
        return "Data stored on-chain in account state".to_string();
    }

    "Sensitive data flows to a public sink".to_string()
}

/// Generate a JSON report
pub fn generate_json_report(
    findings: &[Finding],
    score: u32,
    grade: &str,
    target: &str,
    files_scanned: usize,
) -> Result<String> {
    let summary = Summary {
        critical: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
        high: findings.iter().filter(|f| f.severity == Severity::High).count(),
        medium: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
        low: findings.iter().filter(|f| f.severity == Severity::Low).count(),
        info: findings.iter().filter(|f| f.severity == Severity::Info).count(),
        files_scanned,
    };

    let json_findings: Vec<JsonFinding> = findings
        .iter()
        .map(|f| JsonFinding {
            id: f.id.clone(),
            title: f.title.clone(),
            severity: f.severity,
            file: f.file.clone(),
            line: f.line,
            code_snippet: f.code_snippet.clone(),
            recommendation: f.recommendation.clone(),
            confidence: f.confidence,
            confidence_label: f.confidence_label().to_string(),
            evidence: f.evidence.clone(),
        })
        .collect();

    let report = JsonReport {
        version: "0.1.0".to_string(),
        analyzed_at: chrono::Utc::now().to_rfc3339(),
        target: target.to_string(),
        privacy_score: score,
        grade: grade.to_string(),
        summary,
        findings: json_findings,
    };

    Ok(serde_json::to_string_pretty(&report)?)
}
