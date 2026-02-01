//! Privacy score calculation

use crate::checks::Finding;

/// Calculate the privacy score and grade from findings
/// Uses confidence-weighted scoring: findings with higher confidence have more impact
pub fn calculate_grade(findings: &[Finding]) -> (u32, String) {
    // Weight findings by both severity AND confidence
    // High-confidence findings have full impact, low-confidence findings are discounted
    let total_weight: f64 = findings
        .iter()
        .map(|f| {
            let severity_weight = f.severity.weight() as f64;
            let confidence_factor = f.confidence as f64 / 100.0;
            severity_weight * confidence_factor
        })
        .sum();

    // Score starts at 100 and decreases based on confidence-weighted findings
    let score = 100u32.saturating_sub(total_weight.round() as u32);

    let grade = match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    };

    (score, grade.to_string())
}

/// Get a description for a grade
#[allow(dead_code)]
pub fn grade_description(grade: &str) -> &'static str {
    match grade {
        "A" => "Excellent privacy practices",
        "B" => "Good, minor improvements needed",
        "C" => "Moderate privacy concerns",
        "D" => "Significant privacy gaps",
        "F" => "Critical privacy issues",
        _ => "Unknown",
    }
}
