//! Utility functions for file handling and Git operations

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::TempDir;
use walkdir::WalkDir;

/// Global holder for temporary directories created during GitHub clones.
static TEMP_DIR_HOLDER: Lazy<Mutex<Vec<TempDir>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Resolve a target string to a local path
/// If it's a GitHub URL, clone it to a temp directory
pub fn resolve_target(target: &str) -> Result<PathBuf> {
    if is_github_url(target) {
        clone_github_repo(target)
    } else {
        let path = PathBuf::from(target);
        if !path.exists() {
            anyhow::bail!("Path does not exist: {}", target);
        }
        Ok(path)
    }
}

/// Check if a string is a GitHub URL
fn is_github_url(s: &str) -> bool {
    s.starts_with("https://github.com/") || s.starts_with("git@github.com:")
}

/// Clone a GitHub repository to a temporary directory
fn clone_github_repo(url: &str) -> Result<PathBuf> {
    use colored::*;
    use std::process::Command;

    println!("{} Cloning repository: {}", "[GIT]".bright_blue(), url);

    let temp_dir = tempfile::tempdir()
        .context("Failed to create temporary directory")?;

    let repo_path = temp_dir.path().to_path_buf();

    let output = Command::new("git")
        .args(["clone", "--depth", "1", url])
        .arg(&repo_path)
        .output()
        .context("Failed to execute git clone command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git clone failed: {}", stderr);
    }

    println!("{} Repository cloned successfully", "[OK]".green());

    if let Ok(mut holder) = TEMP_DIR_HOLDER.lock() {
        holder.push(temp_dir);
    } else {
        std::mem::forget(temp_dir);
    }

    Ok(repo_path)
}

/// Maximum directory depth to traverse
const MAX_DIR_DEPTH: usize = 50;

/// Find all Rust source files in a directory
pub fn find_rust_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut rust_files = Vec::new();

    for entry in WalkDir::new(dir)
        .max_depth(MAX_DIR_DEPTH)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        // Skip common non-program directories
        let skip_dirs = ["target", "sdk", "client", "generated", "examples", "wasm", "cli", "tests",
                         "cosmwasm", "evm", "ethereum", "aptos", "sui", "terra", "algorand", "near"];
        if path.components().any(|c| {
            let name = c.as_os_str().to_string_lossy();
            skip_dirs.iter().any(|&skip| name == skip)
        }) {
            continue;
        }

        let relative_path = path.strip_prefix(dir).unwrap_or(path);

        // Skip hidden directories
        if relative_path.components().any(|c| {
            let name = c.as_os_str().to_string_lossy();
            name.starts_with('.') && name.len() > 1 && name != ".."
        }) {
            continue;
        }

        if path.extension().map_or(false, |ext| ext == "rs") {
            // Skip WASM binding files (client-side code, not on-chain)
            let file_name = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
            if file_name == "wasm.rs" || file_name.ends_with("_wasm.rs") {
                continue;
            }
            rust_files.push(path.to_path_buf());
        }
    }

    Ok(rust_files)
}

/// Read a file's contents
pub fn read_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))
}

/// Get a relative path from a base directory
pub fn get_relative_path(path: &Path, base: &Path) -> PathBuf {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_path_buf()
}

/// Extract a code snippet around a specific line
pub fn extract_snippet(content: &str, line_number: usize, context_lines: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();

    if line_number == 0 || line_number > lines.len() {
        return String::new();
    }

    let start = line_number.saturating_sub(context_lines + 1);
    let end = (line_number + context_lines).min(lines.len());

    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let actual_line = start + i + 1;
            if actual_line == line_number {
                format!(">{:4} | {}", actual_line, line)
            } else {
                format!(" {:4} | {}", actual_line, line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
