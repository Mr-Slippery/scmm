//! Path and network generalization algorithms

use std::collections::HashMap;
use std::path::Path;

/// Pattern type for paths
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPattern {
    /// Directory wildcard (e.g., /path/to/dir/*)
    Directory(String),
    /// Recursive wildcard (e.g., /path/to/dir/**)
    Recursive(String),
    /// Template with variable substitution (e.g., /home/${USER}/...)
    Template(String),
}

impl PathPattern {
    pub fn to_yaml_pattern(&self) -> (String, String) {
        match self {
            PathPattern::Directory(p) => (format!("{}/*", p), "glob".to_string()),
            PathPattern::Recursive(p) => (format!("{}/**", p), "glob".to_string()),
            PathPattern::Template(p) => (p.clone(), "template".to_string()),
        }
    }
}

/// Suggestion for path generalization
#[derive(Debug)]
pub struct PathSuggestion {
    /// Original paths this suggestion covers
    pub original_paths: Vec<String>,
    /// Suggested pattern
    pub pattern: PathPattern,
    /// Confidence score (0-1)
    pub confidence: f64,
    /// Human-readable reason
    pub reason: String,
}

/// Path generalizer
pub struct PathGeneralizer {
    /// Known pattern templates
    known_patterns: Vec<(regex::Regex, String, &'static str)>,
}

impl PathGeneralizer {
    pub fn new() -> Self {
        Self {
            known_patterns: vec![
                // User home directories
                (
                    regex::Regex::new(r"^/home/([^/]+)/").unwrap(),
                    "/home/${USER}/".to_string(),
                    "User home directory pattern",
                ),
                // Temporary files with random names
                (
                    regex::Regex::new(r"^/tmp/[a-zA-Z0-9_-]{6,}").unwrap(),
                    "/tmp/*".to_string(),
                    "Temporary file pattern",
                ),
                // Process-specific paths
                (
                    regex::Regex::new(r"^/proc/\d+/").unwrap(),
                    "/proc/self/".to_string(),
                    "Process-specific /proc path",
                ),
                // Library versioned paths
                (
                    regex::Regex::new(r"\.so\.\d+(\.\d+)*$").unwrap(),
                    ".so.*".to_string(),
                    "Versioned shared library",
                ),
                // Cache directories
                (
                    regex::Regex::new(r"^/home/[^/]+/\.cache/").unwrap(),
                    "/home/${USER}/.cache/**".to_string(),
                    "User cache directory",
                ),
                // Config directories
                (
                    regex::Regex::new(r"^/home/[^/]+/\.config/").unwrap(),
                    "/home/${USER}/.config/**".to_string(),
                    "User config directory",
                ),
            ],
        }
    }

    /// Analyze a list of paths and generate suggestions
    pub fn analyze(&self, paths: &[String]) -> Vec<PathSuggestion> {
        let mut suggestions = Vec::new();

        // Group paths by parent directory
        let mut by_parent: HashMap<String, Vec<String>> = HashMap::new();
        for path in paths {
            if let Some(parent) = Path::new(path).parent() {
                by_parent
                    .entry(parent.to_string_lossy().to_string())
                    .or_default()
                    .push(path.clone());
            }
        }

        // Suggest directory patterns for directories with multiple files
        for (parent, files) in &by_parent {
            if files.len() >= 3 {
                suggestions.push(PathSuggestion {
                    original_paths: files.clone(),
                    pattern: PathPattern::Directory(parent.clone()),
                    confidence: calculate_confidence(files),
                    reason: format!(
                        "{} files accessed in {} - consider directory pattern",
                        files.len(),
                        parent
                    ),
                });
            }
        }

        // Apply known pattern templates
        for path in paths {
            for (regex, replacement, reason) in &self.known_patterns {
                if regex.is_match(path) {
                    let generalized = regex.replace(path, replacement.as_str()).to_string();
                    suggestions.push(PathSuggestion {
                        original_paths: vec![path.clone()],
                        pattern: PathPattern::Template(generalized),
                        confidence: 0.8,
                        reason: reason.to_string(),
                    });
                    break; // Only one pattern per path
                }
            }
        }

        // Find common prefixes for recursive patterns
        let common_prefixes = find_common_prefixes(paths, 3);
        for (prefix, matching) in common_prefixes {
            if matching.len() >= 2 {
                suggestions.push(PathSuggestion {
                    original_paths: matching.clone(),
                    pattern: PathPattern::Recursive(prefix.clone()),
                    confidence: 0.7,
                    reason: format!("Common prefix {} for {} paths", prefix, matching.len()),
                });
            }
        }

        suggestions
    }

}

/// Calculate confidence based on path similarity
fn calculate_confidence(paths: &[String]) -> f64 {
    if paths.is_empty() {
        return 0.0;
    }

    let count_factor = (paths.len() as f64).log10() / 2.0;

    // Check extension similarity
    let extensions: Vec<_> = paths
        .iter()
        .filter_map(|p| Path::new(p).extension())
        .collect();

    let ext_similarity = if extensions.is_empty() {
        0.0
    } else {
        let unique: std::collections::HashSet<_> = extensions.iter().collect();
        1.0 - (unique.len() as f64 / extensions.len() as f64)
    };

    (count_factor + ext_similarity).min(1.0).max(0.0)
}

/// Find common path prefixes
fn find_common_prefixes(paths: &[String], min_depth: usize) -> HashMap<String, Vec<String>> {
    let mut prefixes: HashMap<String, Vec<String>> = HashMap::new();

    for path in paths {
        let components: Vec<_> = Path::new(path).components().collect();
        if components.len() < min_depth {
            continue;
        }

        // Build prefix up to min_depth
        let prefix_path: std::path::PathBuf = components[..min_depth].iter().collect();
        let prefix = prefix_path.to_string_lossy().to_string();

        prefixes
            .entry(prefix)
            .or_default()
            .push(path.clone());
    }

    prefixes
}

