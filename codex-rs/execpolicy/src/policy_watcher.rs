use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use anyhow::Context;
use crate::{Policy, PolicyParser};
use crate::threat_state::{ThreatMatrix, ThreatAssessment};

/// Path to the CSV database containing risk assessment scores.
///
/// This is a stub implementation. In the future this should be replaced with
/// a real data source and risk evaluation logic.
const RISK_DB_PATH: &str = "risk_db.csv";

/// Threshold above which policy reloads should be rejected.
const RISK_THRESHOLD: f64 = 0.5;

/// Load the risk score from `RISK_DB_PATH`.
///
/// This stub reads the first numeric value from the CSV and returns it. If the
/// file does not exist or the contents are malformed, `0.0` is returned so that
/// existing behaviour is preserved.
fn current_risk_score() -> f64 {
    let Ok(content) = std::fs::read_to_string(RISK_DB_PATH) else {
        return 0.0;
    };
    for line in content.lines().skip(1) {
        if let Some(field) = line.split(',').next() {
            if let Ok(score) = field.trim().parse::<f64>() {
                return score;
            }
        }
    }
    0.0
}

/// Watches a policy file and reloads it when modified.
///
/// This is useful for environments where the policy may change at runtime.
#[derive(Debug)]
pub struct PolicyWatcher {
    policy: Arc<Mutex<Policy>>,
    path: PathBuf,
    #[allow(dead_code)]
    watcher: RecommendedWatcher,
}

impl PolicyWatcher {
    /// Creates a new `PolicyWatcher` for the given policy path.
    /// The initial contents are loaded immediately.
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        let unparsed = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let parser = PolicyParser::new(&path.to_string_lossy(), &unparsed);
        let policy = Arc::new(Mutex::new(parser.parse().map_err(|e| anyhow::anyhow!(e))?));

        let policy_clone = Arc::clone(&policy);
        let path_clone = path.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_)) {
                    if let Ok(content) = std::fs::read_to_string(&path_clone) {
                        if let Ok(parsed) = PolicyParser::new(&path_clone.to_string_lossy(), &content).parse() {
                            if let Ok(mut lock) = policy_clone.lock() {
                                *lock = parsed;
                            }
                        }
                    }
                }
            }
        })?;
        watcher.watch(&path, RecursiveMode::NonRecursive)?;

        Ok(Self { policy, path, watcher })
    }

    /// Returns a clone of the current policy.
    pub fn policy(&self) -> Policy {
        self.policy.lock().expect("lock poisoned").clone()
    }

    /// Reloads the policy from disk immediately.
    pub fn reload(&self) -> anyhow::Result<()> {
        // Stub risk assessment check. In the future this should consult the
        // real risk database. If the risk score exceeds the threshold, deny the
        // reload request.
        if current_risk_score() > RISK_THRESHOLD {
            anyhow::bail!("policy reload denied: risk level too high");
        }

        let unparsed = std::fs::read_to_string(&self.path)
            .with_context(|| format!("reading {}", self.path.display()))?;
        let parser = PolicyParser::new(&self.path.to_string_lossy(), &unparsed);
        let parsed = parser.parse().map_err(|e| anyhow::anyhow!(e))?;
        if let Ok(mut lock) = self.policy.lock() {
            *lock = parsed;
        }
        Ok(())
    }

    /// Registers a new tool and its risk score in the risk database.
    ///
    /// This appends the tool and score to the `RISK_DB_PATH` CSV file.
    pub fn register_tool(&self, tool_name: &str, risk_score: f64) -> anyhow::Result<()> {
        let mut content = std::fs::read_to_string(RISK_DB_PATH).unwrap_or_default();
        content.push_str(&format!("\n{},{}", tool_name, risk_score));
        std::fs::write(RISK_DB_PATH, content).context("writing to risk database")?;
        Ok(())
    }

    /// Performs a prefilter check on the CSV data.
    ///
    /// This is used to reject CSV data that may be too risky to process.
    pub fn prefilter_csv(&self) -> anyhow::Result<()> {
        let risk_score = current_risk_score();
        if risk_score > RISK_THRESHOLD {
            anyhow::bail!("CSV prefilter rejected: risk score too high");
        }
        Ok(())
    }

    /// Decomposes a list of command strings into their base flags and compiles a batch of CSV values.
    pub fn compile_csv_batch(&self, commands: Vec<String>) -> anyhow::Result<Vec<(String, f64)>> {
        let mut results = Vec::new();
        let Ok(content) = std::fs::read_to_string(RISK_DB_PATH) else {
            return Ok(results);
        };

        let csv_data: Vec<(String, f64)> = content
            .lines()
            .skip(1) // Skip header
            .filter_map(|line| {
                let mut fields = line.split(',');
                let tool_name = fields.next()?.trim().to_string();
                let risk_score = fields.next()?.trim().parse::<f64>().ok()?;
                Some((tool_name, risk_score))
            })
            .collect();

        for command in commands {
            let flags: Vec<String> = command.split_whitespace().map(|s| s.to_string()).collect();
            for flag in flags {
                if let Some((tool_name, risk_score)) = csv_data.iter().find(|(name, _)| name == &flag) {
                    results.push((tool_name.clone(), *risk_score));
                }
            }
        }

        Ok(results)
    }

    /// Stub for modulating results based on history and combined patterns.
    pub fn modulate_results(&self, batch: Vec<(String, f64)>) -> Vec<(String, f64)> {
        // Placeholder for future implementation
        batch
    }

    /// Processes the dimensionality of a ThreatMatrix based on the CSV data and commands.
    pub fn process_threat_matrix(&self, commands: Vec<String>) -> ThreatMatrix {
        let mut matrix = ThreatMatrix::new(100, 0.1); // Example parameters: max_size=100, decay_factor=0.1

        if let Ok(batch) = self.compile_csv_batch(commands) {
            for (tool_name, risk_score) in batch {
                let assessment = ThreatAssessment::new(risk_score, risk_score * 1.2, vec![tool_name]);
                matrix.add_assessment(assessment);
            }
        }

        matrix.apply_decay();
        matrix
    }
}

