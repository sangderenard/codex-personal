use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use anyhow::Context;
use crate::{Policy, PolicyParser};
use crate::threat_state::{
    ThreatMatrix,
    ThreatAssessment,
    ThreatDeliverable,
    RiskVector,
    ThreatLevel,
    DEFAULT_CATEGORY_WEIGHTS,
    load_risk_tree,
    generate_deliverables_with_weights,
    load_risk_matrix,
    risk_vector_score,
    DEFAULT_RISK_SCORE,
};

/// Path to the CSV database containing risk assessment scores.
///
/// The risk matrix is derived from this CSV at runtime.
const RISK_CSV_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/risk_csv.csv");

/// Threshold above which policy reloads should be rejected.
const RISK_THRESHOLD: f64 = 0.5;


/// Load the overall risk score from `RISK_CSV_PATH` by averaging all metrics.
/// If the CSV cannot be read, [`DEFAULT_RISK_SCORE`] is returned so that existing
/// behaviour is preserved.
fn current_risk_score() -> f64 {
    let Ok(tree) = load_risk_tree(std::path::Path::new(RISK_CSV_PATH)) else {
        return DEFAULT_RISK_SCORE;
    };
    let mut sum = 0.0;
    let mut count = 0;
    for env in tree.values() {
        for cmd in env.values() {
            for vec in cmd.values() {
                for v in vec {
                    sum += *v;
                    count += 1;
                }
            }
        }
    }
    if count == 0 { DEFAULT_RISK_SCORE } else { sum / count as f64 }
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
    /// This appends the tool and score to the `RISK_CSV_PATH` CSV file.
    pub fn register_tool(&self, tool_name: &str, risk_score: f64) -> anyhow::Result<()> {
        let mut content = std::fs::read_to_string(RISK_CSV_PATH).unwrap_or_default();
        content.push_str(&format!("\n{},{}", tool_name, risk_score));
        std::fs::write(RISK_CSV_PATH, content).context("writing to risk database")?;
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
    pub fn compile_csv_batch(&self, commands: Vec<String>, env: Option<&str>) -> anyhow::Result<Vec<(String, RiskVector)>> {
        let tree = load_risk_tree(std::path::Path::new(RISK_CSV_PATH))?;
        let mut results = Vec::new();
        let environment = env.map(|e| e.to_lowercase()).unwrap_or_else(|| std::env::consts::OS.to_lowercase());

        for command in commands {
            let mut parts = command.split_whitespace();
            if let Some(cmd) = parts.next() {
                let flags: Vec<String> = parts.map(|s| s.to_string()).collect();
                if let Some(env_map) = tree.get(&environment) {
                    if let Some(cmd_map) = env_map.get(cmd) {
                        for flag in &flags {
                            if let Some(vec) = cmd_map.get(flag) {
                                results.push((flag.clone(), vec.clone()));
                            }
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Combine category scores from threat state into a single risk score.
    pub fn modulate_results(&self, batch: Vec<(String, RiskVector)>) -> Vec<(String, f64)> {
        batch
            .into_iter()
            .map(|(flag, vec)| {
                let score = risk_vector_score(&vec);
                (flag, score)
            })
            .collect()
    }

    /// Processes the dimensionality of a ThreatMatrix based on the CSV data and commands.
    pub fn process_threat_matrix(&self, commands: Vec<String>) -> ThreatMatrix {
        let mut matrix = match load_risk_matrix(std::path::Path::new(RISK_CSV_PATH)) {
            Ok(m) => m,
            Err(_) => ThreatMatrix::new(0, 0.0),
        };

        if let Ok(batch) = self.compile_csv_batch(commands, None) {
            let scored = self.modulate_results(batch);
            for (tool_name, risk_score) in scored {
                let assessment = ThreatAssessment::new(risk_score, risk_score, vec![tool_name]);
                matrix.add_assessment(assessment);
            }
        }

        matrix.apply_decay();
        matrix
    }

    /// Generates threat deliverables by overlaying the current CSV with historical data.
    pub fn threat_deliverables(&self, csv_path: &PathBuf) -> anyhow::Result<ThreatDeliverable> {
        let tree = load_risk_tree(csv_path)?;
        Ok(generate_deliverables_with_weights(tree, &DEFAULT_CATEGORY_WEIGHTS))
    }

    /// Evaluate a [`ThreatMatrix`] and return the overall [`ThreatLevel`].
    pub fn evaluate_matrix(&self, matrix: &ThreatMatrix) -> ThreatLevel {
        matrix.evaluate()
    }
}

