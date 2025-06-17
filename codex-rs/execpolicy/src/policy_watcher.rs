use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use anyhow::Context;
use crate::{Policy, PolicyParser};

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
}

