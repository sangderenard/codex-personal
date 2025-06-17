use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use anyhow::Context;
use crate::{Policy, PolicyParser};

/// Watches a policy file and reloads it when modified.
///
/// This is useful for environments where the policy may change at runtime.
#[derive(Debug)]
pub struct PolicyWatcher {
    policy: Arc<Mutex<Policy>>,
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

        Ok(Self { policy, watcher })
    }

    /// Returns a clone of the current policy.
    pub fn policy(&self) -> Policy {
        self.policy.lock().expect("lock poisoned").clone()
    }
}
