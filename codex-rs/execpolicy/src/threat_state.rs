use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
}

impl Default for ThreatLevel {
    fn default() -> Self {
        Self::Low
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ThreatState {
    pub level: ThreatLevel,
}

impl ThreatState {
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let state = serde_json::from_str(&content)
            .with_context(|| format!("parsing {}", path.display()))?;
        Ok(state)
    }
}

#[derive(Debug)]
pub struct ThreatStateWatcher {
    state: Arc<Mutex<ThreatState>>,
    path: PathBuf,
    #[allow(dead_code)]
    watcher: RecommendedWatcher,
}

impl ThreatStateWatcher {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        let initial = ThreatState::from_path(&path).unwrap_or_default();
        let state = Arc::new(Mutex::new(initial));
        let state_clone = Arc::clone(&state);
        let path_clone = path.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_)) {
                    if let Ok(new_state) = ThreatState::from_path(&path_clone) {
                        if let Ok(mut lock) = state_clone.lock() {
                            *lock = new_state;
                        }
                    }
                }
            }
        })?;
        watcher.watch(&path, RecursiveMode::NonRecursive)?;
        Ok(Self { state, path, watcher })
    }

    pub fn state(&self) -> ThreatState {
        self.state.lock().expect("lock poisoned").clone()
    }

    pub fn reload(&self) -> anyhow::Result<()> {
        let new_state = ThreatState::from_path(&self.path)?;
        if let Ok(mut lock) = self.state.lock() {
            *lock = new_state;
        }
        Ok(())
    }
}
