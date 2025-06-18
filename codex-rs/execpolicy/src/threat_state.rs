use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use lazy_static::lazy_static;
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

#[derive(Clone, Debug, Default)]
/// Represents a rolling window of threat assessments in tensor form.
pub struct ThreatMatrix {
    /// Rolling window of threat assessments.
    window: VecDeque<ThreatAssessment>,
    /// Decay factor for shortening the window over time.
    decay_factor: f64,
    /// Maximum size of the rolling window.
    max_size: usize,
}

#[derive(Clone, Debug)]
/// Represents an individual threat assessment.
pub struct ThreatAssessment {
    /// Original danger level.
    original_danger: f64,
    /// Evaluated danger level.
    evaluated_danger: f64,
    /// Metadata or flags associated with the command.
    flags: Vec<String>,
}

lazy_static! {
    /// Global historical matrix for tracking past threat assessments.
    static ref HISTORICAL_MATRIX: Mutex<ThreatMatrix> = Mutex::new(ThreatMatrix::new(1000, 0.05));
}

impl ThreatMatrix {
    /// Creates a new ThreatMatrix with the specified parameters.
    pub fn new(max_size: usize, decay_factor: f64) -> Self {
        Self {
            window: VecDeque::new(),
            decay_factor,
            max_size,
        }
    }

    /// Adds a new threat assessment to the matrix.
    pub fn add_assessment(&mut self, assessment: ThreatAssessment) {
        if self.window.len() >= self.max_size {
            self.prune_uninteresting();
        }
        self.window.push_back(assessment);
    }

    /// Applies the decay factor to shorten the window over time.
    pub fn apply_decay(&mut self) {
        self.window.retain(|assessment| {
            assessment.evaluated_danger > self.decay_factor
        });
    }

    /// Prunes uninteresting items from the rolling window.
    fn prune_uninteresting(&mut self) {
        self.window.pop_front();
    }

    /// Reassesses the entire matrix for the present moment.
    pub fn reassess(&mut self, reassess_fn: impl Fn(&ThreatAssessment) -> f64) {
        for assessment in &mut self.window {
            assessment.evaluated_danger = reassess_fn(assessment);
        }
    }

    /// Blends the historical matrix with the rescored matrix and aggregates threat values.
    pub fn blend_with_history(&self, rescored_matrix: &ThreatMatrix, aggregate_fn: Option<impl Fn(f64, f64) -> f64>) -> ThreatMatrix {
        let mut blended_matrix = ThreatMatrix::new(self.max_size, self.decay_factor);

        for assessment in &self.window {
            blended_matrix.add_assessment(assessment.clone());
        }

        for assessment in &rescored_matrix.window {
            let aggregated_danger = if let Some(agg_fn) = &aggregate_fn {
                agg_fn(assessment.original_danger, assessment.evaluated_danger)
            } else {
                assessment.evaluated_danger
            };

            blended_matrix.add_assessment(ThreatAssessment::new(
                assessment.original_danger,
                aggregated_danger,
                assessment.flags.clone(),
            ));
        }

        blended_matrix
    }

    /// Updates the global historical matrix with the current matrix.
    pub fn update_historical_matrix(&self) {
        let mut historical = HISTORICAL_MATRIX.lock().expect("Failed to lock historical matrix");
        for assessment in &self.window {
            historical.add_assessment(assessment.clone());
        }
    }

    /// Retrieves the global historical matrix.
    pub fn get_historical_matrix() -> ThreatMatrix {
        let guard = HISTORICAL_MATRIX.lock().expect("Failed to lock historical matrix");
        (*guard).clone()
    }

    /// Stub implementation for `evaluate`.
    /// Returns an n-dimensional tensor representation of the matrix.
    pub fn evaluate(&self) -> ThreatLevel {
        // Placeholder logic: return a default ThreatLevel.
        ThreatLevel::Low
    }
}

impl ThreatAssessment {
    /// Creates a new ThreatAssessment.
    pub fn new(original_danger: f64, evaluated_danger: f64, flags: Vec<String>) -> Self {
        Self {
            original_danger,
            evaluated_danger,
            flags,
        }
    }
}
