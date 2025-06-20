use std::collections::{BTreeMap, VecDeque};
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

    /// Compute the average evaluated danger stored in this matrix.
    pub fn average_danger(&self) -> f64 {
        if self.window.is_empty() {
            return DEFAULT_RISK_SCORE;
        }
        let sum: f64 = self.window.iter().map(|a| a.evaluated_danger).sum();
        sum / self.window.len() as f64
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

    /// Evaluate the current matrix and return the [`ThreatLevel`].
    pub fn evaluate(&self) -> ThreatLevel {
        let avg = self.average_danger();
        if avg == DEFAULT_RISK_SCORE {
            return ThreatLevel::Low;
        }
        if avg > THREAT_HIGH_THRESHOLD {
            ThreatLevel::High
        } else if avg > THREAT_MEDIUM_THRESHOLD {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        }
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

/// Vector of threat metrics per flag.
pub type RiskVector = Vec<f64>;

/// Tree structure mapping environment -> command -> flag -> risk vector.
pub type RiskTree = BTreeMap<String, BTreeMap<String, BTreeMap<String, RiskVector>>>;

/// Default category weights applied during projection.
pub const DEFAULT_CATEGORY_WEIGHTS: [f64; 5] = [1.0; 5];

/// Default risk score when no data is available.
pub const DEFAULT_RISK_SCORE: f64 = 0.0;

/// Threshold at which [`ThreatLevel::Medium`] is triggered.
pub const THREAT_MEDIUM_THRESHOLD: f64 = 2.0;

/// Threshold at which [`ThreatLevel::High`] is triggered.
pub const THREAT_HIGH_THRESHOLD: f64 = 4.0;

/// Sum a weighted [`RiskVector`] into a single risk score.
pub fn risk_vector_score(vec: &RiskVector) -> f64 {
    vec.iter().sum()
}

#[derive(Clone, Debug, Default)]
/// Historical tree storage with a moving window.
pub struct RiskHistory {
    window: VecDeque<RiskTree>,
    _decay_factor: f64,
    max_size: usize,
}

lazy_static! {
    /// Global historical tree for threat evaluations.
    static ref HISTORICAL_TREE: Mutex<RiskHistory> = Mutex::new(RiskHistory::new(100, 0.05));
}

impl RiskHistory {
    pub fn new(max_size: usize, decay_factor: f64) -> Self {
        Self { window: VecDeque::new(), _decay_factor: decay_factor, max_size }
    }

    /// Add a new risk tree to the historical window.
    pub fn add_tree(&mut self, tree: RiskTree) {
        if self.window.len() >= self.max_size {
            self.prune_uninteresting();
        }
        self.window.push_back(tree);
    }

    /// Simple decay-based pruning of the oldest element.
    fn prune_uninteresting(&mut self) {
        if self.window.is_empty() {
            return;
        }
        let (idx, _) = self
            .window
            .iter()
            .enumerate()
            .map(|(i, tree)| {
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
                let avg = if count == 0 { 0.0 } else { sum / count as f64 };
                (i, avg)
            })
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap();
        self.window.remove(idx);
    }

    /// Blend historical trees with the current tree using averaging.
    pub fn blend_with_history(&self, current: &RiskTree) -> RiskTree {
        let mut sums: RiskTree = BTreeMap::new();
        let mut counts: BTreeMap<(String, String, String), usize> = BTreeMap::new();

        let iter = self.window.iter().chain(std::iter::once(current));

        for tree in iter {
            for (env, cmd_map) in tree {
                for (cmd, flag_map) in cmd_map {
                    for (flag, vec) in flag_map {
                        let entry = sums
                            .entry(env.clone())
                            .or_default()
                            .entry(cmd.clone())
                            .or_default()
                            .entry(flag.clone())
                            .or_insert_with(|| vec![0.0; vec.len()]);
                        for (i, v) in vec.iter().enumerate() {
                            if i < entry.len() {
                                entry[i] += v;
                            }
                        }
                        *counts.entry((env.clone(), cmd.clone(), flag.clone())).or_insert(0) += 1;
                    }
                }
            }
        }

        // Compute averages
        for ((env, cmd, flag), count) in counts {
            if let Some(env_map) = sums.get_mut(&env) {
                if let Some(cmd_map) = env_map.get_mut(&cmd) {
                    if let Some(vec) = cmd_map.get_mut(&flag) {
                        for v in vec.iter_mut() {
                            *v /= count as f64;
                        }
                    }
                }
            }
        }
        sums
    }

    /// Access historical window clone.
    pub fn history(&self) -> Vec<RiskTree> {
        self.window.iter().cloned().collect()
    }
}

/// Apply categorical weights to all risk vectors in a tree.
pub fn apply_weights(tree: &RiskTree, weights: &[f64]) -> RiskTree {
    let mut weighted: RiskTree = BTreeMap::new();
    for (env, cmd_map) in tree {
        for (cmd, flag_map) in cmd_map {
            for (flag, vec) in flag_map {
                let mut new_vec = Vec::with_capacity(vec.len());
                for (i, v) in vec.iter().enumerate() {
                    let w = weights.get(i).copied().unwrap_or(1.0);
                    new_vec.push(v * w);
                }
                weighted
                    .entry(env.clone())
                    .or_default()
                    .entry(cmd.clone())
                    .or_default()
                    .insert(flag.clone(), new_vec);
            }
        }
    }
    weighted
}

/// Load a risk tree from a CSV file with the format produced by `risk_csv.csv`.
pub fn load_risk_tree(path: &Path) -> anyhow::Result<RiskTree> {
    let content = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut tree: RiskTree = BTreeMap::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 4 {
            continue;
        }
        let env = fields[0].trim().to_string();
        let cmd = fields[1].trim().to_string();
        let flag = fields[2].trim().to_string();
        let mut vec = Vec::new();
        let metrics_end = 3 + DEFAULT_CATEGORY_WEIGHTS.len();
        for f in &fields[3..metrics_end.min(fields.len())] {
            if let Ok(num) = f.trim().parse::<f64>() {
                vec.push(num);
            }
        }
        tree
            .entry(env)
            .or_default()
            .entry(cmd)
            .or_default()
            .insert(flag, vec);
    }

    Ok(tree)
}

#[derive(Clone, Debug)]
pub struct ThreatDeliverable {
    pub historical: Vec<RiskTree>,
    pub projected: RiskTree,
    pub final_tree: RiskTree,
}

/// Generate deliverables based on the current tree and historical data.
pub fn generate_deliverables_with_weights(current: RiskTree, weights: &[f64]) -> ThreatDeliverable {
    let mut history = HISTORICAL_TREE.lock().expect("Failed to lock historical tree");
    history.add_tree(current.clone());
    let projected = history.blend_with_history(&current);
    let final_tree = apply_weights(&projected, weights);
    ThreatDeliverable {
        historical: history.history(),
        projected,
        final_tree,
    }
}

/// Convenience wrapper using [`DEFAULT_CATEGORY_WEIGHTS`].
pub fn generate_deliverables(current: RiskTree) -> ThreatDeliverable {
    generate_deliverables_with_weights(current, &DEFAULT_CATEGORY_WEIGHTS)
}

/// Convert a `RiskTree` loaded from the CSV into a `ThreatMatrix`.
pub fn load_risk_matrix(path: &Path) -> anyhow::Result<ThreatMatrix> {
    let tree = load_risk_tree(path)?;
    let mut matrix = ThreatMatrix::new(100, 0.05);

    for env in tree.values() {
        for cmd in env.values() {
            for (flag, vec) in cmd {
                let score = if vec.is_empty() { DEFAULT_RISK_SCORE } else { vec.iter().sum::<f64>() / vec.len() as f64 };
                matrix.add_assessment(ThreatAssessment::new(score, score, vec![flag.clone()]));
            }
        }
    }

    Ok(matrix)
}

