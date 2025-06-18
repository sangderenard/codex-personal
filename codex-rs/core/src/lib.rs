//! Core library for Codex.
pub mod exec_env;
pub mod config_types;
pub mod config;
pub mod protocol;
// Add other module declarations if needed, e.g.:
// pub mod codex;
// pub mod another_module;/// global feature flags and defaults
pub mod flags;

/// profiles of per-organization/OpenAI config
pub mod config_profile;

/// per-model/provider metadata
pub mod model_provider_info;