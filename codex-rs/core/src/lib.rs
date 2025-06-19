//! Core library for Codex.
pub mod exec_env;
pub mod config_types;
pub mod config;
pub mod protocol;
// Add other module declarations if needed, e.g.:
// pub mod codex;
// pub mod another_module;

/// High level Codex interface
pub mod codex;

/// Command execution utilities
pub mod exec;
pub mod client;
pub mod client_common;
pub mod conversation_history;
pub mod mcp_connection_manager;
pub mod mcp_tool_call;
pub mod models;
pub mod chat_completions;
pub mod openai_tools;
pub mod is_safe_command;
pub mod project_doc;
pub mod rollout;
pub mod safety;
pub mod user_notification;
pub mod util;
/// global feature flags and defaults
pub mod flags;
/// profiles of per-organization/OpenAI config
pub mod config_profile;

/// per-model/provider metadata
pub mod model_provider_info;

/// error types
pub mod error;

/// message history persistence
pub mod message_history;

/// OpenAI API key utilities
pub mod openai_api_key;

pub mod codex_wrapper;
pub mod black_box;
pub use client_common::model_supports_reasoning_summaries;

pub use model_provider_info::WireApi;
pub use codex::Codex;
pub use model_provider_info::ModelProviderInfo;
