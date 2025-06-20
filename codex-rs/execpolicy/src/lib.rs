#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#[macro_use]
extern crate starlark;

mod arg_matcher;
mod arg_resolver;
mod arg_type;
mod error;
mod exec_call;
mod execv_checker;
mod opt;
mod policy;
mod policy_parser;
pub mod policy_watcher;
pub mod threat_state;
mod program;
mod sed_command;
mod valid_exec;

pub use arg_matcher::ArgMatcher;
pub use arg_resolver::PositionalArg;
pub use arg_type::ArgType;
pub use error::Error;
pub use error::Result;
pub use exec_call::ExecCall;
pub use execv_checker::ExecvChecker;
pub use opt::Opt;
pub use policy::Policy;
pub use policy_parser::PolicyParser;
pub use policy_watcher::PolicyWatcher;
pub use threat_state::{ThreatLevel, ThreatState, ThreatStateWatcher};
pub use program::Forbidden;
pub use program::MatchedExec;
pub use program::NegativeExamplePassedCheck;
pub use program::PositiveExampleFailedCheck;
pub use program::ProgramSpec;
pub use sed_command::parse_sed_command;
pub use valid_exec::MatchedArg;
pub use valid_exec::MatchedFlag;
pub use valid_exec::MatchedOpt;
pub use valid_exec::ValidExec;

use once_cell::sync::OnceCell;


pub static DEFAULT_WATCHER: OnceCell<PolicyWatcher> = OnceCell::new();
pub fn get_default_policy() -> starlark::Result<Policy> {
    panic!("No default policy allowed. A watcher must be established.");
}

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ExecArg {
    pub program: String,

    #[serde(default)]
    pub args: Vec<String>,
}
