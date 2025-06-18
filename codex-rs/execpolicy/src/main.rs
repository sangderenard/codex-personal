use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use codex_execpolicy::{ExecCall, ExecArg as LibExecArg};
use codex_execpolicy::MatchedExec;
use codex_execpolicy::Policy;
use codex_execpolicy::PolicyParser;
use codex_execpolicy::ValidExec;
use codex_execpolicy::get_default_policy;
use serde::Deserialize;
use serde::Serialize;
use serde::de;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use log::debug;
use lazy_static::lazy_static;


const MATCHED_BUT_WRITES_FILES_EXIT_CODE: i32 = 12;
const MIGHT_BE_SAFE_EXIT_CODE: i32 = 13;
const FORBIDDEN_EXIT_CODE: i32 = 14;
const OVERSIGHT_DENIAL_EXIT_CODE: i32 = 15;

const TOKENS_PER_MINUTE: usize = 30_000;
const REQUESTS_PER_MINUTE: usize = 500;
const RISK_THRESHOLD: usize = 100; // Example threshold, adjust as needed

#[derive(Parser, Deserialize, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// If the command fails the policy, exit with 13, but print parseable JSON
    /// to stdout.
    #[clap(long)]
    pub require_safe: bool,

    /// Path to the policy file.
    #[clap(long, short = 'p')]
    pub policy: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Debug, Deserialize, Subcommand)]
pub enum Command {
    /// Checks the command as if the arguments were the inputs to execv(3).
    Check {
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Checks the command encoded as a JSON object.
    #[clap(name = "check-json")]
    CheckJson {
        /// JSON object with "program" (str) and "args" (list[str]) fields.
        #[serde(deserialize_with = "deserialize_from_json")]
        exec: MainExecArg,
    },
}

fn prefilter_command(_exec: &LibExecArg) -> bool {
    let risk_score = current_risk_score();
    if risk_score > RISK_THRESHOLD {
        eprintln!("Command rejected by prefilter: risk score too high");
        return false;
    }
    true
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let policy = match args.policy {
        Some(policy) => {
            let policy_source = policy.to_string_lossy().to_string();
            let unparsed_policy = std::fs::read_to_string(policy)?;
            let parser = PolicyParser::new(&policy_source, &unparsed_policy);
            parser.parse()
        }
        None => get_default_policy(),
    };
    let policy = policy.map_err(|err| err.into_anyhow())?;

    let exec = match args.command {
        Command::Check { command } => match command.split_first() {
            Some((first, rest)) => LibExecArg {
                program: first.to_string(),
                args: rest.iter().map(|s| s.to_string()).collect(),
            },
            None => {
                eprintln!("no command provided");
                std::process::exit(1);
            }
        },
        Command::CheckJson { exec } => exec.0, // Unwrap the newtype
    };

    if !prefilter_command(&exec) {
        std::process::exit(FORBIDDEN_EXIT_CODE);
    }

    let (output, exit_code) = check_command(&policy, exec, args.require_safe);
    let json = serde_json::to_string(&output)?;
    println!("{}", json);
    std::process::exit(exit_code);
}

lazy_static! {
    static ref LAST_EXECUTION: Mutex<Instant> = Mutex::new(Instant::now());
    static ref EXECUTION_TIMES: Mutex<VecDeque<Instant>> = Mutex::new(VecDeque::new());
    static ref REQUEST_COUNT: Mutex<usize> = Mutex::new(0);
}

enum RateLimitMode {
    Tokens,
    Requests,
}

fn enforce_rate_limit(mode: RateLimitMode, used: usize) {
    match mode {
        RateLimitMode::Tokens => enforce_rate_limit_internal(used, TOKENS_PER_MINUTE, 1_440_000),
        RateLimitMode::Requests => enforce_rate_limit_internal(used, REQUESTS_PER_MINUTE, 720_000),
    }
}

fn enforce_rate_limit_internal(_used: usize, per_minute: usize, per_day: usize) {
    let mut execution_times = EXECUTION_TIMES.lock().unwrap();
    let now = Instant::now();

    // Remove outdated entries (older than 1 minute or 1 day)
    let one_minute_ago = now - Duration::from_secs(60);
    let one_day_ago = now - Duration::from_secs(86400);
    execution_times.retain(|&time| time >= one_day_ago);

    // Calculate usage in the last minute and day
    let last_minute_usage = execution_times
        .iter()
        .filter(|&&time| time >= one_minute_ago)
        .count();
    let last_day_usage = execution_times.len();

    // Determine the required delay to stay within limits
    let mut required_delay = Duration::ZERO;
    if last_minute_usage >= per_minute {
        let oldest_in_minute = execution_times
            .iter()
            .find(|&&time| time >= one_minute_ago)
            .unwrap();
        required_delay = (*oldest_in_minute + Duration::from_secs(60)) - now;
    }
    if last_day_usage >= per_day {
        let oldest_in_day = execution_times.front().unwrap();
        required_delay = required_delay.max((*oldest_in_day + Duration::from_secs(86400)) - now);
    }

    // Sleep for the required delay
    if !required_delay.is_zero() {
        std::thread::sleep(required_delay);
    }

    // Record the current execution time
    execution_times.push_back(now);
}

fn track_request_count() {
    let mut request_count = REQUEST_COUNT.lock().unwrap();
    *request_count += 1;
    debug!("Total requests made: {}", *request_count);
}

fn check_command(
    policy: &Policy,
    lib_exec_arg: LibExecArg,
    require_safe: bool,
) -> (Output, i32) {
    // Track the number of requests
    track_request_count();

    // Example usage and limits (to be replaced with actual logic)
    let mode = RateLimitMode::Requests; // Example: switch to RateLimitMode::Tokens if needed
    let used = 1; // Placeholder for usage estimation logic


    // Enforce rate limit before proceeding
    enforce_rate_limit(mode, used);

    let exec_call = ExecCall { program: lib_exec_arg.program, args: lib_exec_arg.args };

    // Call policy.check as normal
    match policy.check(&exec_call) {
        Ok(MatchedExec::Match { exec }) => {
            let exit_code = if require_safe {
                MATCHED_BUT_WRITES_FILES_EXIT_CODE
            } else {
                0
            };
            (Output::Match { r#match: exec }, exit_code)
        }
        Ok(MatchedExec::Overridden { reason }) => { // This variant was missing a require_safe check, assuming OVERSIGHT_DENIAL_EXIT_CODE is always appropriate
            let exit_code = OVERSIGHT_DENIAL_EXIT_CODE;
            (Output::Overridden { reason }, exit_code)
        }
        Ok(MatchedExec::Forbidden { reason, cause }) => {
            let exit_code = if require_safe { FORBIDDEN_EXIT_CODE } else { 0 };
            (Output::Forbidden { reason, cause }, exit_code)
        }
        Err(err) => {
            let exit_code = if require_safe { MIGHT_BE_SAFE_EXIT_CODE } else { 0 };
            (Output::Unverified { error: err }, exit_code)
        }
    }
}
#[derive(Debug, Serialize)]
#[serde(tag = "result")]
pub enum Output {
    /// The command is verified as safe.
    #[serde(rename = "safe")]
    Safe { r#match: ValidExec },

    /// The command has matched a rule in the policy, but the caller should
    /// decide whether it is "safe" given the files it wants to write.
    #[serde(rename = "match")]
    Match { r#match: ValidExec },

    /// The user is forbidden from running the command.
    #[serde(rename = "forbidden")]
    Forbidden {
        reason: String,
        cause: codex_execpolicy::Forbidden,
    },

    /// The command is overridden by policy, requiring oversight.
    #[serde(rename = "overridden")]
    Overridden { reason: String },

    /// The safety of the command could not be verified.
    #[serde(rename = "unverified")]
    Unverified { error: codex_execpolicy::Error },
}

// Newtype wrapper for ExecArg to satisfy orphan rules for FromStr
#[derive(Clone, Debug, Deserialize)]
pub struct MainExecArg(LibExecArg);

impl FromStr for MainExecArg {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lib_exec_arg: LibExecArg = serde_json::from_str(s)?;
        Ok(MainExecArg(lib_exec_arg))
    }
}

fn deserialize_from_json<'de, D>(deserializer: D) -> Result<MainExecArg, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let lib_exec_arg: LibExecArg = serde_json::from_str(&s)
        .map_err(|e| serde::de::Error::custom(format!("JSON parse error: {e}")))?;
    Ok(MainExecArg(lib_exec_arg))
}



fn current_risk_score() -> usize {
    // Placeholder for actual risk assessment logic
    // This function should return a risk score based on the command and environment
    0
}
