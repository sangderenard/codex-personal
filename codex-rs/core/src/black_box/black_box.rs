use std::collections::HashMap;
use std::path::PathBuf;

use crate::config_types::ShellEnvironmentPolicy;
use tokio::process::{Child, Command};
use std::process::Stdio;
use crate::protocol::SandboxPolicy;
use crate::exec::StdioPolicy;
use crate::utils::spawn_wrapper::wrap_spawn_result;
use translation::command_translation::CommandTranslationResult;
use anyhow::Result;
use internal_commands::get_internal_command_function;

pub fn black_box_shell_function(
    _command: Vec<String>,
    _cwd: PathBuf,
    _env: HashMap<String, String>,
    _stdio_policy: StdioPolicy,
) -> Result<()> {
    // Implementation for the shell function in the black_box module
    Ok(())
}

pub const CODEX_BLACK_BOX_SANDBOX_STATE: i32 = 0;

pub static mut BLACK_BOX_SANDBOX_ENABLED: bool = false;

pub fn enable_black_box_sandbox() {
    unsafe { BLACK_BOX_SANDBOX_ENABLED = true; }
}

pub fn disable_black_box_sandbox() {
    unsafe { BLACK_BOX_SANDBOX_ENABLED = false; }
}

pub fn is_black_box_sandbox_enabled() -> bool {
    unsafe { BLACK_BOX_SANDBOX_ENABLED }
}

fn spawn_internal_command_child(stdout: String, stderr: String) -> std::io::Result<Child> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("printf '%s' \"$OUT\"; printf '%s' \"$ERR\" >&2");
    cmd.env("OUT", stdout);
    cmd.env("ERR", stderr);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.spawn()
}

pub async fn spawn_command_under_black_box(
    command: Vec<String>,
    _sandbox_policy: SandboxPolicy,
    cwd: PathBuf,
    stdio_policy: StdioPolicy,
    _env: ShellEnvironmentPolicy,
    translation_result: Option<CommandTranslationResult>,
) -> std::io::Result<(Child, Option<CommandTranslationResult>)> {
    let packaged_command = if let Some(ref result) = translation_result {
        let mut packaged_command = vec![result.translated_command.clone().unwrap_or_else(|| command[0].clone())];
        packaged_command.extend(command.into_iter().skip(1));
        packaged_command
    } else {
        command
    };

    if let Some(internal_command_fn) = get_internal_command_function(&packaged_command[0]) {
        let result = internal_command_fn(&packaged_command[1..], cwd.clone())?;

        // Directly return the results of the internal command
        return Ok((Child::from_internal_results(result.stdout, result.stderr), translation_result));
    }

    let mut cmd = Command::new(&packaged_command[0]);
    cmd.args(&packaged_command[1..]);
    cmd.current_dir(cwd);

    match stdio_policy {
        StdioPolicy::RedirectForShellTool => {
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        StdioPolicy::Inherit => {
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
    }

    let (child, translation_result) = wrap_spawn_result(cmd.spawn(), translation_result)?;
    Ok((child, translation_result))
}
