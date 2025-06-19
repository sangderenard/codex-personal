use std::path::PathBuf;

use super::exec::spawn_command_under_sandbox;
use super::protocol::SandboxPolicy;

use std::collections::HashMap;
use super::StdioPolicy;

use anyhow::{
    Result,
};
pub fn black_box_shell_function(
    command: Vec<String>,
    cwd: PathBuf,
    env: HashMap<String, String>,
    stdio_policy: StdioPolicy,
) -> anyhow::Result<()> {
    // Implementation for the shell function in the black_box module
    Ok(())
}

pub async fn spawn_command_under_black_box(
    command: BlackBoxCommand,
) -> anyhow::Result<()> {
    let BlackBoxCommand {
        full_auto,
        sandbox,
        config_overrides,
        command,
    } = command;

    spawn_command_under_sandbox(
        full_auto,
        sandbox,
        command,
        config_overrides,
        SandboxPolicy::BlackBox,
    )
    .await
}
