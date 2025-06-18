use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;
use super::protocol::SandboxPolicy;
use super::exec_env::{spawn_command_under_api, StdioPolicy};

#[tokio::test]
async fn test_spawn_command_under_api() {
    let command = vec!["echo".to_string(), "Hello, World!".to_string()];
    let sandbox_policy = SandboxPolicy::default(); // Assuming a default implementation exists
    let cwd = PathBuf::from(".");
    let stdio_policy = StdioPolicy::RedirectForShellTool;
    let env = HashMap::new();

    let ctrl_c = Arc::new(Notify::new());

    match spawn_command_under_api(command, &sandbox_policy, cwd, stdio_policy, env).await {
        Ok(child) => {
            let output = child.wait_with_output().await.expect("Failed to wait for child process");
            assert!(output.status.success(), "Process did not exit successfully");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("Hello, World!"), "Unexpected output: {}", stdout);
        }
        Err(e) => {
            panic!("Failed to spawn command under API: {}", e);
        }
    }
}
