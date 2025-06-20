use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use lazy_static::lazy_static;

/// Return the `scripts` directory for the current crate.
fn scripts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate should have parent")
        .join("scripts")
}

// Define the internal commands
lazy_static! {
    static ref INTERNAL_COMMANDS: HashSet<&'static str> = {
        let mut commands = HashSet::new();
        commands.insert("codex_fetch_docs");
        commands.insert("codex_list_docs");
        commands.insert("codex_read_doc");
        commands.insert("codex_delete_doc");
        commands.insert("codex_update_doc");
        commands.insert("codex_create_doc");
        commands.insert("codex_system_exec");
        commands.insert("codex_reset_translator");
        commands.insert("codex_user_exec_dialog");
        commands.insert("codex_user_fork_exec");
        commands.insert("codex_help");
        commands.insert("codex_truncatoin_mode");
        commands.insert("codex_set_pallette");
        commands.insert("codex_set_sandbox_policy");
        commands.insert("codex_commands");
        commands
    };
}

// Function to check if a command is internal
pub fn is_internal_command(command: &str) -> bool {
    INTERNAL_COMMANDS.contains(command)
}

// Trait for external dependencies
pub trait ExternalDependency {
    fn get_setting(&self, key: &str) -> Result<String, String>;
    fn set_setting(&self, key: &str, value: &str) -> Result<(), String>;
}

// Function to interact with external dependencies
pub fn interact_with_dependency(
    command: &str,
    dependency: &dyn ExternalDependency,
) -> Result<(), String> {
    if is_internal_command(command) {
        let setting = dependency.get_setting("example_setting")?;
        
        dependency.set_setting("example_setting", "new_value")?;
        Ok(())
    } else {
        Err(format!("Command '{}' is not internal", command))
    }
}

/// Return a list of document file names available under the `scripts` directory.
pub fn codex_list_docs() -> std::io::Result<Vec<String>> {
    let mut docs = Vec::new();
    for entry in std::fs::read_dir(scripts_dir())? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                docs.push(name.to_string());
            }
        }
    }
    Ok(docs)
}

/// Read the contents of a document in the `scripts` directory.
pub fn codex_read_doc(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(scripts_dir().join(name))
}

/// Return all docs as a vector of `(name, contents)` tuples.
pub fn codex_fetch_docs() -> std::io::Result<Vec<(String, String)>> {
    let mut docs = Vec::new();
    for name in codex_list_docs()? {
        let contents = codex_read_doc(&name).unwrap_or_default();
        docs.push((name, contents));
    }
    Ok(docs)
}

/// Delete a document from the `scripts` directory.
pub fn codex_delete_doc(name: &str) -> std::io::Result<()> {
    std::fs::remove_file(scripts_dir().join(name))
}

/// Update (or create) a document with new contents.
pub fn codex_update_doc(name: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(scripts_dir().join(name), contents)
}

/// Create a new document with the provided contents.
pub fn codex_create_doc(name: &str, contents: &str) -> std::io::Result<()> {
    codex_update_doc(name, contents)
}

/// Execute a system command. This is a thin wrapper around `std::process::Command`.
pub fn codex_system_exec(cmd: &str, args: &[&str]) -> std::io::Result<Output> {
    Command::new(cmd).args(args).output()
}

/// Reset the command translator using the given shell.
pub fn codex_reset_translator(shell: &str) {
    translation::initialize(shell);
}

/// Placeholder for user execution dialog.
pub fn codex_user_exec_dialog() -> Result<(), String> {
    Err("user_exec_dialog is not implemented".to_string())
}

/// Placeholder for forking execution to the user.
pub fn codex_user_fork_exec() -> Result<(), String> {
    Err("user_fork_exec is not implemented".to_string())
}

/// Return a help string listing all internal commands.
pub fn codex_help() -> String {
    let mut cmds: Vec<&str> = INTERNAL_COMMANDS.iter().copied().collect();
    cmds.sort();
    format!("Available internal commands:\n{}", cmds.join("\n"))
}

/// Stub for enabling/disabling truncation mode.
pub fn codex_truncatoin_mode(_mode: &str) -> Result<(), String> {
    Ok(())
}

/// Stub for adjusting the palette.
pub fn codex_set_pallette(_pal: &str) -> Result<(), String> {
    Ok(())
}

/// Stub for adjusting sandbox policy.
pub fn codex_set_sandbox_policy(_policy: &str) -> Result<(), String> {
    Ok(())
}

/// Return the list of known internal commands.
pub fn codex_commands() -> Vec<&'static str> {
    INTERNAL_COMMANDS.iter().copied().collect()
}

/// Retrieve the function corresponding to an internal command string.
/// Returns `None` if the command is not internal.
pub fn get_internal_command_function(
    command: &str,
) -> Option<fn(args: &[String], cwd: PathBuf) -> std::io::Result<InternalCommandOutput>> {
    match command {
        "codex_fetch_docs" => Some(|_, _| {
            let docs = codex_fetch_docs()?;
            Ok(InternalCommandOutput {
                stdout: format!("{:?}", docs),
                stderr: String::new(),
            })
        }),
        "codex_list_docs" => Some(|_, _| {
            let docs = codex_list_docs()?;
            Ok(InternalCommandOutput {
                stdout: format!("{:?}", docs),
                stderr: String::new(),
            })
        }),
        "codex_read_doc" => Some(|args, _| {
            if let Some(name) = args.get(0) {
                let content = codex_read_doc(name)?;
                Ok(InternalCommandOutput {
                    stdout: content,
                    stderr: String::new(),
                })
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing document name"))
            }
        }),
        // ... Add other internal commands here ...
        _ => None,
    }
}

/// Struct to represent the output of an internal command.
pub struct InternalCommandOutput {
    pub stdout: String,
    pub stderr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_docs_returns_files() {
        let docs = codex_list_docs().expect("list docs");
        assert!(!docs.is_empty());
    }

    #[test]
    fn read_doc_works() {
        let docs = codex_list_docs().expect("list docs");
        let first = docs.first().expect("at least one doc");
        let content = codex_read_doc(first).expect("read doc");
        assert!(!content.is_empty());
    }

    #[test]
    fn commands_contains_help() {
        let cmds = codex_commands();
        assert!(cmds.contains(&"codex_help"));
    }
}
