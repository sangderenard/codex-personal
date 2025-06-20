use std::collections::HashSet;
use lazy_static::lazy_static;

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
        println!("Interacting with dependency using setting: {}", setting);
        dependency.set_setting("example_setting", "new_value")?;
        Ok(())
    } else {
        Err(format!("Command '{}' is not internal", command))
    }
}
