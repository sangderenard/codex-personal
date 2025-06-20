use std::collections::HashSet;
use lazy_static::lazy_static;

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

pub fn is_internal_command(command: &str) -> bool {
    INTERNAL_COMMANDS.contains(command)
}
