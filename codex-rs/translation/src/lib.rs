pub mod command_translation;
pub use command_translation::CommandTranslator;
use once_cell::sync::OnceCell;
use std::sync::Mutex;

pub static OPERATING_SHELL: OnceCell<String> = OnceCell::new();
pub static DEFAULT_TRANSLATOR: OnceCell<Mutex<CommandTranslator>> = OnceCell::new();

/// Initialize the global translator using the provided risk CSV and shell name.
pub fn initialize(shell: &str) {
    OPERATING_SHELL.set(shell.to_string()).ok();
    DEFAULT_TRANSLATOR.set(Mutex::new(CommandTranslator::new())).ok();
}
