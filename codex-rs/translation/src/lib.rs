pub mod command_translation;
use command_translation::CommandTranslator;
use once_cell::sync::OnceCell;

// Add any additional modules or exports here as needed.
pub static OPERATING_SHELL: OnceCell<String> = OnceCell::new();
pub static DEFAULT_TRANSLATOR: OnceCell<CommandTranslator> = OnceCell::new();
