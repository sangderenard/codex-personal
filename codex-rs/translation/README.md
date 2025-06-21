# Translation Crate

This crate provides basic command translations across operating systems. It loads mappings from `command_translations.json` at runtime and can normalize simple filesystem paths.

## Supported Shells

- CMD
- PowerShell
- Generic API
- Dummy (some are not implemented).
- macOS (Seatbelt)
- Linux (Landlock)
- Windows Subsystem for Linux (WSL)

These options mirror the sandbox implementations referenced in the
[risk policy documentation](../execpolicy/README.md).
