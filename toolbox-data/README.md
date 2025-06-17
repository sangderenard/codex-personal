# Toolbox Threat Database Skeleton

This directory provides a compact sample dataset listing command-line options and their associated threat categories. The file `threat_db.csv` is optimized for ingestion by future tooling such as a hypothetical `toolbox.rs` module.

The CSV has the following columns in order:

```
shell,command,argument,system_damage,data_loss,privilege_escalation,denial_of_service,code_injection
```

Each row lists a shell (bash, cmd, or PowerShell), a command, one argument string, and five risk dimensions. The risk columns contain float values from `0.0` (no risk) to `1.0` (maximum risk) expressing the relative intensity of each threat. This dataset is intentionally small and ready for future expansion.
The dataset now includes multiple entries for the same command to capture risk with and without specific options. Argumentless variants are rated so future tooling can calculate baseline threat levels. Use this as a starting point for expansion.
