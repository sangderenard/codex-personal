# codex_execpolicy

The goal of this library is to classify a proposed [`execv(3)`](https://linux.die.net/man/3/execv) command into one of the following states:

- `safe` The command is safe to run (\*).
- `match` The command matched a rule in the policy, but the caller should decide whether it is safe to run based on the files it will write.
- `forbidden` The command is not allowed to be run.
- `unverified` The safety cannot be determined: make the user decide.

## Supported Shells

The policy covers commands in the following shell environments, which
matches the list supported by the translation crate:

- CMD
- PowerShell
- Generic API
- Dummy (some are not implemented).
- macOS (Seatbelt)
- Linux (Landlock)
- Windows Subsystem for Linux (WSL)


(\*) Whether an `execv(3)` call should be considered "safe" often requires additional context beyond the arguments to `execv()` itself. For example, if you trust an autonomous software agent to write files in your source tree, then deciding whether `/bin/cp foo bar` is "safe" depends on `getcwd(3)` for the calling process as well as the `realpath` of `foo` and `bar` when resolved against `getcwd()`.
To that end, rather than returning a boolean, the validator returns a structured result that the client is expected to use to determine the "safety" of the proposed `execv()` call.

For example, to check the command `ls -l foo`, the checker would be invoked as follows:

```shell
cargo run -- check ls -l foo | jq
```

It will exit with `0` and print the following to stdout:

```json
{
  "result": "safe",
  "match": {
    "program": "ls",
    "flags": [
      {
        "name": "-l"
      }
    ],
    "opts": [],
    "args": [
      {
        "index": 1,
        "type": "ReadableFile",
        "value": "foo"
      }
    ],
    "system_path": ["/bin/ls", "/usr/bin/ls"]
  }
}
```

Of note:

- `foo` is tagged as a `ReadableFile`, so the caller should resolve `foo` relative to `getcwd()` and `realpath` it (as it may be a symlink) to determine whether `foo` is safe to read.
- While the specified executable is `ls`, `"system_path"` offers `/bin/ls` and `/usr/bin/ls` as viable alternatives to avoid using whatever `ls` happens to appear first on the user's `$PATH`. If either exists on the host, it is recommended to use it as the first argument to `execv(3)` instead of `ls`.

Further, "safety" in this system is not a guarantee that the command will execute successfully. As an example, `cat /Users/mbolin/code/codex/README.md` may be considered "safe" if the system has decided the agent is allowed to read anything under `/Users/mbolin/code/codex`, but it will fail at runtime if `README.md` does not exist. (Though this is "safe" in that the agent did not read any files that it was not authorized to read.)

## Policy

The default policy is produced dynamically from [`risk_csv.csv`](./src/risk_csv.csv).
Each row in this CSV describes a command and its threat metrics. When the
policy watcher loads the file, it feeds these vectors through the threat
evaluation pipeline to generate Starlark rules. Commands deemed risky by the
aggregator are forbidden, while the rest are allowed via a generic
`define_program` rule that accepts unverified arguments. This means there is no
static `default.policy` in the repository—the policy is always derived from the
CSV at runtime.

The system uses [Starlark](https://bazel.build/rules/language) because it allows
macros without compromising safety or reproducibility. (Under the hood we use
[`starlark-rust`](https://github.com/facebook/starlark-rust).)

`PolicyWatcher` keeps the parsed threat vectors in memory. Its methods allow
callers to query the overall risk score or raw vector for a command at runtime.

The integrity of the generated policy is verified [via unit tests](./tests). The
CLI also supports a `--policy` option to load an alternative `.policy` file for
ad-hoc testing.

## Output Type: `match`

Going back to the `cp` example, because the rule matches an `ARG_WFILE`, it will return `match` instead of `safe`:

```shell
cargo run -- check cp src1 src2 dest | jq
```

If the caller wants to consider allowing this command, it should parse the JSON to pick out the `WriteableFile` arguments and decide whether they are safe to write:

```json
{
  "result": "match",
  "match": {
    "program": "cp",
    "flags": [],
    "opts": [],
    "args": [
      {
        "index": 0,
        "type": "ReadableFile",
        "value": "src1"
      },
      {
        "index": 1,
        "type": "ReadableFile",
        "value": "src2"
      },
      {
        "index": 2,
        "type": "WriteableFile",
        "value": "dest"
      }
    ],
    "system_path": ["/bin/cp", "/usr/bin/cp"]
  }
}
```

Note the exit code is still `0` for a `match` unless the `--require-safe` flag is specified, in which case the exit code is `12`.

## Output Type: `forbidden`

It is also possible to define a rule that, if it matches a command, should flag it as _forbidden_. For example, we do not want agents to be able to run `applied deploy` _ever_, so we define the following rule:

```python
define_program(
    program="applied",
    args=["deploy"],
    forbidden="Infrastructure Risk: command contains 'applied deploy'",
    should_match=[
        ["deploy"],
    ],
    should_not_match=[
        ["lint"],
    ],
)
```

Note that for a rule to be forbidden, the `forbidden` keyword arg must be specified as the reason the command is forbidden. This will be included in the output:

```shell
cargo run -- check applied deploy | jq
```

```json
{
  "result": "forbidden",
  "reason": "Infrastructure Risk: command contains 'applied deploy'",
  "cause": {
    "Exec": {
      "exec": {
        "program": "applied",
        "flags": [],
        "opts": [],
        "args": [
          {
            "index": 0,
            "type": {
              "Literal": "deploy"
            },
            "value": "deploy"
          }
        ],
        "system_path": []
      }
    }
  }
}
```
