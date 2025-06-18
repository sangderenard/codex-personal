export enum SandboxType {
  NONE = "none",
  MACOS_SEATBELT = "macos.seatbelt",
  LINUX_LANDLOCK = "linux.landlock",
  BLACK_BOX = "black.box",
  DUMMY_SANDBOX = "dummy.sandbox",
  WIN64_CMD = "win64.cmd",
  WIN64_PS = "win64.ps",
  API = "api",
}

// ---------------------------------------------------------------------------
// IMPORTANT: Future Work Stub
// ---------------------------------------------------------------------------
// The `SandboxType` enum currently includes foundational sandbox types like
// `MACOS_SEATBELT` and `LINUX_LANDLOCK`. We aim to expand this with:
//
// 1. A `BLACK_BOX` sandbox type that integrates with a REST API for bidirectional
//    control of Python execution, allowing LLM-interpreted programmatic actions.
// 2. A `DUMMY_SANDBOX` type that acts as a placeholder for testing and simulating
//    execution without invoking actual commands.
//
// These additions will enhance flexibility and security in tool execution.
// ---------------------------------------------------------------------------

export type ExecInput = {
  cmd: Array<string>;
  workdir: string | undefined;
  timeoutInMillis: number | undefined;
};

/**
 * Result of executing a command. Caller is responsible for checking `code` to
 * determine whether the command was successful.
 */
export type ExecResult = {
  stdout: string;
  stderr: string;
  exitCode: number;
};

/**
 * Value to use with the `metadata` field of a `ResponseItem` whose type is
 * `function_call_output`.
 */
export type ExecOutputMetadata = {
  exit_code: number;
  duration_seconds: number;
};
