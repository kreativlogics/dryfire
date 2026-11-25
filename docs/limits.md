# What a replay can and cannot tell you

dryfire answers "what would this guard have decided for each call I made?". That is close to, but not the same as,
"what would have happened with this guard on". The differences:

## Each call is judged on its own

Every distinct past call runs in a fresh temp folder with a fresh HOME, and identical calls are judged once and
counted as often as they happened. So:

- **Hooks that remember earlier calls** (rate limits, "the third push in a row", session state kept in a file) never
  see that history and decide as if each call were the first. `tests/test_cli.py` keeps this as a known miss.
- **Order is lost.** With a guard on, a block changes what the agent does next; the replay only sees what it did
  without the guard. Counts after the first block in a session are an estimate of friction, not a forecast.
- **`updatedInput` chains** are not followed: a hook that rewrites a call is counted as "modified", and the rewritten
  call is not replayed through the other guards.

## The world is not the one the call ran in

- **The working folder is a temp folder**, not the folder the call was made in. A hook that looks at the real
  repository (current branch, staged files, a lock file) sees an empty folder. Also kept as a known miss.
- **Your home folder is hidden** under the macOS sandbox, apart from the hook's own files, its interpreter and paths
  you allow with `allow_read`. A hook that reads its own config from `~` gets an error unless you allow that path.
- **No network** under the macOS sandbox. A hook that calls a service errors.
- **Time is now**, not when the call was made. Rules about working hours or dates decide by today.
- **The environment is clean.** Variables a hook expects from your shell are missing unless they are plugin options.

Errors are counted apart from blocks, so a hook that cannot run in the sandbox shows up as errors, not as a quiet
guard: the headline says how many, and warns when they are more than 10% of its calls. A hook that times out on 8
calls in a row (or fails on 50) is stopped, and the calls left are not replayed. If a hook needs one of these things, the honest result is the error count; loosening the sandbox (`env`)
gives it your environment variables back but still not your files or history.

## What is read

- Only PreToolUse is replayed. Other hook events (PostToolUse, UserPromptSubmit, Stop, ...) are not.
- Calls come from assistant `tool_use` blocks in `~/.claude/projects/**/*.jsonl` and `$CLAUDE_CONFIG_DIR/projects`
  (plus `transcript_roots`). Calls Claude Code never recorded, or transcripts you deleted, are not there.
- Hooks and settings are detected under `~/.claude` and the project's `.claude` folder; `detect` does not look in
  `$CLAUDE_CONFIG_DIR` for settings. Pass such a hook with `--hook` instead.
- A transcript's permission mode is the one last recorded before the call. Use `--permission-mode as-recorded` to send
  it; the default sends `default`.
- Very large tool inputs are skipped and counted, and unreadable lines are counted, in the report's Run section.
- A run with hooks reads the transcripts twice (counts first, then the inputs of the calls kept). A call whose
  transcript changed in between is left out, with a note.

## Platforms

- **macOS**: full sandbox (`sandbox-exec`).
- **Linux**: temp HOME, temp folders and a clean environment only; there is no OS-level sandbox in v0.1, the report
  says so, and `sandbox: required` refuses to run hooks. A Linux sandbox (bubblewrap) is planned.
- **Windows**: not supported (process groups and POSIX pipes).

## Formats

destructive_command_guard and cc-safety-net rules are evaluated by dryfire itself, following each tool's documented
behaviour. Where dryfire's reading differs from the real tool, [adapters.md](adapters.md) says how. To be exact,
replay the tool's own binary as a hook (`--hook`), which needs approval like any hook.

## Not in v0.1

- Mining rules from your history (which commands you corrected or refused) is planned for v0.2.
- A Linux OS sandbox.
