# dryfire reference

dryfire v0.1. Every command below is `python3 plugins/dryfire/scripts/cli.py <command>` (the skills use
`${CLAUDE_PLUGIN_ROOT}/scripts/cli.py`). The settings tool is `scripts/cfgtool.py`.

## Commands

### detect

Lists, without running anything:

- transcript folders (`~/.claude/projects`, and `$CLAUDE_CONFIG_DIR/projects` when set) with file count and size;
- whether the macOS sandbox is available;
- PreToolUse command hooks in `~/.claude/settings.json`, `~/.claude/settings.local.json`, the project's
  `.claude/settings.json` and `.claude/settings.local.json`, the managed settings files, and the `hooks/hooks.json`
  of each installed plugin. Each has an ID (`settings:user#0.0`, `plugin:name@market#0.1`) for `--detected`, and
  shows whether it is approved;
- checkrein installs, destructive_command_guard packs under `~/.config/dcg`, and cc-safety-net configs.

### scan

Counts past tool calls in the window by tool and by project folder. Shows no command text; tool names are
masked like everything else, since they come from transcripts.

### replay

Replays the chosen guards against past calls and prints a report.

Guards (at least one):

| Flag | Guard | Runs code |
|---|---|---|
| `--pack FILE` | a dryfire JSON rule pack (format below) | no |
| `--dcg` / `--dcg-pack FILE` | destructive_command_guard packs ([adapters](adapters.md#destructive_command_guard)) | no |
| `--safetynet [PATH]` | cc-safety-net rulebooks ([adapters](adapters.md#cc-safety-net)) | no |
| `--hook CMD` (`--matcher`, `--plugin-root`) | any PreToolUse hook command | yes, after approval |
| `--detected ID` or `all` | a hook found by `detect` | yes, after approval |
| `--use NAME` or `all` | a named hook from dryfire's settings | yes, after approval |
| `--checkrein [PATH]` (`--checkrein-preset`, `--checkrein-config`) | checkrein's hook at one or more presets | yes, after approval |

Run options:

| Flag | Meaning |
|---|---|
| `--preset quick\|standard\|deep` | window and call limit from a preset |
| `--window-days N` | days of history (1 to 3650) |
| `--scope all\|project` | every project's transcripts, or only calls made in this project |
| `--max-calls N` | most distinct calls a hook runs on (most recent kept); rule packs always see every call. With hooks, transcripts are read twice: once for counts, once for the inputs of the calls kept, so memory stays small |
| `--timeout N` | seconds per hook call; can only lower the configured value |
| `--sandbox env\|auto\|required` | can only make the sandbox stricter |
| `--workers N` | hooks run in parallel |
| `--samples N` | sample calls shown per rule (0 to 20) |
| `--permission-mode MODE` | `permission_mode` sent to hooks, or `as-recorded` |
| `--out FILE` (`--force`) | write the report to a file and print only the headline |
| `--json` | JSON instead of Markdown |
| `--quiet` | no progress lines |

`--out` refuses a path inside dryfire's data or plugin folders (symlinks resolved), and an existing file unless
`--force` is given.

### approve

```text
approve --hook CMD [--matcher M] [--plugin-root DIR]   # or --detected ID, --use NAME, --checkrein [PATH]
approve --list
approve --revoke FINGERPRINT|all                        # 8 or more characters of the fingerprint
```

An approval is the sha256 of the hook's command, arguments and plugin folder, the sha256 of each existing file the
command names after expansion (the program each part of the command starts with, found on `PATH`, and its script, also inside `bash -c "..."`, after `cd DIR &&`, after `;` and when set in a variable first, as in `X=/dir/g.sh; sh $X`, `D=/dir; sh "$D/g.sh"` or `D=/dir; cd "$D" && sh g.sh`, quoted paths on a line Python's shell reader cannot read included; files the command only writes to through `>`, `>>` or `&>` are left out, unless the line also has a quoted or escaped `>`; every such file is hashed, up to 256 MB in all, and a hook naming more than that cannot be approved), and,
for a hook from a project's settings file, that project. Editing the script therefore needs a new approval; files
the script imports or reads are not covered. Matcher, options and the `if` filter are not part of it, because they
only decide which calls reach the hook. `--list` shows commands masked.

Paths are pinned before the fingerprint is taken: a relative path in `--hook` is made absolute from the current
folder, and a relative path or `$CLAUDE_PROJECT_DIR` in a project's hook from that project, because the hook itself
runs in a temp folder. A path is pinned only up to the first `cd` or `pushd` (after one, relative paths mean
something else); a quoted path with spaces stays one word, and words that look like shell code (quotes, `$`,
globs, separators) are left as they are.

### Common flags

`--data DIR` (dryfire's data folder; default `$CLAUDE_PLUGIN_DATA`, else `~/.claude/dryfire`), `--project DIR`
(default `$CLAUDE_PROJECT_DIR`, else the current folder), `--json`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | an error (bad flag value, unreadable file, no guard chosen, no transcripts) |
| 2 | usage error (unknown flag, no command) |
| 3 | a hook is not approved; the message gives the exact `approve` command |
| 4 | `sandbox: required` on a system without the OS sandbox |

## Rule packs

A dryfire rule pack is a JSON file for drafting a rule before writing a hook:

```json
{
  "version": 1,
  "name": "my-draft",
  "rules": [
    {"id": "no-force-push", "pattern": "git\\s+push\\b.*--force", "decision": "deny",
     "reason": "Force push rewrites shared history", "scope": "segment"},
    {"id": "env-files", "tool": "Write|Edit", "field": "file_path", "pattern": "\\.env$", "decision": "ask"}
  ]
}
```

| Field | Default | Meaning |
|---|---|---|
| `id` | required | unique within the pack; shown in the report |
| `pattern` | required | Python regular expression, searched (not anchored) |
| `decision` | `deny` | `deny` or `ask` |
| `reason` | the id | shown in the report |
| `tool` | `Bash` | a hook matcher: tool name, `A\|B`, a regex, or `*` |
| `field` | `command` | the `tool_input` field matched |
| `ignore_case` | `false` | match without regard to case |
| `scope` | `command` | `command`: the whole field. `segment`: each simple command of a Bash command after wrappers such as `sudo` and `env` are removed |

The first matching rule decides. A rule that does not compile, or repeats an id, is reported and skipped.

## Settings

Settings are layered, later layers on top:

1. built-in defaults;
2. the preset's values (`window_days`, `max_calls`);
3. the plugin settings screen (`preset`, `sandbox`, `timeout_seconds`);
4. **yours**: `config.json` in the data folder (`/dryfire:config set ...`, which asks you first);
5. **the project's** `.dryfire/config.json`; a project hook named like one of yours becomes `project:NAME`;
6. run flags.

Layers 3, 5 and 6 can only tighten safety keys. The settings-screen values reach dryfire as `CLAUDE_PLUGIN_OPTION_*`
variables in the environment of whoever runs it, which can be the agent; the project file can come from a
repository you cloned; and run flags are typed by whoever runs the command. A value that would loosen is ignored
and the report says so. To loosen a safety key (for example `sandbox: env`), set it in your `config.json`.

| Key | Kind | Default | Meaning |
|---|---|---|---|
| `preset` | preference | `standard` | `quick` 7 days / 2,000 distinct calls; `standard` 30 / 20,000; `deep` 365 / 100,000 |
| `window_days` | preference | from preset | days of history (1 to 3650) |
| `max_calls` | preference | from preset | most distinct calls a hook runs on |
| `workers` | preference | CPUs, at most 8 | hooks in parallel (1 to 32) |
| `samples` | preference | 3 | sample calls per rule (0 to 20) |
| `permission_mode` | preference | `default` | sent to hooks; `as-recorded` uses the transcript's |
| `timeout_seconds` | safety, lower only | 10 | per hook call (1 to 120) |
| `sandbox` | safety, stricter only | `auto` | `env` < `auto` < `required` |
| `scope` | safety, narrower only | `all` | `all` or `project` |
| `redact_home` | safety, on only | `true` | show the home folder as `~` |
| `redact_patterns` | safety, added up | `[]` | extra regular expressions masked everywhere; a project's pattern whose shape can backtrack for minutes (a repeated group holding a repeat, an optional part or alternatives, such as `(a+)+` or `(a?){25}`, more than two wide repeats such as `a*`, `a+` or `[ab]{1,200}`, or more than four repeats of any kind such as `a?`), and one in verbose mode (`(?x)`) or with a comment group (`(?#...)`), is ignored with a note |
| `transcript_roots` | yours only | `[]` | extra transcript folders; ignored in a project file |
| `allow_read` | needs approval in a project | `[]` | home-folder paths a hook may read inside the macOS sandbox |
| `hooks` | needs approval | `{}` | named hooks: `{name: {command or args, matcher, plugin_root, options, if, on_failure}}`; `if` is one permission rule as in Claude Code (`Bash(git push:*)`, `Edit(src/**)`), and only calls it matches reach the hook |

Unknown keys, wrong types and values that look like secrets are refused with the file, the key, what was expected
and the nearest key name. `cfgtool.py explain KEY` prints the same descriptions.

Settings tool commands: `show [--json]`, `explain [KEY]`, `set KEY VALUE [--project-layer]`,
`unset KEY [--project-layer]`, `init [--project-layer]`, `approve allow_read`, `doctor`.

## What a hook under test sees

For each distinct past call, dryfire runs the hook once with a PreToolUse payload on stdin:
`session_id`, `transcript_path` (a file in the temp folder), `cwd` (a temp project folder), `permission_mode`,
`hook_event_name: "PreToolUse"`, `tool_name`, `tool_input`, `tool_use_id`.

- `HOME`, `TMPDIR` and `CLAUDE_PROJECT_DIR` point into a fresh temp folder that is removed after the call. A hook
  with a plugin folder also gets `CLAUDE_PLUGIN_ROOT` (that folder) and `CLAUDE_PLUGIN_DATA` (in the temp folder).
- The environment is rebuilt from `PATH` and locale variables only, plus `CLAUDE_PLUGIN_OPTION_*` values from the
  hook's `options` and a `DRYFIRE_RUN` marker (see below).
- On macOS (`sandbox: auto` or `required`) the hook runs under `sandbox-exec`: network denied, writes outside the
  temp folder denied, reads in the home folder denied except the hook's own script and plugin folders, its
  interpreter and `allow_read` paths, and system services that would read or write for it (preferences,
  pasteboard, keychain, Launch Services, Spotlight, file coordination) denied. A version-manager shim gets its
  manager's folder readable; the report notes when a hook starts with one.
- The call is killed with its whole process group at the time limit or once it exits. A process that left the
  group (started in a new session, as daemons are) is found by the `DRYFIRE_RUN` marker in its environment when
  that hook's replay ends, killed, and named in the guard's notes. Output beyond 256 KB is cut.
- A hook that times out on 8 calls in a row, or fails on 50 in a row, is stopped; the headline, the warning and
  the notes say how many calls were not replayed. Ctrl-C ends the hooks that are running at once.

The reply is read as Claude Code reads it: exit 2 blocks (stderr is the reason); JSON on stdout with
`hookSpecificOutput.permissionDecision` of `allow`, `ask`, `deny` or `defer` decides on any exit code; the older
`decision: block|approve` is understood; `continue: false` is counted as a stop, not a block; any other exit code,
a timeout or broken JSON is an error, reported apart from blocks. With `on_failure: block` an error counts as a
block. `updatedInput` is counted as "modified".

## The report

Markdown (default) or JSON (`--json`). Both start with a notice that the content is data from past sessions.

- **Headline** per guard: "would have blocked N of M of your commands (x%) and asked on K", plus ", but it failed
  or timed out on E" when it did, and "and was stopped before replaying S" when it was stopped. When more than 10%
  of its calls failed, or it was stopped, a warning follows: its numbers undercount what it would block. With
  `--out`, the warning is printed with the headline too.
- **Run**: window, active days, sandbox used, calls and distinct calls, transcript files read and skipped, and notes
  (settings that were ignored, lines that could not be read).
- **Per guard**: counts by decision; by rule or reason, with calls, share, rate per active day, first and last date
  and masked samples; by tool; by project folder.
- **Combined** (two or more guards): the merged decision, deny > defer > ask > allow.
- **Where the guards disagree**: calls one guard blocks and another lets through, with samples.

JSON top level: `notice`, `run` (with `reader` counters and `notes`), `calls`, `distinct_calls`, `active_days`,
`all_bash`, `guards[]` (each with `name`, `kind`, `label`, `seen`, `counts`, `rules`, `by_tool`, `by_project`,
`notes`), and `combined` and `differences` when more than one guard ran.
