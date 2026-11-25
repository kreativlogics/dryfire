# Adapters

Rule formats dryfire reads, what it supports, and where its reading differs from the tool itself. Anything a pack
uses that dryfire does not support is reported in the run's notes, never silently ignored. For the exact behaviour
of a tool, replay its binary as a hook (`replay --hook '<the tool's hook command>'`), which needs approval.

## dryfire rule packs

dryfire's own JSON format, for drafting a rule before writing a hook. See
[reference.md](reference.md#rule-packs). Fully supported, as it is dryfire's own.

## checkrein

`--checkrein [PATH]` builds checkrein's own PreToolUse hook from a checkout (the repository or its `plugins/checkrein`
folder) or the installed plugin, and replays it as a hook: sandboxed, after approval. Nothing is reimplemented, so
the result is checkrein's own decision.

- `--checkrein-preset relaxed,standard,strict` replays one or more presets side by side; the report then shows
  where they disagree.
- `--checkrein-config FILE` replays with a copy of a checkrein `config.json` (it is copied into the temp folder; the
  original is not touched).
- Rule ids are read from checkrein's reason lines, so the report breaks counts down by rule.
- Rules that depend on state outside the call (the install ledger, the real repository) see the temp folder; see
  [limits.md](limits.md).

## destructive_command_guard

`--dcg` reads the custom packs under `~/.config/dcg` (YAML); `--dcg-pack FILE` reads one pack. Evaluated in-process;
nothing runs.

**Read:** `schema_version` (1), `id` (`namespace.name`), `keywords`, `destructive_patterns[]` (`name`, `pattern`,
`severity` critical / high / medium / low, default high, `executables`), `safe_patterns[]` (`name`, `pattern`).
Message fields (`description`, `explanation`, `suggestions`, `denial_banner`, `denial_trailer`, `name`, `version`)
are accepted and do not change the decision.

**Judged as dcg documents it:**

- a pack with keywords is skipped unless one of them appears in the command;
- the command is split into segments at `;`, `&&`, `||`, `|`, `&` and newlines;
- a segment that matches a safe pattern is exempt;
- a destructive pattern with `executables` applies only to segments whose command, after wrappers such as `sudo` and
  `env`, is one of them (by basename, ASCII case-insensitive);
- quoted text is data: destructive patterns see each segment, and the whole command, with quoted text blanked;
  `$(...)` and backticks inside double quotes are kept, because the shell runs them;
- critical and high are counted as blocks, medium as warnings, low as log-only.

**Differences from dcg:**

| dcg | dryfire |
|---|---|
| Patterns use the `fancy-regex` engine | Python's `re`. A pattern Python cannot compile (rare lookaround forms) is reported and skipped |
| A span classifier decides what is data (heredoc bodies, `-c` code of interpreters, prose flags such as `--body`) | Quoted text is blanked; heredoc bodies and unquoted prose arguments are still matched, so dryfire can over-count |
| Keywords are matched against the parsed command | Keywords are matched against the raw text, so a keyword inside a quoted string still selects the pack |
| Built-in packs, `config.toml` policy and allowlists | Not read. Replay the `dcg` binary as a hook to include them |
| An invalid pack is skipped with a warning | Same: reported in the run's notes; the run fails only if no pack is usable |

The YAML reader is deliberately small ([yamlite](../plugins/dryfire/scripts/dryfire/adapters/yamlite.py)): block
mappings and sequences, plain and quoted scalars, block scalars (`|`, `>` and their variants), one-line flow
sequences and comments. Anchors, aliases, tags, flow mappings with content and multi-document files are reported as
errors instead of guessed at.

## cc-safety-net

`--safetynet` reads the user scope (`~/.cc-safety-net`) and the project scope (`.cc-safety-net` in the project), and
the older inline config (`.safety-net.json`); `--safetynet PATH` reads one rulebook, `rule.json` or config file.
Evaluated in-process; nothing runs.

**Read:**

- rulebooks at `<scope>/rules/<name>/rulebook.json`, `rulebook_version` 1 or 2:
  - v1 rule: `name`, `command`, `subcommand` (optional), `block_args`, `reason`;
  - v2 rule: `name`, `match` (`command_path`, `any_args`, `exclude_args`), `reason`, with the rulebook's
    `options_with_values`;
  - `allowed_commands` (a rule's command must be listed) and `tests[]`;
- `<scope>/rules/rule.json`: which local rulebooks are on, `overrides` (`"book/rule": "off"` or
  `{"reason": ...}`) and `transparent_wrappers`;
- the older inline config.

**Judged:** the command is split into simple commands, wrappers (`sudo`, `env`, `timeout`, `nohup` and the
configured transparent wrappers) are removed, and each simple command is checked against each rule in order; the
first match blocks, reported as `custom.<rule>` with `[<rule>] <reason>`. User scope runs before project scope.

**Self-check:** each rulebook's own `tests[]` are run through dryfire's reading of it, and the report lists any that
fail, so a difference from cc-safety-net shows up as a failed test rather than a silent miscount.

**Not covered:**

| cc-safety-net | dryfire |
|---|---|
| Built-in rules and the standard / strict / paranoid levels | Not reimplemented. Replay the `cc-safety-net` binary as a hook |
| Rulebooks fetched from GitHub (`owner/repo#ref/name`) | Not fetched (dryfire has no network code); reported in the notes |
| `command_tools` | Not read; reported in the notes |
