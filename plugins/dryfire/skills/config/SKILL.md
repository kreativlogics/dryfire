---
name: config
description: Show or change dryfire's settings - how much history to replay, the sandbox and time limit for hooks under test, extra masking patterns, named hooks - and check the setup. Use when the user asks to configure dryfire, explain a dryfire setting, or why a replay could not run.
argument-hint: "[show | explain <key> | set <key> <value> | unset <key> | doctor]"
allowed-tools: Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" --data "${CLAUDE_PLUGIN_DATA}" show*), Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" --data "${CLAUDE_PLUGIN_DATA}" explain*), Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" --data "${CLAUDE_PLUGIN_DATA}" doctor*)
---

# dryfire config

`CFG` below means `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" --data "${CLAUDE_PLUGIN_DATA}"`.

Request: $ARGUMENTS

- **See the settings:** `CFG show` lists each value and the layer it comes from (default, preset, your config,
  the project's `.dryfire/config.json`).
- **Explain a key:** `CFG explain <key>`, or `CFG explain` for all of them.
- **Check the setup:** `CFG doctor` reports the Python version, whether the macOS sandbox is available, the
  transcript folders found and whether the config files are valid.
- **Change a setting:** `CFG set <key> <value>` writes your own config; `--project-layer` writes the project's
  file instead. `CFG unset <key>` removes it. `CFG init` writes a starter file. Claude Code asks the user to
  confirm each of these; never edit dryfire's config files directly.

Things to tell the user when they come up:

- The project file is shared with whoever works in the project, so it can only make things stricter: a shorter
  time limit, a stricter sandbox, more masking. It cannot add transcript folders, and the hooks and `allow_read`
  paths it names run or apply only after the user approves them for that project (`CFG approve allow_read`,
  and `cli.py approve --use <name>` for a hook).
- `sandbox`: `env` gives a hook a temp home and a clean environment; `auto` adds the macOS sandbox (no network,
  no writes outside a temp folder, no reads in the home folder) where it exists; `required` refuses to run hooks
  without it.
- Run flags on `replay` follow the same rule as the project file: they can only tighten.
