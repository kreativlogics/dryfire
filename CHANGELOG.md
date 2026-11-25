# Changelog

## 0.1.0 (unreleased)

First version.

- Replay any PreToolUse hook command against past Claude Code transcripts: sandboxed per call (temp HOME and
  folders, clean environment, time limit with process-group kill, macOS `sandbox-exec`), opt-in approval per hook bound to the content of every file it names (up to 256 MB in all; past that it cannot be approved), paths and folders set in a variable first included (`cd "$D"`, `for D in ...` and `${D:-/dir}` too), output redirection targets left out (unless the line has a quoted or escaped `>`); processes a hook leaves behind are ended;
  a hook that keeps timing out is stopped.
- Rule formats evaluated in-process: dryfire JSON packs, destructive_command_guard YAML packs, cc-safety-net
  rulebooks (v1, v2, `rule.json`, older inline config) with their own tests replayed as a self-check.
- checkrein adapter: builds checkrein's hook at any preset, with a copy of the user's config.
- Report in Markdown or JSON: headline "would have blocked N of M", per-rule counts, rate per active day, first and
  last date, masked samples, by tool, by folder, combined decision and differences between guards.
- `detect`, `scan`, `approve` commands; settings tool with show, explain, set, unset, init, approve, doctor; layered
  settings where project files and run flags can only tighten.
- Self-guard hook: approvals and settings changes ask the user and are denied unattended; writes into dryfire's own
  folders are denied; a run that moves `HOME` or `CLAUDE_PLUGIN_DATA` asks, launchers such as `arch`, `flock`,
  `env -S` and `find -exec` are seen through, and a line it cannot follow that names dryfire and a changing
  subcommand asks, as does a run with no subcommand on the line.
- Reports, `detect`, `approve --list` and the settings view mask secrets with your `redact_patterns` too.
- The scripts write no bytecode, so the installed plugin folder stays exactly as shipped.
- Skills: `replay`, `config`.
