# Security

## Reporting a problem

Please report security problems privately through GitHub's "Report a vulnerability" on
https://github.com/kreativlogics/dryfire/security, not in a public issue. Include the dryfire version, your OS and
Python version, and the smallest steps that show the problem. Do not include real transcript content or secrets;
a made-up example is enough.

## What dryfire promises

- The transcript reader never sends anything anywhere, and the package has no network code.
- Transcript content is treated as untrusted data.
- Secrets in replayed commands are masked in every report.
- Hooks under test run in a sandboxed temp HOME with a time limit, never against your real files (on macOS; see
  [THREAT-MODEL.md](THREAT-MODEL.md) for Linux).
- Replaying a hook is opt-in for each hook.

[THREAT-MODEL.md](THREAT-MODEL.md) gives the controls behind each promise and where each one stops.

## Scanner notes

Scanned folder: `plugins/dryfire`, which is what Claude Code installs.

Last full scan of `plugins/dryfire` (SkillSpector through a local install gate, 2026-11-25): one HIGH, PE3
"credential access", matched on the word `keyring` in the list of secret-fetching commands that `redact.py`
uses to decide which `$(...)` values it may keep. That name was removed from the list, so `$(keyring ...)`
values are now masked like any other text (the safe direction). The only change since that scan was the
removed word; the scan before it, of the same code without that word, had no HIGH. The re-scan that would
confirm this was held back by the scanner's two-hour cooldown.

Findings left, each reviewed:

- MEDIUM RA2 "session persistence" at `main.py` (a comment about reading transcripts twice) and at
  `selfguard.py` (the list of shell builtins). Neither writes a cron job, a startup file or any state outside
  dryfire's own data folder.
- MEDIUM AST4 "subprocess" at `sandbox.py`: the hook under test is started with an argument list (no shell),
  a scrubbed environment, a temp HOME, a timeout and its own process group; `/bin/ps` is run with a fixed
  argument list to find and stop leftover processes from that group.
- LOW BH1 bundled hook: `hooks/hooks.json` registers the self-guard (PreToolUse), which only reads the tool
  call and answers allow or ask.
- LOW AST7 `getattr()` in `main.py` and `transcripts.py`: attribute names come from fixed tables in the code,
  never from transcript content.

Scanning the whole repository (tests and docs included) adds HIGHs that are test fixtures: destructive
command strings (`rm -rf /`, `git push --force`, `curl x | sh`), `.env` paths, an injection phrase and
fake tokens built at run time, all of which the tests feed to dryfire as hostile input, and `~/.claude/settings`
paths in `docs/reference.md` that say where Claude Code keeps hook settings. None of these ship in the plugin.
