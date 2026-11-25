# dryfire

**Know what a guard will do before you turn it on.**

dryfire replays a Claude Code PreToolUse guard against your own past sessions and tells you what it would have done, for example:

> **checkrein (strict) would have blocked 212 of 18,430 of your commands (1.2%) and asked on 640 (3.5%)**

Then it shows which rules fired, how often per active day, when they first and last fired, and masked sample
commands for each, so you can tune a guard on real history instead of finding out in the middle of your work.

Other tools test a hook with made-up input, or mine your history for allow rules. dryfire is the one that runs the
guard itself over what you actually did. It works with any PreToolUse hook command, and reads the rule formats of
[destructive_command_guard](docs/adapters.md#destructive_command_guard) and
[cc-safety-net](docs/adapters.md#cc-safety-net) directly, so it can compare the guards you are choosing between.

- **Read-only and local.** Transcripts are read from `~/.claude/projects`; nothing is sent anywhere. The package has
  no network code, and a test checks that.
- **Masked.** Every command, reason and path in a report goes through secret masking first.
- **Opt-in per hook.** A hook command runs only after you approve that exact command. Rule files are data and run
  nothing.
- **Sandboxed.** Each hook call runs in a fresh temp folder with a temp HOME, a clean environment and a time limit.
  On macOS it also runs under `sandbox-exec`: no network, no writes outside the temp folder, no reads of your home
  folder.
- **No dependencies.** Python 3.9 or newer, standard library only. macOS and Linux.

## Install

```text
/plugin marketplace add kreativlogics/dryfire
/plugin install dryfire@dryfire
```

Claude Code installs only the `plugins/dryfire` folder; the repository's tests and docs stay out of it.

## Use

Ask Claude in plain words ("what would this hook have blocked last month?") or use the skills:

- `/dryfire:replay` finds the guards you have, replays the one you pick, and summarises the report.
- `/dryfire:config` shows and changes settings, and checks the setup.

Or run the command line directly (`DF` is `python3 plugins/dryfire/scripts/cli.py`):

```text
DF detect                                   # transcripts, hooks, rule files dryfire can replay
DF scan                                     # how many past calls, by tool (no commands shown)
DF replay --pack my-rules.json              # a draft rule pack: runs nothing
DF replay --dcg                             # your destructive_command_guard packs
DF replay --safetynet                       # your cc-safety-net rulebooks
DF replay --detected settings:user#0.0      # a hook from your settings (asks for approval first)
DF replay --checkrein --checkrein-preset standard,strict
DF replay --hook './my-guard.sh' --matcher 'Bash' --preset deep --out report.md
```

A relative path in `--hook` is read from the folder you run dryfire in, and one in a project's hook (or
`$CLAUDE_PROJECT_DIR`) from that project, even though each call runs in a temp folder.

Several guards in one run are also merged (deny beats ask beats allow) into a combined column, and the report lists
the calls where they disagree.

### Approving a hook

A hook is a program, so dryfire runs it only after you approve it:

```text
DF approve --hook './my-guard.sh'           # or --detected ID, --use NAME, --checkrein
DF approve --list
DF approve --revoke <fingerprint>
```

The approval covers that exact command, arguments and plugin folder, and the content of each file the command
names (the script and the program that runs it); change any of them and it needs approving again. Files the script
imports or reads are not covered. When Claude runs `approve`, dryfire's own hook asks you first, and refuses outright in an unattended session.

## What a report looks like

```text
**pack draft would have blocked 2 of 87 of your commands (2.3%) and asked on 3 (3.45%)**

| Rule          | Decision | Calls | Share | Per active day | First      | Last       |
|---------------|----------|------:|------:|---------------:|------------|------------|
| no-force-push | deny     |     2 |  2.3% |            2.0 | 2026-11-20 | 2026-11-20 |
| rm-rf         | ask      |     3 | 3.45% |            3.0 | 2026-11-20 | 2026-11-20 |
```

`--json` gives the same data for scripts. The full layout is in [docs/reference.md](docs/reference.md#the-report).

## Settings

Defaults suit most people. The ones you are most likely to change are also in the plugin's settings screen:

| Key | Default | What it does |
|---|---|---|
| `preset` | `standard` | How much history: `quick` 7 days, `standard` 30, `deep` 365 |
| `sandbox` | `auto` | `env`, `auto` (adds the macOS sandbox where available) or `required` |
| `timeout_seconds` | `10` | Time limit for each hook call |

All keys, the layering (defaults, your settings, the project's `.dryfire/config.json`, run flags) and why a project
file can only tighten are in [docs/reference.md](docs/reference.md#settings).

## Limits

A replay judges each past call on its own, in a clean temp folder. A hook that counts earlier calls, reads the real
repository, needs the network or depends on the time of day can decide differently live. Rule mining is planned for
v0.2. See [docs/limits.md](docs/limits.md) and, for the dcg and cc-safety-net formats,
[docs/adapters.md](docs/adapters.md).

## Security

[SECURITY.md](SECURITY.md) covers reporting a problem and the scanner notes; [THREAT-MODEL.md](THREAT-MODEL.md)
says what dryfire protects, how, and where the protection stops. To scan dryfire yourself, scan `plugins/dryfire`:
it is what Claude Code installs. The tests are left out of it because they contain the risky commands guards exist
to catch.

## Development

```text
cd tests && python3 -m unittest discover
claude plugin validate --strict plugins/dryfire
python3 tools/make_icon.py plugins/dryfire/.claude-plugin/icon.png   # the icon is generated, not drawn
```

Some modules are copied from checkrein; [VENDORED.md](VENDORED.md) lists them with their hashes.

## License

MIT, see [LICENSE](LICENSE).
