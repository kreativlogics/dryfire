# Vendored code

These modules are copied byte for byte from [checkrein](https://github.com/kreativlogics/checkrein) (same author,
MIT), from `plugins/checkrein/scripts/checkrein/` in that repository. They are not edited here, with the one
exception below: a fix is made in checkrein first and copied over, and the hashes below are updated.
`tests/test_static.py` fails when a file no longer matches its hash.

| File in `plugins/dryfire/scripts/dryfire/` | What dryfire uses it for | sha256 |
|---|---|---|
| `secrets.py` | Token patterns behind every masked report (`redact.py` builds on it) | `ac97b456ebe244497e45d30df887b00ae9c176fd3e6b9a7eab6cd99606aed019` |
| `shell.py` | Splitting shell commands into simple commands (rule packs, dcg, cc-safety-net, selfguard) | `0a3d78a3b92c30ecb2e36e75c9f5cd7fa107a58c30f4bf0f4b2191e6cdf72d52` |
| `context.py` | The paths a shell command writes to (selfguard) | `d9d4f85b96f7dc56b33b59ee36a92d41dc46395950a1afc738677053606a0e40` |
| `approve.py` | Approval fingerprints and the approvals file | `b870cb21657c22d098fcca35a920f0b909c3dd10a5d6d5f8d476b739019dd123` |
| `ledger.py` | Locked, atomic JSON writes for `approve.py` | `6fb32121b105a5e915722c278bf500013a93a0929c11958c44435eeecd578a1e` |

Because the files are unchanged, a few lines name checkrein: the docstring of `approve.py` mentions checkrein's
self-protection rule, `context.default_data_dir` and the ledger version message name checkrein's own folder and
plugin. dryfire never calls those paths; its data folder comes from `--data` / `CLAUDE_PLUGIN_DATA`.
`ledger.py` also holds checkrein's install-ledger functions, which dryfire does not use.

## Local changes to `shell.py`

`shell.py` comes from an earlier checkrein release (sha256
`59c3646588eb95afc75723e03a323b6b9db3754d26cc34359e05a0142568d08b`); checkrein has since rewritten its parser, so
there is no upstream fix to copy. dryfire carries four changes of its own, each with a test in `tests/test_guards.py` or `tests/test_selfguard.py`:

- A backslash-newline joins the two lines with nothing between them, as a shell does (it used to become a space,
  so `sh /dir/gu\<newline>ard.sh` named two words).
- Matching parentheses is done in one pass per line (`_closers`), so a long run of unclosed `(` is read in
  milliseconds rather than minutes.
- `cd` and `pushd` skip their options (`-P`, `-L`, `-e`, `-@`, `--`) before the folder, so `cd -P /dir && sh g.sh`
  names `/dir/g.sh` (it used to drop the folder whenever the first word after `cd` started with `-`).
- A `#` after a `(` glued to a word, or after a `(` that follows a word and a blank, starts no comment
  (`opens_pattern`): in zsh `/(#i)x`, `ls (#i)x` and `echo x=(#i)y` are patterns, so `ls /(#i)x; rm -rf <dir>` runs the `rm`. `NAME=(` at the start of a command opens an array, where
  the `#` does start a comment. Arrays also open in places this does not follow (`x=1 a=(`, `declare a=(`), so
  selfguard asks on any such `#` near dryfire's folders rather than trust either reading.
