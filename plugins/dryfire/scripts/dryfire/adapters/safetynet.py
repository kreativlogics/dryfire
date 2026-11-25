"""cc-safety-net custom rules, evaluated in-process.

Read:
  - rulebooks (<scope>/rules/<name>/rulebook.json), rulebook_version 1 or 2:
      v1 rule: name, command, subcommand (optional), block_args, reason
      v2 rule: name, match {command_path, any_args, exclude_args}, reason,
               with the rulebook's options_with_values
    plus allowed_commands (a rule's command must be listed) and tests[];
  - rule.json (<scope>/rules/rule.json): which local rulebooks are on,
    overrides ("book/rule": "off" or {"reason": ...}) and transparent_wrappers;
  - the older inline config (.safety-net.json, ~/.cc-safety-net/config.json).

A command is split into simple commands (programs that only wrap the
next command removed); each is checked against each rule in order and
the first match blocks, reported as custom.<rule> with "[<rule>] <reason>".
User scope runs before project scope.

Not covered (docs/adapters.md): cc-safety-net's built-in rules and its
standard/strict/paranoid levels (replay the cc-safety-net binary as a hook),
rulebooks fetched from GitHub ("owner/repo#ref/name": no network), and
command_tools. Each rulebook's own tests[] are replayed as a self-check, so a
difference from cc-safety-net shows up as a failed test in the report.
"""

import json
import os
import re

from .. import shell
from ..guards import Guard
from ..hookio import DENY, NONE, Outcome

NAME_RX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$")
CMD_RX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")
BUILTIN_WRAPPERS = {"caffeinate", "exec", "nice", "nohup", "setsid", "stdbuf", "time", "timeout"}
GLOBAL_VALUE_OPTS = {
    "git": {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix",
            "--config-env"},
    "docker": {"-H", "--host", "--config", "--context", "-c", "-l", "--log-level", "--tlscacert", "--tlscert",
               "--tlskey"},
}


class Rule(object):
    __slots__ = ("book", "name", "version", "command", "subcommand", "block_args", "path", "any_args",
                 "exclude_args", "reason", "off")

    def __init__(self, book, name, reason):
        self.book = book
        self.name = name
        self.reason = reason
        self.version = 1
        self.command = ""
        self.subcommand = None
        self.block_args = []
        self.path = []
        self.any_args = []
        self.exclude_args = []
        self.off = False


class Book(object):
    def __init__(self, name, source):
        self.name = name
        self.source = source
        self.rules = []
        self.options_with_values = set()
        self.tests = []
        self.errors = []
        self.notes = []


def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_rulebook(path):
    try:
        data = _load_json(path)
    except (OSError, ValueError) as exc:
        book = Book(os.path.basename(os.path.dirname(path)) or "rulebook", path)
        book.errors.append("cannot read: %s" % exc)
        return book
    return parse_book(data, path)


def parse_book(data, source):
    book = Book("?", source)
    if not isinstance(data, dict):
        book.errors.append("a rulebook must be a JSON object")
        return book
    name = data.get("name")
    if not isinstance(name, str) or not NAME_RX.match(name):
        book.errors.append("name %r is not valid" % name)
    book.name = name if isinstance(name, str) else "?"
    version = data.get("rulebook_version")
    if version not in (1, 2):
        book.errors.append("rulebook_version must be 1 or 2 (got %r)" % version)
        return book
    allowed = data.get("allowed_commands")
    if not isinstance(allowed, list) or not all(isinstance(a, str) for a in allowed):
        book.errors.append("allowed_commands must be a list of command names")
        allowed = []
    allowed = {a.lower() for a in allowed}
    owv = data.get("options_with_values") or []
    if isinstance(owv, list):
        book.options_with_values = {o for o in owv if isinstance(o, str)}
    for i, r in enumerate(data.get("rules") or []):
        rule = _rule(r, version, book, i)
        if rule is None:
            continue
        cmd = rule.command if version == 1 else (rule.path[0] if rule.path else "")
        if cmd.lower() not in allowed:
            book.errors.append("rule %s: command %r is not in allowed_commands" % (rule.name, cmd))
            continue
        book.rules.append(rule)
    tests = data.get("tests") or []
    if isinstance(tests, list):
        book.tests = [t for t in tests if isinstance(t, dict) and isinstance(t.get("command"), str)]
    return book


def _strs(value):
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def _rule(r, version, book, i):
    if not isinstance(r, dict):
        book.errors.append("rules[%d] must be an object" % i)
        return None
    name, reason = r.get("name"), r.get("reason")
    if not isinstance(name, str) or not NAME_RX.match(name):
        book.errors.append("rules[%d]: name %r is not valid" % (i, name))
        return None
    if not isinstance(reason, str) or not reason:
        book.errors.append("rule %s: reason is required" % name)
        return None
    made = Rule(book.name, name, reason)
    made.version = version
    if version == 1:
        cmd, sub, block = r.get("command"), r.get("subcommand"), r.get("block_args")
        if not isinstance(cmd, str) or not CMD_RX.match(cmd):
            book.errors.append("rule %s: command %r is not valid" % (name, cmd))
            return None
        if sub is not None and (not isinstance(sub, str) or not CMD_RX.match(sub)):
            book.errors.append("rule %s: subcommand %r is not valid" % (name, sub))
            return None
        if not _strs(block):
            book.errors.append("rule %s: block_args must be a non-empty list" % name)
            return None
        made.command, made.subcommand, made.block_args = cmd.lower(), sub, list(block)
        return made
    match = r.get("match")
    if not isinstance(match, dict) or not _strs(match.get("command_path")):
        book.errors.append("rule %s: match.command_path is required" % name)
        return None
    for key in ("any_args", "exclude_args"):
        if key in match and not (isinstance(match[key], list) and all(isinstance(v, str) for v in match[key])):
            book.errors.append("rule %s: match.%s must be a list of strings" % (name, key))
            return None
    made.path = list(match["command_path"])
    made.path[0] = made.path[0].lower()
    made.any_args = list(match.get("any_args") or [])
    made.exclude_args = list(match.get("exclude_args") or [])
    return made


def _cmd_name(argv0):
    name = os.path.basename(argv0).lower()
    return name[:-4] if name.endswith(".exe") else name


def _positionals(name, args, extra_value_opts):
    """Non-option tokens in order, skipping the values of options that take one. -- ends options."""
    value_opts = GLOBAL_VALUE_OPTS.get(name, set()) | extra_value_opts
    out, skip, ended = [], False, False
    for a in args:
        if skip:
            skip = False
            continue
        if ended:
            out.append(a)
            continue
        if a == "--":
            ended = True
            continue
        if a.startswith("-") and a != "-":
            if a in value_opts:
                skip = True
            continue
        out.append(a)
    return out


def _has_arg(args, wanted):
    for a in args:
        if a == wanted:
            return True
        # A short cluster like -Ap holds -A and -p.
        if (len(wanted) == 2 and wanted[0] == "-" and wanted[1] != "-" and a.startswith("-")
                and not a.startswith("--") and len(a) > 2 and "=" not in a and wanted[1] in a[1:]):
            return True
    return False


def _match(rule, name, args, book):
    if rule.version == 1:
        if name != rule.command:
            return False
        rest = args
        if rule.subcommand is not None:
            pos = _positionals(name, args, book.options_with_values)
            if not pos or pos[0] != rule.subcommand:
                return False
            idx = args.index(pos[0])
            rest = args[:idx] + args[idx + 1:]
        return any(_has_arg(rest, b) for b in rule.block_args)
    if name != rule.path[0]:
        return False
    pos = _positionals(name, args, book.options_with_values)
    if pos[:len(rule.path) - 1] != rule.path[1:]:
        return False
    if rule.any_args and not any(a in args for a in rule.any_args):
        return False
    if any(a in args for a in rule.exclude_args):
        return False
    return True


def _unwrap_extra(argv, wrappers):
    for _ in range(8):
        if not argv or _cmd_name(argv[0]) not in wrappers:
            return argv
        argv = argv[1:]
        while argv and argv[0].startswith("-"):
            argv = argv[1:]
    return argv


class Setup(object):
    """Everything one scope (user or project) contributes."""

    def __init__(self):
        self.books = []
        self.wrappers = set(BUILTIN_WRAPPERS)
        self.notes = []
        self.errors = []


def load_path(path):
    """A rulebook.json, a rule.json, an inline config, or a scope folder (~/.cc-safety-net)."""
    setup = Setup()
    path = os.path.expanduser(path)
    if os.path.isdir(path):
        rule_json = os.path.join(path, "rules", "rule.json")
        if os.path.isfile(rule_json):
            _load_rule_json(rule_json, setup)
        else:
            setup.notes.append("%s has no rules/rule.json; nothing is turned on there" % path)
        for legacy in (os.path.join(path, "config.json"),):
            if os.path.isfile(legacy):
                _load_legacy(legacy, setup)
        return setup
    try:
        data = _load_json(path)
    except (OSError, ValueError) as exc:
        setup.errors.append("%s: cannot read: %s" % (path, exc))
        return setup
    if isinstance(data, dict) and "rulebook_version" in data:
        setup.books.append(parse_book(data, path))
    elif isinstance(data, dict) and os.path.basename(path) == "rule.json":
        _load_rule_json(path, setup, data)
    elif isinstance(data, dict) and isinstance(data.get("rules"), list):
        _load_legacy(path, setup, data)
    else:
        setup.errors.append("%s: not a rulebook, rule.json or safety-net config" % path)
    return setup


def _load_rule_json(path, setup, data=None):
    try:
        data = data if data is not None else _load_json(path)
    except (OSError, ValueError) as exc:
        setup.errors.append("%s: cannot read: %s" % (path, exc))
        return
    if not isinstance(data, dict) or data.get("version") != 1:
        setup.errors.append("%s: version must be 1" % path)
        return
    base_dir = os.path.dirname(path)
    for entry in data.get("rules") or []:
        if not isinstance(entry, str):
            continue
        if "/" in entry or "#" in entry:
            setup.notes.append("%s: rulebook %r comes from GitHub; dryfire does not fetch it (no network)"
                               % (path, entry))
            continue
        book_path = os.path.join(base_dir, entry, "rulebook.json")
        if not NAME_RX.match(entry) or not os.path.isfile(book_path):
            setup.errors.append("%s: rulebook %r not found at %s" % (path, entry, book_path))
            continue
        setup.books.append(load_rulebook(book_path))
    overrides = data.get("overrides") or {}
    if isinstance(overrides, dict):
        for key, value in overrides.items():
            book_name, _, rule_name = key.partition("/")
            hit = False
            for book in setup.books:
                for rule in book.rules:
                    if book.name == book_name and rule.name == rule_name:
                        hit = True
                        if value == "off":
                            rule.off = True
                        elif isinstance(value, dict) and isinstance(value.get("reason"), str):
                            rule.reason = value["reason"]
            if not hit:
                setup.notes.append("%s: override %r matches no loaded rule" % (path, key))
    wrappers = data.get("transparent_wrappers") or []
    if isinstance(wrappers, list):
        setup.wrappers |= {w.lower() for w in wrappers if isinstance(w, str)}
    if data.get("command_tools"):
        setup.notes.append("%s: command_tools is not replayed by dryfire" % path)


def _load_legacy(path, setup, data=None):
    try:
        data = data if data is not None else _load_json(path)
    except (OSError, ValueError) as exc:
        setup.errors.append("%s: cannot read: %s" % (path, exc))
        return
    if not isinstance(data, dict) or data.get("version") != 1:
        setup.errors.append("%s: version must be 1" % path)
        return
    book = Book(os.path.basename(path), path)
    for i, r in enumerate(data.get("rules") or []):
        rule = _rule(r, 1, book, i)
        if rule is not None:
            book.rules.append(rule)
    setup.books.append(book)


class SafetyNetGuard(Guard):
    kind = "safetynet"

    def __init__(self, name, setups):
        Guard.__init__(self, name)
        self.setups = setups
        books = [b for s in setups for b in s.books]
        self.label = "cc-safety-net rules (%s)" % (", ".join(b.name for b in books) or "none")
        for s in setups:
            self.notes.extend(s.errors)
            self.notes.extend(s.notes)
            for b in s.books:
                self.notes.extend("%s: %s" % (b.source, e) for e in b.errors)
                self.notes.extend("%s: %s" % (b.source, n) for n in b.notes)
        self.self_check = self._run_tests()

    def accepts(self, tool, tool_input=None, cwds=()):
        return tool == "Bash"

    def check(self, command):
        for setup in self.setups:
            for cmd in shell.parse(command).cmds:
                argv = _unwrap_extra(cmd.argv, setup.wrappers)
                if not argv:
                    continue
                name = _cmd_name(argv[0])
                args = argv[1:]
                for book in setup.books:
                    for candidate in book.rules:
                        if not candidate.off and _match(candidate, name, args, book):
                            return candidate
        return None

    def evaluate(self, tool, tool_input, mode):
        command = tool_input.get("command") if isinstance(tool_input, dict) else None
        if not isinstance(command, str) or not command:
            return Outcome(NONE)
        rule = self.check(command)
        if rule is None:
            return Outcome(NONE)
        return Outcome(DENY, "[%s] %s" % (rule.name, rule.reason), rule="custom.%s" % rule.name)

    def _run_tests(self):
        passed, failed = 0, []
        for setup in self.setups:
            for book in setup.books:
                for t in book.tests:
                    rule = self.check(t["command"])
                    expect = t.get("expect")
                    ok = (rule is not None) == (expect == "blocked")
                    if ok and expect == "blocked" and t.get("rule"):
                        ok = rule.name == t["rule"] or "custom.%s" % rule.name == t["rule"]
                    if ok:
                        passed += 1
                    else:
                        failed.append("%s: %r expected %s, dryfire got %s" % (
                            book.name, t["command"], expect, "blocked by %s" % rule.name if rule else "allowed"))
        return {"passed": passed, "failed": failed}
