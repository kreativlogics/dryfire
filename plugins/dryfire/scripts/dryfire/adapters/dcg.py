"""destructive_command_guard custom packs (YAML), evaluated in-process.

What dryfire reads from a pack:
  schema_version (1), id ("namespace.name"), keywords,
  destructive_patterns[]: name, pattern, severity (critical|high|medium|low,
    default high), executables
  safe_patterns[]: name, pattern
Fields that only shape dcg's message (description, explanation,
suggestions, denial_banner, denial_trailer, name, version) are accepted and
not used for the decision.

How a command is judged, following dcg's documented behaviour:
  - a pack with keywords is skipped unless one of them appears in the command;
  - the command is split into segments at ; && || | & and newlines;
  - a segment matching a safe pattern is exempt;
  - a destructive pattern with executables applies only to segments whose
    command (after sudo/env and similar wrappers) is one of them,
    compared by basename, ASCII case-insensitive;
  - destructive patterns see each segment, and (without executables) the
    whole command, with quoted text blanked out as data; $(...) and
    backticks inside double quotes are kept, since they run;
  - critical and high deny, medium warns, low only logs.

Known gaps (also in docs/adapters.md): dcg's regex engine (fancy-regex)
is approximated with Python's re, so a pattern Python cannot compile is
reported and skipped; dcg's built-in packs, config.toml policy and
allowlists are not read (replay the dcg binary as a hook for those).
dcg's full span classifier (heredoc bodies, interpreter -c code, prose
flags such as --body) is approximated by blanking quoted text.
"""

import re

from .. import shell
from ..guards import Guard
from ..hookio import DENY, LOG, NONE, WARN, Outcome
from . import yamlite

ID_RX = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
SEVERITIES = ("critical", "high", "medium", "low")
DISPLAY_ONLY = {"description", "explanation", "suggestions", "denial_banner", "denial_trailer"}
PACK_KEYS = {"schema_version", "id", "name", "version", "description", "keywords", "destructive_patterns",
             "safe_patterns"}
POSIX = {"[:alpha:]": "a-zA-Z", "[:digit:]": "0-9", "[:alnum:]": "a-zA-Z0-9", "[:upper:]": "A-Z",
         "[:lower:]": "a-z", "[:space:]": r"\s", "[:xdigit:]": "0-9A-Fa-f", "[:word:]": r"\w",
         "[:punct:]": r"!-/:-@\[-`{-~", "[:blank:]": r" \t"}


def translate(pattern):
    """fancy-regex syntax to Python re where they differ in spelling."""
    out = re.sub(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", r"(?P<\1>", pattern)
    out = out.replace(r"\z", r"\Z")
    for k, v in POSIX.items():
        out = out.replace(k, v)
    return out


class Pattern(object):
    __slots__ = ("name", "rx", "severity", "executables", "description")

    def __init__(self, name, rx, severity="high", executables=None, description=""):
        self.name = name
        self.rx = rx
        self.severity = severity
        self.executables = executables
        self.description = description


class Pack(object):
    def __init__(self, source):
        self.source = source
        self.id = ""
        self.keywords = []
        self.destructive = []
        self.safe = []
        self.errors = []  # Problems that make dcg skip the whole pack.
        self.notes = []  # Patterns dryfire could not use, and ignored fields.

    @property
    def valid(self):
        return not self.errors


def load(path):
    pack = Pack(path)
    try:
        with open(path, encoding="utf-8") as fh:
            data = yamlite.loads(fh.read())
    except (OSError, UnicodeDecodeError) as exc:
        pack.errors.append("cannot read %s: %s" % (path, exc))
        return pack
    except yamlite.YamlError as exc:
        pack.errors.append("YAML: %s" % exc)
        return pack
    return from_data(data, path)


def from_data(data, source="pack"):
    pack = Pack(source)
    if not isinstance(data, dict):
        pack.errors.append("a pack must be a mapping")
        return pack
    for k in sorted(set(data) - PACK_KEYS):
        pack.notes.append("unknown top-level field %r ignored" % k)
    if data.get("schema_version") != 1:
        pack.errors.append("schema_version must be 1 (got %r)" % data.get("schema_version"))
    pid = data.get("id")
    if not isinstance(pid, str) or not ID_RX.match(pid):
        pack.errors.append("id must look like 'namespace.name' in lower case (got %r)" % pid)
    pack.id = pid if isinstance(pid, str) else "?"
    kw = data.get("keywords") or []
    if not isinstance(kw, list) or not all(isinstance(k, str) and k for k in kw):
        pack.errors.append("keywords must be a list of non-empty strings")
        kw = []
    pack.keywords = kw
    for field, safe in (("destructive_patterns", False), ("safe_patterns", True)):
        items = data.get(field) or []
        if not isinstance(items, list):
            pack.errors.append("%s must be a list" % field)
            continue
        for i, item in enumerate(items):
            p = _pattern(item, safe, "%s[%d]" % (field, i), pack)
            if p is not None:
                (pack.safe if safe else pack.destructive).append(p)
    if not data.get("destructive_patterns"):
        pack.errors.append("a pack needs at least one destructive pattern")
    return pack


def _pattern(item, safe, where, pack):
    if not isinstance(item, dict):
        pack.errors.append("%s must be a mapping" % where)
        return None
    name, pattern = item.get("name"), item.get("pattern")
    if not isinstance(name, str) or not name or not isinstance(pattern, str) or not pattern:
        pack.errors.append("%s needs a name and a pattern" % where)
        return None
    known = {"name", "pattern", "description"} | (set() if safe else ({"severity", "executables"} | DISPLAY_ONLY))
    for k in sorted(set(item) - known):
        pack.notes.append("%s: field %r ignored" % (where, k))
    severity = "high"
    executables = None
    if not safe:
        severity = item.get("severity", "high")
        if severity not in SEVERITIES:
            pack.errors.append("%s: severity must be one of %s" % (where, ", ".join(SEVERITIES)))
            return None
        if "executables" in item:
            ex = item.get("executables")
            if not isinstance(ex, list) or not ex or not all(isinstance(e, str) and e for e in ex):
                pack.errors.append("%s: executables must be a non-empty list of names" % where)
                return None
            executables = {e.lower() for e in ex}
    try:
        rx = re.compile(translate(pattern))
    except re.error as exc:
        pack.notes.append("%s (%s): pattern cannot be evaluated by dryfire (%s); dcg may still use it"
                          % (where, name, exc))
        return None
    return Pattern(name, rx, severity, executables, item.get("description") or "")


_SPLIT = re.compile(r"\|\||&&|\|&|[;|&\n]")


def segments(command):
    """Top-level segments of a command line, split outside quotes."""
    out, cur, quote, i = [], [], None, 0
    while i < len(command):
        ch = command[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(command):
                cur.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < len(command):
            cur.append(command[i:i + 2])
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
            i += 1
            continue
        m = _SPLIT.match(command, i)
        if m:
            seg = "".join(cur).strip()
            if seg:
                out.append(seg)
            cur = []
            i = m.end()
            continue
        cur.append(ch)
        i += 1
    seg = "".join(cur).strip()
    if seg:
        out.append(seg)
    return out


_SUBST = re.compile(r"\$\([^()]*\)|`[^`]*`")


def blank_quotes(command):
    """The command with quoted text replaced by spaces, as dcg treats quoted strings as data.

    Command substitutions inside double quotes ($(...) and backticks) still run,
    so they are kept.
    """
    def repl(m):
        text = m.group(0)
        body = text[1:-1]
        if text[0] == '"':
            kept = [" "] * len(body)
            for s in _SUBST.finditer(body):
                kept[s.start():s.end()] = body[s.start():s.end()]
            body = "".join(kept)
        else:
            body = " " * len(body)
        return text[0] + body + text[-1]
    return re.sub(r"'[^']*'|\"(?:\\.|[^\"\\])*\"", repl, command)


def _executable(segment):
    cmds = shell.parse(segment).cmds
    return cmds[0].name.lower() if cmds else ""


_LEVEL = {"critical": DENY, "high": DENY, "medium": WARN, "low": LOG}


def judge(pack, command):
    """(severity, pattern) of the first destructive match, or None."""
    if pack.keywords and not any(k in command for k in pack.keywords):
        return None
    for seg in segments(command):
        if any(p.rx.search(seg) for p in pack.safe):
            continue
        data_free = blank_quotes(seg)
        exe = None
        for p in pack.destructive:
            if p.executables is not None:
                exe = _executable(seg) if exe is None else exe
                if exe not in p.executables:
                    continue
            if p.rx.search(data_free):
                return p
    whole = blank_quotes(command)
    if any(p.rx.search(command) for p in pack.safe):
        return None
    for p in pack.destructive:
        if p.executables is None and p.rx.search(whole):
            return p
    return None


class DcgGuard(Guard):
    kind = "dcg"

    def __init__(self, name, packs):
        Guard.__init__(self, name)
        self.packs = packs
        self.label = "dcg packs (%s)" % ", ".join(p.id for p in packs)
        for p in packs:
            for e in p.errors:
                self.notes.append("%s: dcg would skip this pack: %s" % (p.source, e))
            for n in p.notes:
                self.notes.append("%s: %s" % (p.source, n))

    def accepts(self, tool, tool_input=None, cwds=()):
        return tool == "Bash"

    def evaluate(self, tool, tool_input, mode):
        command = tool_input.get("command") if isinstance(tool_input, dict) else None
        if not isinstance(command, str) or not command:
            return Outcome(NONE)
        for pack in self.packs:
            if not pack.valid:
                continue
            p = judge(pack, command)
            if p is not None:
                decision = _LEVEL[p.severity]
                return Outcome(decision, "dcg %s:%s (%s)%s" % (pack.id, p.name, p.severity,
                                                                ": " + p.description if p.description else ""),
                               rule="%s:%s" % (pack.id, p.name))
        return Outcome(NONE)
