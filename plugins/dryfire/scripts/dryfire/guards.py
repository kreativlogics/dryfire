"""Guards: the things dryfire replays history against.

A HookGuard runs a real hook command in the sandbox (needs approval). Rule
guards (dryfire packs, destructive_command_guard packs, cc-safety-net
rulebooks) are data evaluated in-process and run nothing.
"""

import hashlib
import itertools
import json
import os
import re
import shlex
import shutil

from . import hookio, sandbox, shell

_PLAIN_MATCHER = re.compile(r"^[A-Za-z0-9_\- ,|]*$")


def matcher_accepts(matcher, tool):
    """Claude Code's PreToolUse matcher rules.

    Empty, missing or "*" matches every tool. A matcher made only of letters,
    digits, _, -, spaces, commas and | is a list of exact tool names. Anything
    else is a regular expression searched anywhere in the tool name.
    """
    if matcher is None or matcher in ("", "*"):
        return True
    if _PLAIN_MATCHER.match(matcher):
        names = [n.strip() for n in re.split(r"[|,]", matcher) if n.strip()]
        return tool in names
    try:
        return re.search(matcher, tool) is not None
    except re.error:
        return False


def matcher_error(matcher):
    if matcher and not _PLAIN_MATCHER.match(matcher) and matcher != "*":
        try:
            re.compile(matcher)
        except re.error as exc:
            return "matcher %r is not a valid regular expression (%s)" % (matcher, exc)
    return ""


_IF_RX = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*(?:\((.*)\))?\s*$", re.S)


def if_filter(rule, home=None, source=""):
    """The hook 'if' field: one permission rule, Tool or Tool(pattern).

    Returns (function(tool, input, cwds=()) -> bool, note). cwds are the
    folders the call was made from. A form dryfire does not understand
    returns a filter that accepts everything, with a note.
    """
    if not rule:
        return (lambda tool, tool_input, cwds=(): True), ""
    m = _IF_RX.match(rule)
    if not m:
        return (lambda tool, tool_input, cwds=(): True), \
            "'if' %r not understood; the hook was replayed on every call" % rule
    want_tool, pattern = m.group(1), m.group(2)
    pat = (pattern or "").strip()

    def check(tool, tool_input, cwds=()):
        if tool != want_tool:
            return False
        if pat in ("", "*"):
            return True
        if tool == "Bash":
            return _bash_if(tool_input.get("command") or "", pat)
        return _path_if(tool_input, pat, home, source, cwds)
    return check, ""


def _star_rx(pattern):
    """Permission-rule wildcards: '*' matches anything, every other character is literal."""
    return re.compile(".*".join(re.escape(part) for part in pattern.split("*")) + r"\Z", re.S)


def _bash_if(command, pat):
    if pat.endswith(":*"):  # 'git push:*' is the same rule as 'git push *'.
        pat = pat[:-2] + " *"
    rxs = [_star_rx(pat)]
    if pat.endswith(" *"):  # A trailing ' *' also matches the bare command.
        rxs.append(_star_rx(pat[:-2]))
    parsed = shell.parse(command)
    if parsed.error:
        return True  # Claude Code runs the hook when it can't split the command.
    texts = [command] + [" ".join(cmd.argv) for cmd in parsed.cmds]
    if any(rx.match(t) for rx in rxs for t in texts):
        return True
    # A pattern naming more than the command runs anyway when words are hidden in $(), backticks or $VAR.
    names_more = " " in (pat[:-2] if pat.endswith(" *") else pat).strip()
    return names_more and re.search(r"\$\(|`|\$[A-Za-z_{]", command) is not None


def _glob_rx(pattern):
    """gitignore-style: '**/' any folders, '**' anything, '*' and '?' within one name; a folder covers its contents."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"(?:/.*)?\Z", re.S)


def _path_bases(pat, home, source, cwds):
    """(pattern without its anchor, folders it is anchored at); an empty folder list means anywhere."""
    if pat.startswith("//"):
        return pat[1:], [""]
    if pat.startswith("~/"):
        return pat[1:], [(home or os.path.expanduser("~")).rstrip("/")]
    if pat.startswith("/"):
        # Anchored at the settings source: ~/.claude for user settings, otherwise the project.
        if source.startswith("settings:user") and home:
            return pat, [os.path.join(home, ".claude")]
        return pat, [c.rstrip("/") for c in cwds]
    rel = pat[2:] if pat.startswith("./") else pat
    if "/" not in rel.rstrip("/"):
        rel = "**/" + rel  # A bare name matches at any depth, as in gitignore.
    return "/" + rel, [c.rstrip("/") for c in cwds]


def _path_if(tool_input, pat, home, source, cwds):
    tail, bases = _path_bases(pat, home, source, cwds)
    if not bases:
        bases = [""]
        if tail.startswith("/**/"):
            tail = tail[1:]
    rxs = [_glob_rx(b + tail) for b in bases]
    for key in ("file_path", "notebook_path", "path", "url", "pattern"):
        value = tool_input.get(key)
        if isinstance(value, str) and any(rx.match(os.path.normpath(value) if key != "url" else value)
                                          for rx in rxs):
            return True
    return False


class Guard(object):
    """Base: name, which tools it sees, and evaluate(tool, input, mode) -> Outcome."""

    kind = "guard"
    runs_code = False

    def __init__(self, name):
        self.name = name
        self.notes = []
        self.label = name
        self.not_replayed = set()  # Keys of the distinct calls a stopped hook never ran on.

    def accepts(self, tool, tool_input=None, cwds=()):
        return True

    def evaluate(self, tool, tool_input, mode):
        raise NotImplementedError

    def rule_of(self, outcome):
        return outcome.rule or ""

    def describe(self):
        return {"name": self.name, "kind": self.kind, "label": self.label}


class HookSpec(object):
    """One hook command as it would sit in settings or a plugin's hooks.json."""

    def __init__(self, command="", args=None, matcher="*", plugin_root=None, options=None, on_failure=False,
                 if_rule="", seed_files=None, source=""):
        self.command = command or ""
        self.args = list(args) if args else None
        self.matcher = matcher if matcher is not None else "*"
        self.plugin_root = plugin_root or None
        self.options = dict(options or {})
        self.on_failure = bool(on_failure)
        self.if_rule = if_rule or ""
        self.seed_files = dict(seed_files or {})
        self.source = source

    def approval_value(self, home):
        """What an approval is bound to: the code that will run, not its options.

        That is the command, the plugin folder, and the content of each file the command names (the
        script, the interpreter), so editing the script needs a new approval. A file the hook loads
        on its own, such as a module it imports, is not covered.
        """
        value = {"command": self.command, "args": self.args, "plugin_root": self.plugin_root}
        files = named_files(self, home)
        if files:
            value["files"] = files
        return value

    def pinned(self, base, project_dir):
        """This hook with relative and $CLAUDE_PROJECT_DIR script paths made absolute (see sandbox.pin_paths)."""
        self.command = sandbox.pin_paths(self.command, base, project_dir) if self.command else self.command
        self.args = sandbox.pin_args(self.args, base, project_dir) if self.args else self.args
        return self

    def fingerprint(self, home):
        blob = json.dumps(self.approval_value(home), sort_keys=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def from_dict(cls, d, source=""):
        if not isinstance(d, dict):
            raise ValueError("a hook must be an object with a command")
        on_failure = d.get("on_failure", d.get("onFailure"))
        return cls(command=d.get("command") or "", args=d.get("args"), matcher=d.get("matcher", "*"),
                   plugin_root=d.get("plugin_root"), options=d.get("options"),
                   on_failure=on_failure == "block" or on_failure is True, if_rule=d.get("if", ""),
                   source=source)


class HookGuard(Guard):
    kind = "hook"
    runs_code = True

    def __init__(self, name, spec, home, timeout=10, sandbox_mode="env", allow_read=(), rule_rx=None,
                 label=None):
        Guard.__init__(self, name)
        self.spec = spec
        self.home = home
        self.timeout = timeout
        self.sandbox_mode = sandbox_mode
        self.allow_read = list(allow_read or [])
        self.rule_rx = rule_rx
        self.label = label or name
        self._if, note = if_filter(spec.if_rule, home, spec.source)
        if note:
            self.notes.append(note)
        err = matcher_error(spec.matcher)
        if err:
            self.notes.append(err)
        self.command = sandbox.expand_command(spec.command, home, spec.plugin_root) if spec.command else ""
        try:
            words = shlex.split(self.command) if self.command else [str(a) for a in spec.args or []]
        except ValueError:
            words = self.command.split()
        if spec.args:
            words = [sandbox.expand_command(str(a), home, spec.plugin_root) for a in spec.args]
        self.args = words if spec.args else None
        self.read_paths = sandbox.read_paths_for(words, home, spec.plugin_root, self.allow_read)
        note = sandbox.shim_note(words, home) if sandbox_mode == "os" else ""
        if note:
            self.notes.append(note)

    def accepts(self, tool, tool_input=None, cwds=()):
        if not matcher_accepts(self.spec.matcher, tool):
            return False
        if tool_input is not None and self.spec.if_rule:
            return self._if(tool, tool_input, cwds)
        return True

    def evaluate(self, tool, tool_input, mode):
        with sandbox.Box(self.spec.seed_files) as box:
            plugin_data_env = None
            if self.spec.plugin_root:
                plugin_data_env = box.data
            env = sandbox.build_env(box, self.spec.plugin_root, self.spec.options)
            argv = sandbox.hook_argv(self.command if not self.args else None, self.args, self.sandbox_mode, box,
                                     self.home, self.read_paths)
            if plugin_data_env:
                argv = [a.replace("${CLAUDE_PLUGIN_DATA}", box.data) for a in argv]
            data = hookio.payload(tool, tool_input, box.project, box.transcript, mode, "dryfire-replay",
                                  "toolu_dryfire_replay")
            res = sandbox.run(argv, json.dumps(data).encode("utf-8"), env, box.project, self.timeout)
        out = hookio.interpret(res.rc, res.stdout, res.stderr, timed_out=res.timed_out,
                               start_error=res.start_error, truncated=res.truncated,
                               on_failure=self.spec.on_failure)
        if self.rule_rx and out.reason:
            m = self.rule_rx.search(out.reason)
            if m:
                out.rule = m.group(1)
        return out

    def describe(self):
        d = Guard.describe(self)
        d.update({"matcher": self.spec.matcher, "sandbox": self.sandbox_mode, "timeout_seconds": self.timeout,
                  "source": self.spec.source})
        return d


# How much file content one hook's approval may hash in all. Past it, the files left are marked UNBOUND and
# the hook cannot be approved, so no named file is ever bound by anything weaker than its content.
MAX_HASHED_BYTES = 256 * 1024 * 1024
UNBOUND = "unbound: more file content than an approval can hash"


def named_files(spec, home):
    """{path: sha256} for each existing file the hook's command or arguments name, after expansion.

    A command line is also read the way a shell would split it, so the programs and scripts of each part of
    'cd /dir && sh g.sh', 'cd /dir && ./g.sh', 'bash -c "sh /dir/g.sh"' or '/dir/g.sh;true' are bound too, and
    so is a path set in a variable first (X=/dir/g.sh; sh $X).
    """
    if spec.args:
        words = [sandbox.expand_command(str(a), home, spec.plugin_root) for a in spec.args]
        words = _with_program(words)
    else:
        expanded = sandbox.expand_command(spec.command, home, spec.plugin_root)
        lex = shlex.shlex(expanded, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""  # A '#' inside a word (a#b) starts no comment in a shell.
        try:
            words = list(lex)
        except ValueError:
            words = _PLAIN_WORD.findall(expanded)  # D=/dir; keeps its ';' in a whitespace split.
            words += [_QUOTES.sub("", w) for w in words]  # "/dir/g.sh" keeps its quotes in a plain split.
        if not _has_quoted_angle(expanded):
            words = _not_written(words)
        known = {}
        words = _with_program(_with_variables(words, known))
        lines = [expanded]
        filled = _fill_line(expanded, known)
        if filled != expanded:
            lines.append(filled)  # D=/dir; cd "$D" && sh g.sh: the parser follows cd into /dir.
        for cmd in (c for line in lines for c in shell.parse(line, cwd=None, home=home).cmds):
            part = _with_program(list(cmd.argv))
            if cmd.cwd and part:  # After a cd, a relative word names a file in that folder, ./g.sh included.
                rest = part[1:] if "/" not in part[0] else part
                part = part[:1] + [os.path.normpath(os.path.join(cmd.cwd, w)) for w in rest]
                # A script read from input after a cd (cd /dir && bash < g.sh) is in that folder too.
                part += [os.path.normpath(os.path.join(cmd.cwd, t)) for op, t in cmd.redirects if op in ("<", "<>")]
            words += part + list(cmd.env.values())
    out, budget = {}, MAX_HASHED_BYTES
    for w in words:
        path = w.split("=", 1)[1] if "=" in w and not w.startswith("/") else w
        if not path.startswith("/") or path in out:
            continue
        real = os.path.realpath(path)
        if os.path.isfile(real):
            out[path], budget = _digest(real, budget)
    return out


def unbound_files(value):
    """The named files an approval value could not bind (see MAX_HASHED_BYTES); such a value approves nothing."""
    return sorted(p for p, v in value.get("files", {}).items() if v == UNBOUND)


# The longest variable value put into later words (a path is shorter than this), and the most text all the
# words and lines with values put in may add up to.
MAX_VALUE = 4096
MAX_FILLED = 1 << 20
_QUOTES = re.compile(r"[\"']")
# $NAME, ${NAME}, and ${NAME-word} or ${NAME=word}, whose word is the value when NAME is not set (with ':',
# also when it is empty). Groups: braced name, ':', word, plain name.
_VAR_REF = re.compile(r"\$(?:\{([A-Za-z_]\w*)(?:(:?)[-=]([^{}]*))?\}|([A-Za-z_]\w*))")
# A word of a line shlex cannot read (an unclosed quote): a run of characters other than spaces and
# ; & | ( ) < >, or a run of those operators.
_PLAIN_WORD = re.compile(r"[^\s;&|()<>]+|[;&|()<>]+")
_NAME = re.compile(r"^[A-Za-z_]\w*$")
# The most values of one for loop, and of value combinations of the loops one word uses, tried in that word;
# and the most text all those tries may read, so a line of many loops and names stays quick.
MAX_LOOP_VALUES = 64
MAX_LOOP_WORK = 1 << 22
_ASSIGNMENT = re.compile(r"^([A-Za-z_]\w*)=(.*)$", re.S)


def _with_variables(words, known=None):
    """The words, plus each word that uses a variable set earlier on the line with that value put in, so the
    script of 'D=/dir; sh $D/g.sh' or 'export D=/dir && sh "${D}/g.sh"' is bound too. A word that would grow
    past MAX_VALUE (D=$D$D on each word, $D$D$D...) is left out: it names no file, and building it could
    take all the memory there is; past MAX_FILLED in all, no more words are added. ${D:-/dir} puts in /dir
    when D is not set, and the name of 'for D in /a /b' is tried with each value (up to MAX_LOOP_VALUES).
    known, when given, is filled with the values found (a loop name with its first)."""
    known, out, total, held = {} if known is None else known, list(words), 0, 0
    loops, loop, loop_at = {}, None, 0  # for NAME in WORDS: the values after the first, tried in turn.

    def put_in(w):
        parts, size, last = [], 0, 0
        for m in _VAR_REF.finditer(w):
            value = _value_of(m, known)
            parts += [w[last:m.start()], value]
            size += m.start() - last + len(value)
            last = m.end()
            if size > MAX_VALUE:
                return None
        parts.append(w[last:])
        return "".join(parts) if size + len(w) - last <= MAX_VALUE else None

    work = [0]

    def fillings(w):
        """The word with values put in, then once for each further combination of the values of the loop
        names it uses (nested loops run each with each), up to MAX_LOOP_VALUES and MAX_LOOP_WORK."""
        yield put_in(w)
        names = sorted(n for n in {m.group(1) or m.group(4) for m in _VAR_REF.finditer(w)}
                       if n in loops and n in known and loops[n])
        if not names:
            return
        firsts = dict((n, known[n]) for n in names)
        try:
            combos = itertools.product(*[[firsts[n]] + loops[n] for n in names])
            next(combos)  # The first of each is the word as already filled.
            for combo in itertools.islice(combos, MAX_LOOP_VALUES):
                work[0] += len(w)
                if work[0] > MAX_LOOP_WORK:
                    return
                known.update(zip(names, combo))
                yield put_in(w)
        finally:
            known.update(firsts)

    for k, w in enumerate(words):
        if "$" in w:
            for filled in fillings(w):
                if total >= MAX_FILLED:
                    break
                if filled is not None and filled != w and total + len(filled) <= MAX_FILLED:
                    out.append(filled)
                    total += len(filled)
        if w == "for" and k + 2 < len(words) and words[k + 2] == "in" and _NAME.match(words[k + 1]):
            loop, loop_at = words[k + 1], k + 3  # for NAME in WORDS: its values start after 'in'.
            known.pop(loop, None)
            loops[loop] = []
            continue
        if loop and k >= loop_at:
            if w in (";", "do", "&&", "||", "|", "&", "\n"):
                loop = None
            else:
                value = put_in(w)
                if value is not None and held + len(value) <= MAX_FILLED:
                    if loop not in known:
                        known[loop] = value
                        held += len(value)
                    elif len(loops[loop]) < MAX_LOOP_VALUES:
                        loops[loop].append(value)
                        held += len(value)
            continue
        m = _ASSIGNMENT.match(w)
        if m:
            value = put_in(m.group(2))
            known.pop(m.group(1), None)
            # Values count toward MAX_FILLED too, or many names set to long values would have no size bound.
            if value is not None and held + len(value) <= MAX_FILLED:
                known[m.group(1)] = value
                held += len(value)
    return out


def _value_of(m, known):
    """What a variable reference stands for: its value when set on the line, or the word of ${NAME:-word} when it
    is not set (or empty, with the ':'), else the reference as it is."""
    name, colon, word = m.group(1) or m.group(4), m.group(2), m.group(3)
    value = known.get(name)
    if word is not None and (value is None or colon and value == ""):
        return word
    return m.group(0) if value is None else value


def _fill_line(line, known):
    """The line with each variable set on it put in, or the line as it is when that would pass MAX_FILLED."""
    if "$" not in line:
        return line
    parts, size, last = [], len(line), 0
    for m in _VAR_REF.finditer(line):
        value = _value_of(m, known)
        size += len(value) - len(m.group(0))
        if size > MAX_FILLED:
            return line  # Stopped here, before the filled line is built.
        parts += [line[last:m.start()], value]
        last = m.end()
    parts.append(line[last:])
    return "".join(parts)


# Redirections whose next word is a file the command only writes (2>>log, &>out, >& out).
_WRITE_REDIRECTS = shell.REDIRECT_WRITE | {">&"}


def _has_quoted_angle(text):
    """True when a '>' sits inside quotes or after a backslash: it is text then, though it reads the same as a
    redirect once the quotes are gone, so no word of such a line is taken for a redirect target."""
    quote, escaped = None, False
    for ch in text:
        if escaped:
            escaped = False
            if ch == ">":
                return True
        elif ch == "\\" and quote != "'":
            escaped = True
        elif quote:
            if ch == quote:
                quote = None
            elif ch == ">":
                return True
        elif ch in "'\"":
            quote = ch
    return False


def _not_written(words):
    """The words without the targets of output redirections: a log the hook appends to is not code it runs,
    and binding it would undo the approval each time the hook runs for real. A file the command also reads
    or runs is still bound through that other word."""
    return [w for i, w in enumerate(words) if not (i and words[i - 1] in _WRITE_REDIRECTS)]


def _with_program(words):
    """The words with the program they start with found on PATH, as the hook's shell would."""
    if words and "/" not in words[0]:
        found = shutil.which(words[0])
        return [found or words[0]] + words[1:]
    return words


def _digest(path, budget):
    """(sha256 of the file, or UNBOUND when it would go past the budget; the budget left)."""
    try:
        if os.path.getsize(path) > budget:
            return UNBOUND, 0
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                budget -= len(block)
                if budget < 0:
                    return UNBOUND, 0  # It grew while being read.
                h.update(block)
        return h.hexdigest(), budget
    except OSError:
        return "unreadable", budget


def reason_signature(reason):
    """A short, stable key for a reason without a rule id: its first line with numbers and quoted text folded."""
    first = (reason or "").strip().split("\n", 1)[0]
    first = re.sub(r"(['\"`]).*?\1", r"\1…\1", first)
    first = re.sub(r"\d+", "#", first)
    first = re.sub(r"\s+", " ", first)
    return first[:100] or "(no reason given)"


def describe_hook_for_approval(spec, home):
    """A human-readable account of what approving this hook allows."""
    return {
        "command": spec.command or None,
        "args": spec.args,
        "plugin_root": spec.plugin_root,
        "runs_as": sandbox.expand_command(spec.command, home, spec.plugin_root) if spec.command else None,
        "fingerprint": spec.fingerprint(home),
    }


def default_hook_name(spec, index):
    base = spec.plugin_root and os.path.basename(spec.plugin_root.rstrip("/")) or "hook"
    return "%s-%d" % (base, index)
