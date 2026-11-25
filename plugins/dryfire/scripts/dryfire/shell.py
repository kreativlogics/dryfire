"""Split a shell command line into simple commands for the guard rules.

This is a best-effort reader, not a shell. It handles quoting, separators,
command substitution, `sh -c` / `eval`, leading VAR=value assignments, common
wrappers (sudo, env, timeout, xargs...) and `cd` inside a chain. What it can't
see (aliases, functions, variables expanded at run time, scripts written and
then run) is listed in the repository's docs/limits.md.
"""

import functools
import os
import shlex

SEPARATORS = {";", "&&", "||", "|", "&", "|&", ";;", ";&", "(", ")", "{", "}"}
REDIRECT_WRITE = {">", ">>", ">|", "&>", "&>>"}
REDIRECT_OTHER = {"<", "<<", "<<<", "<>", ">&", "<&"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox"}
# Wrappers and the options of theirs that take a value.
WRAPPERS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-S", "-C", "--unset", "--chdir", "--split-string"},
    "command": set(),
    "builtin": set(),
    "exec": {"-a"},
    "nohup": set(),
    "time": {"-f", "-o"},
    "nice": {"-n"},
    "ionice": {"-c", "-n", "-p"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "gtimeout": {"-s", "-k", "--signal", "--kill-after"},
    "caffeinate": {"-t", "-w"},
    "xargs": {"-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file"},
    "chronic": set(),
    "unbuffer": set(),
    "watch": {"-n", "-d"},
}


class Cmd(object):
    """One simple command after wrappers and assignments are stripped."""

    __slots__ = ("name", "argv", "args", "env", "redirects", "cwd", "depth")

    def __init__(self, argv, env, redirects, cwd, depth):
        self.argv = argv
        self.name = os.path.basename(argv[0]) if argv else ""
        self.args = argv[1:]
        self.env = env
        self.redirects = redirects  # list of (operator, target)
        self.cwd = cwd
        self.depth = depth

    def __repr__(self):
        return "Cmd(%r, env=%r, redirects=%r, cwd=%r)" % (self.argv, self.env, self.redirects, self.cwd)


class ParseResult(object):
    def __init__(self):
        self.cmds = []
        self.error = False


_WORD_BREAK = " \t\n;&|()<>"
_DELIM_STOP = " \t\n;&|()<>"


def _extract_substitutions(text):
    """Pull out $(...), `...` and <(...) bodies; drop comments and heredoc bodies; turn unquoted newlines into ';'.

    Returns (rewritten_text, [inner_texts]). Inner texts are parsed separately.
    """
    out, inners, _end = _scan(text, 0, False)
    return out, inners


def _scan(text, i, in_subst):
    """Walk text from i with quote state known. In a $(...) body, stop at its closing paren.

    Returns (rewritten_text, inners, index just past the closing paren or len(text)).
    """
    out = []
    inners = []
    n = len(text)
    quote = None
    word_start = True  # Unquoted position where a new word begins (so # starts a comment).
    depth = 0  # Plain ( ... ) groups inside a $(...) body.
    heredocs = []  # (delimiter, strip_tabs, expands) waiting for the next newline.
    while i < n:
        c = text[i]
        if quote == "'":
            out.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            if text[i + 1] != "\n":  # A backslash-newline joins the lines: it is taken out.
                out.append(text[i:i + 2])
                word_start = False
            i += 2
            continue
        if quote is None and c == "'":
            quote = "'"
            out.append(c)
            word_start = False
            i += 1
            continue
        if c == '"':
            quote = None if quote == '"' else '"'
            out.append(c)
            word_start = False
            i += 1
            continue
        arith = i + 1 if c == "$" else i
        if (c == "$" or (quote is None and word_start)) and text.startswith("((", arith) and _is_arith(text, arith):
            # Arithmetic: skip to the matching close so << or # inside it mean nothing.
            out.append("__ARITH__")
            word_start = False
            i = _match_parens(text, arith)
            continue
        if (c == "$" or (c in "<>" and quote is None)) and i + 1 < n and text[i + 1] == "(":
            _o, _in, j = _scan(text, i + 2, True)
            inners.append(text[i + 2:j - 1] if j <= n and text[j - 1:j] == ")" else text[i + 2:j])
            out.append("__SUBST__")
            word_start = False
            i = j
            continue
        if c == "`":
            j = text.find("`", i + 1)
            if j == -1:
                j = n
            inners.append(text[i + 1:j])
            out.append("__SUBST__")
            word_start = False
            i = j + 1
            continue
        if quote == '"':
            out.append(c)
            i += 1
            continue
        # Unquoted from here on.
        if c == "#" and word_start and not (i and text[i - 1] == "(" and opens_pattern(text, i - 1)):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "<" and text.startswith("<<<", i):
            out.append("<<<")
            word_start = True
            i += 3
            continue
        if c == "<" and text.startswith("<<", i):
            i, delim = _heredoc_start(text, i + 2)
            if delim is not None:
                heredocs.append(delim)
            out.append(" << __HEREDOC__ ")
            word_start = True
            continue
        if c == "\n":
            out.append(" ; ")
            i += 1
            word_start = True
            for delim, strip_tabs, expands in heredocs:
                i, body = _heredoc_body(text, i, delim, strip_tabs)
                if expands:
                    inners.extend(_body_substitutions(body))
            heredocs = []
            continue
        if in_subst and c == "(":
            depth += 1
        elif in_subst and c == ")":
            if depth == 0:
                return "".join(out), inners, i + 1
            depth -= 1
        out.append(c)
        word_start = c in _WORD_BREAK
        i += 1
    return "".join(out), inners, n


_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def opens_pattern(text, k):
    """True when the '(' at text[k] is glued to a word, which makes it part of a pattern (zsh's /(#i)x glob
    flag, or x=(#i)y as an argument), so a '#' after it starts no comment. NAME=( or NAME+=( as the first word
    of a command opens an array instead, where a '#' does start one (a=(# x)). A '(' after a word and a blank
    is a pattern too (zsh's ls (#i)x; bash refuses the line); one that starts a command opens a subshell. Only
    the name or the blanks before the '(' are read, so the calls for a line stay linear."""
    if k == 0 or text[k - 1] in "\n;&|($<>":
        return False
    if text[k - 1] in " \t":
        j = k - 1
        while j > 0 and text[j - 1] in " \t":
            j -= 1
        return j > 0 and text[j - 1] not in "\n;&|("

    if text[k - 1] != "=":
        return True
    end = k - 2 if k > 1 and text[k - 2] == "+" else k - 1
    start = end
    while start > 0 and text[start - 1] in _NAME_CHARS:
        start -= 1
    if start == end or text[start].isdigit():
        return True
    while start > 0 and text[start - 1] in " \t":
        start -= 1
    return start > 0 and text[start - 1] not in ";&|(\n"


def _cd_folder(args):
    """The folder cd or pushd goes to, after its options (-P, -L, -e, -@, --); None for cd - or no folder."""
    for k, a in enumerate(args):
        if a == "--":
            return args[k + 1] if k + 1 < len(args) else None
        if not (a.startswith("-") and len(a) > 1 and set(a[1:]) <= set("PLe@")):
            return None if a.startswith("-") else a
    return None


def _match_parens(text, i):
    """Index just past the parens group that opens at text[i] (the end of the text when it never closes)."""
    return _closers(text).get(i, len(text))


@functools.lru_cache(maxsize=8)
def _closers(text):
    """Each '(' of the text mapped to the index just past its ')', found in one pass: matching from each '('
    in turn rescans the rest of the text, which a long run of unclosed ones makes take minutes."""
    out, opened = {}, []
    for k, ch in enumerate(text):
        if ch == "(":
            opened.append(k)
        elif ch == ")" and opened:
            out[opened.pop()] = k + 1
    return out


def _is_arith(text, i):
    """True when the (( at text[i] closes with )) as one pair, as the shell requires for arithmetic."""
    inner_end = _match_parens(text, i + 1)
    return inner_end < len(text) and text[inner_end] == ")" and _match_parens(text, i) == inner_end + 1


def _heredoc_start(text, i):
    """Read the delimiter after << or <<-. Returns (index after it, (word, strip_tabs, expands) or None)."""
    n = len(text)
    strip_tabs = text.startswith("-", i)
    if strip_tabs:
        i += 1
    while i < n and text[i] in " \t":
        i += 1
    word = []
    quoted = False
    quote = None
    while i < n:
        c = text[i]
        if quote:
            if c == quote:
                quote = None
            else:
                word.append(c)
            i += 1
            continue
        if c in "'\"":
            quote = c
            quoted = True
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            quoted = True
            word.append(text[i + 1])
            i += 2
            continue
        if c in _DELIM_STOP:
            break
        word.append(c)
        i += 1
    if not word:
        return i, None
    return i, ("".join(word), strip_tabs, not quoted)


def _heredoc_body(text, i, delim, strip_tabs):
    """Skip lines up to and including the delimiter line. Returns (index after it, body)."""
    n = len(text)
    start = i
    while i < n:
        j = text.find("\n", i)
        line_end = n if j == -1 else j
        line = text[i:line_end]
        if (line.lstrip("\t") if strip_tabs else line) == delim:
            return (line_end + 1 if j != -1 else n), text[start:i]
        i = line_end + 1 if j != -1 else n
    return n, text[start:]  # No delimiter line: the shell reads to the end too.


def _body_substitutions(body):
    """$(...) and `...` in an unquoted heredoc body run when the heredoc is read."""
    found = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "$" and body.startswith("$(", i) and not body.startswith("$((", i):
            _o, _in, j = _scan(body, i + 2, True)
            found.append(body[i + 2:j - 1] if body[j - 1:j] == ")" else body[i + 2:j])
            i = j
            continue
        if c == "`":
            j = body.find("`", i + 1)
            j = n if j == -1 else j
            found.append(body[i + 1:j])
            i = j + 1
            continue
        i += 1
    return found


_OPERATORS = sorted(SEPARATORS | REDIRECT_WRITE | REDIRECT_OTHER, key=len, reverse=True)
_PUNCT = set("();<>|&")


def _tokens(text):
    lex = shlex.shlex(text, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    out = []
    for tok in lex:
        if tok and set(tok) <= _PUNCT and tok not in SEPARATORS and tok not in REDIRECT_WRITE \
                and tok not in REDIRECT_OTHER:
            out.extend(_split_operators(tok))
        else:
            out.append(tok)
    return out


def _split_operators(tok):
    """shlex glues runs of operator characters (`);`, `((`); split them into shell operators."""
    parts = []
    i = 0
    while i < len(tok):
        op = next((o for o in _OPERATORS if tok.startswith(o, i)), tok[i])
        parts.append(op)
        i += len(op)
    return parts


def _is_assignment(tok):
    if "=" not in tok or tok.startswith("="):
        return False
    name = tok.split("=", 1)[0]
    return name.replace("_", "a").isalnum() and not name[0].isdigit()


def _unwrap(argv, env):
    """Remove wrapper commands and their options. Returns (argv, env)."""
    guard = 0
    while argv and guard < 10:
        guard += 1
        name = os.path.basename(argv[0])
        if name not in WRAPPERS:
            break
        takes = WRAPPERS[name]
        i = 1
        if name == "command" and len(argv) > 1 and argv[1] in ("-v", "-V"):
            return [], env  # a lookup, not a run
        while i < len(argv):
            a = argv[i]
            if name == "env" and _is_assignment(a):
                k, v = a.split("=", 1)
                env[k] = v
                i += 1
                continue
            if a == "--":
                i += 1
                break
            if a.startswith("-") and len(a) > 1:
                if a in takes:
                    i += 2
                else:
                    i += 1
                continue
            if name in ("timeout", "gtimeout") and a[:1].isdigit():
                i += 1
                continue
            if name == "nice" and a.lstrip("-").isdigit():
                i += 1
                continue
            break
        argv = argv[i:]
    return argv, env


def _expand_path(word, cwd, home):
    """Expand ~ and $HOME-style references and make a path absolute."""
    w = word
    if w.startswith("~/") or w == "~":
        w = home + w[1:]
    for var in ("$HOME", "${HOME}"):
        if w.startswith(var):
            w = home + w[len(var):]
    for var, val in (("$CLAUDE_PLUGIN_DATA", os.environ.get("CLAUDE_PLUGIN_DATA")),
                     ("${CLAUDE_PLUGIN_DATA}", os.environ.get("CLAUDE_PLUGIN_DATA")),
                     ("$CLAUDE_PLUGIN_ROOT", os.environ.get("CLAUDE_PLUGIN_ROOT")),
                     ("${CLAUDE_PLUGIN_ROOT}", os.environ.get("CLAUDE_PLUGIN_ROOT")),
                     ("$CLAUDE_PROJECT_DIR", os.environ.get("CLAUDE_PROJECT_DIR")),
                     ("${CLAUDE_PROJECT_DIR}", os.environ.get("CLAUDE_PROJECT_DIR"))):
        if val and w.startswith(var):
            w = val + w[len(var):]
    if not os.path.isabs(w):
        w = os.path.join(cwd or os.getcwd(), w)
    return os.path.normpath(w)


def expand_path(word, cwd, home=None):
    return _expand_path(word, cwd, home or os.path.expanduser("~"))


def parse(command, cwd=None, home=None, _depth=0, _result=None):
    """Parse a command line into a ParseResult with a flat list of Cmd."""
    result = _result if _result is not None else ParseResult()
    home = home or os.path.expanduser("~")
    if _depth > 6 or not command:
        return result
    text, inners = _extract_substitutions(command)
    for inner in inners:
        parse(inner, cwd, home, _depth + 1, result)
    try:
        tokens = _tokens(text)
    except ValueError:
        result.error = True
        tokens = text.split()

    current = []
    groups = []
    for tok in tokens:
        if tok in SEPARATORS:
            if current:
                groups.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        groups.append(current)

    for group in groups:
        env = {}
        redirects = []
        argv = []
        i = 0
        while i < len(group):
            tok = group[i]
            if tok in REDIRECT_WRITE or tok in REDIRECT_OTHER:
                target = group[i + 1] if i + 1 < len(group) else ""
                redirects.append((tok, target))
                i += 2
                continue
            if not argv and _is_assignment(tok):
                k, v = tok.split("=", 1)
                env[k] = v
                i += 1
                continue
            argv.append(tok)
            i += 1
        # A trailing fd number before a redirect (2>file) stays as an argument; drop pure digits.
        argv = [a for a in argv if not (a.isdigit() and len(a) == 1 and redirects)] if redirects else argv
        argv, env = _unwrap(argv, env)
        if not argv:
            if redirects:
                result.cmds.append(Cmd([":"], env, redirects, cwd, _depth))
            continue
        name = os.path.basename(argv[0])
        if name in ("cd", "pushd"):
            folder = _cd_folder(argv[1:])
            if folder:
                cwd = _expand_path(folder, cwd, home)
            continue
        if name in SHELLS:
            script = _shell_c_arg(argv)
            if script is not None:
                parse(script, cwd, home, _depth + 1, result)
                continue
        if name == "eval":
            parse(" ".join(argv[1:]), cwd, home, _depth + 1, result)
            continue
        result.cmds.append(Cmd(argv, env, redirects, cwd, _depth))
    return result


def _shell_c_arg(argv):
    for i, a in enumerate(argv[1:], 1):
        if a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]):
            return argv[i + 1] if i + 1 < len(argv) else ""
    return None


def short_flags(arg, takes_value=""):
    """Letters in a short-option cluster like -fd, stopping at a value-taking letter."""
    if not arg.startswith("-") or arg.startswith("--") or len(arg) < 2:
        return ""
    letters = []
    for ch in arg[1:]:
        letters.append(ch)
        if ch in takes_value:
            break
    return "".join(letters)
