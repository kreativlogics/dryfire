"""dryfire's own PreToolUse hook: keep the agent from approving hooks for itself
or changing dryfire's approvals, config or code.

Approving a hook is the one step that lets dryfire run code, so it must come
from you, not from the agent: the approve commands ask (and are refused when
nobody is there to answer). Writes into dryfire's data folder or plugin
folder are refused outright.

This is a speed bump, not a wall: an agent with unrestricted shell access can
reach the same files in ways no command parser sees (for example by writing
a script first and running it). THREAT-MODEL.md says what it does and does
not cover.
"""

import json
import os
import re
import shlex

from . import context, secrets, shell

UNATTENDED = context.UNATTENDED_MODES
OWN_SCRIPTS = ("cli.py", "cfgtool.py")
# Every subcommand each script has. Any other word in that place ($A, $(...), xargs' {}) is only known when the
# line runs, so it could be one of the changing ones.
SUBCOMMANDS = {
    "cli.py": {"detect", "scan", "replay", "approve"},
    "cfgtool.py": {"show", "explain", "set", "unset", "init", "approve", "doctor"},
}
CHANGING = {
    "cli.py": {"approve"},
    "cfgtool.py": {"set", "unset", "init", "approve"},
}
# Options each script takes before its subcommand, with a value (cfgtool.py --data X show).
GLOBAL_VALUE_OPTIONS = {
    "cli.py": (),
    "cfgtool.py": ("--data", "--project"),
}
READ_ONLY = {
    "cat", "head", "tail", "less", "more", "ls", "stat", "file", "wc", "grep", "egrep", "fgrep", "rg", "jq",
    "diff", "cmp", "shasum", "sha256sum", "sha1sum", "md5", "md5sum", "du", "tree", "realpath", "readlink",
    "basename", "dirname", "echo", "printf", "test", "[", "true", "false", "pwd", "find",
}
FIND_ACTIONS = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
# Programs that run a Python script named among their arguments.
RUNNERS = {"pypy", "pypy3", "uv", "uvx", "pipx", "pipenv", "poetry", "pdm", "hatch", "rye", "pixi", "conda", "mamba",
           "micromamba", "pyenv", "asdf", "mise", "rtx"}
EDIT_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
DATA_REFS = ("$CLAUDE_PLUGIN_DATA", "${CLAUDE_PLUGIN_DATA}")
_PY = re.compile(r"^python(\d+(\.\d+)?)?$")
# Launchers the shared parser does not unwrap (arch, script, flock, taskpolicy, parallel, find -exec...): a
# command whose later word is an interpreter, a runner or dryfire's script is also read from that word on.
LAUNCHER_DEPTH = 4
# Launchers with an option that takes a whole command line (flock -c, script -qc, --command=...).
COMMAND_OPTION = {"flock": ("c", "--command"), "script": ("c", "--command")}
# env's short options that take a value (-u NAME, -C DIR, -P PATH). Its -S (--split-string) takes a whole
# command line, which the shared parser drops along with the rest of the env command, so it is read here.
ENV_VALUE_LETTERS = "uCPa"
# env's long options that take a value in the next word; getopt accepts any unambiguous prefix (--spl, --un).
ENV_VALUE_OPTIONS = ("unset", "chdir", "argv0")
# env -S escapes: \_ separates words, \c ends the line, \f \n \r \t \v are whitespace.
_ENV_ESCAPE = re.compile(r"\\(.)", re.S)
# Words with which a script runs without a subcommand and changes nothing.
NO_SUBCOMMAND = {"--help", "-h", "--version"}
# Leading words of a part of the line whose arguments are text, not a command to run. find (-exec) is left
# out, and git counts only with one of GIT_TEXT right after it: git -c alias.x='!...' or a ! alias it
# runs can run a command line.
TEXT_COMMANDS = READ_ONLY - {"find", "git", "rg"}  # rg --pre runs a command.
GIT_TEXT = {"commit", "log", "show", "diff", "status", "add", "blame"}  # Not grep: -O runs a command.
# Ways a line can turn text into the words of another command (xargs, a heredoc or here-string body the
# parser does not trace, a command or process substitution): with any of them, text commands are read like
# the rest.
# printf -v stores its text in a variable (-v quoted or escaped too), and a coprocess is a shell reading what
# is sent to it (>&$fd). A ${...} that runs code counts as well, inside double quotes too: bash's ${ cmd; } and
# ${| cmd; }, zsh's flags such as ${(e)...}, which run what a value spells, and bash's ${v@P}.
_RUNS_IN_BRACES = re.compile(r"\$\{[\s|(]|\$\{[^{}]*@P")
_FEEDS = re.compile(r"\bxargs\b|\bparallel\b|<<|[$<>]\(|`|\bcoproc\b|[<>]&\s*[\"']?\$")
# Text kept in a variable or a string and run later on the same line feeds too, matched outside quotes: eval,
# trap, source, let or . as a word of a command that is not a text command or a program named by a bare word
# (_RUNNER_WORDS; 2>/dev/null eval, time -p eval, x=1 . f), a -c or -S whose word may expand (sh -c "$x",
# bash -c "H""$x", env -S $x; _DASH_C), and the places a value is read as an arithmetic expression, whose
# array subscripts run $(...) (((, [[).
_RUNS_TEXT = re.compile(r"(?:^|[;&|(\n])\s*\.\s|\(\(|\[\[")
_RUNNER_WORDS = {"eval", "trap", "source", "let", "."}
_ASSIGNMENT_WORD = re.compile(r"^[A-Za-z_]\w*\+?=")
_DASH_C = re.compile(r"\s-[A-Za-z]*[cS][A-Za-z]*\s*")
_SPELLED = re.compile(r"[\\'\"$`]")
_WORD_END = re.compile(r"[\s;&|]")
# Any ${...} but a plain ${NAME}, in code or double quotes: ${!v}, ${v:n} and ${a[n]} read a value as code.
_BRACED = re.compile(r"\$\{(?![A-Za-z_]\w*\})")
# printf -v (the -v quoted or escaped too) after printf in the same command.
_PRINTF_V = re.compile(r"\s['\"\\]*-['\"\\]*v")
_COMMAND_END = re.compile(r"[;|&\n]")


def _feeds(text):
    """True when the text holds a way to turn text into a command or a value read as code (_FEEDS,
    _RUNS_TEXT, _BRACED), or a printf -v. Each command is searched once from its first printf, so many
    printf words stay linear."""
    if _FEEDS.search(text):
        return True
    blanked = _blank_quoted(text)
    braced = [m.start() for m in _BRACED.finditer(text)]
    if _RUNS_TEXT.search(blanked) or _runs_stored_text(text, blanked) or \
            any(_code_or_double_quoted(text, blanked, braced)):
        return True
    for command in _COMMAND_END.split(text):
        at = command.find("printf")
        if at >= 0 and _PRINTF_V.search(command, at):
            return True
    return False


def _runs_stored_text(text, blanked):
    """True when eval, trap, source, let or . is a word of a command that may run it as a builtin, or a -c
    or -S is given a word that can expand ($x, "$x", "H""$x"). Text commands and programs named by a bare word
    only name them (grep -c "approve", echo let, make eval); anything else counts, whatever stands before the
    word (2>/dev/null eval, command -p eval, repeat 1 eval). Each part and each -c word is read once."""
    for part in _SEPARATORS.split(blanked):
        words = part.split()
        while words and _ASSIGNMENT_WORD.match(words[0]):
            words = words[1:]  # X=1 eval: the command comes after the assignments.
        if not words or _is_text(words) or words[0] in _PLAIN_BUILTINS:
            continue
        if _LITERAL_NAME.match(words[0]) and words[0] not in _SHELL_WORDS:
            continue
        # A word spelled through quotes, a backslash or an expansion may be eval itself ($E, \eval, e''val).
        if _RUNNER_WORDS.intersection(words) or any(_SPELLED.search(w) for w in words):
            return True
    for m in _DASH_C.finditer(blanked):
        end = _WORD_END.search(blanked, m.end())
        span = text[m.end():end.start() if end else len(text)]
        if "$" in span or "`" in span:
            return True
    return False


# Where one command of a line ends: a '|' or '&' that is part of a redirect (2>&1, &>f, >&2, >|f) is not one.
# It is matched on a copy with quoted and escaped characters blanked, so grep -E "a|b" stays one part.
_SEPARATORS = re.compile(r"\|\||(?<!>)\|&?|&&|(?<![<>])&(?!>)|[;\n(){}`]")
# env as a word of a line shlex could not read ($'env', "env", \env, $(true)env), not .env, my-env or environment.
_ENV_WORD = re.compile(r"(?<![\w.\-])env(?=[\s'\"\\;|&)]|$)")
# HOME decides where dryfire's fallback data folder is; CLAUDE_PLUGIN_DATA is the plugin's own one. Any
# mention of either that is not a plain read ($HOME, ${HOME}, ${HOME:-x}) may set it (HOME=x, HOME+=x,
# read HOME, for HOME in, printf -v HOME, ${HOME:=x}), so a line with one that runs dryfire is asked about.
_DATA_VAR = re.compile(r"(?<![A-Za-z0-9_])(HOME|CLAUDE_PLUGIN_DATA)(?![A-Za-z0-9_])")
# The words that make the scripts change approvals or config, and a word that names dryfire's code.
CHANGING_WORDS = {"approve", "set", "unset", "init"}
_WORD = re.compile(r"[^\s'\"`;|&()<>=]+")
_MODULE = re.compile(r"^(?:-[A-Za-z]*m)?(?:dryfire(?:\.\w+)*|(?:scripts\.)?(?:cli|cfgtool))$")
_QUOTING = re.compile(r"[\\'\"]")
_M_OPTION = re.compile(r"^-[A-Za-z]*m$")


class Verdict(object):
    __slots__ = ("decision", "reason")

    def __init__(self, decision, reason):
        self.decision = decision
        self.reason = reason


def protected_dirs(home, env):
    """dryfire's data folders: the plugin's own and the fallback used outside the plugin."""
    out = [os.path.join(home, ".claude", "dryfire")]
    data = (env.get("CLAUDE_PLUGIN_DATA") or "").strip()
    if data:
        out.insert(0, data)
    return [os.path.normpath(p) for p in out]


def _ask(reason, unattended):
    if unattended:
        return Verdict("deny", reason + " Nobody is there to confirm in this permission mode, so it is refused.")
    return Verdict("ask", reason)


def _own_script(cmd, plugin_root):
    """(script, arguments after it, verified) when cmd runs one of dryfire's scripts, else (None, None, False).

    The script may be the command itself or an argument of an interpreter or a runner (python3 with any
    flags, uv run, pipenv run, ...). A script with the same name somewhere else is not dryfire's, so it gets
    no exemption. 'python3 -m dryfire.main' can't be traced to a folder: it is treated as dryfire's for the
    approval check (verified False) but gets no exemption either, and so is a top-level module named cli or
    cfgtool ('python3 -m cli' run from the scripts folder or with it on PYTHONPATH, or 'scripts.cli').
    """
    words = list(cmd.argv) or [cmd.name] + list(cmd.args)
    if cmd.name in OWN_SCRIPTS and _is_ours(words[0], cmd, plugin_root):
        return cmd.name, words[1:], True
    if not (_PY.match(cmd.name) or cmd.name in RUNNERS):
        return None, None, False
    for i, w in enumerate(words[1:], 1):
        module, after = _module(words, i)
        if module is not None:
            if not _MODULE.match(module):
                return None, None, False  # Another package's cli module (myapp.cli) is not dryfire's.
            return ("cfgtool.py" if module.endswith("cfgtool") else "cli.py"), words[after:], False
        if os.path.basename(w) in OWN_SCRIPTS and _is_ours(w, cmd, plugin_root):
            return os.path.basename(w), words[i + 1:], True
    return None, None, False


def _module(words, i):
    """(module, index after it) when words[i] is -m or a short-option cluster ending in m (-Im, -mx.y)."""
    w = words[i]
    if not w.startswith("-") or w.startswith("--"):
        return None, 0
    for j, ch in enumerate(w[1:], 1):
        if ch in "WXc":  # These take a value, so any later m is part of it.
            return None, 0
        if ch == "m":
            if w[j + 1:]:
                return w[j + 1:], i + 1
            return (words[i + 1], i + 2) if i + 1 < len(words) else (None, 0)
    return None, 0


def _is_ours(script, cmd, plugin_root):
    folder = os.path.dirname(script)
    if folder in ("${CLAUDE_PLUGIN_ROOT}/scripts", "$CLAUDE_PLUGIN_ROOT/scripts"):
        return True
    if not plugin_root:
        return False
    path = shell.expand_path(script, cmd.cwd, None)
    return os.path.normpath(os.path.dirname(os.path.realpath(path))) == \
        os.path.normpath(os.path.join(plugin_root, "scripts"))


def _subcommand(script, rest):
    """The script's subcommand: the first word that is neither an option nor a global option's value.

    The scripts refuse abbreviated options, so only the full names need skipping.
    """
    skip = False
    for a in rest:
        if skip:
            skip = False
        elif a in GLOBAL_VALUE_OPTIONS[script]:
            skip = True
        elif not a.startswith("-"):
            return a
    return ""


def _data_args(rest):
    out = []
    for i, a in enumerate(rest):
        if a == "--data" and i + 1 < len(rest):
            out.append(rest[i + 1])
        elif a.startswith("--data="):
            out.append(a[len("--data="):])
    return out


def _is_read_only(cmd):
    if cmd.name not in READ_ONLY:
        return False
    if cmd.name == "find" and any(a in FIND_ACTIONS for a in cmd.args):
        return False
    return True


def _mentions(text, dirs, home):
    for d in dirs:
        forms = {d, d.rstrip("/") + "/"}
        if home and context.inside(d, home):
            forms.add("~" + d[len(home.rstrip("/")):])
            forms.add("$HOME" + d[len(home.rstrip("/")):])
            forms.add("${HOME}" + d[len(home.rstrip("/")):])
        if any(f in text for f in forms):
            return True
    return any(ref in text for ref in DATA_REFS)


def _short(command):
    text = secrets.mask(command).replace("\n", " ")
    return text if len(text) <= 160 else text[:157] + "..."


def _launched(cmds, home, depth=0, text_ok=True):
    """Each command, followed by the commands it launches that the shared parser left as arguments. With
    text_ok False (the line may redefine commands), text commands are unwrapped like the rest."""
    for cmd in cmds:
        yield cmd
        if depth >= LAUNCHER_DEPTH:
            continue
        if text_ok and ((cmd.name in READ_ONLY and cmd.name != "find") or _is_text(cmd.argv)):
            continue  # git log -- cli.py names the script as a path; a text command runs none of its words.
        words = list(cmd.argv)
        for i in range(1, len(words)):
            name = os.path.basename(words[i])
            line = _command_option(cmd.name, words, i)
            if line is not None:
                inner = shell.parse(line, cwd=cmd.cwd, home=home).cmds
            elif _PY.match(name) or name in RUNNERS or name in OWN_SCRIPTS or name in shell.SHELLS:
                inner = shell.parse(" ".join(shlex.quote(w) for w in words[i:]), cwd=cmd.cwd, home=home).cmds
            else:
                continue
            for c in inner:
                c.env = dict(cmd.env, **c.env)
            for c in _launched(inner, home, depth + 1, text_ok):
                yield c
            break


def _command_option(name, words, i):
    """The command line words[i] hands to a launcher (flock -c X, script -qc X, --command=X), else None."""
    short, long_name = COMMAND_OPTION.get(name, ("", ""))
    w = words[i]
    if not short:
        return None
    if w.startswith(long_name + "="):
        return w[len(long_name) + 1:]
    if w == long_name or (w.startswith("-") and not w.startswith("--") and w.endswith(short)):
        return words[i + 1] if i + 1 < len(words) else None
    return None


def _split_strings(command):
    """The command lines handed to env -S or --split-string anywhere in the line, or None when unreadable."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""  # A '#' inside a word (a#b) starts no comment in a shell.
    try:
        words = list(lex)
    except ValueError:
        return None
    out = []
    i = 0
    while i < len(words):
        if not _may_be_env(words[i]):
            i += 1
            continue
        line, i = _env_split_string(words, i + 1)
        if line is not None:
            out.append(_env_unescape(line))
    return out


def _may_be_env(word):
    """True when the word is env or may turn into it when the line expands ($'env', ${E}env, e$Xnv)."""
    return os.path.basename(word) == "env" or "$" in word or "`" in word


def _env_unescape(line):
    """The line as env -S splits it, for the escapes that change where words break or end."""
    out, last = [], 0
    for m in _ENV_ESCAPE.finditer(line):
        out.append(line[last:m.start()])
        ch = m.group(1)
        if ch == "c":
            return "".join(out)
        out.append(" " if ch == "_" or ch in "fnrtv" else m.group(0))
        last = m.end()
    out.append(line[last:])
    return "".join(out)


def _env_split_string(words, k):
    """(the value of env's -S, or None; where reading stopped) for env's options starting at words[k].

    Reading goes on from where this stops, so each word is read once even on a long line.
    """
    while k < len(words):
        w = words[k]
        name, eq, value = w[2:].partition("=")
        if w.startswith("--") and name and "split-string".startswith(name):
            if eq:
                return value, k + 1
            return (words[k + 1] if k + 1 < len(words) else None), k + 2
        if w.startswith("--") and name and not eq and any(o.startswith(name) for o in ENV_VALUE_OPTIONS):
            k += 2
        elif w.startswith("--"):
            k += 1  # Other long options take no value or carry it after '='.
        elif w.startswith("-") and len(w) > 1:
            k += 1
            for j, ch in enumerate(w[1:], 1):
                if ch == "S":
                    if w[j + 1:]:
                        return w[j + 1:], k
                    return (words[k] if k < len(words) else None), k + 1
                if ch in ENV_VALUE_LETTERS:
                    k += 0 if w[j + 1:] else 1
                    break
        elif "=" in w and not w.startswith("="):
            k += 1
        else:
            return None, k  # The command env runs, which is read on its own.
    return None, k


# The variables a line that runs dryfire may read as they are: the plugin's own folders and HOME.
_OWN_REFS = re.compile(r"\$(?:\{(?:HOME|CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA)\}|(?:HOME|CLAUDE_PLUGIN_ROOT|"
                       r"CLAUDE_PLUGIN_DATA)(?!\w))")
# What can make a name only once the line runs: any expansion ($V, ${V^^}, $'\x48', $(...), `...`), a brace
# list or range, a glob or a zsh glob qualifier glued to a word (/(e:...:)), and text the shell reads
# again (source, ., eval, trap, emulate -c, printf -v), declare, typeset or local (-u and -l change a value's
# case, -i evaluates it), arithmetic, which reads a variable's value as an expression ((( n )), let n), and
# the commands that give a variable a value from outside the line (read, mapfile, select, vared, sysread):
# echo 0=EMOH | rev | (read n; (( n ))) sets HOME.
_MAY_BUILD = re.compile(r"[$`{*?\[]|\(\(|(?<=[^\s;&|(<>\"'])\(|(?<![\w./-])(?:source|eval|trap|emulate|printf|"
                        r"declare|typeset|local|let|read|mapfile|readarray|select|vared|sysread|\.)(?![\w./-])")


def _changes_data_var(command):
    """True when the line may set HOME or CLAUDE_PLUGIN_DATA. Quotes and backslashes do not stop a word from
    being a name to the shell (HO''ME=x, H\\OME=x). A name can also be built in more ways than can be listed
    (HO${Z}ME, {HO,}ME, HOM?, $'HO\\x4dE', text decoded and sourced), so any of those asks; this is only
    used on lines that run dryfire, which its own commands keep free of them. Each test is made on the text
    as it is and with quotes and backslashes taken out (e''val), and a backslash-newline in single quotes
    is taken out too, as text read again would join it (trap 'HO\\<newline>ME=x')."""
    plain = _QUOTING.sub("", command.replace("\\\n", ""))
    return _data_var_set(command) or _data_var_set(plain) or \
        any(_MAY_BUILD.search(_OWN_REFS.sub("", text)) for text in (command, plain))


def _starts_comment(text, k):
    """True when the '#' at text[k] starts a comment: it begins a word, outside quotes (the caller's part), and
    the character before it is not escaped. After a '(' it starts one only when that '(' does not make a
    pattern (shell.opens_pattern, which the parser uses too, so both read the same comments)."""
    if k and text[k - 1] not in " \t\n;&|()":
        return False
    if k and text[k - 1] == "(" and shell.opens_pattern(text, k - 1):
        return False  # zsh's /(#i)x glob flag and echo x=(#i)y; a=(# x at a command's start is a comment.
    escapes, j = 0, k - 2
    while j >= 0 and text[j] == "\\":
        escapes, j = escapes + 1, j - 1
    return escapes % 2 == 0  # After \; or \  the '#' is part of the word (echo \;#), not a comment.


def _joined(text):
    """The text with each backslash-newline outside single quotes and comments taken out, as the shell joins
    those lines (HO, a backslash-newline, then ME=x sets HOME). A comment ends at its newline whatever comes
    before it, so the next line still runs; inside $'...' a backslash escapes the next character."""
    out, quote, k, n = [], None, 0, len(text)
    while k < n:
        ch = text[k]
        if quote is None and ch == "#" and _starts_comment(text, k):
            end = text.find("\n", k)
            end = n if end < 0 else end
            out.append(text[k:end])
            k = end
            continue
        if ch == "\\" and quote != "'" and k + 1 < n:
            if text[k + 1] != "\n" or quote == "$'":
                out.append(text[k:k + 2])
            k += 2
            continue
        if quote is None and ch == "$" and text.startswith("'", k + 1):
            quote = "$'"
            out.append("$'")
            k += 2
            continue
        if ch == "'" and quote in ("'", "$'"):
            quote = None
        elif ch in "'\"" and quote in (None, ch):
            quote = None if quote else ch
        out.append(ch)
        k += 1
    return "".join(out)


def _names_data_var(command):
    """True when HOME or CLAUDE_PLUGIN_DATA is written on the line other than as a plain read, quotes and
    backslash-newlines taken out too (x='HO''ME=/x ...')."""
    return _data_var_set(command) or _data_var_set(_QUOTING.sub("", command.replace("\\\n", "")))


def _only_text_commands(command):
    """True when every part of the line is a text command or a plain builtin (git commit, grep, echo, cd),
    so no part can read a value as words to run or as names to set (bash -ce "$x", env $x, perl -e)."""
    for part in _SEPARATORS.split(_blank_quoted(command)):
        words = part.split()
        if words and not (_is_text(words) or words[0] in _PLAIN_BUILTINS):
            return False
    return True


def _data_var_set(command):
    for m in _DATA_VAR.finditer(command):
        before, after = command[:m.start()], command[m.end():]
        if before.endswith("${") and not after.startswith((":=", "=")):
            continue
        if before.endswith("$") and not before.endswith("\\$"):
            continue
        return True
    return False


def _names_dryfire(command, plugin_root, cwd=None):
    """True when the line names dryfire or its plugin folder, or runs from inside that folder (cli.py)."""
    inside = bool(plugin_root and cwd and context.inside(cwd, plugin_root))
    return inside or "dryfire" in command or bool(plugin_root and plugin_root in command) or \
        "CLAUDE_PLUGIN_ROOT" in command


# dryfire's scripts or modules named on a line: cli.py, cfgtool.py, -m dryfire..., -m cli, -m scripts.cli.
_OWN_CODE = re.compile(r"(?<![\w.-])(?:cli|cfgtool)\.py(?![\w.-])|-[A-Za-z]*m\s*(?:dryfire|(?:scripts\.)?(?:cli|cfgtool))"
                       r"(?![\w-])")


def _names_own_code(command, plugin_root, cwd=None):
    """True when the line names dryfire's scripts or modules, its plugin folder, or runs from inside it; a path
    that only passes through a folder named dryfire (ls ~/src/dryfire | sort) does not count."""
    inside = bool(plugin_root and cwd and context.inside(cwd, plugin_root))
    return inside or bool(_OWN_CODE.search(command)) or bool(plugin_root and plugin_root in command) or \
        "CLAUDE_PLUGIN_ROOT" in command


def _untraced_run(consumed, command, plugin_root, text_ok=True):
    """True when a line names dryfire's code and has a changing word that no traced run accounts for.

    It reads the raw text, not the parsed commands, because what it is for is the lines the parser could
    not follow (env -S '...', a copy of the scripts, words fed in by xargs). The first word of each part
    of the line is a command (set -e), not an argument.
    """
    tokens = []
    feeds = _feeds(_without_text_heredocs(command))
    parts, feeding = _feeding_parts(command, text_ok)
    for n, words in enumerate(parts):
        if text_ok and not feeds and not feeding[n] and _is_text(words):
            continue  # grep approve cli.py, git log -p -- cli.py: text about dryfire, not a run of it.
        tokens += [(t, i > 0) for i, t in enumerate(words)]
    left = [t for t, is_arg in tokens if is_arg and t in CHANGING_WORDS]
    for word in consumed:
        if word in left:
            left.remove(word)
    if not left:
        return False
    names_dryfire = _names_dryfire(command, plugin_root)
    for k, (t, _) in enumerate(tokens):
        if _MODULE.match(t) and (t.startswith("-") or (k and _M_OPTION.match(tokens[k - 1][0]))):
            return True
        if names_dryfire and os.path.basename(t) in OWN_SCRIPTS:
            return True
    return False


def _feeding_parts(command, text_ok=True):
    """The words of each part of the line, and for each part whether its output is piped into a command,
    directly or through text commands (echo ... | cat | sh); a pipe into text commands only (grep ... | head)
    feeds none, unless the line may redefine them (text_ok False)."""
    parts, seps, start = [], [], 0
    for m in _SEPARATORS.finditer(_blank_quoted(command)):
        parts.append(_WORD.findall(command[start:m.start()]))
        seps.append(m.group())
        start = m.end()
    parts.append(_WORD.findall(command[start:]))
    feeding = [False] * len(parts)
    for n in range(len(parts) - 2, -1, -1):
        if seps[n] in ("|", "|&"):
            feeding[n] = not (text_ok and _is_text(parts[n + 1])) or feeding[n + 1]
    return parts, feeding


def _feeds_text(command, text_ok=True):
    """True when the line can turn text into another command's words: a pipe into a command, xargs, a heredoc
    or here-string, a substitution (a commit message's quoted heredoc printed by cat is left out)."""
    return _feeds(_without_text_heredocs(command)) or any(_feeding_parts(command, text_ok)[1])


# The builtins and reserved words of bash 5 and zsh 5 (compgen -b -k; ${(k)builtins} ${(k)reswords}): the only
# command names that run inside the shell itself, so the only ones that can change what a later command name
# runs (eval, source, alias, hash, read PATH, typeset -f, functions, enable, emulate...). A command found on
# PATH (make, python3, tee) runs in a process of its own and cannot.
_SHELL_WORDS = frozenset("""
    ! - . : [ [[ ]] { } alias autoload bg bind bindkey break builtin bye caller case cd chdir command compadd
    comparguments compcall compctl compdescribe compfiles compgen complete compgroups compopt compquote compset
    comptags comptry compvalues continue coproc declare dirs disable disown do done echo echotc echoti elif else
    emulate enable end esac eval exec exit export false fc fg fi float for foreach function functions getln
    getopts hash help history if in integer jobs kill let limit local log logout mapfile nocorrect noglob popd
    print printf private pushd pushln pwd r read readarray readonly rehash repeat return sched select set setopt
    shift shopt source suspend test then time times trap true ttyctl type typeset ulimit umask unalias unfunction
    unhash unlimit unset unsetopt until vared wait whence where which while zcompile zformat zle zmodload
    zparseopts zregexparse zstyle
""".split())
# The builtins a plain line may start with: they only print or move between folders. Other builtins counted
# as text commands (printf -v, test -v 'a[...]' and [ evaluate or set names) make the line not plain.
_PLAIN_COMMANDS = {"cd", "pushd", "popd"}
_PLAIN_BUILTINS = {"echo", "pwd", "true", "false"} | _PLAIN_COMMANDS
# A command word that is only the name it says: no path, quote, escape, expansion or assignment.
_LITERAL_NAME = re.compile(r"^[A-Za-z0-9_][\w.+-]*$")
# What a plain line may not hold outside quotes: a group, subshell, function body or substitution.
_GROUPING = re.compile(r"[(){}`]")


def _is_plain_text_line(command):
    """True when nothing on the line can change what a command name runs, so its text commands (grep, cat,
    git log, git commit...) only read or record text: every part starts with a text command, cd, or a command
    found on PATH (make, tee), named as a bare literal word, and there is no group, function, substitution,
    assignment or redirect before it. Any other line may (git() { "$@"; }, BASH_CMDS[cat]=env, read PATH < f,
    noglob eval ..., d/cat, printf -v), so text commands on it are read like the rest. Quoted text is not
    looked at, except for a ${...} that runs code, which runs inside double quotes too."""
    blanked = _blank_quoted(command)
    braced = [m.start() for m in _RUNS_IN_BRACES.finditer(command)]
    if _GROUPING.search(blanked) or any(_code_or_double_quoted(command, blanked, braced)):
        return False
    for part in _SEPARATORS.split(blanked):
        words = part.split()
        if not words:
            continue
        if words[0] in _SHELL_WORDS:
            if words[0] not in _PLAIN_BUILTINS:
                return False
        elif not (_is_text(words) or _LITERAL_NAME.match(words[0])):
            return False
    return True


# $(cat <<'EOF' ... EOF): a quoted heredoc printed by cat is its text as it is, nothing in it expands (the
# git commit -m form). Only the first few are taken out, so a line with thousands is not searched for each.
_TEXT_HEREDOC = re.compile(r"\$\(cat[ \t]+<<-?[ \t]*(['\"])(\w+)\1[ \t]*\n")
MAX_TEXT_HEREDOCS = 8
def _without_text_heredocs(command):
    """The command with each $(cat <<'EOF' ... EOF) taken out, for telling whether text feeds a command.
    Nothing is taken out unless the rest is a plain text line and each heredoc is a word of a text command
    whose output goes to no other command (git commit -m): anything else may change what cat runs (cat() {,
    BASH_CMDS[cat]=sh) or run the text (echo "$(cat <<'EOF' ...)" | sh, sh -c, bash <<<, python3 -c)."""
    out, last, at, size = [], 0, [], 0
    blanked = _blank_quoted(command)
    for count, m in enumerate(_TEXT_HEREDOC.finditer(command)):
        if count == MAX_TEXT_HEREDOCS or m.start() < last:
            break
        if not _code_or_double_quoted(command, blanked, [m.start()])[0]:
            break
        # The heredoc ends at the first line holding its marker; only a ')' right after it closes the $( ).
        # Anything else there runs inside the $( ), so the rest of the line is left as it is.
        marker = re.compile(r"\n[ \t]*%s[ \t]*\n" % re.escape(m.group(2))).search(command, m.end() - 1)
        close = marker and re.compile(r"[ \t]*\)").match(command, marker.end())
        # A body line that starts with the marker (EOF) ends the heredoc in bash too: the rest is commands.
        starts = re.compile(r"\n[ \t]*%s" % re.escape(m.group(2)))
        early = marker and starts.search(command, m.end() - 1, marker.start())
        if not close or early:
            break
        out.append(command[last:m.start()])
        size += m.start() - last
        at.append(size)
        last = close.end()
    out.append(command[last:])
    stripped = "".join(out)
    if not at or _is_plain_text_line(stripped) and all(_only_text_at(stripped, k) for k in at):
        return stripped
    return command


def _code_or_double_quoted(command, blanked, offsets):
    """For each offset, in order, True when the character there is shell code or inside "...": not inside
    '...', $'...', a comment or after a backslash, where a $( or ${ is only text (echo '$(cat <<'EOF' ...'
    runs what follows the quote). A blanked run is opened by the character before it: quote marks are never
    blanked, so that is the quote around it, or the '#' of a comment or a backslash. One pass for all."""
    out, opener, k = [], None, 0
    for at in offsets:
        while k <= at:
            if blanked[k] == "_" and (k == 0 or blanked[k - 1] != "_"):
                opener = blanked[k - 1] if k else None
            k += 1
        out.append(blanked[at] == command[at] or opener == '"')
    return out


def _only_text_at(command, k):
    """True when the part of the line holding offset k is a text command whose output, if piped on, goes
    only to text commands (git commit ... | tail), never to one that may run it (echo ... | sh)."""
    blanked, start, found = _blank_quoted(command), 0, False
    for sep in _SEPARATORS.finditer(blanked):
        if found or sep.start() >= k:
            if not _is_text(blanked[start:sep.start()].split()):
                return False
            if sep.group() not in ("|", "|&"):
                return True
            found = True
        start = sep.end()
    return _is_text(blanked[start:].split())


def _blank_quoted(text):
    """The text with each quoted, backslash-escaped or commented character replaced by '_', so offsets still
    match. Inside "..." and $'...' a backslash escapes the next character; a quote in a comment is text.

    An unclosed quote leaves the rest of the text as it is: hiding it could hide a command after it.
    """
    out, n = list(text), 0
    while n < len(text):
        ch = text[n]
        if ch == "#" and _starts_comment(text, n):
            end = text.find("\n", n)
            end = len(text) if end < 0 else end
            out[n:end] = "_" * (end - n)
            n = end
            continue
        if ch == "\\" and n + 1 < len(text):
            out[n + 1] = "_"
            n += 2
            continue
        if ch in "'\"":
            escapes = ch == '"' or n > 0 and out[n - 1] == "$"  # "..." and $'...', not '...' or \$'.
            end = n + 1
            while end < len(text) and text[end] != ch:
                end += 2 if escapes and text[end] == "\\" else 1
            if end >= len(text):
                return "".join(out)
            out[n + 1:end] = "_" * (end - n - 1)
            n = end
        n += 1
    return "".join(out)


def _is_text(words):
    """True when this part of the line only reads or records text (grep, echo, git commit, git log...)."""
    if not words:
        return False
    if words[0] == "git":
        k = 1
        while k + 1 < len(words) and words[k] == "-C":
            k += 2  # git -C <folder> log: -C only changes the folder (-c can set a pager, so it is not skipped).
        return k < len(words) and words[k] in GIT_TEXT
    return words[0] in TEXT_COMMANDS


# The longest command read. Reading costs more than linear time on some shapes of text, and the hook has a
# few seconds before Claude Code stops waiting for it; a longer command is asked about.
MAX_COMMAND = 32 * 1024


_UNCLEAR_HASH = ("dryfire: this command has a '#' right after a '(', which shells read in different ways (a zsh "
                 "pattern such as (#i), or a comment in an array), so dryfire cannot tell what the rest of the line "
                 "runs. Confirm only if you expected it.")
_PAREN_HASH = re.compile(r"(?<![$<>])\(#")
_NEAR_DRYFIRE = ("dryfire", ".claude", "CLAUDE_PLUGIN", "cli.py", "cfgtool")


def _hash_after_parenthesis(command):
    """True when a '#' follows a '(' outside quotes (not $(#, <(# or >(#). Whether it starts a comment depends on
    the shell and on what stands before the '(' (a=(# x, x=1 a=(# x and declare a=(# x are comments, while
    zsh's ls (#i)x and /(#i)x are patterns), and a quote in the comment changes where the next quote ends,
    so no single reading is safe. The first such '(' is read correctly, since nothing before it is in doubt."""
    text = _without_text_heredocs(command)
    blanked = _blank_quoted(text)
    return any(blanked[m.start()] == "(" for m in _PAREN_HASH.finditer(text))


def _near_dryfire(command, cwd, dirs, home, plugin_root):
    """True when the line, quotes taken out, names dryfire, the .claude folder, its plugin folders or scripts,
    or runs from inside dryfire's folders (where approvals.json needs no folder name)."""
    plain = _QUOTING.sub("", command)
    inside = bool(cwd) and any(context.inside(cwd, d) for d in dirs + ([plugin_root] if plugin_root else []))
    return inside or any(w in plain for w in _NEAR_DRYFIRE) or bool(plugin_root and plugin_root in plain) or \
        _mentions(plain, dirs, home)


_SETS_DATA_VAR = ("dryfire: this command sets HOME or CLAUDE_PLUGIN_DATA before running dryfire, which changes "
                  "where it reads approvals from. Confirm only if you chose it.")


def check_bash(command, cwd, home, dirs, plugin_root, unattended):
    if len(command) > MAX_COMMAND:
        return _ask("dryfire: this command is too long for dryfire to check (over 32,768 characters). Confirm only if you "
                    "expected it.", unattended)
    command = _joined(command)
    parsed = shell.parse(command, cwd=cwd, home=home)
    ctx = _PathCtx(cwd, home)
    asks = []
    sets_data_var = _changes_data_var(command)
    if _hash_after_parenthesis(command) and _near_dryfire(command, cwd, dirs, home, plugin_root):
        asks.append(_UNCLEAR_HASH)
    consumed = []
    text_ok = _is_plain_text_line(_without_text_heredocs(command))
    cmds = list(_launched(parsed.cmds, home, text_ok=text_ok))
    lines = _split_strings(command)
    if lines is None and _ENV_WORD.search(command):
        asks.append("dryfire: this command could not be read reliably and may run an env -S command line.")
    for _ in range(LAUNCHER_DEPTH):
        if not lines:
            break
        nested = []
        for line in lines:
            inner = shell.parse(line, cwd=cwd, home=home).cmds
            cmds += list(_launched(inner, home, text_ok=text_ok))
            nested += _split_strings(line) or []
        lines = nested
    for cmd in cmds:
        for path, _kind in context.write_targets(cmd, ctx):
            for d in dirs + ([plugin_root] if plugin_root else []):
                if context.inside(path, d):
                    return Verdict("deny", "dryfire: this command writes into dryfire's own folder (%s). Its "
                                           "approvals, config and code are changed only by you." % d)
        script, rest, verified = _own_script(cmd, plugin_root)
        if script:
            sub = _subcommand(script, rest)
            consumed.append(sub)
            listing = script == "cli.py" and sub == "approve" and ("--list" in rest or "--revoke" in rest)
            if sub in CHANGING[script] and not listing:
                asks.append("dryfire: '%s %s' changes what dryfire may run or read. Confirm only if you asked "
                            "for it: %s" % (script, sub, _short(command)))
            elif not sub and not NO_SUBCOMMAND & set(rest):
                asks.append("dryfire: this runs %s with no subcommand on the line, so the words that choose it "
                            "come from somewhere else (xargs, a file) and could change what dryfire may run or "
                            "read. Confirm only if you asked for it: %s" % (script, _short(command)))
            elif sub and sub not in SUBCOMMANDS[script]:
                asks.append("dryfire: this runs %s with a subcommand that is only known when the line runs, so it "
                            "could change what dryfire may run or read. Confirm only if you asked for it: %s" %
                            (script, _short(command)))
            for value in _data_args(rest):
                if value in ("",) + DATA_REFS:
                    continue  # The plugin's own folder, or the fallback (both protected).
                target = os.path.normpath(shell.expand_path(value, cmd.cwd, home))
                if not any(target == d or os.path.realpath(target) == os.path.realpath(d) for d in dirs):
                    asks.append("dryfire: this run uses a different data folder (%s), where approvals could "
                                "have been planted. Confirm only if you chose it." % _short(value))
            if sets_data_var or "HOME" in cmd.env or "CLAUDE_PLUGIN_DATA" in cmd.env:
                asks.append(_SETS_DATA_VAR)
            if verified:
                continue  # dryfire's own script may name its data folder; the checks below are for everything else.
        if any(k == "CLAUDE_PLUGIN_DATA" for k in cmd.env) or \
                cmd.name in ("export", "declare", "typeset", "set") and "CLAUDE_PLUGIN_DATA" in " ".join(cmd.args):
            asks.append("dryfire: this command changes CLAUDE_PLUGIN_DATA. Confirm only if you chose it.")
            continue
        if not _is_read_only(cmd) and _mentions(" ".join(cmd.argv), dirs, home):
            return Verdict("deny", "dryfire: this command touches dryfire's data folder and is not a plain read. "
                                   "Its approvals and config are changed only by you, from a terminal or with "
                                   "/dryfire:config.")
    if sets_data_var and _names_dryfire(command, plugin_root, cwd) and parsed.error:
        asks.append(_SETS_DATA_VAR)  # The run may be in the part the parser could not read.
    else:
        fed = _without_text_heredocs(command)  # A commit message's quoted heredoc is text, not a run.
        # The run may be text fed to a shell (echo 'HOME=/x ... scan' | sh), or text a command reads as words
        # to run or names to set (x='HOME=/x ... scan'; bash -ce "$x", env $x): a line that writes HOME on
        # it passes only when every part is a text command.
        if _names_own_code(fed, plugin_root, cwd) and (
                _feeds_text(command, text_ok) and _changes_data_var(fed) or
                _names_data_var(fed) and not (text_ok and _only_text_commands(fed))
        ):
            asks.append(_SETS_DATA_VAR)
    if parsed.error and _mentions(command, dirs, home):
        asks.append("dryfire: this command mentions dryfire's data folder and could not be read reliably.")
    if not asks and _untraced_run(consumed, command, plugin_root, text_ok):
        asks.append("dryfire: this line runs dryfire in a way it could not follow, and may change what dryfire "
                    "may run or read. Confirm only if you asked for it: %s" % _short(command))
    if asks:
        return _ask(" ".join(dict.fromkeys(asks)), unattended)
    return None


class _PathCtx(object):
    """The two things context.write_targets needs: path() and home."""

    def __init__(self, cwd, home):
        self.cwd = cwd
        self.home = home

    def path(self, word, cwd=None):
        return shell.expand_path(word, cwd or self.cwd, self.home)


def check(payload, home=None, env=None, plugin_root=PLUGIN_ROOT):
    env = os.environ if env is None else env
    home = home or os.path.expanduser("~")
    if not isinstance(payload, dict):
        return Verdict("ask", "dryfire: the hook input was not an object, so dryfire could not check this call.")
    mode = payload.get("permission_mode") or "default"
    unattended = mode in UNATTENDED
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input")
    cwd = payload.get("cwd") or os.getcwd()
    dirs = protected_dirs(home, env)
    if not isinstance(ti, dict):
        return _ask("dryfire: this call's input was not an object, so dryfire could not check it.", unattended)
    if tool == "Bash":
        command = ti.get("command")
        if not isinstance(command, str):
            return _ask("dryfire: this Bash call has no command text, so dryfire could not check it.", unattended)
        return check_bash(command, cwd, home, dirs, plugin_root, unattended)
    if tool in EDIT_TOOLS:
        target = ti.get("file_path") or ti.get("notebook_path")
        if not isinstance(target, str) or not target:
            return None
        path = shell.expand_path(target, cwd, home)
        for d in dirs + ([plugin_root] if plugin_root else []):
            if context.inside(path, d):
                return Verdict("deny", "dryfire: %s into dryfire's own folder (%s) is refused. Its approvals, "
                                       "config and code are changed only by you." % (tool, d))
    return None


def main(stdin, stdout):
    try:
        payload = json.loads(stdin.read() or "null")
    except Exception:  # Not JSON, or nested too deep to read: check() asks about input it cannot read.
        payload = None
    try:
        verdict = check(payload)
    except Exception as exc:  # A crash must not silently allow: ask, or refuse when nobody can confirm.
        mode = payload.get("permission_mode") if isinstance(payload, dict) else None
        verdict = _ask("dryfire: its self-check failed (%s); confirm this call yourself." % type(exc).__name__,
                       mode in UNATTENDED)
    if verdict is None:
        return 0
    stdout.write(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": verdict.decision,
        "permissionDecisionReason": verdict.reason,
    }}))
    stdout.write("\n")
    return 0
