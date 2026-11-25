"""What every rule sees: the tool call, where it runs, the config, and helpers
that find which paths a shell command writes to."""

import fnmatch
import os
import re

from . import shell

UNATTENDED_MODES = ("dontAsk", "bypassPermissions")
LEVELS = ("off", "ask", "deny")


def default_data_dir(home):
    env = os.environ.get("CLAUDE_PLUGIN_DATA", "").strip()
    return env or os.path.join(home, ".claude", "checkrein")


class Hit(object):
    """One rule match. level None means: use the rule's configured level."""

    __slots__ = ("rule", "reason", "level", "cap")

    def __init__(self, rule, reason, level=None, cap=None):
        self.rule = rule
        self.reason = reason
        self.level = level
        self.cap = cap  # Highest level this hit may reach (e.g. generic secret patterns: ask).


class Ctx(object):
    def __init__(self, payload, eff, home=None, data_dir=None, plugin_root=None):
        self.payload = payload
        self.tool_name = payload.get("tool_name") or ""
        self.tool_input = payload.get("tool_input") or {}
        self.cwd = payload.get("cwd") or os.getcwd()
        self.permission_mode = payload.get("permission_mode") or "default"
        self.home = home or os.path.expanduser("~")
        self.project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or self.cwd
        self.data_dir = data_dir or default_data_dir(self.home)
        self.plugin_root = plugin_root
        self.eff = eff
        self._parsed = None

    @property
    def unattended(self):
        return self.permission_mode in UNATTENDED_MODES

    @property
    def command(self):
        return self.tool_input.get("command") or "" if self.tool_name == "Bash" else ""

    @property
    def parsed(self):
        if self._parsed is None:
            self._parsed = shell.parse(self.command, cwd=self.cwd, home=self.home)
        return self._parsed

    def path(self, word, cwd=None):
        return shell.expand_path(word, cwd or self.cwd, self.home)

    def file_path(self):
        """The target of Write, Edit, MultiEdit or NotebookEdit, absolute."""
        p = self.tool_input.get("file_path") or self.tool_input.get("notebook_path") or ""
        return self.path(p) if p else ""


def inside(path, root):
    if not path or not root:
        return False
    path = os.path.normpath(path)
    root = os.path.normpath(root)
    if path == root or path.startswith(root.rstrip(os.sep) + os.sep):
        return True
    try:
        real_root = os.path.realpath(root)
        real_path = os.path.realpath(path)
    except OSError:
        return False
    return real_path == real_root or real_path.startswith(real_root.rstrip(os.sep) + os.sep)


def matches_globs(path, globs, project_dir):
    rel = os.path.relpath(path, project_dir) if project_dir and inside(path, project_dir) else None
    for g in globs:
        if fnmatch.fnmatch(path, g) or (rel and fnmatch.fnmatch(rel, g)) or fnmatch.fnmatch(os.path.basename(path), g):
            return True
    return False


def settings_files(ctx):
    """Claude Code settings files that can turn hooks or plugins off."""
    out = [os.path.join(ctx.home, ".claude", "settings.json"),
           os.path.join(ctx.home, ".claude", "settings.local.json"),
           os.path.join(ctx.home, ".claude.json")]
    if ctx.project_dir:
        out.append(os.path.join(ctx.project_dir, ".claude", "settings.json"))
        out.append(os.path.join(ctx.project_dir, ".claude", "settings.local.json"))
    return [os.path.normpath(p) for p in out]


# Commands that copy, download or unpack content into a destination.
_DEST_LAST = {"cp", "mv", "rsync", "install", "ln", "ditto", "scp", "gcp", "gmv"}
_DELETE = {"rm", "rmdir", "unlink", "shred", "trash"}
_MODIFY_ARGS = {"touch", "chmod", "chown", "chflags", "chgrp", "truncate", "xattr", "setfacl"}


def _nonopts(args, takes_value=()):
    out = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in takes_value:
            skip = True
            continue
        if a.startswith("-") and a != "-":
            continue
        out.append(a)
    return out


def write_targets(cmd, ctx):
    """Paths a simple command writes, copies into, unpacks into or deletes.

    Returns a list of (absolute_path, kind) with kind one of: bring, modify, delete.
    "bring" means new content arrives from somewhere else (copy, download, clone, unpack).
    """
    out = []
    p = lambda w: ctx.path(w, cmd.cwd)  # noqa: E731
    for op, target in cmd.redirects:
        if op in shell.REDIRECT_WRITE and target and not target.startswith("&") and target != "/dev/null":
            out.append((p(target), "bring"))
    name, args = cmd.name, cmd.args
    if name in _DEST_LAST:
        takes = {"-t", "--target-directory", "-S", "--suffix", "-e", "--rsh", "-m", "--mode", "-o", "-g"}
        target_dir = None
        for i, a in enumerate(args):
            if a in ("-t", "--target-directory") and i + 1 < len(args):
                target_dir = args[i + 1]
            elif a.startswith("--target-directory="):
                target_dir = a.split("=", 1)[1]
        words = _nonopts(args, takes)
        if target_dir:
            out.append((p(target_dir), "bring"))
        elif len(words) >= 2:
            dest = words[-1]
            if ":" in dest and name in ("scp", "rsync") and not dest.startswith(("/", ".", "~")):
                pass  # Remote destination.
            else:
                out.append((p(dest), "bring"))
        if name in ("mv", "gmv"):
            for w in words[:-1]:
                out.append((p(w), "delete"))
    elif name == "tee":
        for w in _nonopts(args):
            out.append((p(w), "bring"))
    elif name in ("sort", "gsort"):
        out.extend((p(w), "bring") for w in _option_values(args, ("-o",), ("--output",), "ktTS"))
    elif name in ("uniq", "guniq"):
        words = _nonopts(args, {"-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"})
        if len(words) >= 2:
            out.append((p(words[1]), "bring"))
    elif name == "tree":
        out.extend((p(w), "bring") for w in _option_values(args, ("-o",), (), "LPIHT"))
    elif name in ("awk", "gawk", "mawk", "nawk"):
        for script in _awk_programs(args):
            out.extend((p(w), "bring") for w in _awk_outputs(script))
    elif name in ("patch", "gpatch"):
        out.extend(_patch_targets(cmd, ctx))
    elif name in _DELETE:
        for w in _nonopts(args):
            out.append((p(w), "delete"))
    elif name in _MODIFY_ARGS:
        words = _nonopts(args)
        if name in ("chmod", "chown", "chgrp", "chflags") and words:
            words = words[1:]
        for w in words:
            out.append((p(w), "modify"))
    elif name in ("sed", "gsed", "perl") and any(a.startswith("-i") or a == "--in-place" or a.startswith("-pi")
                                                 for a in args):
        words = _nonopts(args, {"-e", "-f", "--expression", "--file"})
        script_given = any(a in ("-e", "-f", "--expression", "--file") for a in args)
        for w in (words if script_given else words[1:]):
            out.append((p(w), "modify"))
        if name != "perl":
            out.extend((p(w), "bring") for w in _sed_outputs(args))
    elif name in ("sed", "gsed"):
        out.extend((p(w), "bring") for w in _sed_outputs(args))
    elif name == "dd":
        for a in args:
            if a.startswith("of="):
                out.append((p(a[3:]), "bring"))
    elif name in ("curl", "wget"):
        out.extend(_download_targets(cmd, ctx))
    elif name == "gh" and args[:2] == ["repo", "clone"]:
        rest = args[2:]
        if "--" in rest:
            rest = rest[:rest.index("--")]
        words = _nonopts(rest, {"-u", "--upstream-remote-name"})
        if len(words) >= 2:
            out.append((p(words[1]), "bring"))
        elif words:
            out.append((p(words[0].rstrip("/").rsplit("/", 1)[-1]), "bring"))
    elif name == "git" and args:
        sub, sub_args = git_subcommand(args)
        _configs, cdir = git_globals(args)
        gcwd = p(cdir) if cdir else cmd.cwd or ctx.cwd
        out.extend((ctx.path(w, gcwd), "bring") for w in _option_values(sub_args, (), ("--output",)))
        if sub == "format-patch":
            out.extend((ctx.path(w, gcwd), "bring")
                       for w in _option_values(sub_args, ("-o",), ("--output-directory",)))
        if sub in _GIT_UPDATES_TREE:
            out.append((gcwd, "bring"))
        elif sub == "apply" and not any(a in _GIT_APPLY_READ for a in sub_args):
            dirs = _option_values(sub_args, (), ("--directory",))
            out.append((ctx.path(dirs[0], gcwd) if dirs else gcwd, "modify"))
        elif sub == "worktree" and sub_args[:1] == ["add"]:
            words = _nonopts(sub_args[1:], {"-b", "-B", "--reason"})
            if words:
                out.append((ctx.path(words[0], gcwd), "bring"))
        elif sub == "submodule" and sub_args[:1] == ["add"]:
            words = _nonopts(sub_args[1:], {"-b", "--branch", "--name", "--reference", "--depth"})
            if len(words) >= 2:
                out.append((ctx.path(words[1], gcwd), "bring"))
        if sub == "clone":
            words = _nonopts(sub_args, {"-b", "--branch", "-o", "--origin", "--depth", "-c", "--config",
                                         "--reference", "--separate-git-dir", "-u", "--upload-pack", "--filter",
                                         "-j", "--jobs", "--template", "--shallow-since", "--shallow-exclude"})
            if len(words) >= 2:
                out.append((p(words[1]), "bring"))
            elif words:
                base = words[0].rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
                out.append((p(base[:-4] if base.endswith(".git") else base), "bring"))
    elif name in ("tar", "gtar", "bsdtar"):
        extract = any(a.startswith("-") and "x" in a and not a.startswith("--") or a in ("--extract", "--get")
                      for a in args) or (args and not args[0].startswith("-") and "x" in args[0])
        if extract:
            dest = None
            for i, a in enumerate(args):
                if a in ("-C", "--directory") and i + 1 < len(args):
                    dest = args[i + 1]
                elif a.startswith("--directory="):
                    dest = a.split("=", 1)[1]
            out.append((p(dest) if dest else cmd.cwd or ctx.cwd, "bring"))
    elif name in ("unzip", "7z", "7za", "bsdunzip"):
        dest = None
        for i, a in enumerate(args):
            if a == "-d" and i + 1 < len(args):
                dest = args[i + 1]
            elif a.startswith("-o") and name.startswith("7z") and len(a) > 2:
                dest = a[2:]
        out.append((p(dest) if dest else cmd.cwd or ctx.cwd, "bring"))
    return out


# git subcommands that put new content into the working tree they run in.
_GIT_UPDATES_TREE = {"pull", "fetch", "checkout", "switch", "reset", "merge", "rebase", "am", "cherry-pick",
                     "restore", "submodule", "read-tree", "checkout-index"}
_GIT_APPLY_READ = {"--check", "--stat", "--numstat", "--summary", "--cached"}


def _option_values(args, short, long, stop=""):
    """Values of options like -o X, -oX, -no X, --output X, --output=X (long names may be abbreviated).

    short holds options like "-o"; stop holds other short letters that take a value (they end a cluster).
    """
    out = []
    letters = "".join(s[1:] for s in short)
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else None
        if letters and a.startswith("-") and not a.startswith("--") and len(a) > 1:
            for k, ch in enumerate(a[1:], 1):
                if ch in letters:
                    if k + 1 < len(a):
                        out.append(a[k + 1:])
                    elif nxt is not None:
                        out.append(nxt)
                    break
                if ch in stop:
                    break
        for lg in long:
            opt, eq, val = a.partition("=")
            if long_option(opt, lg, 1):
                if eq:
                    out.append(val)
                elif nxt is not None:
                    out.append(nxt)
    return out


def long_option(arg, full, min_len=2):
    """True when arg is full or a prefix of it that git/getopt accept (at least min_len letters after --)."""
    if not arg.startswith("--") or not full.startswith("--"):
        return False
    body = arg[2:]
    return body == full[2:] or (len(body) >= min_len and full[2:].startswith(body))


def _sed_scripts(args):
    scripts = []
    given = False
    for i, a in enumerate(args):
        if a in ("-e", "--expression") and i + 1 < len(args):
            scripts.append(args[i + 1])
            given = True
        elif a.startswith("--expression="):
            scripts.append(a.split("=", 1)[1])
            given = True
        elif a.startswith("-e") and len(a) > 2 and not a.startswith("--"):
            scripts.append(a[2:])
            given = True
        elif a in ("-f", "--file"):
            given = True
    if not given:
        words = _nonopts(args, {"-l", "--line-length", "-s"})
        if words:
            scripts.append(words[0])
    return scripts


def _sed_skip_regex(s, i):
    """Index just past a delimited regex/text whose delimiter is s[i]."""
    delim = s[i]
    i += 1
    while i < len(s) and s[i] != delim:
        i += 2 if s[i] == "\\" else 1
    return i + 1


def _sed_actions(script):
    """Yield (command letter, argument) for each sed command; s commands yield ("s", flags)."""
    s = script
    n = len(s)
    i = 0
    while i < n:
        while i < n and s[i] in " \t\n;{}":
            i += 1
        # Addresses: numbers, $, /re/, \cREc, ranges and steps.
        while i < n:
            c = s[i]
            if c.isdigit() or c in "$,~+":
                i += 1
            elif c == "/":
                i = _sed_skip_regex(s, i)
                while i < n and s[i] in "IM":
                    i += 1
            elif c == "\\" and i + 1 < n:
                i = _sed_skip_regex(s, i + 1)
            else:
                break
        while i < n and s[i] in " \t!":
            i += 1
        if i >= n:
            return
        c = s[i]
        i += 1
        if c in "sy" and i < n:
            i = _sed_skip_regex(s, i) - 1  # Pattern and replacement share the middle delimiter.
            i = _sed_skip_regex(s, i)
            j = i
            while i < n and s[i] not in ";}\n":
                if s[i] in "wW":
                    i = n if s.find("\n", i) == -1 else s.find("\n", i)
                    break
                i += 1
            yield c, s[j:i]
        elif c in "wWrRaic:btTev":
            j = s.find("\n", i)
            j = n if j == -1 else j
            if c in ":btTv":
                k = min([x for x in (s.find(";", i), s.find("}", i), j) if x != -1])
                j = k
            yield c, s[i:j].strip()
            i = j
        else:
            yield c, ""


def _sed_outputs(args):
    out = []
    for script in _sed_scripts(args):
        for c, arg in _sed_actions(script):
            if c in "wW" and arg:
                out.append(arg)
            elif c == "s":
                m = re.search(r"[wW]\s*(.+)$", arg)
                if m:
                    out.append(m.group(1).strip())
    return [t for t in out if t not in ("/dev/stdout", "/dev/stderr")]


def _awk_programs(args):
    progs = []
    skip = False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in ("-v", "-F", "-f", "--assign", "--field-separator", "--file"):
            skip = True
            continue
        if a.startswith("-"):
            continue
        progs.append(a)
        break
    return progs


# print/printf output redirection: > "file", >> "file", | "command".
_AWK_REDIRECT = re.compile(r"\bprintf?\b[^;{}\n]*?(>>|>|\|)\s*\"([^\"]*)\"")
_AWK_ANY_REDIRECT = re.compile(r"\bprintf?\b[^;{}\n]*?(>>?|\|)")


def _awk_outputs(script):
    out = []
    for m in _AWK_REDIRECT.finditer(script):
        if m.group(1) == "|":
            # A pipe runs a shell command; look for its redirects.
            out.extend(t for op, t in _inner_redirects(m.group(2)))
        else:
            out.append(m.group(2))
    return out


def _inner_redirects(command):
    try:
        parsed = shell.parse(command)
    except Exception:  # noqa: BLE001 - best effort on a nested string
        return []
    return [(op, t) for c in parsed.cmds for op, t in c.redirects if op in shell.REDIRECT_WRITE]


def awk_writes_or_runs(args):
    """True when an awk program redirects output, pipes it, or runs commands."""
    for script in _awk_programs(args):
        if "system(" in script or "getline" in script and "|" in script or _AWK_ANY_REDIRECT.search(script):
            return True
    return any(a in ("-f", "--file") or a.startswith("--file=") for a in args)


def sed_writes_or_runs(args):
    """True when a sed program writes files (w, W, s///w) or runs commands (e, s///e)."""
    if _sed_outputs(args):
        return True
    for script in _sed_scripts(args):
        for c, arg in _sed_actions(script):
            if c == "e" or (c == "s" and "e" in re.split(r"[wW]", arg, 1)[0]):
                return True
    return any(a in ("-f", "--file") or a.startswith("--file=") for a in args)


def _patch_targets(cmd, ctx):
    args = cmd.args
    if any(a in ("--dry-run", "-C", "--check") for a in args):
        return []
    p = lambda w: ctx.path(w, cmd.cwd)  # noqa: E731
    dirs = _option_values(args, ("-d",), ("--directory",), "BDFiopreVYz")
    base = p(dirs[0]) if dirs else cmd.cwd or ctx.cwd
    out = [(base, "modify")]
    out.extend((p(w), "modify") for w in _option_values(args, ("-o",), ("--output",), "BDFdipreVYz"))
    words = _nonopts(args, {"-d", "--directory", "-p", "-i", "--input", "-o", "--output", "-r", "--reject-file",
                            "-B", "--prefix", "-D", "--ifdef", "-F", "--fuzz", "-V", "--version-control",
                            "-z", "--suffix", "-Y", "--basename-prefix"})
    if words:
        out.append((ctx.path(words[0], base), "modify"))
    return out


def _download_targets(cmd, ctx):
    out = []
    args = cmd.args
    p = lambda w: ctx.path(w, cmd.cwd)  # noqa: E731
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else None
        if cmd.name == "curl":
            if a in ("-o", "--output") and nxt:
                out.append((p(nxt), "bring"))
            elif a.startswith("--output="):
                out.append((p(a.split("=", 1)[1]), "bring"))
            elif a in ("--output-dir",) and nxt:
                out.append((p(nxt), "bring"))
            elif a in ("-O", "--remote-name", "--remote-name-all") or (
                    a.startswith("-") and not a.startswith("--") and "O" in a):
                out.append((cmd.cwd or ctx.cwd, "bring"))
        else:
            if a in ("-O", "--output-document") and nxt:
                out.append((p(nxt), "bring"))
            elif a.startswith("--output-document="):
                out.append((p(a.split("=", 1)[1]), "bring"))
            elif a in ("-P", "--directory-prefix") and nxt:
                out.append((p(nxt), "bring"))
            elif a.startswith("--directory-prefix="):
                out.append((p(a.split("=", 1)[1]), "bring"))
    if cmd.name == "wget" and not out:
        out.append((cmd.cwd or ctx.cwd, "bring"))
    return out


# git options that come before the subcommand and take a value.
_GIT_GLOBAL_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix",
                     "--config-env", "--list-cmds", "--attr-source"}


def git_subcommand(args):
    """Return (subcommand, its args) from git's argv[1:], skipping global options."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in _GIT_GLOBAL_VALUE:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a, args[i + 1:]
    return "", []


def git_globals(args):
    """Global -c key=value pairs and -C dir before the subcommand."""
    configs = []
    cdir = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-c", "--config-env") and i + 1 < len(args):
            configs.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--config-env="):
            configs.append(a.split("=", 1)[1])
            i += 1
            continue
        if a == "-C" and i + 1 < len(args):
            cdir = args[i + 1]
            i += 2
            continue
        if a in _GIT_GLOBAL_VALUE:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        break
    return configs, cdir
