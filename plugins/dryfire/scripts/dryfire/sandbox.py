"""Run a hook under test away from the user's real files.

Every call gets a fresh, private temp folder holding the HOME, project folder,
plugin data folder and TMPDIR the hook sees, and the folder is removed after
the call. The environment is rebuilt from scratch (PATH, locale, and the
CLAUDE_* values a hook expects), so tokens in the user's environment never
reach the hook.

On macOS the hook also runs under sandbox-exec with a profile that denies all
network access, all writes outside the temp folder, and reads of the real home
folder except paths the hook needs (its own script folder, its plugin folder,
its interpreter, and paths the user allowed). Elsewhere only the temp folder
and environment apply; the report says so, and sandbox "required" refuses.

The hook runs in its own process group with a deadline; on timeout or once it
exits, the whole group is killed. A process that left the group (a new session,
as daemons do) is found by a marker in its environment once that hook's replay
ends, and killed too; only one that also clears its environment can outlive the
run, and on macOS it stays inside the sandbox. Output is read with a size cap.
"""

import errno
import os
import re
import secrets
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
OUTPUT_CAP = 256 * 1024
EXIT_GRACE = 0.25

ENV_PASS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TERM")

# Every hook this dryfire process starts carries this marker, so processes that left the hook's process
# group can still be found and ended. It is random per process: nothing else on the machine carries it.
MARK = "DRYFIRE_RUN"
RUN_ID = "%d-%s" % (os.getpid(), secrets.token_hex(8))


def os_sandbox_available():
    return sys.platform == "darwin" and os.path.exists(SANDBOX_EXEC)


def mode_for(setting):
    """Resolve the sandbox setting to 'os' or 'env'; raises when 'required' cannot be met."""
    if setting == "env":
        return "env"
    if os_sandbox_available():
        return "os"
    if setting == "required":
        raise SandboxUnavailable("sandbox is 'required' but no OS sandbox is available on this system "
                                 "(dryfire uses macOS sandbox-exec; Linux has only the environment sandbox in v0.1).")
    return "env"


class SandboxUnavailable(Exception):
    pass


class Box(object):
    """A per-call temp folder with home, project, data and tmp inside it."""

    def __init__(self, seed_files=None):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="dryfire-"))
        os.chmod(self.root, 0o700)
        self.home = os.path.join(self.root, "home")
        self.project = os.path.join(self.root, "project")
        self.data = os.path.join(self.root, "data")
        self.tmp = os.path.join(self.root, "tmp")
        for d in (self.home, self.project, self.data, self.tmp):
            os.mkdir(d, 0o700)
        self.transcript = os.path.join(self.root, "transcript.jsonl")
        with open(self.transcript, "w"):
            pass
        for rel, src in (seed_files or {}).items():
            dest = os.path.normpath(os.path.join(self.data, rel))
            if not dest.startswith(self.data + os.sep):
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(src, dest)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def build_env(box, plugin_root=None, options=None, base=None):
    base = os.environ if base is None else base
    env = {k: base[k] for k in ENV_PASS if base.get(k)}
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    env.update({
        "HOME": box.home,
        "TMPDIR": box.tmp + os.sep,
        "CLAUDE_PROJECT_DIR": box.project,
        "PYTHONDONTWRITEBYTECODE": "1",
        MARK: RUN_ID,
    })
    if plugin_root:
        env["CLAUDE_PLUGIN_ROOT"] = plugin_root
        env["CLAUDE_PLUGIN_DATA"] = box.data
    for key, value in (options or {}).items():
        name = "CLAUDE_PLUGIN_OPTION_" + "".join(c if c.isalnum() else "_" for c in str(key)).upper()
        env[name] = "" if value is None else str(value)
    return env


def expand_command(command, home, plugin_root=None, plugin_data=None):
    """Put the real paths into a hook command the way Claude Code would.

    ~ and $HOME point at the real home so the hook's own script can be found;
    the hook itself still runs with HOME set to the temp folder.
    """
    out = command
    if plugin_root:
        out = out.replace("${CLAUDE_PLUGIN_ROOT}", plugin_root).replace("$CLAUDE_PLUGIN_ROOT", plugin_root)
    if plugin_data:
        out = out.replace("${CLAUDE_PLUGIN_DATA}", plugin_data).replace("$CLAUDE_PLUGIN_DATA", plugin_data)
    out = out.replace("${HOME}", home).replace("$HOME", home)
    try:
        words = shlex.split(out)
    except ValueError:
        words = []
    for w in words:
        if w == "~" or w.startswith("~/"):
            out = out.replace(w, home + w[1:], 1)
    return out


_PROJECT_VAR = re.compile(r"\$\{CLAUDE_PROJECT_DIR\}|\$CLAUDE_PROJECT_DIR(?![A-Za-z0-9_])")


def pin_paths(command, base, project_dir):
    """The command with its script paths fixed to real folders, as Claude Code would run it.

    The hook runs in a temp project folder, so ./guard.sh or "$CLAUDE_PROJECT_DIR"/.claude/hooks/guard.sh
    would name a file that is not there. $CLAUDE_PROJECT_DIR becomes the real project folder, and a
    relative path (./x, ../x, or bin/x when that file exists) is taken from base. Nothing after a cd or
    pushd is pinned, since its folder is no longer base, and words that hold shell code are left alone.
    The hook's own environment still points CLAUDE_PROJECT_DIR at the temp folder.
    """
    out = _PROJECT_VAR.sub(lambda m: project_dir, command) if project_dir else command
    spans = _word_spans(out)
    if spans is None:
        return out
    pieces, pos = [], 0
    for start, end in spans:
        try:
            value = shlex.split(out[start:end])
        except ValueError:
            return out
        if len(value) != 1:
            continue
        if value[0] in ("cd", "pushd"):
            break
        pinned = _pin_word(value[0], base)
        if pinned != value[0]:
            pieces += [out[pos:start], shlex.quote(pinned)]
            pos = end
    return "".join(pieces) + out[pos:]


_SEPARATORS = ";&|()<>"


def _word_spans(command):
    """(start, end) of each shell word in command, quotes kept inside the word; None if a quote is left open."""
    spans, i, n = [], 0, len(command)
    while i < n:
        if command[i].isspace() or command[i] in _SEPARATORS:
            i += 1
            continue
        start = i
        while i < n and not command[i].isspace() and command[i] not in _SEPARATORS:
            c = command[i]
            if c == "\\":
                i += 2
            elif c == "'":
                end = command.find("'", i + 1)
                if end < 0:
                    return None
                i = end + 1
            elif c == '"':
                i += 1
                while i < n and command[i] != '"':
                    i += 2 if command[i] == "\\" else 1
                if i >= n:
                    return None
                i += 1
            else:
                i += 1
        spans.append((start, min(i, n)))
    return spans


def pin_args(args, base, project_dir):
    out = []
    for a in args:
        a = _PROJECT_VAR.sub(lambda m: project_dir, str(a)) if project_dir else str(a)
        out.append(_pin_word(a, base))
    return out


_SHELL_CODE = re.compile(r"[\"'$`*?\[\\;&|()<>]")


def _pin_word(word, base):
    if not base or word.startswith(("/", "~", "$", "-")) or "/" not in word or "=" in word:
        return word
    if _SHELL_CODE.search(word):  # A script string or a pattern, not a path.
        return word
    path = os.path.normpath(os.path.join(base, word))
    if os.path.exists(path) or (word.startswith(("./", "../")) and not any(c.isspace() for c in word)):
        return path
    return word


VERSION_FILES = (".tool-versions", ".python-version", ".ruby-version", ".node-version", ".nvmrc")


def shim_note(command_words, home):
    """A note when the hook's program is a version-manager shim, which may not find its setup in the temp HOME."""
    exe = shutil.which(command_words[0]) if command_words else None
    if not exe or os.path.basename(os.path.dirname(os.path.realpath(exe))) != "shims":
        return ""
    return ("%s is a version-manager shim; dryfire lets it read the manager's folder, but a shim that looks "
            "for its setup under HOME sees the temp HOME. If replays fail with exit 127 or 'no version set', "
            "use the interpreter's full path in the hook command."
            % _tilde(os.path.realpath(exe), home))


def _tilde(path, home):
    home = os.path.realpath(home).rstrip("/")
    return "~" + path[len(home):] if path == home or path.startswith(home + "/") else path


def read_paths_for(command_words, home, plugin_root=None, extra=None):
    """Real-home paths the hook may read inside the OS sandbox."""
    home_real = os.path.realpath(home)
    paths = []

    def add(p):
        if not p:
            return
        real = os.path.realpath(os.path.expanduser(p))
        if real.startswith(home_real + os.sep) and real not in paths:
            paths.append(real)

    for w in command_words:
        if w.startswith("/") or w.startswith("~"):
            p = os.path.realpath(os.path.expanduser(w))
            if os.path.isfile(p):
                add(os.path.dirname(p))
            elif os.path.isdir(p):
                add(p)
    if command_words:
        exe = shutil.which(command_words[0])
        if exe:
            real = os.path.realpath(exe)
            folder = os.path.basename(os.path.dirname(real))
            if folder == "shims":
                # A version-manager shim (pyenv, asdf, mise, rbenv) reads the manager's whole folder and
                # the version files in your home, then runs the real interpreter from there.
                add(os.path.dirname(os.path.dirname(real)))
                for name in VERSION_FILES:
                    if os.path.isfile(os.path.join(home_real, name)):
                        add(os.path.join(home_real, name))
            else:
                # An interpreter in the home folder (nvm, cargo, volta): allow its install prefix.
                parent = os.path.dirname(os.path.dirname(real))
                add(parent if folder == "bin" else os.path.dirname(real))
    add(plugin_root)
    for p in extra or []:
        add(p)
    return paths


# System services the profile below denies to the hook under test. Each one acts for its caller outside the
# file rules: preferences, the clipboard, the security daemons, Apple Events, Launch Services, Spotlight and file
# coordination. Denying them keeps the hook inside its temp folder.
DENIED_SERVICES = (
    "com.apple.cfprefsd.*",
    "com.apple.pasteboard.*",
    "com.apple.SecurityServer",
    "com.apple.securityd.*",
    "com.apple.coreservices.appleevents",
    "com.apple.coreservices.launchservicesd",
    "com.apple.lsd.*",
    "com.apple.metadata.mds",
    "com.apple.FileCoordination",
)


def _q(path):
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def profile(box_root, home, read_paths):
    """sandbox-exec profile: no network, writes only in the box, no home reads except read_paths."""
    home_real = os.path.realpath(home)
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny network*)",
        "(deny file-write*)",
        "(allow file-write* (subpath %s) (literal \"/dev/null\") (literal \"/dev/tty\") "
        "(literal \"/dev/dtracehelper\"))" % _q(box_root),
        "(deny file-read* (subpath %s))" % _q(home_real),
        "(allow file-read* (literal %s) (subpath %s))" % (_q(home_real), _q(box_root)),
        # System services that read or write your files on a caller's behalf, past the file rules above.
        "(deny mach-lookup %s)" % " ".join(
            '(global-name "%s")' % n if not n.endswith("*") else '(global-name-prefix "%s")' % n[:-1]
            for n in DENIED_SERVICES),
    ]
    # Let a hook list the folders on the way to its own files, without reading anything else in them.
    parents = set()
    for p in read_paths:
        d = os.path.dirname(p)
        while d.startswith(home_real + os.sep):
            parents.add(d)
            d = os.path.dirname(d)
    if parents:
        lines.append("(allow file-read-metadata %s)" % " ".join("(literal %s)" % _q(p) for p in sorted(parents)))
    if read_paths:
        lines.append("(allow file-read* %s)" % " ".join("(subpath %s)" % _q(p) for p in read_paths))
    return "\n".join(lines) + "\n"


class RunResult(object):
    __slots__ = ("rc", "stdout", "stderr", "timed_out", "truncated", "start_error", "seconds")

    def __init__(self):
        self.rc = None
        self.stdout = ""
        self.stderr = ""
        self.timed_out = False
        self.truncated = False
        self.start_error = ""
        self.seconds = 0.0


# Set when the replay is interrupted: every running hook is ended as if its time were up.
STOP = threading.Event()


def run(argv, stdin_bytes, env, cwd, timeout, cap=OUTPUT_CAP):
    """Run argv with a deadline and capped output, then kill its process group."""
    res = RunResult()
    started = time.monotonic()
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=cwd, env=env, close_fds=True, start_new_session=True)
    except OSError as exc:
        res.start_error = exc.strerror or str(exc)
        return res
    deadline = started + timeout
    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
    bufs = {out_fd: bytearray(), err_fd: bytearray()}
    sel = selectors.DefaultSelector()
    pending = memoryview(stdin_bytes or b"")
    if pending:
        os.set_blocking(proc.stdin.fileno(), False)
        sel.register(proc.stdin, selectors.EVENT_WRITE)
    else:
        proc.stdin.close()
    for stream in (proc.stdout, proc.stderr):
        os.set_blocking(stream.fileno(), False)
        sel.register(stream, selectors.EVENT_READ)
    exited_at = None
    try:
        while sel.get_map():
            now = time.monotonic()
            if now >= deadline or STOP.is_set():
                res.timed_out = True
                break
            if exited_at is None and proc.poll() is not None:
                exited_at = now
            if exited_at is not None and now - exited_at > EXIT_GRACE:
                break  # Something the hook started still holds the pipes open.
            for key, _ in sel.select(timeout=min(0.05, max(0.0, deadline - now))):
                if key.fileobj is proc.stdin:
                    try:
                        n = os.write(proc.stdin.fileno(), pending[:65536])
                        pending = pending[n:]
                    except (BrokenPipeError, OSError) as exc:
                        if isinstance(exc, OSError) and exc.errno == errno.EAGAIN:
                            continue
                        pending = pending[:0]
                    if not pending:
                        sel.unregister(proc.stdin)
                        proc.stdin.close()
                    continue
                try:
                    chunk = os.read(key.fd, 65536)
                except OSError as exc:
                    if exc.errno == errno.EAGAIN:
                        continue
                    chunk = b""
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                buf = bufs[key.fd]
                room = cap - len(buf)
                if room > 0:
                    buf.extend(chunk[:room])
                if len(chunk) > max(room, 0):
                    res.truncated = True
    finally:
        sel.close()
        _kill_group(proc)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    res.rc = None if res.timed_out else proc.returncode
    res.stdout = bytes(bufs[out_fd]).decode("utf-8", "replace")
    res.stderr = bytes(bufs[err_fd]).decode("utf-8", "replace")
    res.seconds = time.monotonic() - started
    return res


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def sweep():
    """Kill every process still carrying this run's marker and return how many there were."""
    found = 0
    for pid in _marked_pids():
        try:
            os.kill(pid, signal.SIGKILL)
            found += 1
        except OSError:
            pass
    return found


def _marked_pids():
    """Ids of this user's processes whose environment holds MARK=RUN_ID."""
    needle = ("%s=%s" % (MARK, RUN_ID)).encode()
    me = os.getpid()
    pids = []
    if os.path.isdir("/proc/self"):
        for name in os.listdir("/proc"):
            if not name.isdigit() or int(name) == me:
                continue
            try:
                with open("/proc/%s/environ" % name, "rb") as fh:
                    if needle in fh.read().split(b"\0"):
                        pids.append(int(name))
            except OSError:
                continue
        return pids
    # macOS: ps -E adds each process's environment after its command (readable for your own processes).
    try:
        out = subprocess.run(["/bin/ps", "-A", "-E", "-ww", "-o", "pid=,command="], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return pids
    for line in out.splitlines():
        words = line.split()
        if len(words) > 1 and words[0].isdigit() and int(words[0]) != me and needle in words[1:]:
            pids.append(int(words[0]))
    return pids


def hook_argv(command=None, args=None, mode="env", box=None, home=None, read_paths=()):
    """argv for a hook in shell form (sh -c) or exec form (args), wrapped by sandbox-exec in 'os' mode."""
    if args:
        argv = [str(a) for a in args]
    else:
        argv = ["/bin/sh", "-c", command]
    if mode == "os":
        argv = [SANDBOX_EXEC, "-p", profile(box.root, home, read_paths)] + argv
    return argv
