"""Shared test helpers: paths, made-up secrets, and transcripts built at run time.

Every secret-shaped value is assembled from pieces here so no real-looking
credential sits in the repository as one string. Transcripts are generated
per test in a temp folder; no real user data is used.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "plugins", "dryfire")
SCRIPTS = os.path.join(PLUGIN, "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
CHECKREIN_CHECKOUT = os.path.expanduser("~/Sites/personal/checkrein")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

_BODY = "Q7w9ErT2yU4iO6pA8sD1fG3hJ5kL0zX"


def fake(kind):
    """A made-up value shaped like a real secret of the given kind."""
    if kind == "github":
        return "gh" + "p_" + _BODY + "abcde"
    if kind == "aws-id":
        return "AK" + "IA" + "QW7ER9TY2UI4OP6A"
    if kind == "anthropic":
        return "sk-" + "ant-" + "api03-" + _BODY + _BODY
    if kind == "slack":
        return "xo" + "xb-" + "1234567890-" + _BODY
    if kind == "private-key":
        return "-----BEGIN " + "RSA PRIVATE KEY-----"
    if kind == "url":
        return "postgres://app:" + "Zx9Qw7Er5Ty3" + "@db.example.test:5432/app"
    if kind == "assigned":
        return 'api_key = "' + "Zx9Qw7Er5Ty3Ui1Op" + '"'
    if kind == "env-token":
        return "DEPLOY_" + "TOKEN=" + "Vb7Nm3Kq9Lp2Xc5Zr8Tw"
    if kind == "bearer":
        return "Authorization: " + "Bearer " + "eyJhbGciOi" + "JIUzI1NiJ9.e30.Zm9vYmFyYmF6cXV4"
    if kind == "password-flag":
        return "--pass" + "word=" + "Hunter2Correct9Horse"
    if kind == "long-random":
        return "a9F3kL0pQ7zX2mN8vB4cR6tY1uI5oP3sD7fG9hJ2"
    raise KeyError(kind)


SECRET_KINDS = ("github", "aws-id", "anthropic", "slack", "private-key", "url", "assigned", "env-token",
                "bearer", "password-flag", "long-random")


def secret_core(kind):
    """The part of fake(kind) that must never appear in a report."""
    value = fake(kind)
    return {
        "url": "Zx9Qw7Er5Ty3",
        "assigned": "Zx9Qw7Er5Ty3Ui1Op",
        "env-token": "Vb7Nm3Kq9Lp2Xc5Zr8Tw",
        "bearer": "Zm9vYmFyYmF6cXV4",
        "password-flag": "Hunter2Correct9Horse",
        "private-key": "PRIVATE KEY-----",
    }.get(kind, value)


class Transcripts(object):
    """A temp HOME with ~/.claude/projects/<folder>/<session>.jsonl files."""

    def __init__(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="dryfire-test-"))
        self.home = os.path.join(self.root, "home")
        self.projects = os.path.join(self.home, ".claude", "projects")
        self.data = os.path.join(self.root, "data")
        self.project_dir = os.path.join(self.root, "work", "app")
        for d in (self.projects, self.data, self.project_dir):
            os.makedirs(d)
        self._n = 0

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def folder_for(self, project_dir):
        import re
        return re.sub(r"[^A-Za-z0-9]", "-", project_dir)

    def write(self, records, session="s1", project_dir=None, sub=None, raw_tail=b""):
        folder = os.path.join(self.projects, self.folder_for(project_dir or self.project_dir))
        if sub:
            folder = os.path.join(folder, sub)
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, session + ".jsonl")
        with open(path, "ab") as fh:
            for r in records:
                fh.write((r if isinstance(r, str) else json.dumps(r)).encode("utf-8") + b"\n")
            fh.write(raw_tail)
        return path

    def call(self, tool, tool_input, ts="2026-11-20T10:00:00.123Z", cwd=None, tid=None, extra_blocks=()):
        self._n += 1
        tid = tid or "toolu_%04d" % self._n
        return {
            "type": "assistant", "timestamp": ts, "cwd": cwd or self.project_dir, "sessionId": "s1",
            "message": {"role": "assistant", "content": list(extra_blocks) + [
                {"type": "tool_use", "id": tid, "name": tool, "input": tool_input}]},
        }

    def bash(self, command, **kw):
        return self.call("Bash", {"command": command, "description": "x"}, **kw)

    def user(self, mode="default", text="hi"):
        return {"type": "user", "permissionMode": mode, "message": {"role": "user", "content": text},
                "timestamp": "2026-11-20T09:59:00Z", "cwd": self.project_dir}


class TempCase(unittest.TestCase):
    """A test with a fresh Transcripts world and HOME pointing into it."""

    def setUp(self):
        self.t = Transcripts()
        self._home = os.environ.get("HOME")
        os.environ["HOME"] = self.t.home
        self._saved = {k: os.environ.pop(k, None) for k in ("CLAUDE_PLUGIN_DATA", "CLAUDE_PROJECT_DIR",
                                                            "CLAUDE_CONFIG_DIR", "CLAUDE_PLUGIN_OPTION_PRESET",
                                                            "CLAUDE_PLUGIN_OPTION_SANDBOX",
                                                            "CLAUDE_PLUGIN_OPTION_TIMEOUT_SECONDS")}

    def tearDown(self):
        os.environ["HOME"] = self._home
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v
        self.t.close()

    def cli(self, *argv, env_extra=None):
        """Run dryfire's CLI in-process. Returns (exit code, stdout, stderr)."""
        from dryfire import main
        out, err = io.StringIO(), io.StringIO()
        old = dict(os.environ)
        try:
            os.environ.update(env_extra or {})
            argv = list(argv)
            if argv and argv[0] in ("detect", "scan", "replay", "approve"):
                argv[1:1] = ["--data", self.t.data, "--project", self.t.project_dir]
            code = main.main(argv, out, err)
        finally:
            os.environ.clear()
            os.environ.update(old)
        return code, out.getvalue(), err.getvalue()

    def cfgtool(self, *argv):
        from dryfire import cfgtool
        out, err = io.StringIO(), io.StringIO()
        code = cfgtool.main(["--data", self.t.data, "--project", self.t.project_dir] + list(argv), out, err,
                            environ={})
        return code, out.getvalue(), err.getvalue()


def py_hook(body):
    """A hook command running a short Python program that reads the payload as `d`."""
    script = "import sys, json\nd = json.load(sys.stdin)\nc = d['tool_input'].get('command', '')\n" + body
    return "%s -c %s" % (sys.executable, _shquote(script))


def _shquote(s):
    import shlex
    return shlex.quote(s)


def run_script(name, stdin_text, env=None, timeout=20):
    return subprocess.run([sys.executable, os.path.join(SCRIPTS, name)], input=stdin_text.encode("utf-8"),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=timeout)


@contextlib.contextmanager
def quiet_stderr():
    with contextlib.redirect_stderr(io.StringIO()):
        yield


@contextlib.contextmanager
def chdir(path):
    old = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old)
