import json
import os
import shlex
import socket
import sys
import time
import unittest

import helpers
from dryfire import guards, hookio, sandbox

MAC = sandbox.os_sandbox_available()


def py(body):
    return [sys.executable, "-c", body]


class RunTest(unittest.TestCase):
    def test_stdin_is_delivered_and_output_read(self):
        res = sandbox.run(py("import sys; print(sys.stdin.read().upper())"), b"hello", None, None, 10)
        self.assertEqual((res.rc, res.stdout.strip(), res.timed_out), (0, "HELLO", False))

    def test_timeout_kills_the_whole_process_group(self):
        t = helpers.Transcripts()
        self.addCleanup(t.close)
        marker = os.path.join(t.root, "child-alive")
        child = "import time; time.sleep(1.5); open(%r, 'w').close()" % marker
        body = ("import subprocess, sys, time\n"
                "subprocess.Popen([sys.executable, '-c', %r])\n"
                "time.sleep(30)\n" % child)
        started = time.monotonic()
        res = sandbox.run(py(body), b"", None, None, 0.5)
        self.assertTrue(res.timed_out, res.stderr)
        self.assertIsNone(res.rc)
        self.assertLess(time.monotonic() - started, 5)
        time.sleep(2)
        self.assertFalse(os.path.exists(marker), "a grandchild outlived the timeout")

    def test_background_child_holding_pipes_does_not_hang(self):
        body = ("import subprocess, sys\n"
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
                "print('done')\n")
        started = time.monotonic()
        res = sandbox.run(py(body), b"", None, None, 10)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(res.rc, 0)
        self.assertIn("done", res.stdout)

    def test_output_is_capped(self):
        res = sandbox.run(py("import sys; sys.stdout.write('x' * 100000)"), b"", None, None, 10, cap=1000)
        self.assertEqual(len(res.stdout), 1000)
        self.assertTrue(res.truncated)

    def test_missing_program_is_a_start_error(self):
        res = sandbox.run(["/nonexistent/hook"], b"", None, None, 5)
        self.assertTrue(res.start_error)

    def test_large_stdin_does_not_deadlock(self):
        payload = b"y" * (1024 * 1024)
        res = sandbox.run(py("import sys; print(len(sys.stdin.buffer.read()))"), payload, None, None, 10)
        self.assertEqual(res.stdout.strip(), str(len(payload)))


class PinPathsTest(helpers.TempCase):
    def setUp(self):
        helpers.TempCase.setUp(self)
        self.base = self.t.root
        os.makedirs(os.path.join(self.base, "my hooks"))
        open(os.path.join(self.base, "my hooks", "run.sh"), "w").close()

    def pin(self, command):
        return sandbox.pin_paths(command, self.base, "/proj")

    def test_relative_script_and_project_variable(self):
        self.assertEqual(self.pin("./guard.sh --strict"), os.path.join(self.base, "guard.sh") + " --strict")
        self.assertEqual(self.pin('"$CLAUDE_PROJECT_DIR"/.claude/g.sh'), '"/proj"/.claude/g.sh')

    def test_nothing_after_a_cd_is_pinned(self):
        for c in ("cd ~/tools/guard && ./run.sh", "cd $HOME/tools && ./run.sh", "pushd x; ./run.sh"):
            self.assertEqual(self.pin(c), c)

    def test_quoted_relative_paths_stay_one_word(self):
        want = shlex.split(self.pin("bash 'my hooks/run.sh' x"))
        self.assertEqual(want, ["bash", os.path.join(self.base, "my hooks", "run.sh"), "x"])
        self.assertEqual(shlex.split(self.pin('sh ./"my hooks"/run.sh'))[1],
                         os.path.join(self.base, "my hooks", "run.sh"))

    def test_a_script_string_is_left_alone(self):
        for c in ("sh -c './\"my hooks\"/run.sh'", "sh -c './x.sh arg'", "bash -c 'cd /a && ./b'",
                  "./g.sh $(echo x/y)", "./g.sh 'a;b'"):
            words = shlex.split(self.pin(c))
            self.assertEqual(words[1:], shlex.split(c)[1:], c)


class BoxAndEnvTest(unittest.TestCase):
    def test_box_is_private_and_removed(self):
        with sandbox.Box() as box:
            root = box.root
            self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
            for d in (box.home, box.project, box.data, box.tmp):
                self.assertTrue(os.path.isdir(d))
        self.assertFalse(os.path.exists(root))

    def test_seed_files_cannot_escape_the_data_folder(self):
        t = helpers.Transcripts()
        try:
            src = os.path.join(t.root, "seed.json")
            with open(src, "w") as fh:
                fh.write("{}")
            with sandbox.Box({"cfg/seed.json": src, "../escape.json": src}) as box:
                self.assertTrue(os.path.exists(os.path.join(box.data, "cfg", "seed.json")))
                self.assertFalse(os.path.exists(os.path.join(box.root, "escape.json")))
        finally:
            t.close()

    def test_environment_is_rebuilt_without_user_tokens(self):
        base = {"PATH": "/usr/bin", "GH_TOKEN": "abc", "AWS_SECRET_ACCESS_KEY": "x", "LANG": "C"}
        with sandbox.Box() as box:
            env = sandbox.build_env(box, "/plug", {"preset": "strict", "fail-mode": None}, base=base)
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
            self.assertEqual(env["HOME"], box.home)
            self.assertEqual(env["CLAUDE_PLUGIN_DATA"], box.data)
            self.assertEqual(env["CLAUDE_PLUGIN_OPTION_PRESET"], "strict")
            self.assertEqual(env["CLAUDE_PLUGIN_OPTION_FAIL_MODE"], "")

    def test_mode_for(self):
        self.assertEqual(sandbox.mode_for("env"), "env")
        if MAC:
            self.assertEqual(sandbox.mode_for("required"), "os")
        else:
            with self.assertRaises(sandbox.SandboxUnavailable):
                sandbox.mode_for("required")
            self.assertEqual(sandbox.mode_for("auto"), "env")

    def test_expand_command(self):
        cmd = sandbox.expand_command('python3 "${CLAUDE_PLUGIN_ROOT}/x.py" ~/a $HOME/b', "/h", "/p")
        self.assertEqual(cmd, 'python3 "/p/x.py" /h/a /h/b')

    def test_version_manager_shim_allows_its_root(self):
        # A pyenv/asdf/mise shim is a script that reads the manager's whole folder, not just the shim.
        import shutil
        import tempfile
        home = os.path.realpath(tempfile.mkdtemp(prefix="dryfire-shim-"))
        try:
            shims = os.path.join(home, ".pyenv", "shims")
            os.makedirs(shims)
            shim = os.path.join(shims, "python3")
            with open(shim, "w") as fh:
                fh.write("#!/bin/sh\n")
            os.chmod(shim, 0o755)
            with open(os.path.join(home, ".tool-versions"), "w") as fh:
                fh.write("python 3.12.0\n")
            paths = sandbox.read_paths_for([shim, "-c", "pass"], home)
            self.assertIn(os.path.join(home, ".pyenv"), paths)
            self.assertIn(os.path.join(home, ".tool-versions"), paths)
            self.assertIn("shim", sandbox.shim_note([shim, "x"], home))
            self.assertEqual(sandbox.shim_note([sys.executable, "x"], home), "")
        finally:
            shutil.rmtree(home, ignore_errors=True)


@unittest.skipUnless(MAC, "the OS sandbox is macOS only")
class OsSandboxTest(unittest.TestCase):
    """The hook runs under sandbox-exec: no network, no writes outside the box, no reads of the real home."""

    def setUp(self):
        self.t = helpers.Transcripts()
        self.real_home = self.t.home  # A stand-in "real home" with a private file in it.
        self.private = os.path.join(self.real_home, "private.txt")
        with open(self.private, "w") as fh:
            fh.write("private")

    def tearDown(self):
        self.t.close()

    def run_boxed(self, body, read_paths=()):
        with sandbox.Box() as box:
            argv = sandbox.hook_argv(None, py(body), "os", box, self.real_home, list(read_paths))
            env = sandbox.build_env(box)
            return sandbox.run(argv, b"", env, box.project, 20)

    def test_reads_of_the_real_home_are_denied(self):
        res = self.run_boxed("print(open(%r).read())" % self.private)
        self.assertNotEqual(res.rc, 0)
        self.assertNotIn("private", res.stdout)

    def test_allowed_read_path_is_readable(self):
        res = self.run_boxed("print(open(%r).read())" % self.private, [self.real_home])
        self.assertEqual(res.stdout.strip(), "private")

    def test_writes_outside_the_box_are_denied(self):
        target = os.path.join(self.t.root, "written.txt")
        res = self.run_boxed("open(%r, 'w').write('x')" % target)
        self.assertNotEqual(res.rc, 0)
        self.assertFalse(os.path.exists(target))

    def test_writes_inside_the_box_work(self):
        res = self.run_boxed("import os; p = os.path.join(os.environ['HOME'], 'f'); open(p, 'w').write('x'); "
                             "print(open(p).read())")
        self.assertEqual(res.stdout.strip(), "x")

    def test_preference_daemon_cannot_write_for_the_hook(self):
        # cfprefsd writes ~/Library/Preferences on a caller's behalf, outside the file rules.
        import subprocess
        import uuid
        domain = "dryfire.sandbox.probe." + uuid.uuid4().hex[:12]
        try:
            self.run_boxed("import subprocess; subprocess.run(['/usr/bin/defaults', 'write', %r, 'k', 'escaped'])"
                           % domain)
            read = subprocess.run(["/usr/bin/defaults", "read", domain, "k"], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL)
            self.assertNotIn(b"escaped", read.stdout)
        finally:
            subprocess.run(["/usr/bin/defaults", "delete", domain], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            plist = os.path.expanduser("~/Library/Preferences/%s.plist" % domain)
            if os.path.exists(plist):
                os.unlink(plist)

    def test_profile_denies_services_that_act_for_the_hook(self):
        text = sandbox.profile("/box", "/h", [])
        for name in ("com.apple.cfprefsd", "com.apple.pasteboard", "com.apple.SecurityServer",
                     "com.apple.coreservices.appleevents", "com.apple.coreservices.launchservicesd",
                     "com.apple.metadata.mds"):
            self.assertIn(name, text)

    def test_network_is_denied(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            res = self.run_boxed("import socket; s = socket.create_connection(('127.0.0.1', %d), 2); "
                                 "print('connected')" % port)
        finally:
            srv.close()
        self.assertNotIn("connected", res.stdout)
        self.assertNotEqual(res.rc, 0)


class HookGuardTest(helpers.TempCase):
    def guard(self, body, mode="env", **spec):
        s = guards.HookSpec(command=helpers.py_hook(body), matcher=spec.pop("matcher", "Bash"), **spec)
        return guards.HookGuard("h", s, self.t.home, timeout=10, sandbox_mode=mode)

    def test_hook_sees_temp_home_and_project_not_real_ones(self):
        body = ("import os\nprint(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', "
                "'permissionDecision': 'deny', 'permissionDecisionReason': os.environ['HOME'] + '|' + d['cwd']}}))")
        g = self.guard(body)
        out = g.evaluate("Bash", {"command": "ls"}, "default")
        self.assertEqual(out.decision, hookio.DENY)
        home, cwd = out.reason.split("|")
        self.assertNotEqual(home, self.t.home)
        self.assertNotEqual(home, os.path.expanduser("~"))
        self.assertTrue(cwd.startswith(os.path.dirname(home)))
        self.assertFalse(os.path.exists(home), "the box was not removed")

    def test_exit_2_hook_denies(self):
        g = self.guard("if 'rm' in c:\n    sys.stderr.write('no rm')\n    sys.exit(2)")
        self.assertEqual(g.evaluate("Bash", {"command": "rm -rf x"}, "default").decision, hookio.DENY)
        self.assertEqual(g.evaluate("Bash", {"command": "ls"}, "default").decision, hookio.NONE)

    def test_permission_mode_reaches_the_hook(self):
        g = self.guard("print(json.dumps({'decision': 'block', 'reason': d['permission_mode']}))")
        self.assertEqual(g.evaluate("Bash", {"command": "ls"}, "plan").reason, "plan")

    def test_rule_rx_pulls_a_rule_id(self):
        import re
        s = guards.HookSpec(command=helpers.py_hook("sys.stderr.write('tool GIT01 (deny): no'); sys.exit(2)"))
        g = guards.HookGuard("h", s, self.t.home, rule_rx=re.compile(r"\b([A-Z]{2,5}\d{2})\b"))
        self.assertEqual(g.evaluate("Bash", {"command": "x"}, "default").rule, "GIT01")

    @unittest.skipUnless(MAC, "the OS sandbox is macOS only")
    def test_hook_under_os_sandbox_cannot_touch_real_home(self):
        target = os.path.join(self.t.home, "touched")
        g = self.guard("open(%r, 'w').write('x')" % target, mode="os")
        out = g.evaluate("Bash", {"command": "ls"}, "default")
        self.assertFalse(os.path.exists(target))
        self.assertEqual(out.decision, hookio.ERROR)


if __name__ == "__main__":
    unittest.main()
