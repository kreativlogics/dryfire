"""Checks on the repository itself: no network code, vendored files intact, manifests and skills consistent."""

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

import helpers

PKG = os.path.join(helpers.SCRIPTS, "dryfire")
NETWORK_MODULES = {"socket", "ssl", "urllib", "http", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib",
                   "xmlrpc", "requests", "asyncio", "webbrowser"}


def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def py_files(*roots):
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in files:
                if f.endswith(".py"):
                    yield os.path.join(dirpath, f)


def text_files():
    for dirpath, dirs, files in os.walk(helpers.ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for f in files:
            if not f.endswith((".png", ".pyc")):
                yield os.path.join(dirpath, f)


class NoNetworkTest(unittest.TestCase):
    def test_no_network_module_is_imported(self):
        for path in py_files(helpers.SCRIPTS):
            tree = ast.parse(read(path), path)
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module or ""]
                elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "__import__":
                    names = ["__import__"]
                for name in names:
                    self.assertNotIn(name.split(".")[0], NETWORK_MODULES | {"__import__", "importlib"},
                                     "%s imports %s" % (path, name))


class VendoredTest(unittest.TestCase):
    def test_vendored_files_match_their_recorded_hash(self):
        text = read(os.path.join(helpers.ROOT, "VENDORED.md"))
        rows = re.findall(r"^\| `([a-z_]+\.py)` \|.*\| `([0-9a-f]{64})` \|$", text, re.M)
        self.assertEqual(sorted(r[0] for r in rows),
                         ["approve.py", "context.py", "ledger.py", "secrets.py", "shell.py"])
        for name, digest in rows:
            with open(os.path.join(PKG, name), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest, name)


class ManifestTest(unittest.TestCase):
    def load(self, *parts):
        with open(os.path.join(helpers.ROOT, *parts), encoding="utf-8") as fh:
            return json.load(fh)

    def test_manifests_agree(self):
        market = self.load(".claude-plugin", "marketplace.json")
        plugin = self.load("plugins", "dryfire", ".claude-plugin", "plugin.json")
        self.assertEqual(market["plugins"][0]["source"], "./plugins/dryfire")
        self.assertEqual(plugin["name"], "dryfire")
        from dryfire import __version__
        self.assertEqual(plugin["version"], __version__)
        self.assertNotIn("email", json.dumps(market["owner"]) + json.dumps(plugin["author"]))

    def test_user_config_matches_the_settings_schema(self):
        from dryfire import cfg
        options = self.load("plugins", "dryfire", ".claude-plugin", "plugin.json")["userConfig"]
        self.assertEqual(sorted(options), sorted(cfg.OPTION_KEYS))
        for key, spec in options.items():
            schema = cfg.SCHEMA[key]
            self.assertEqual(str(spec["default"]), str(schema["default"]), key)
            if "choices" in schema:
                self.assertEqual(sorted(spec["options"]), sorted(schema["choices"]), key)

    def test_icon_is_a_512_png_the_generator_reproduces(self):
        icon = os.path.join(helpers.PLUGIN, ".claude-plugin", "icon.png")
        with open(icon, "rb") as fh:
            data = fh.read()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(data[16:24], b"\x00\x00\x02\x00\x00\x00\x02\x00")
        sys.path.insert(0, os.path.join(helpers.ROOT, "tools"))
        try:
            import make_icon
        finally:
            sys.path.pop(0)
        self.assertEqual(make_icon.png(make_icon.render()), data)

    def test_hook_runs_selfguard_on_the_tools_it_checks(self):
        hooks = self.load("plugins", "dryfire", "hooks", "hooks.json")["hooks"]
        entry = hooks["PreToolUse"][0]
        self.assertEqual(entry["matcher"], "Bash|Write|Edit|MultiEdit|NotebookEdit")
        self.assertIn("/scripts/selfguard.py", entry["hooks"][0]["command"])
        self.assertLessEqual(entry["hooks"][0]["timeout"], 10)


class SkillTest(unittest.TestCase):
    def skills(self):
        root = os.path.join(helpers.PLUGIN, "skills")
        for name in sorted(os.listdir(root)):
            with open(os.path.join(root, name, "SKILL.md"), encoding="utf-8") as fh:
                yield name, fh.read()

    def test_skills_name_scripts_that_exist(self):
        for name, text in self.skills():
            for script in re.findall(r"\$\{CLAUDE_PLUGIN_ROOT\}/(scripts/[a-z_]+\.py)", text):
                self.assertTrue(os.path.isfile(os.path.join(helpers.PLUGIN, script)), (name, script))

    def test_no_skill_preapproves_an_approval_or_a_settings_change(self):
        for name, text in self.skills():
            allowed = re.search(r"^allowed-tools: (.*)$", text, re.M).group(1)
            for word in (" approve", " set", " unset", " init"):
                self.assertNotIn(word, allowed, name)

    def test_frontmatter_has_name_and_description(self):
        for name, text in self.skills():
            self.assertTrue(text.startswith("---\nname: %s\ndescription: " % name), name)


class SourceTest(unittest.TestCase):
    def test_no_email_address_anywhere(self):
        rx = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}")
        for path in text_files():
            text = read(path)
            # git@host is an SSH remote, not a mailbox.
            found = [m for m in rx.findall(text) if not m.endswith((".test", ".example")) and
                     not m.startswith("git@")]
            self.assertEqual(found, [], path)

    def test_no_invisible_characters_anywhere(self):
        # They hide what code does from a reader; code spells them as escapes instead.
        rx = re.compile("[\u00a0\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]")
        for path in text_files():
            self.assertIsNone(rx.search(read(path)), path)

    def test_runs_on_python_3_9(self):
        py39 = "/usr/bin/python3"
        if not os.path.exists(py39):
            self.skipTest("no system Python to compare with")
        out = subprocess.run([py39, "-c", "import sys; print(sys.version_info[:2] >= (3, 9))"],
                             stdout=subprocess.PIPE).stdout
        if out.strip() != b"True":
            self.skipTest("system Python is not 3.9+")
        files = list(py_files(helpers.SCRIPTS, os.path.join(helpers.ROOT, "tests"),
                              os.path.join(helpers.ROOT, "tools")))
        code = "import ast, sys\nfor p in sys.argv[1:]:\n    with open(p) as fh:\n        ast.parse(fh.read(), p)\n"
        res = subprocess.run([py39, "-c", code] + files, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(res.returncode, 0, res.stderr.decode())


class NoBytecodeTest(helpers.TempCase):
    def test_running_the_plugin_leaves_no_bytecode_in_its_folder(self):
        # A skill audit compares the installed folder with what it scanned; __pycache__ written there on first use
        # would read as the plugin changing itself and shipping bytecode.
        copy = os.path.join(self.t.root, "plugin")
        shutil.copytree(helpers.PLUGIN, copy, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.t.home, "CLAUDE_PLUGIN_DATA": self.t.data}
        scripts = os.path.join(copy, "scripts")
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/"}).encode()
        for argv, stdin in (([os.path.join(scripts, "selfguard.py")], payload),
                            ([os.path.join(scripts, "cli.py"), "--version"], b""),
                            ([os.path.join(scripts, "cfgtool.py"), "--help"], b"")):
            subprocess.run([sys.executable] + argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=env, cwd=self.t.root, timeout=30)
        left = [os.path.join(d, f) for d, dirs, files in os.walk(copy) for f in dirs + files
                if f == "__pycache__" or f.endswith((".pyc", ".pyo"))]
        self.assertEqual(left, [])


if __name__ == "__main__":
    unittest.main()
