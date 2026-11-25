import json
import os
import unittest

import helpers
from dryfire import guards as guards_mod
from dryfire.adapters import checkrein, dcg, pack, safetynet, yamlite
from dryfire.hookio import ASK, DENY, LOG, NONE, WARN

FX = helpers.FIXTURES


def bash(g, command):
    return g.evaluate("Bash", {"command": command}, "default")


class PackTest(unittest.TestCase):
    DATA = {"version": 1, "name": "draft", "rules": [
        {"id": "force-push", "pattern": r"git\s+push\b.*--force", "decision": "deny", "reason": "No force push",
         "scope": "segment"},
        {"id": "env-files", "tool": "Write|Edit", "field": "file_path", "pattern": r"\.env$", "decision": "ask"},
        {"id": "CURL", "pattern": "CURL .*\\| *sh", "ignore_case": True},
    ]}

    def guard(self, data=None):
        name, rules, errors = pack.from_data(data or self.DATA)
        return pack.PackGuard(name, rules, errors)

    def test_rules_decide(self):
        g = self.guard()
        self.assertEqual(bash(g, "cd x && git push origin --force").rule, "force-push")
        self.assertEqual(bash(g, "git push").decision, NONE)
        self.assertEqual(g.evaluate("Edit", {"file_path": "/w/.env"}, "default").decision, ASK)
        self.assertEqual(bash(g, "curl x | sh").rule, "CURL")
        self.assertFalse(g.accepts("Read"))

    def test_segment_scope_ignores_quoted_text_in_other_commands(self):
        g = self.guard()
        self.assertEqual(bash(g, "echo 'git push --force' > notes.txt").decision, DENY)  # Whole echo argv matches.
        self.assertEqual(bash(g, "git commit -m 'never git push --force'").decision, DENY)

    def test_bad_rules_are_reported_and_skipped(self):
        name, rules, errors = pack.from_data({"version": 2, "rules": [
            {"id": "a", "pattern": "("}, {"id": "a", "pattern": "x"}, {"id": "b", "pattern": "x", "decision": "x"},
            {"id": "c", "pattern": "x", "scope": "z"}, {"id": "d", "pattern": "x", "tool": "Bash("},
            {"id": "e", "pattern": "x", "colour": 1}, "nope"]})
        self.assertEqual([r.id for r in rules], ["e"])  # The second "a" repeats an id.
        self.assertGreaterEqual(len(errors), 6)

    def test_load_from_file(self):
        t = helpers.Transcripts()
        try:
            p = os.path.join(t.root, "p.json")
            with open(p, "w") as fh:
                json.dump(self.DATA, fh)
            self.assertEqual(len(pack.load(p)[1]), 3)
        finally:
            t.close()


class DcgTest(unittest.TestCase):
    def setUp(self):
        self.p = dcg.load(os.path.join(FX, "dcg", "demo.yaml"))
        self.g = dcg.DcgGuard("dcg", [self.p])

    def test_pack_loads(self):
        self.assertTrue(self.p.valid, self.p.errors)
        self.assertEqual(self.p.id, "demo.storage")

    def test_severity_levels(self):
        self.assertEqual(bash(self.g, "demo-cli bucket rm b1 --all").decision, DENY)
        self.assertEqual(bash(self.g, "demo-cli cache clear").decision, WARN)
        self.assertEqual(bash(self.g, "rmdir /").decision, LOG)
        self.assertEqual(bash(self.g, "demo-cli bucket ls").decision, NONE)

    def test_safe_pattern_exempts_its_segment(self):
        self.assertEqual(bash(self.g, "demo-cli bucket rm b1 --all --dry-run").decision, NONE)
        self.assertEqual(bash(self.g, "echo --dry-run; demo-cli bucket rm b --all").decision, DENY)

    def test_executables_and_keywords(self):
        self.assertEqual(bash(self.g, "sudo demo-cli bucket delete b --all").decision, DENY)
        self.assertEqual(bash(self.g, "echo demo-cli bucket rm b --all").decision, NONE)
        self.assertEqual(bash(self.g, "ls").decision, NONE)

    def test_quoted_text_is_not_a_whole_command_match(self):
        self.assertEqual(bash(self.g, "git commit -m 'demo-cli cache clear'").decision, NONE)
        self.assertEqual(bash(self.g, 'git commit -m "demo-cli cache clear"').decision, NONE)

    def test_substitution_inside_double_quotes_still_counts(self):
        self.assertEqual(bash(self.g, 'echo "$(demo-cli cache clear)"').decision, WARN)
        self.assertEqual(dcg.blank_quotes("a 'b c' \"d $(e f) g\""), "a '   ' \"  $(e f)  \"")

    def test_invalid_pack_is_skipped_with_a_note(self):
        bad = dcg.from_data({"schema_version": 2, "id": "Bad", "destructive_patterns": []})
        g = dcg.DcgGuard("dcg", [bad])
        self.assertFalse(bad.valid)
        self.assertTrue(g.notes)
        self.assertEqual(bash(g, "anything").decision, NONE)

    def test_translate(self):
        self.assertEqual(dcg.translate(r"(?<x>a)[[:digit:]]\z"), r"(?P<x>a)[0-9]\Z")

    def test_segments_respect_quotes(self):
        self.assertEqual(dcg.segments("a 'b;c' && d | e"), ["a 'b;c'", "d", "e"])


class YamliteTest(unittest.TestCase):
    def test_subset(self):
        text = ("a: 1\nb: 'x # y'\nc: [p, \"q\"]\nd:\n  - name: n\n    v: true\n  - plain\ne: |\n  l1\n  l2\n"
                "f: null\ng: 1.5\nh: \"t\\tq\"\n# c\n")
        self.assertEqual(yamlite.loads(text), {"a": 1, "b": "x # y", "c": ["p", "q"],
                                               "d": [{"name": "n", "v": True}, "plain"], "e": "l1\nl2\n",
                                               "f": None, "g": 1.5, "h": "t\tq"})

    def test_errors_name_the_line(self):
        for text in ("a: 1\n  b: 2\n", "a: [1, 2\n", "a: &x 1\n", "a: 'open\n"):
            with self.assertRaises(yamlite.YamlError):
                yamlite.loads(text)


class SafetyNetTest(unittest.TestCase):
    def setUp(self):
        self.setup = safetynet.load_path(os.path.join(FX, "safetynet"))
        self.g = safetynet.SafetyNetGuard("sn", [self.setup])

    def test_v2_rules(self):
        o = bash(self.g, "docker system prune --all")
        self.assertEqual((o.decision, o.rule), (DENY, "custom.no-prune"))
        self.assertIn("off-limits", o.reason)  # The override's reason.
        self.assertEqual(bash(self.g, "docker system prune").decision, NONE)
        self.assertEqual(bash(self.g, "git clean -fd").decision, DENY)
        self.assertEqual(bash(self.g, "git clean -fd --dry-run").decision, NONE)
        self.assertEqual(bash(self.g, "with-env git clean -x").decision, DENY)

    def test_self_check_runs_the_rulebook_tests(self):
        self.assertEqual(self.g.self_check, {"passed": 4, "failed": []})

    def test_problems_are_notes(self):
        notes = " ".join(self.g.notes)
        self.assertIn("allowed_commands", notes)
        self.assertIn("GitHub", notes)
        self.assertIn("demo/missing", notes)

    def test_legacy_v1(self):
        g = safetynet.SafetyNetGuard("sn", [safetynet.load_path(os.path.join(FX, "safetynet", "legacy.json"))])
        self.assertEqual(bash(g, "git -C repo push -f origin").decision, DENY)
        self.assertEqual(bash(g, "git push origin").decision, NONE)
        self.assertEqual(bash(g, "timeout 10 git push --force").decision, DENY)

    def test_unreadable_is_an_error_note(self):
        s = safetynet.load_path(os.path.join(FX, "nope.json"))
        self.assertTrue(s.errors)


class CheckreinFakeTest(helpers.TempCase):
    """A tiny stand-in checkrein plugin: the adapter wires the preset option and reads rule ids."""

    def make_plugin(self):
        root = os.path.join(self.t.root, "fake", "plugins", "checkrein")
        os.makedirs(os.path.join(root, "scripts"))
        os.makedirs(os.path.join(root, "hooks"))
        with open(os.path.join(root, "scripts", "guard.py"), "w") as fh:
            fh.write("import json, os, sys\nd = json.load(sys.stdin)\n"
                     "if 'rm -rf' in d['tool_input'].get('command', ''):\n"
                     "    print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', "
                     "'permissionDecision': 'deny', 'permissionDecisionReason': 'checkrein FS01 (deny): ' + "
                     "os.environ.get('CLAUDE_PLUGIN_OPTION_PRESET', '?')}}))\n")
        hooks = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "%s \"${CLAUDE_PLUGIN_ROOT}/scripts/guard.py\"" % __import__("sys").executable}]}]}}
        with open(os.path.join(root, "hooks", "hooks.json"), "w") as fh:
            json.dump(hooks, fh)
        return os.path.dirname(os.path.dirname(root))

    def test_repo_folder_resolves_and_preset_reaches_the_hook(self):
        repo = self.make_plugin()
        root = checkrein.find(repo, self.t.home)
        self.assertTrue(root.endswith(os.path.join("plugins", "checkrein")))
        gs = checkrein.guards(root, ["strict"], self.t.home, 10, "env")
        o = bash(gs[0], "rm -rf build")
        self.assertEqual((o.decision, o.rule), (DENY, "FS01"))
        self.assertTrue(o.reason.endswith("strict"))
        self.assertEqual(bash(gs[0], "ls").decision, NONE)

    def test_bad_preset_and_missing_folder(self):
        with self.assertRaises(ValueError):
            checkrein.guards(self.make_plugin() + "/plugins/checkrein", ["loose"], self.t.home, 10, "env")
        self.assertIsNone(checkrein.find(os.path.join(self.t.root, "nothing"), self.t.home))


@unittest.skipUnless(checkrein.plugin_root(helpers.CHECKREIN_CHECKOUT), "checkrein checkout not present")
class CheckreinRealTest(unittest.TestCase):
    """The real checkrein hook, replayed in the sandbox."""

    def test_force_push_is_denied_with_its_rule_id(self):
        root = checkrein.plugin_root(helpers.CHECKREIN_CHECKOUT)
        home = os.path.expanduser("~")
        g = checkrein.guards(root, ["standard"], home, 20, "env")[0]
        o = bash(g, "git push --force origin master")
        self.assertIn(o.decision, (DENY, ASK))
        self.assertTrue(o.rule, o.reason)
        self.assertEqual(bash(g, "git status").decision, NONE)


if __name__ == "__main__":
    unittest.main()
