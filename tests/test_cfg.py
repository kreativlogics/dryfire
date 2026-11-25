import json
import os
import unittest

import helpers
from dryfire import approve, cfg


class CfgCase(helpers.TempCase):
    def write_user(self, data):
        cfg.write_layer(cfg.user_path(self.t.data), data)

    def write_project(self, data):
        path = cfg.project_path(self.t.project_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(data, fh)

    def resolve(self, flags=None, env=None):
        return cfg.resolve(self.t.data, self.t.project_dir, flags, env or {})


class ValidateTest(unittest.TestCase):
    def test_unknown_key_with_hint(self):
        errs = cfg.validate({"timout": 5}, "x")
        self.assertEqual(len(errs), 1)
        self.assertIn("timeout_seconds", errs[0])

    def test_types_ranges_and_choices(self):
        self.assertTrue(cfg.validate({"timeout_seconds": True}, "x"))
        self.assertTrue(cfg.validate({"timeout_seconds": "5"}, "x"))
        self.assertTrue(cfg.validate({"timeout_seconds": 0}, "x"))
        self.assertTrue(cfg.validate({"sandbox": "off"}, "x"))
        self.assertTrue(cfg.validate({"redact_patterns": ["("]}, "x"))
        self.assertTrue(cfg.validate({"allow_read": [1]}, "x"))
        self.assertEqual(cfg.validate({"timeout_seconds": 5, "sandbox": "required"}, "x"), [])

    def test_hooks_shape(self):
        self.assertEqual(cfg.validate({"hooks": {"g": {"command": "x", "matcher": "Bash"}}}, "x"), [])
        self.assertTrue(cfg.validate({"hooks": {"g": {"matcher": "Bash"}}}, "x"))
        self.assertTrue(cfg.validate({"hooks": {"g": {"command": "x", "run": 1}}}, "x"))
        self.assertTrue(cfg.validate({"hooks": {"../g": {"command": "x"}}}, "x"))
        self.assertTrue(cfg.validate({"hooks": {"g": {"command": "x", "on_failure": "maybe"}}}, "x"))

    def test_secret_values_are_refused(self):
        errs = cfg.validate({"hooks": {"g": {"command": "x --token " + helpers.fake("github")}}}, "x")
        self.assertTrue(any("secret" in e for e in errs))

    def test_newer_version_refused(self):
        self.assertTrue(cfg.validate({"version": cfg.VERSION + 1}, "x"))

    def test_parse_value(self):
        self.assertEqual(cfg.parse_value("timeout_seconds", "5"), 5)
        self.assertEqual(cfg.parse_value("sandbox", "env"), "env")
        self.assertEqual(cfg.parse_value("redact_patterns", '["a"]'), ["a"])
        with self.assertRaises(cfg.ConfigError):
            cfg.parse_value("timeout_seconds", "five")
        with self.assertRaises(cfg.ConfigError):
            cfg.parse_value("nope", "1")


class ResolveTest(CfgCase):
    def test_defaults_and_preset(self):
        eff = self.resolve()
        self.assertEqual((eff.values["window_days"], eff.values["timeout_seconds"]), (30, 10))
        eff = self.resolve({"preset": "quick"})
        self.assertEqual(eff.values["window_days"], 7)

    def test_user_options_env_and_file(self):
        self.write_user({"version": 1, "timeout_seconds": 30})
        eff = self.resolve(env={"CLAUDE_PLUGIN_OPTION_SANDBOX": "required",
                                "CLAUDE_PLUGIN_OPTION_TIMEOUT_SECONDS": "5", "CLAUDE_PLUGIN_OPTION_PRESET": "deep"})
        self.assertEqual(eff.values["sandbox"], "required")
        self.assertEqual(eff.values["window_days"], 365)
        self.assertEqual(eff.values["timeout_seconds"], 30)  # The file beats the option.
        self.assertEqual(eff.source["timeout_seconds"], "user")

    def test_plugin_options_in_the_environment_only_tighten(self):
        # Whoever runs the CLI sets its environment, and that may be the agent: options can't loosen safety.
        eff = self.resolve(env={"CLAUDE_PLUGIN_OPTION_SANDBOX": "env", "CLAUDE_PLUGIN_OPTION_TIMEOUT_SECONDS": "120"})
        self.assertEqual((eff.values["sandbox"], eff.values["timeout_seconds"]), ("auto", 10))
        self.assertTrue(any("sandbox" in n for n in eff.notes), eff.notes)
        self.assertTrue(any("timeout_seconds" in n for n in eff.notes), eff.notes)
        self.write_user({"sandbox": "env"})
        self.assertEqual(self.resolve().values["sandbox"], "env")  # Your own config file still can.

    def test_project_can_only_tighten(self):
        self.write_user({"timeout_seconds": 20, "sandbox": "env", "scope": "all", "redact_home": True})
        self.write_project({"timeout_seconds": 60, "sandbox": "required", "scope": "project", "redact_home": False})
        eff = self.resolve()
        v = eff.values
        self.assertEqual((v["timeout_seconds"], v["sandbox"], v["scope"], v["redact_home"]),
                         (20, "required", "project", True))
        self.assertTrue(any("timeout_seconds" in n for n in eff.notes))
        self.assertTrue(any("redact_home" in n for n in eff.notes))

    def test_run_flags_can_only_tighten(self):
        self.write_user({"sandbox": "required"})
        eff = self.resolve({"sandbox": "env", "timeout_seconds": 3})
        self.assertEqual((eff.values["sandbox"], eff.values["timeout_seconds"]), ("required", 3))

    def test_redact_patterns_add_up(self):
        self.write_user({"redact_patterns": ["a"]})
        self.write_project({"redact_patterns": ["b", "a"]})
        self.assertEqual(self.resolve().values["redact_patterns"], ["a", "b"])

    def test_project_patterns_that_can_backtrack_for_ages_are_dropped(self):
        self.write_user({"redact_patterns": ["(a+)+$"]})
        self.write_project({"redact_patterns": ["(x+)+y", "(?:ab|a)*c", "tok_[A-Za-z0-9]{20}", "(\\d{3})-\\d+",
                                                "a+a+a+b"]})
        eff = self.resolve()
        self.assertEqual(eff.values["redact_patterns"], ["(a+)+$", "tok_[A-Za-z0-9]{20}", "(\\d{3})-\\d+"])
        self.assertEqual(sum("user config" in n for n in eff.notes), 3, eff.notes)

    def test_transcript_roots_user_only(self):
        self.write_project({"transcript_roots": ["/elsewhere"]})
        eff = self.resolve()
        self.assertEqual(eff.values["transcript_roots"], [])
        self.assertTrue(eff.notes)

    def test_project_allow_read_needs_approval(self):
        self.write_project({"allow_read": ["~/secrets"]})
        eff = self.resolve()
        self.assertEqual(eff.values["allow_read"], [])
        self.assertIn("approve", eff.notes[0])
        approve.grant(self.t.data, self.t.project_dir, "allow_read", "~/secrets")
        self.assertEqual(self.resolve().values["allow_read"], ["~/secrets"])

    def test_allow_read_approval_is_bound_to_the_project(self):
        approve.grant(self.t.data, "/some/other/project", "allow_read", "~/secrets")
        self.write_project({"allow_read": ["~/secrets"]})
        self.assertEqual(self.resolve().values["allow_read"], [])

    def test_project_hooks_are_bound_to_the_project(self):
        self.write_user({"hooks": {"mine": {"command": "a"}}})
        self.write_project({"hooks": {"theirs": {"command": "b"}}})
        hooks = self.resolve().hooks
        self.assertEqual(hooks["mine"][1:], ("user", ""))
        self.assertEqual(hooks["theirs"][1:], ("project", self.t.project_dir))

    def test_project_hook_does_not_shadow_a_user_hook_of_the_same_name(self):
        self.write_user({"hooks": {"guard": {"command": "mine"}}})
        self.write_project({"hooks": {"guard": {"command": "theirs"}}})
        eff = self.resolve()
        self.assertEqual(eff.hooks["guard"], ({"command": "mine"}, "user", ""))
        self.assertEqual(eff.hooks["project:guard"], ({"command": "theirs"}, "project", self.t.project_dir))
        self.assertTrue(any("project:guard" in n for n in eff.notes), eff.notes)

    def test_write_layer_does_not_follow_a_planted_temp_file(self):
        victim = os.path.join(self.t.root, "victim.txt")
        with open(victim, "w") as fh:
            fh.write("keep")
        path = cfg.user_path(self.t.data)
        os.symlink(victim, path + ".tmp")
        self.write_user({"timeout_seconds": 5})
        with open(victim) as fh:
            self.assertEqual(fh.read(), "keep")
        self.assertEqual(self.resolve().values["timeout_seconds"], 5)

    def test_bad_project_file_is_an_error(self):
        self.write_project({"sandbox": "nope"})
        with self.assertRaises(cfg.ConfigError):
            self.resolve()
        path = cfg.project_path(self.t.project_dir)
        with open(path, "w") as fh:
            fh.write("{not json")
        with self.assertRaises(cfg.ConfigError):
            self.resolve()

    def test_write_layer_validates_first(self):
        with self.assertRaises(cfg.ConfigError):
            self.write_user({"timeout_seconds": 999})
        self.assertFalse(os.path.exists(cfg.user_path(self.t.data)))


class CfgToolTest(CfgCase):
    def test_set_show_unset(self):
        self.assertEqual(self.cfgtool("set", "timeout_seconds", "7")[0], 0)
        code, out, _ = self.cfgtool("show", "--json")
        data = json.loads(out)
        self.assertEqual((data["values"]["timeout_seconds"], data["source"]["timeout_seconds"]), (7, "user"))
        self.assertEqual(self.cfgtool("unset", "timeout_seconds")[0], 0)
        self.assertEqual(self.cfgtool("unset", "timeout_seconds")[0], 1)

    def test_set_hook_reminds_about_approval_and_rejects_bad_json(self):
        code, out, _ = self.cfgtool("set", "hooks.g", '{"command": "x", "matcher": "Bash"}')
        self.assertEqual(code, 0)
        self.assertIn("approve --use g", out)
        self.assertEqual(self.cfgtool("set", "hooks.g", "{nope")[0], 1)

    def test_show_masks_hook_commands(self):
        data = {"hooks": {"g": {"command": "x"}}}
        cfg.write_layer(cfg.user_path(self.t.data), data)
        with open(cfg.user_path(self.t.data)) as fh:
            raw = json.load(fh)
        raw["hooks"]["g"]["command"] = "x " + helpers.fake("env-token")
        with open(cfg.user_path(self.t.data), "w") as fh:
            json.dump(raw, fh)
        code, out, err = self.cfgtool("show")
        self.assertNotIn(helpers.secret_core("env-token"), out + err)

    def test_show_json_masks_values_and_notes_too(self):
        token = helpers.fake("env-token")
        self.write_user({"transcript_roots": ["/x/" + token]})
        self.write_project({"allow_read": ["/y/" + token]})  # Not approved, so it comes back as a note.
        for argv in (("show",), ("show", "--json")):
            code, out, err = self.cfgtool(*argv)
            self.assertEqual(code, 0, err)
            self.assertNotIn(helpers.secret_core("env-token"), out + err, argv)
        data = json.loads(self.cfgtool("show", "--json")[1])
        self.assertTrue(data["notes"])

    def test_show_applies_your_patterns_and_cuts_once(self):
        word = "Inter" + "nalHost" + "Name7"
        self.write_user({"redact_patterns": ["InternalHost\\w+"],
                         "hooks": {"g": {"command": "guard --target " + word + " " + "x" * 400}}})
        for argv in (("show",), ("show", "--json")):
            code, out, err = self.cfgtool(*argv)
            self.assertEqual(code, 0, err)
            self.assertNotIn(word, out, argv)
        command = json.loads(self.cfgtool("show", "--json")[1])["values"]["hooks"]["g"]["command"]
        self.assertEqual(command.count("chars)"), 1, command)

    def test_show_json_keeps_names_that_mask_alike(self):
        self.write_user({"redact_patterns": ["Host\\w+"], "hooks": {"HostA1": {"command": "a"},
                                                                    "HostB2": {"command": "b"}}})
        hooks = json.loads(self.cfgtool("show", "--json")[1])["values"]["hooks"]
        self.assertEqual(sorted(h["command"] for h in hooks.values()), ["a", "b"])

    def test_init_and_explain_and_doctor(self):
        self.assertEqual(self.cfgtool("init")[0], 0)
        self.assertEqual(self.cfgtool("init")[0], 1)
        code, out, _ = self.cfgtool("explain", "sandbox")
        self.assertIn("required", out)
        code, out, _ = self.cfgtool("doctor")
        self.assertIn("config: preset standard", out)

    def test_project_layer_and_allow_read_approval(self):
        self.assertEqual(self.cfgtool("set", "allow_read", '["~/x"]', "--project-layer")[0], 0)
        self.assertEqual(self.resolve().values["allow_read"], [])
        self.assertEqual(self.cfgtool("approve", "allow_read")[0], 0)
        self.assertEqual(self.resolve().values["allow_read"], ["~/x"])


if __name__ == "__main__":
    unittest.main()
