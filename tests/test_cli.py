import json
import os
import sys
import unittest

import helpers
from dryfire import approve, cfg, main
from dryfire.guards import HookSpec

DENY_RM = helpers.py_hook("if 'rm -rf' in c:\n    sys.stderr.write('no rm -rf')\n    sys.exit(2)")
PACK = {"version": 1, "name": "draft", "rules": [
    {"id": "force-push", "pattern": r"git\s+push\b.*--force", "reason": "No force push"}]}


class CliCase(helpers.TempCase):
    def setUp(self):
        helpers.TempCase.setUp(self)
        t = self.t
        t.write([t.user(), t.bash("git status"), t.bash("git status"), t.bash("rm -rf build"),
                 t.bash("git push --force origin master"),
                 t.bash("echo " + helpers.fake("github")), t.call("Read", {"file_path": "/w/a"})])
        self.pack = os.path.join(t.root, "pack.json")
        with open(self.pack, "w") as fh:
            json.dump(PACK, fh)

    def replay(self, *extra):
        return self.cli("replay", "--quiet", "--window-days", "3650", *extra)


class ReplayCliTest(CliCase):
    def test_pack_headline(self):
        code, out, err = self.replay("--pack", self.pack)
        self.assertEqual(code, 0, err)
        self.assertIn("pack draft would have blocked 1 of 5 of your commands (20.0%)", out)

    def test_json_has_no_raw_secret(self):
        code, out, _ = self.replay("--pack", self.pack, "--json")
        data = json.loads(out)
        self.assertEqual(data["calls"], 5)
        self.assertNotIn(helpers.secret_core("github"), out)

    def test_no_guard_is_an_error(self):
        code, _, err = self.replay()
        self.assertEqual(code, 1)
        self.assertIn("choose at least one guard", err)

    def test_unapproved_hook_exits_3_with_the_command_to_run(self):
        code, _, err = self.replay("--hook", DENY_RM)
        self.assertEqual(code, main.EXIT_UNAPPROVED)
        self.assertIn("approve", err)
        self.assertIn("--hook", err)

    def test_approve_then_replay(self):
        self.assertEqual(self.cli("approve", "--hook", DENY_RM)[0], 0)
        code, out, err = self.replay("--hook", DENY_RM, "--sandbox", "env")
        self.assertEqual(code, 0, err)
        self.assertIn("would have blocked 1 of 5", out)

    def test_hook_runs_hold_inputs_only_for_the_calls_they_replay(self):
        from dryfire import replay
        seen = []
        orig = replay.run

        def spy(guards, uniques, *a, **kw):
            seen.append(sum(u.input is not None for u in uniques))
            return orig(guards, uniques, *a, **kw)

        made = []
        orig_init = replay.Unique.__init__

        def track(u, key, tool, tool_input, mode):
            orig_init(u, key, tool, tool_input, mode)
            made.append(u)

        self.cli("approve", "--hook", DENY_RM)
        replay.run, replay.Unique.__init__ = spy, track
        try:
            code, out, err = self.replay("--hook", DENY_RM, "--sandbox", "env", "--max-calls", "2")
        finally:
            replay.run, replay.Unique.__init__ = orig, orig_init
        self.assertEqual(code, 0, err)
        self.assertEqual(seen, [2])
        self.assertEqual(sum(u.input is not None for u in made), 2)

    def test_changed_hook_needs_a_new_approval(self):
        self.cli("approve", "--hook", DENY_RM)
        self.assertEqual(self.replay("--hook", DENY_RM + " ")[0], main.EXIT_UNAPPROVED)

    def write_guard(self, folder, body="case \"$(cat)\" in *'rm -rf'*) echo no >&2; exit 2;; esac\n"):
        path = os.path.join(folder, "guard.sh")
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)
        return path

    def test_editing_the_hook_script_needs_a_new_approval(self):
        hook = "sh " + self.write_guard(self.t.root)
        self.cli("approve", "--hook", hook)
        self.assertEqual(self.replay("--hook", hook, "--sandbox", "env")[0], 0)
        self.write_guard(self.t.root, "exit 0\n")
        code, _, err = self.replay("--hook", hook, "--sandbox", "env")
        self.assertEqual(code, main.EXIT_UNAPPROVED, err)

    def test_relative_hook_path_runs_from_the_folder_it_was_typed_in(self):
        self.write_guard(self.t.root)
        with helpers.chdir(self.t.root):
            self.assertEqual(self.cli("approve", "--hook", "./guard.sh")[0], 0)
            code, out, err = self.replay("--hook", "./guard.sh", "--sandbox", "env")
        self.assertEqual(code, 0, err)
        self.assertIn("would have blocked 1 of 5", out)
        with helpers.chdir(self.t.home):  # Another folder's ./guard.sh is another hook.
            self.assertEqual(self.replay("--hook", "./guard.sh", "--sandbox", "env")[0], main.EXIT_UNAPPROVED)

    def test_relative_path_in_a_project_hook_is_the_project_folder(self):
        self.write_guard(self.t.project_dir)
        cfgdir = os.path.join(self.t.project_dir, ".dryfire")
        os.makedirs(cfgdir)
        with open(os.path.join(cfgdir, "config.json"), "w") as fh:
            json.dump({"hooks": {"p": {"command": "./guard.sh"}}}, fh)
        self.assertEqual(self.cli("approve", "--use", "p")[0], 0)
        code, out, err = self.replay("--use", "p", "--sandbox", "env")
        self.assertEqual(code, 0, err)
        self.assertIn("would have blocked 1 of 6", out)  # No matcher: every tool call.

    def test_project_dir_variable_names_the_real_project(self):
        os.makedirs(os.path.join(self.t.project_dir, ".claude"))
        self.write_guard(os.path.join(self.t.project_dir, ".claude"))
        with open(os.path.join(self.t.project_dir, ".claude", "settings.json"), "w") as fh:
            json.dump({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": '"$CLAUDE_PROJECT_DIR"/.claude/guard.sh'}]}]}}, fh)
        hid = json.loads(self.cli("detect", "--json")[1])["hooks"][0]["id"]
        self.assertEqual(self.cli("approve", "--detected", hid)[0], 0)
        self.assertTrue(json.loads(self.cli("detect", "--json")[1])["hooks"][0]["approved"])
        code, out, err = self.replay("--detected", hid, "--sandbox", "env")
        self.assertEqual(code, 0, err)
        self.assertIn("would have blocked 1 of 5", out)

    def test_approval_is_tied_to_the_data_folder(self):
        approve.grant(os.path.join(self.t.root, "elsewhere"), "", "hook",
                      HookSpec(command=DENY_RM).approval_value(self.t.home))
        self.assertEqual(self.replay("--hook", DENY_RM)[0], main.EXIT_UNAPPROVED)

    def test_list_and_revoke(self):
        code, out, _ = self.cli("approve", "--hook", DENY_RM)
        fp = out.split("[")[1].split("]")[0]
        code, out, _ = self.cli("approve", "--list")
        self.assertIn(fp, out)
        self.assertEqual(self.cli("approve", "--revoke", fp[:4])[0], 1)
        self.assertEqual(self.cli("approve", "--revoke", fp[:8])[0], 0)
        self.assertEqual(self.cli("approve", "--list")[1], "Nothing is approved yet.\n")

    def test_revoke_holds_the_approvals_lock(self):
        import contextlib
        from dryfire import ledger
        self.cli("approve", "--hook", DENY_RM)
        held = []
        real = ledger.locked

        @contextlib.contextmanager
        def spy(data_dir, name="ledger"):
            with real(data_dir, name):
                held.append(name)
                yield

        ledger.locked = spy
        try:
            self.assertEqual(self.cli("approve", "--revoke", "all")[0], 0)
        finally:
            ledger.locked = real
        self.assertEqual(held, ["approvals"])
        self.assertEqual([n for n in os.listdir(self.t.data) if n.endswith(".tmp")], [])

    def test_list_masks_secrets(self):
        hook = "x --token " + helpers.fake("long-random")
        self.cli("approve", "--hook", hook)
        self.assertNotIn(helpers.secret_core("long-random"), self.cli("approve", "--list")[1])

    def test_project_hooks_need_approval_for_this_project(self):
        cfgdir = os.path.join(self.t.project_dir, ".dryfire")
        os.makedirs(cfgdir)
        with open(os.path.join(cfgdir, "config.json"), "w") as fh:
            json.dump({"hooks": {"p": {"command": DENY_RM}}}, fh)
        approve.grant(self.t.data, "", "hook", HookSpec(command=DENY_RM).approval_value(self.t.home))
        self.assertEqual(self.replay("--use", "p")[0], main.EXIT_UNAPPROVED)
        self.assertEqual(self.cli("approve", "--use", "p")[0], 0)
        self.assertEqual(self.replay("--use", "p", "--sandbox", "env")[0], 0)

    def test_hook_and_pack_together_show_differences(self):
        self.cli("approve", "--hook", DENY_RM)
        code, out, _ = self.replay("--hook", DENY_RM, "--pack", self.pack, "--sandbox", "env")
        self.assertIn("Where the guards disagree", out)

    def test_out_file_rules(self):
        target = os.path.join(self.t.root, "r.md")
        code, out, _ = self.replay("--pack", self.pack, "--out", target)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(target))
        self.assertIn("Report written", out)
        self.assertEqual(self.replay("--pack", self.pack, "--out", target)[0], 1)
        self.assertEqual(self.replay("--pack", self.pack, "--out", target, "--force")[0], 0)
        self.assertEqual(self.replay("--pack", self.pack, "--out", os.path.join(self.t.data, "r.md"))[0], 1)
        link = os.path.join(self.t.root, "link")
        os.symlink(self.t.data, link)
        self.assertEqual(self.replay("--pack", self.pack, "--out", os.path.join(link, "r.md"))[0], 1)

    def test_out_prints_the_failure_warning_too(self):
        broken = helpers.py_hook("sys.exit(3)")
        self.cli("approve", "--hook", broken)
        code, out, err = self.replay("--hook", broken, "--sandbox", "env", "--out", os.path.join(self.t.root, "r.md"))
        self.assertEqual(code, 0, err)
        self.assertIn("Warning:", out)
        self.assertIn("Report written", out)

    def test_out_does_not_follow_a_planted_temp_file(self):
        victim = os.path.join(self.t.data, "approvals.json")
        with open(victim, "w") as fh:
            fh.write("{}")
        target = os.path.join(self.t.root, "r2.md")
        os.symlink(victim, target + ".dryfire-tmp")
        self.assertEqual(self.replay("--pack", self.pack, "--out", target)[0], 0)
        with open(victim) as fh:
            self.assertEqual(fh.read(), "{}")

    @unittest.skipIf(sys.platform == "darwin", "the OS sandbox exists here")
    def test_required_sandbox_without_os_sandbox_exits_4(self):
        self.cli("approve", "--hook", DENY_RM)
        self.assertEqual(self.replay("--hook", DENY_RM, "--sandbox", "required")[0], main.EXIT_SANDBOX)

    def test_run_flags_cannot_loosen(self):
        self.cfgtool("set", "sandbox", "required")
        code, out, _ = self.replay("--pack", self.pack, "--sandbox", "env", "--json")
        self.assertEqual(code, 0)
        self.assertTrue(any("sandbox" in n for n in json.loads(out)["run"]["notes"]))

    def test_bad_config_value_is_a_clean_error(self):
        code, _, err = self.replay("--pack", self.pack, "--permission-mode", "yolo")
        self.assertEqual(code, 1)
        self.assertIn("permission_mode", err)


    def test_config_errors_mask_the_values_they_quote(self):
        path = cfg.project_path(self.t.project_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump({"timeout_seconds": helpers.fake("github"), helpers.fake("anthropic"): 1}, fh)
        code, out, err = self.replay("--pack", self.pack)
        self.assertEqual(code, 1)
        self.assertIn("timeout_seconds", err)
        for kind in ("github", "anthropic"):
            self.assertNotIn(helpers.secret_core(kind), out + err)
        code, out, err = self.cfgtool("show")
        self.assertEqual(code, 1)
        for kind in ("github", "anthropic"):
            self.assertNotIn(helpers.secret_core(kind), out + err)


class OtherCommandsTest(CliCase):
    def test_scan_counts_without_commands(self):
        code, out, _ = self.cli("scan", "--window-days", "3650", "--json")
        data = json.loads(out)
        self.assertEqual((data["calls"], data["by_tool"]["Bash"]), (6, 5))
        self.assertNotIn("rm -rf", out)

    def test_scan_masks_tool_names_from_transcripts(self):
        # Tool names come from transcripts, which are untrusted: one may carry a secret.
        self.t.write([self.t.call("mcp__x__" + helpers.fake("github"), {})])
        for flags in (("--json",), ()):
            code, out, _ = self.cli("scan", "--window-days", "3650", *flags)
            self.assertEqual(code, 0)
            self.assertNotIn(helpers.secret_core("github"), out)

    def test_detect_json_does_not_spell_out_the_home_folder(self):
        os.makedirs(os.path.join(self.t.home, ".cc-safety-net"))
        with open(os.path.join(self.t.home, ".cc-safety-net", "config.json"), "w") as fh:
            fh.write("{}")
        code, out, _ = self.cli("detect", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["safetynet"]["legacy"], ["~/.cc-safety-net/config.json"])
        self.assertNotIn(self.t.home, out)

    def test_detect_lists_settings_hooks_masked(self):
        settings = os.path.join(self.t.home, ".claude", "settings.json")
        with open(settings, "w") as fh:
            json.dump({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "guard --key " + helpers.fake("anthropic")}]}]}}, fh)
        code, out, _ = self.cli("detect", "--json")
        data = json.loads(out)
        self.assertEqual(len(data["hooks"]), 1)
        self.assertFalse(data["hooks"][0]["approved"])
        self.assertNotIn(helpers.secret_core("anthropic"), out)
        code, md, _ = self.cli("detect")
        self.assertIn("PreToolUse hooks", md)

    def test_detect_and_approval_list_apply_your_patterns(self):
        from dryfire import cfg
        word = "Inter" + "nalHost" + "Name7"
        cfg.write_layer(cfg.user_path(self.t.data), {"redact_patterns": ["InternalHost\\w+"]})
        settings = os.path.join(self.t.home, ".claude", "settings.json")
        with open(settings, "w") as fh:
            json.dump({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "guard --target " + word}]}]}}, fh)
        for flags in (("--json",), ()):
            self.assertNotIn(word, self.cli("detect", *flags)[1], flags)
        self.assertEqual(self.cli("approve", "--hook", "guard --target " + word)[0], 0)
        self.assertNotIn(word, self.cli("approve", "--list")[1])

    def test_approve_line_hides_masked_text_and_is_not_shown_broken(self):
        from dryfire import cfg
        word = "corp-" + "secretname"
        cfg.write_layer(cfg.user_path(self.t.data), {"redact_patterns": ["corp-[a-z]+"]})
        code, _, err = self.replay("--hook", "sh /x/g.sh " + word)
        self.assertEqual(code, main.EXIT_UNAPPROVED)
        self.assertNotIn(word, err)
        self.assertIn("not shown because part of it is masked", err)
        self.assertIn("--data", err)
        code, _, err = self.replay("--hook", DENY_RM)
        self.assertIn("run this yourself", err)

    def test_approve_refuses_a_hook_it_cannot_bind(self):
        from unittest import mock
        from dryfire import guards
        script = os.path.join(self.t.root, "g.sh")
        with open(script, "w") as fh:
            fh.write("exit 0\n" * 100)
        with mock.patch.object(guards, "MAX_HASHED_BYTES", 10), mock.patch.object(main, "MAX_HASHED_BYTES", 10):
            code, _, err = self.cli("approve", "--hook", "sh " + script)
        self.assertNotEqual(code, 0)
        self.assertIn("was not approved", err)
        self.assertFalse(os.path.exists(os.path.join(self.t.data, "approvals.json")))

    def test_an_approval_holding_an_unbound_file_approves_nothing(self):
        # An approval stored while a file was past the hash budget (it grew between check and grant) must not
        # let the file change freely afterwards.
        from unittest import mock
        from dryfire import guards
        script = os.path.join(self.t.root, "g.sh")
        with open(script, "w") as fh:
            fh.write("exit 0\n" * 100)
        with mock.patch.object(guards, "MAX_HASHED_BYTES", 10), mock.patch.object(main, "MAX_HASHED_BYTES", 10), \
                mock.patch.object(main, "unbound_files", lambda *a: []):
            self.cli("approve", "--hook", "sh " + script)
        with open(os.path.join(self.t.data, "approvals.json")) as fh:
            self.assertIn(guards.UNBOUND, fh.read())
        with open(script, "w") as fh:
            fh.write("exit 2\n" * 100)
        with mock.patch.object(guards, "MAX_HASHED_BYTES", 10):
            self.assertEqual(self.replay("--hook", "sh " + script)[0], main.EXIT_UNAPPROVED)

    def test_detect_does_not_show_an_approval_holding_an_unbound_file_as_approved(self):
        from unittest import mock
        from dryfire import approve, guards
        script = os.path.join(self.t.root, "g.sh")
        with open(script, "w") as fh:
            fh.write("exit 0\n" * 100)
        with open(os.path.join(self.t.home, ".claude", "settings.json"), "w") as fh:
            json.dump({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "sh " + script}]}]}}, fh)
        with mock.patch.object(guards, "MAX_HASHED_BYTES", 10), mock.patch.object(main, "MAX_HASHED_BYTES", 10):
            with mock.patch.object(main, "unbound_files", lambda *a: []):
                self.cli("approve", "--hook", "sh " + script)
            # The ledger holds the value (an approval stored by an older build), yet nothing is approved.
            with mock.patch.object(approve, "is_approved", lambda *a: True):
                self.assertFalse(json.loads(self.cli("detect", "--json")[1])["hooks"][0]["approved"])

    def test_detected_hook_replays_after_approval(self):
        settings = os.path.join(self.t.home, ".claude", "settings.json")
        with open(settings, "w") as fh:
            json.dump({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": DENY_RM}]}]}}, fh)
        hid = json.loads(self.cli("detect", "--json")[1])["hooks"][0]["id"]
        self.assertEqual(self.replay("--detected", hid)[0], main.EXIT_UNAPPROVED)
        self.cli("approve", "--detected", hid)
        code, out, err = self.replay("--detected", hid, "--sandbox", "env")
        self.assertEqual(code, 0, err)
        self.assertIn("blocked 1 of 5", out)

    def test_no_command_prints_help(self):
        self.assertEqual(self.cli()[0], 2)


class ReplayTest(unittest.TestCase):
    def test_as_recorded_modes_are_separate_calls(self):
        from dryfire import replay, transcripts
        ts = transcripts.parse_ts("2026-11-20T00:00:00Z")
        calls = [transcripts.Call("a", "Bash", {"command": "ls"}, ts, "/w", "s", "plan", "/p"),
                 transcripts.Call("b", "Bash", {"command": "ls"}, ts, "/w", "s", "default", "/p")]
        self.assertEqual(len(replay.collect(calls)), 1)
        self.assertEqual(len(replay.collect(calls, "as-recorded")), 2)

    def test_select_keeps_the_most_recent(self):
        from dryfire import replay, transcripts
        calls = [transcripts.Call(str(i), "Bash", {"command": "c%d" % i},
                                  transcripts.parse_ts("2026-11-%02dT00:00:00Z" % (i + 1)), "/w", "s", None, "/p")
                 for i in range(5)]
        kept, nd, nc = replay.select(replay.collect(calls), 2)
        self.assertEqual([u.input["command"] for u in kept], ["c4", "c3"])
        self.assertEqual((nd, nc), (3, 3))

    def test_a_broken_guard_is_an_error_not_a_crash(self):
        from dryfire import replay, transcripts
        from dryfire.guards import Guard
        from dryfire.hookio import ERROR

        class Broken(Guard):
            runs_code = True

            def evaluate(self, tool, tool_input, mode):
                raise RuntimeError("boom")
        u = list(replay.collect([transcripts.Call("a", "Bash", {"command": "ls"}, None, "/w", "s", None, "/p")])
                 .values())
        res = replay.run([Broken("b")], u)
        self.assertEqual(res["b"][u[0].key].decision, ERROR)


class KnownMissesTest(CliCase):
    """What a replay cannot show, kept as expected failures so a fix is noticed."""

    @unittest.expectedFailure
    def test_a_hook_that_counts_earlier_calls_sees_history(self):
        # Each call runs in a fresh temp folder, so a hook that blocks the third push in a row never sees the
        # first two.
        hook = helpers.py_hook("import os\np = os.path.join(os.environ['HOME'], 'n')\n"
                               "n = int(open(p).read()) if os.path.exists(p) else 0\nopen(p, 'w').write(str(n + 1))\n"
                               "sys.exit(2 if n >= 1 else 0)")
        self.t.write([self.t.bash("git push"), self.t.bash("git push origin")], session="s9")
        self.cli("approve", "--hook", hook)
        code, out, _ = self.replay("--hook", hook, "--sandbox", "env")
        self.assertIn("would have blocked 1 of", out)

    @unittest.expectedFailure
    def test_a_hook_that_reads_the_repo_sees_the_real_repo(self):
        # The hook's cwd is a temp project folder, not the folder the call was made in.
        hook = helpers.py_hook("import os\nsys.exit(2 if os.path.exists(os.path.join(d['cwd'], 'marker')) else 0)")
        open(os.path.join(self.t.project_dir, "marker"), "w").close()
        self.cli("approve", "--hook", hook)
        code, out, _ = self.replay("--hook", hook, "--sandbox", "env")
        self.assertIn("would have blocked 5 of", out)


if __name__ == "__main__":
    unittest.main()
