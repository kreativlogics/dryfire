import unittest

import helpers  # noqa: F401
from dryfire import guards


class MatcherTest(unittest.TestCase):
    def test_empty_star_and_none_match_everything(self):
        for m in (None, "", "*"):
            self.assertTrue(guards.matcher_accepts(m, "Bash"))

    def test_plain_list_is_exact_names(self):
        self.assertTrue(guards.matcher_accepts("Edit|Write", "Write"))
        self.assertTrue(guards.matcher_accepts("Edit, Write", "Edit"))
        self.assertFalse(guards.matcher_accepts("Edit|Write", "MultiEdit"))
        self.assertFalse(guards.matcher_accepts("Bash", "BashOutput"))

    def test_regex_searches_the_name(self):
        self.assertTrue(guards.matcher_accepts("mcp__.*", "mcp__x__y"))
        self.assertTrue(guards.matcher_accepts("^(Edit|Write)$", "Edit"))
        self.assertFalse(guards.matcher_accepts("^Edit$", "MultiEdit"))

    def test_bad_regex_matches_nothing_and_is_reported(self):
        self.assertFalse(guards.matcher_accepts("Bash(", "Bash"))
        self.assertTrue(guards.matcher_error("Bash("))
        self.assertEqual(guards.matcher_error("Bash|Edit"), "")


class IfFilterTest(unittest.TestCase):
    def test_bash_pattern_matches_whole_command_or_a_part(self):
        f, note = guards.if_filter("Bash(git push*)")
        self.assertEqual(note, "")
        self.assertTrue(f("Bash", {"command": "git push --force"}))
        self.assertTrue(f("Bash", {"command": "cd x && git push origin"}))
        self.assertFalse(f("Bash", {"command": "git status"}))
        self.assertFalse(f("Edit", {"file_path": "git push"}))

    def test_path_pattern_for_file_tools(self):
        f, _ = guards.if_filter("Edit(*.env)")
        self.assertTrue(f("Edit", {"file_path": "/w/.env"}))
        self.assertFalse(f("Edit", {"file_path": "/w/app.py"}))

    def test_colon_star_suffix_and_bare_command(self):
        # Permission-rule syntax: 'git push:*' is 'git push *', and a trailing ' *' also matches the bare command.
        f, _ = guards.if_filter("Bash(git push:*)")
        self.assertTrue(f("Bash", {"command": "git push origin master"}))
        self.assertTrue(f("Bash", {"command": "git push"}))
        self.assertFalse(f("Bash", {"command": "git pushx"}))
        f, _ = guards.if_filter("Bash(ls *)")
        self.assertTrue(f("Bash", {"command": "ls"}))
        self.assertFalse(f("Bash", {"command": "lsof"}))

    def test_star_is_the_only_wildcard(self):
        f, _ = guards.if_filter("Bash(rm [abc]*)")
        self.assertTrue(f("Bash", {"command": "rm [abc]x"}))
        self.assertFalse(f("Bash", {"command": "rm a"}))

    def test_bash_runs_anyway_when_the_command_hides_words(self):
        f, _ = guards.if_filter("Bash(git push *)")
        self.assertTrue(f("Bash", {"command": "echo $(date)"}))
        self.assertTrue(f("Bash", {"command": "echo `date`"}))
        self.assertTrue(f("Bash", {"command": "$CMD origin"}))
        self.assertTrue(f("Bash", {"command": "echo 'unclosed"}))
        f, _ = guards.if_filter("Bash(git *)")
        self.assertFalse(f("Bash", {"command": "echo $(date)"}))

    def test_path_patterns_are_anchored_like_permission_rules(self):
        f, _ = guards.if_filter("Edit(src/**)", home="/h")
        self.assertTrue(f("Edit", {"file_path": "/w/src/a/b.ts"}, cwds=["/w"]))
        self.assertFalse(f("Edit", {"file_path": "/w/lib/src/b.ts"}, cwds=["/w"]))
        f, _ = guards.if_filter("Edit(**/src/**)", home="/h")
        self.assertTrue(f("Edit", {"file_path": "/w/lib/src/b.ts"}, cwds=["/w"]))
        self.assertTrue(f("Edit", {"file_path": "/w/src/b.ts"}, cwds=["/w"]))
        f, _ = guards.if_filter("Edit(//etc/*.conf)", home="/h")
        self.assertTrue(f("Edit", {"file_path": "/etc/x.conf"}, cwds=["/w"]))
        self.assertFalse(f("Edit", {"file_path": "/etc/sub/x.conf"}, cwds=["/w"]))
        f, _ = guards.if_filter("Edit(~/.ssh/**)", home="/h")
        self.assertTrue(f("Edit", {"file_path": "/h/.ssh/config"}, cwds=["/w"]))
        f, _ = guards.if_filter("Edit(/docs/*.md)", home="/h", source="settings:project#0.0")
        self.assertTrue(f("Edit", {"file_path": "/w/docs/a.md"}, cwds=["/w"]))
        self.assertFalse(f("Edit", {"file_path": "/docs/a.md"}, cwds=["/w"]))
        f, _ = guards.if_filter("Edit(/rules/*.md)", home="/h", source="settings:user#0.0")
        self.assertTrue(f("Edit", {"file_path": "/h/.claude/rules/a.md"}, cwds=["/w"]))
        f, _ = guards.if_filter("Edit(*.env)", home="/h")
        self.assertTrue(f("Edit", {"file_path": "/w/deep/.env"}, cwds=["/w"]))
        self.assertFalse(f("Edit", {"file_path": "/w/deep/.envrc"}, cwds=["/w"]))

    def test_hook_guard_passes_the_call_folders_to_the_filter(self):
        spec = guards.HookSpec(command="true", matcher="Edit", if_rule="Edit(src/**)")
        g = guards.HookGuard("g", spec, home="/h", timeout=5, sandbox_mode="env")
        self.assertTrue(g.accepts("Edit", {"file_path": "/w/src/x"}, cwds=["/w"]))
        self.assertFalse(g.accepts("Edit", {"file_path": "/w/src/x"}, cwds=["/elsewhere"]))

    def test_bare_tool_and_unknown_form(self):
        f, _ = guards.if_filter("Bash")
        self.assertTrue(f("Bash", {"command": "anything"}))
        f, note = guards.if_filter("Bash git push")
        self.assertTrue(note)
        self.assertTrue(f("Write", {}))


class SpecTest(unittest.TestCase):
    def test_options_do_not_change_the_fingerprint(self):
        a = guards.HookSpec(command="x", options={"preset": "relaxed"})
        b = guards.HookSpec(command="x", options={"preset": "strict"})
        self.assertEqual(a.fingerprint("/h"), b.fingerprint("/h"))

    def test_command_args_and_root_do(self):
        base = guards.HookSpec(command="x").fingerprint("/h")
        self.assertNotEqual(base, guards.HookSpec(command="x ").fingerprint("/h"))
        self.assertNotEqual(base, guards.HookSpec(command="x", plugin_root="/p").fingerprint("/h"))
        self.assertNotEqual(guards.HookSpec(args=["a"]).fingerprint("/h"), guards.HookSpec(args=["b"]).fingerprint("/h"))

    def test_files_named_inside_a_compound_command_are_bound(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            script = os.path.join(d, "g.sh")
            with open(script, "w") as fh:
                fh.write("exit 0\n")
            for command in ('bash -c "sh %s"' % script, "cd %s && sh g.sh" % d, "%s;true" % script,
                            "true && sh %s" % script, "cd %s && ./g.sh" % d,
                            "cd %s && ../%s/g.sh" % (d, os.path.basename(d))):
                self.assertIn(script, guards.named_files(guards.HookSpec(command=command), "/h"), command)

    def test_no_named_file_is_left_out_of_the_approval(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            names = []
            for i in range(25):
                names.append(os.path.join(d, "f%d" % i))
                with open(names[-1], "w") as fh:
                    fh.write("x\n")
            script = os.path.join(d, "g.sh")
            with open(script, "w") as fh:
                fh.write("exit 0\n")
            many = "cat %s >/dev/null; sh %s" % (" ".join(names), script)
            for command in (many, "X=%s; sh $X" % script, "X=%s;sh $X" % script, "true a#b; X=%s; sh $X" % script):
                self.assertIn(script, guards.named_files(guards.HookSpec(command=command), "/h"), command[-40:])
            before = guards.HookSpec(command=many).approval_value("/h")
            with open(script, "w") as fh:
                fh.write("exit 2 # changed\n")
            self.assertNotEqual(before, guards.HookSpec(command=many).approval_value("/h"))

    def test_a_hook_naming_more_than_the_hash_budget_cannot_be_approved(self):
        import os
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            names = []
            for i in range(3):
                names.append(os.path.join(d, "f%d" % i))
                with open(names[-1], "w") as fh:
                    fh.write("x" * 100)
            spec = guards.HookSpec(command=" ".join(names))
            with mock.patch.object(guards, "MAX_HASHED_BYTES", 250):
                self.assertEqual(guards.unbound_files(spec.approval_value("/h")), [names[2]])
                self.assertNotIn(guards.UNBOUND, [v for p, v in guards.named_files(spec, "/h").items()
                                                  if p != names[2]])
            self.assertEqual(guards.unbound_files(spec.approval_value("/h")), [])

    def test_a_file_the_hook_only_writes_is_not_bound(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            hook, log = os.path.join(d, "h.py"), os.path.join(d, "hook.log")
            for p in (hook, log):
                with open(p, "w") as fh:
                    fh.write("x\n")
            for c in ("python3 %s 2>>%s", "python3 %s >%s", "python3 %s > %s", "python3 %s &>%s",
                      "python3 %s >& %s", "python3 %s >|%s"):
                files = guards.named_files(guards.HookSpec(command=c % (hook, log)), "/h")
                self.assertIn(hook, files, c)
                self.assertNotIn(log, files, c)
            # A file the hook also reads stays bound.
            files = guards.named_files(guards.HookSpec(command="cat %s; python3 %s >>%s" % (log, hook, log)), "/h")
            self.assertIn(log, files)

    def test_a_quoted_or_escaped_angle_bracket_is_an_argument_not_a_redirect(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            hook, data = os.path.join(d, "h.sh"), os.path.join(d, "rules.txt")
            for p in (hook, data):
                with open(p, "w") as fh:
                    fh.write("x\n")
            for c in ("sh %s '>' %s", 'sh %s ">" %s', "sh %s \\> %s", "sh %s 'a>' %s"):
                files = guards.named_files(guards.HookSpec(command=c % (hook, data)), "/h")
                self.assertIn(data, files, c)
            # Quotes that close before the '>' leave it a redirect.
            for c in ('sh "%s" >%s', "sh '%s'>%s"):
                self.assertNotIn(data, guards.named_files(guards.HookSpec(command=c % (hook, data)), "/h"), c)

    def test_a_quoted_script_on_a_line_shlex_cannot_read_is_bound(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            hook = os.path.join(d, "g.sh")
            with open(hook, "w") as fh:
                fh.write("x\n")
            for c in ('sh "%s" $\'\\\'\'', "sh '%s' $'\\''"):
                self.assertIn(hook, guards.named_files(guards.HookSpec(command=c % hook), "/h"), c)

    def test_a_folder_from_a_variable_used_through_cd_is_followed(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            hook = os.path.join(d, "g.sh")
            with open(hook, "w") as fh:
                fh.write("x\n")
            for c in ('D=%s; cd "$D" && sh g.sh', "D=%s; cd $D; ./g.sh", "export D=%s && cd ${D} && sh ./g.sh"):
                self.assertIn(hook, guards.named_files(guards.HookSpec(command=c % d), "/h"), c)

    def test_many_long_variable_words_stay_small_in_all(self):
        words = ["D=/" + "a" * 4000] + ["$D"] * 3000
        self.assertLess(sum(len(w) for w in guards._with_variables(words)), 2 * guards.MAX_FILLED)

    def test_filling_a_long_line_of_variables_stays_small_in_memory(self):
        import tracemalloc
        value = "/" + "b" * 4000
        for command in ("b=%s; true " % value + "$b" * 30000, "b=%s; true " % value + "${b}" * 20000,
                        "b=%s; " % value + " ".join("v%d=$b" % n for n in range(14000)) + "; sh $b"):
            tracemalloc.start()
            try:
                guards.named_files(guards.HookSpec(command=command), "/h")
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertLess(peak, 40 * guards.MAX_FILLED, command[:20])

    def test_a_script_path_split_by_a_line_continuation_is_bound(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            hook = os.path.join(d, "guard.sh")
            with open(hook, "w") as fh:
                fh.write("x\n")
            command = "sh " + hook[:-4] + "\\\n" + hook[-4:]
            self.assertIn(hook, guards.named_files(guards.HookSpec(command=command), "/h"))

    def test_a_long_run_of_unclosed_parentheses_is_read_quickly(self):
        import time
        started = time.monotonic()
        guards.named_files(guards.HookSpec(command="sh g.sh\n" + "(" * 30000), "/h")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_nested_loops_and_an_empty_value_with_a_default_are_followed(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            os.makedirs(os.path.join(d, "b"))
            hook = os.path.join(d, "b", "y.sh")
            with open(hook, "w") as fh:
                fh.write("x\n")
            for c in ("for A in %s/a %s/b; do for B in x y; do sh $A/$B.sh; done; done",
                      "G=; sh ${G:-%s/b/y.sh}", "G=''; sh ${G:=%s/b/y.sh}"):
                self.assertIn(hook, guards.named_files(guards.HookSpec(command=c.replace("%s", d)), "/h"), c)
            # Without the colon an empty value stays empty, as in the shell.
            self.assertNotIn(hook, guards.named_files(guards.HookSpec(command="G=; sh ${G-%s/b/y.sh}" % d), "/h"))

    def test_many_loops_and_names_stay_fast(self):
        import time
        names = ["N%d" % k for k in range(40)]
        loops = " ".join("for %s in %s; do" % (n, " ".join("/v%d" % v for v in range(64))) for n in names)
        word = "".join("$%s" % n for n in names)
        command = loops + " " + " ".join([word] * 200)
        started = time.monotonic()
        guards.named_files(guards.HookSpec(command=command), "/h")
        self.assertLess(time.monotonic() - started, 2.0)

    def test_a_script_opened_for_reading_and_writing_after_a_cd_is_followed(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            hook = os.path.join(d, "g.sh")
            with open(hook, "w") as fh:
                fh.write("x\n")
            self.assertIn(hook, guards.named_files(guards.HookSpec(command="cd %s && bash <>g.sh" % d), "/h"))

    def test_cd_with_options_and_a_script_read_from_input_are_followed(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            os.mkdir(os.path.join(d, "a"))
            hook = os.path.join(d, "a", "g.sh")
            with open(hook, "w") as fh:
                fh.write("x\n")
            for c in ("cd -P %s/a && sh g.sh", "cd -- %s/a && sh g.sh", "cd -P %s/a && ./g.sh", "cd -L -P %s/a && sh g.sh",
                      "cd %s/a && bash < g.sh", "cd %s/a && sh <g.sh"):
                self.assertIn(hook, guards.named_files(guards.HookSpec(command=c % d), "/h"), c)

    def test_a_folder_from_a_loop_a_default_or_a_line_with_a_comment_is_followed(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            hook = os.path.join(d, "g.sh")
            with open(hook, "w") as fh:
                fh.write("x\n")
            for c in ("for D in %s; do sh $D/g.sh; done", "for D in /nope %s; do sh $D/g.sh; done",
                      "D=%s; sh ${D:-/nope}/g.sh", "sh ${D:-%s}/g.sh", "D=%s; sh $D/g.sh # don't",
                      "D=%s; cd \"$D\" && sh g.sh # don't"):
                self.assertIn(hook, guards.named_files(guards.HookSpec(command=c % d), "/h"), c)

    def test_a_variable_doubled_on_each_word_stays_small(self):
        words = ["D=x"] + ["D=$D$D"] * 24 + ["sh", "$D", "$D" * 5000]
        self.assertLessEqual(max(len(w) for w in guards._with_variables(words)), len("$D" * 5000))

    def test_a_folder_set_in_a_variable_first_is_followed(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            script = os.path.join(d, "g.sh")
            with open(script, "w") as fh:
                fh.write("exit 0\n")
            for c in ("D=%s; sh $D/g.sh", 'D=%s; sh "$D/g.sh"', "export D=%s && sh ${D}/g.sh",
                      "B=%s; D=$B; sh $D/g.sh"):
                spec = guards.HookSpec(command=c % d)
                before = spec.approval_value("/h")
                self.assertIn(script, before.get("files", {}), c)
                with open(script, "w") as fh:
                    fh.write("exit 2\n")
                self.assertNotEqual(spec.approval_value("/h"), before, c)
                with open(script, "w") as fh:
                    fh.write("exit 0\n")

    def test_from_dict(self):
        s = guards.HookSpec.from_dict({"command": "c", "matcher": "Bash", "onFailure": "block", "if": "Bash(x)"})
        self.assertTrue(s.on_failure)
        self.assertEqual((s.matcher, s.if_rule), ("Bash", "Bash(x)"))
        with self.assertRaises(ValueError):
            guards.HookSpec.from_dict("c")

    def test_reason_signature_folds_numbers_and_quotes(self):
        a = guards.reason_signature("blocked 'rm -rf /tmp/a' after 3 tries\nmore")
        b = guards.reason_signature("blocked 'git reset' after 12 tries")
        self.assertEqual(a, b)
        self.assertEqual(guards.reason_signature(""), "(no reason given)")


if __name__ == "__main__":
    unittest.main()
