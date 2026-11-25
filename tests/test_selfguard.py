import io
import json
import os
import subprocess
import sys
import time
import unittest

import helpers
from dryfire import selfguard

HOME = "/Users/someone"
DATA = HOME + "/.claude/plugins/data/dryfire-x"
ROOT = HOME + "/.claude/plugins/cache/x/dryfire/0.1.0"
ENV = {"CLAUDE_PLUGIN_DATA": DATA}
CLI = 'python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cli.py"'
CFG = 'python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py"'


def decide(tool, tool_input, mode="default", cwd="/w"):
    v = selfguard.check({"tool_name": tool, "tool_input": tool_input, "permission_mode": mode, "cwd": cwd},
                        home=HOME, env=ENV, plugin_root=ROOT)
    return v.decision if v else "allow"


def bash(command, mode="default"):
    return decide("Bash", {"command": command}, mode)


class SelfGuardTest(unittest.TestCase):
    def test_ordinary_commands_pass(self):
        for c in ("ls -la", "git status", "python3 app.py", CLI + " replay --pack p.json",
                  CLI + " approve --list", CLI + " approve --revoke abcdef12", CFG + " show",
                  CLI + ' replay --data "${CLAUDE_PLUGIN_DATA}" --pack p.json',
                  "cat %s/config.json" % DATA, "ls ~/.claude/dryfire", "grep x $CLAUDE_PLUGIN_DATA/config.json",
                  "find %s -name '*.json'" % DATA):
            self.assertEqual(bash(c), "allow", c)

    def test_approving_asks(self):
        for c in (CLI + " approve --hook 'x'", CLI + " approve --use all", CFG + " set sandbox env",
                  CFG + " unset hooks.g", CFG + " init", CFG + " approve allow_read",
                  "python3 -I %s/scripts/cli.py approve --checkrein" % ROOT):
            self.assertEqual(bash(c), "ask", c)

    def test_interpreter_flags_and_runners_still_ask(self):
        script = '"${CLAUDE_PLUGIN_ROOT}/scripts/cli.py"'
        for prefix in ("python3 -X utf8", "python3 -W ignore", "python3 -IS", "python3 -I -X dev -W error",
                       "python3.12", "/usr/bin/python3", "uv run", "uv run python3 -X utf8", "uvx --from x python",
                       "pipenv run python", "poetry run python3", "env python3", "nice -n 5 python3"):
            c = "%s %s approve --hook x" % (prefix, script)
            self.assertEqual(bash(c), "ask", c)
        self.assertEqual(bash(script + " approve --use all"), "ask")
        self.assertEqual(bash('python3 -X utf8 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" set sandbox env'), "ask")

    def test_module_form_asks_and_gets_no_exemption(self):
        self.assertEqual(bash("python3 -m dryfire.main approve --hook x"), "ask")
        self.assertEqual(bash("python3 -m dryfire.cfgtool set sandbox env"), "ask")
        self.assertEqual(bash("python3 -m dryfire.main run --data %s/approvals.json" % DATA), "deny")

    def test_reading_a_script_is_not_running_it(self):
        self.assertEqual(bash('cat "${CLAUDE_PLUGIN_ROOT}/scripts/cli.py"'), "allow")
        self.assertEqual(bash('mytool "${CLAUDE_PLUGIN_ROOT}/scripts/cli.py" %s/approvals.json' % DATA), "deny")

    def test_ask_becomes_deny_when_nobody_can_answer(self):
        for mode in ("dontAsk", "bypassPermissions"):
            self.assertEqual(bash(CLI + " approve --hook x", mode), "deny")

    def test_writes_into_protected_folders_are_denied(self):
        for c in ("echo {} > %s/approvals.json" % DATA, "rm -rf ~/.claude/dryfire",
                  "cp evil.json $HOME/.claude/dryfire/approvals.json", "tee %s/scripts/x.py" % ROOT,
                  "sed -i '' s/a/b/ %s/config.json" % DATA,
                  "python3 -c \"open('%s/approvals.json','w')\"" % DATA,
                  "find %s -delete" % DATA, "mv x $CLAUDE_PLUGIN_DATA/approvals.json"):
            self.assertEqual(bash(c), "deny", c)

    def test_edit_tools_into_protected_folders_are_denied(self):
        for tool in ("Write", "Edit", "MultiEdit"):
            self.assertEqual(decide(tool, {"file_path": DATA + "/approvals.json"}), "deny")
            self.assertEqual(decide(tool, {"file_path": "~/.claude/dryfire/config.json"}), "deny")
            self.assertEqual(decide(tool, {"file_path": ROOT + "/hooks/hooks.json"}), "deny")
            self.assertEqual(decide(tool, {"file_path": "/w/app.py"}), "allow")
        self.assertEqual(decide("NotebookEdit", {"notebook_path": DATA + "/n.ipynb"}), "deny")

    def test_changing_subcommand_after_a_global_data_flag_asks(self):
        for c in (CFG + ' --data "${CLAUDE_PLUGIN_DATA}" approve allow_read',
                  CFG + ' --data "$CLAUDE_PLUGIN_DATA" set preset deep',
                  CFG + ' --project /w --data=%s unset preset' % DATA,
                  CFG + ' --data "${CLAUDE_PLUGIN_DATA}" init --project-layer'):
            self.assertEqual(bash(c), "ask", c)
        self.assertEqual(bash(CFG + ' --data "${CLAUDE_PLUGIN_DATA}" show'), "allow")

    def test_abbreviated_data_flag_is_refused_by_the_scripts(self):
        from dryfire import cfgtool, main
        for argv in (["replay", "--dat", "/tmp/x", "--pack", "p"], ["approve", "--da=/tmp/x", "--list"]):
            with self.assertRaises(SystemExit, msg=argv), helpers.quiet_stderr():
                main.parser().parse_args(argv)
        with self.assertRaises(SystemExit), helpers.quiet_stderr():
            cfgtool.parser().parse_args(["--dat", "/tmp/x", "show"])

    def test_other_data_folder_or_env_asks(self):
        self.assertEqual(bash(CLI + " replay --data /tmp/planted --use all"), "ask")
        self.assertEqual(bash(CLI + " replay --data=/tmp/planted --use all"), "ask")
        self.assertEqual(bash("CLAUDE_PLUGIN_DATA=/tmp/p " + CLI + " replay --use all"), "ask")
        self.assertEqual(bash("export CLAUDE_PLUGIN_DATA=/tmp/p"), "ask")
        self.assertEqual(bash(CLI + " replay --data %s --pack p.json" % DATA), "allow")

    def test_moving_home_before_a_run_asks(self):
        # dryfire finds its fallback data folder under HOME, so a moved HOME could point it at planted approvals.
        for c in ("HOME=/tmp/p " + CLI + " replay --use all", "env HOME=/tmp/p " + CLI + " replay --use all",
                  "HOME=/tmp/p; " + CLI + " replay --use all", "export HOME=/tmp/p && " + CLI + " replay --use all",
                  "CLAUDE_PLUGIN_DATA=/tmp/p; " + CLI + " replay --use all"):
            self.assertEqual(bash(c), "ask", c)
        self.assertEqual(bash("HOME=/tmp/p npm test"), "allow")
        self.assertEqual(bash(CLI + " replay --use all"), "allow")

    def test_launchers_the_parser_does_not_unwrap_still_ask(self):
        for prefix in ("arch -arm64", "/usr/bin/arch -x86_64", "script -q /dev/null", "flock /tmp/l",
                       "taskpolicy -c utility", "parallel", "caffeinate -i arch -arm64"):
            c = "%s python3 %s/scripts/cli.py approve --hook x" % (prefix, ROOT)
            self.assertEqual(bash(c), "ask", c)
        for c in ("find . -name x -exec python3 %s/scripts/cli.py approve --hook x \\;" % ROOT,
                  "flock /tmp/l -c 'python3 %s/scripts/cli.py approve --hook x'" % ROOT,
                  "script -q /dev/null -c 'python3 %s/scripts/cfgtool.py set sandbox env'" % ROOT,
                  "arch -arm64 touch %s/approvals.json" % DATA):
            self.assertIn(bash(c), ("ask", "deny"), c)
        self.assertEqual(bash("arch -arm64 python3 %s/scripts/cli.py replay --use all" % ROOT), "allow")

    def test_a_subcommand_known_only_at_run_time_asks(self):
        for c in ("A=approve; " + CLI + " $A --hook x", CLI + ' "$A" --hook x', CLI + " $(echo approve) --hook x",
                  "xargs -I{} python3 %s/scripts/cli.py {} --hook x" % ROOT, CFG + " ${S} sandbox env"):
            self.assertEqual(bash(c), "ask", c)
        self.assertEqual(bash(CLI + " scan --window-days 1"), "allow")

    def test_runs_the_parser_cannot_follow_still_ask(self):
        script = "%s/scripts/cli.py" % ROOT
        for c in ("echo approve h | xargs python3 " + script,
                  "python3 -mdryfire.main approve --hook x", "python3 -Imdryfire.main approve --hook x",
                  "script -qc 'python3 %s approve --hook x' /dev/null" % script,
                  "flock --command='python3 %s approve --hook x' /tmp/l" % script,
                  "env -S 'python3 %s approve --hook x'" % script,
                  "cp -r %s/scripts /tmp/s && python3 /tmp/s/cli.py approve --hook x" % ROOT):
            self.assertEqual(bash(c), "ask", c)
        for c in ("python3 %s approve --list && cat %s" % (script, script), "python3 manage/cli.py init",
                  "cd ~/src/dryfire && git commit -m 'set up'", "set -e; python3 %s scan --json" % script):
            self.assertEqual(bash(c), "allow", c)

    def test_home_changed_without_a_plain_assignment_asks(self):
        for pre in ("HOME+=/p; ", "read HOME < f; ", "for HOME in /tmp/p; do ", "printf -v HOME /tmp/p; ",
                    "unset HOME; : ${HOME:=/tmp/p}; ", "declare -x CLAUDE_PLUGIN_DATA; "):
            c = pre + CLI + " replay --use all" + ("; done" if pre.startswith("for") else "")
            self.assertEqual(bash(c), "ask", c)
        self.assertEqual(bash(CLI + ' replay --use all --out "$HOME/r.txt"'), "allow")
        self.assertEqual(bash(CLI + ' replay --use all --out "${HOME:-/tmp}/r.txt"'), "ask")  # := would set it.

    def test_cli_and_cfgtool_run_as_modules_ask(self):
        # From the scripts folder, or with it on PYTHONPATH, 'python3 -m cli' runs dryfire's cli.py.
        for c in ('cd "$CLAUDE_PLUGIN_ROOT/scripts" && python3 -m cli approve --hook x',
                  'cd "$CLAUDE_PLUGIN_ROOT/scripts" && python3 -m cfgtool set sandbox env',
                  'PYTHONPATH="$CLAUDE_PLUGIN_ROOT/scripts" python3 -m cli approve --hook x',
                  "python3 -mcli approve --hook x"):
            for mode in ("default", "bypassPermissions"):
                self.assertNotEqual(bash(c, mode), "allow", (c, mode))
        self.assertEqual(bash('cd "$CLAUDE_PLUGIN_ROOT/scripts" && python3 -m cli scan --json'), "allow")

    def test_env_split_string_lines_are_checked(self):
        script = "%s/scripts/cli.py" % ROOT
        for c in ('env -S "cp /tmp/a.json %s/approvals.json"' % DATA,
                  'env -S "cp /tmp/a.json $CLAUDE_PLUGIN_DATA/approvals.json"',
                  'env -S "tee %s/approvals.json" < /tmp/a.json' % DATA,
                  'env --split-string="cp /tmp/a.json %s/approvals.json"' % DATA,
                  'env -S"cp /tmp/a.json %s/approvals.json"' % DATA,
                  'env -i -u X -S "cp /tmp/x.py %s/scripts/dryfire/cfg.py"' % ROOT,
                  'nohup env -S "env -S \'cp /tmp/a %s/approvals.json\'"' % DATA):
            self.assertEqual(bash(c), "deny", c)
        self.assertEqual(bash("env -S \"python3 %s 'appr'ove --hook x\"" % script), "ask")
        self.assertEqual(bash('env -S "echo hi there"'), "allow")

    def test_long_env_lines_are_read_in_linear_time(self):
        for c in ("env -u " * 20000, "env --unset " * 20000, "env -i " * 20000, "env -S " * 5000 + "x"):
            started = time.monotonic()
            bash(c)
            self.assertLess(time.monotonic() - started, 2.0, c[:20])

    def test_home_set_through_a_quoted_name_asks(self):
        for pre in ("export HO''ME=/tmp/h; ", "export H\\OME=/tmp/h; ", 'read "HOME" < f; ',
                    "export HOM$'E'=/tmp/x; ", "export HO$()ME=/tmp/x; ", "export HO${Z}ME=/tmp/x; ",
                    "declare -x HO``ME=/tmp/x; ", "export $V; ", "env HO$()ME=/tmp/x "):
            self.assertEqual(bash(pre + CLI + " replay --use all"), "ask", pre)
        for pre in ('export PATH="/x"; ', 'env X="$HOME/a" '):
            self.assertEqual(bash(pre + CLI + " scan --json"), "allow", pre)

    def test_text_fed_to_xargs_in_an_untraced_body_asks(self):
        script = "%s/scripts/cli.py" % ROOT
        for c in ("bash <<< 'true; echo approve --hook /tmp/h.sh | xargs python3 %s'" % script,
                  "sh <<'EOF'\necho approve --hook /tmp/h.sh | xargs python3 %s\nEOF" % script,
                  "bash <<< 'echo approve > /tmp/a; xargs python3 %s < /tmp/a'" % script):
            self.assertEqual(bash(c), "ask", c)

    def test_env_spelled_through_quotes_or_expansions_is_read(self):
        script = "%s/scripts/cli.py" % ROOT
        for c in ("$'env' -S 'python3 %s appr${E}ove --hook /tmp/h.sh'", "${E}env -S 'python3 %s appr${E}ove --hook x'",
                  "e$'n'v -S 'python3 %s appr${E}ove --hook x'"):
            self.assertEqual(bash(c % script), "ask", c)

    def test_many_declarer_words_are_read_quickly(self):
        import time
        c = "export" + " export" * 9000 + "; " + CLI + " approve --hook /tmp/h.sh"
        started = time.monotonic()
        self.assertEqual(bash(c), "ask")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_unreadable_lines_that_only_mention_env_files_pass(self):
        for c in ("git commit -F - <<'EOF'\nDon't read .env in tests\nEOF", "cp .env.example .env  # don't commit it",
                  "cat > notes.txt <<EOF\nThe environment isn't ready\nEOF"):
            self.assertEqual(bash(c), "allow", c)

    def test_home_named_at_run_time_by_read_printf_or_eval_asks(self):
        for pre in ("read HO${Z}ME <<< /tmp/fh; ", "printf -v HO${Z}ME %s /tmp/fh; ", "eval HO${Z}ME=/tmp/fh; ",
                    "V=HO; eval ${V}ME=/tmp/x ", "A=HO; V=${A}ME=/tmp/x; eval \"$V\"; "):
            self.assertEqual(bash(pre + CLI + " replay --hook /tmp/h.sh"), "ask", pre)
        self.assertEqual(bash('V=HO; bash -c "${V}ME=/tmp/x %s replay --use all"' % CLI.replace('"', "'")), "ask")

    def test_paths_ending_in_a_declarer_name_are_not_declarers(self):
        for c in (CLI + ' detect --project /usr/local --data "${CLAUDE_PLUGIN_DATA}"',
                  CLI + ' replay --data "${CLAUDE_PLUGIN_DATA}" --pack ~/rules/env --use all',
                  "echo a=b; " + CLI + " scan --json", CLI + " replay --since=2026-11-01 --use all"):
            self.assertEqual(bash(c), "allow", c)

    def test_text_fed_through_process_substitution_asks(self):
        cli = "python3 %s/scripts/cli.py" % ROOT
        for c in ("bash <(echo %s approve --hook x)", "source <(echo %s approve --hook x)",
                  "sh < <(echo %s approve --hook x)", ". <(printf '%%s' '%s approve --hook x')"):
            self.assertEqual(bash(c % cli), "ask", c)

    def test_git_grep_with_a_pager_command_is_read(self):
        cli = "python3 %s/scripts/cli.py" % ROOT
        for c in ('git grep -O"%s approve --hook x" foo', 'git grep --open-files-in-pager="%s approve --hook x" foo'):
            self.assertEqual(bash(c % cli), "ask", c)

    def test_home_set_behind_a_wrapper_or_inside_case_asks(self):
        run = CLI + " replay --pack p.json"
        for pre in ("timeout 9 env $V ", "nice env $V ", "command -p export $V; ", "case a in a) export $V;; esac; ",
                    "time -p read HO${Z}ME <<< /tmp/f; ", "time -p printf -v HO${Z}ME x; ",
                    "declare -n R=HO${Z}ME; R=/tmp/f; ", "env -u X HO${Z}ME=/tmp/f ", "read -r -a HO${Z}ME <<< x; "):
            self.assertEqual(bash("V=$(printf 'HO%sE=/tmp/evil' M); " + pre + run), "ask", pre)

    def test_home_built_through_a_substitution_appended_or_in_arithmetic_asks(self):
        for line in ('V=HO; bash -c "${V}ME+=/x %s"', 'V=HO; bash -c "${V}ME+=/x; %s"',
                     'bash -c "$(printf HO)ME=/x %s"', 'bash -c "$(echo HO)ME=/x %s"', "$(printf HO)ME=/x %s",
                     "V=HO; (( ${V}ME = 0 )); %s", 'V=HO; let "${V}ME = 0"; %s', "V=HO; : $(( ${V}ME = 0 )); %s",
                     "V=HO; getopts a: ${V}ME -a /x; %s", ". <(printf '%%sME=/x\\n' HO); %s",
                     "source <(printf '%%sME=/x\\n' HO); %s", 'echo $(V=HO; bash -c "${V}ME=/x %s")'):
            c = line % (CLI + " scan")
            self.assertEqual(bash(c), "ask", c)

    def test_a_line_continuation_inside_a_name_still_sets_it(self):
        for c in ("HO\\\nME=/x %s", "CLAUDE_PLUGIN_\\\nDATA=/x %s", "export HO\\\nME=/x; %s"):
            self.assertEqual(bash(c % (CLI + " scan")), "ask", c)
        self.assertEqual(bash("python3 %s/scripts/cli.py appr\\\nove --hook x" % ROOT), "ask")

    def test_text_stored_by_printf_or_sent_to_a_coprocess_asks(self):
        run = "python3 %s/scripts/cli.py approve --hook x" % ROOT
        for c in ("printf -v C '%%s' '%s'; $C", "printf -vC '%%s' '%s'; eval \"$C\"",
                  "coproc sh; echo '%s' >&${COPROC[1]}", "coproc S { sh; }; echo '%s' >&\"${S[1]}\""):
            self.assertEqual(bash(c % run), "ask", c)

    def test_a_deeply_nested_line_asks_quickly_without_failing(self):
        line = "$(cat <<'E'\n" * 5000 + CLI + " scan"
        started = time.monotonic()
        self.assertEqual(bash(line), "ask")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_env_after_a_backslash_or_a_substitution_on_an_unreadable_line_asks(self):
        line = "'python3\\_%s/scripts/cli.py\\_approve\\_--hook\\_x'; : $'\\''" % ROOT
        for env in ("\\env", "$(true)env", "/usr/bin/env"):
            self.assertEqual(bash(env + " -S " + line), "ask", env)

    def test_pipes_into_text_commands_and_or_lists_pass(self):
        script = "%s/scripts/cli.py" % ROOT
        for c in ("grep -n approve %s | head -20", "grep -n approve %s || true", "grep approve %s | grep -v x | wc -l"):
            self.assertEqual(bash(c % script), "allow", c)
        for c in ("grep approve %s | head | sh", "echo python3 %s approve --hook x | cat | bash"):
            self.assertEqual(bash(c % script), "ask", c)

    def test_a_bar_inside_quotes_or_after_a_redirect_is_not_a_pipe(self):
        script = "%s/scripts/cli.py" % ROOT
        for c in ('grep -E "approve|set" %s', "grep -E 'approve|set' %s | head", "grep approve\\|set %s",
                  "grep approve %s >| /tmp/o", "grep 'a;b' %s", 'grep "(approve)" %s'):
            self.assertEqual(bash(c % script), "allow", c)

    def test_text_piped_into_a_shell_after_a_redirect_asks(self):
        run = "echo python3 %s/scripts/cli.py approve --hook x" % ROOT
        for tail in (" 2>&1 | sh", " &>/dev/null | sh", " >&2 | sh", " 2>&1 |& sh", " <&0 | sh"):
            self.assertEqual(bash(run + tail), "ask", tail)

    def test_an_unclosed_quote_does_not_hide_the_rest_of_the_line(self):
        c = "echo 'x ; python3 %s/scripts/cli.py approve --hook x" % ROOT
        self.assertEqual(bash(c), "ask")

    def test_a_commit_message_from_a_quoted_heredoc_is_text(self):
        body = "dryfire: approve and set in %s/scripts/cli.py" % ROOT
        msg = "git commit -m \"$(cat <<'EOF'\n%s\nEOF\n)\"" % body
        self.assertEqual(bash(msg), "allow")
        self.assertEqual(bash(msg.replace("<<'EOF'", "<<\"EOF\"")), "allow")
        # The same text run by a shell, or piped into one, still asks; so does an unquoted heredoc.
        run = "python3 %s/scripts/cli.py approve --hook x" % ROOT
        for c in ("bash -c \"$(cat <<'EOF'\n%s\nEOF\n)\"", "echo \"$(cat <<'EOF'\n%s\nEOF\n)\" | sh",
                  "git commit -m \"$(cat <<EOF\n%s $(id)\nEOF\n)\"; sh -c \"$(cat <<'EOF'\n%s\nEOF\n)\""):
            self.assertEqual(bash(c.replace("%s", run)), "ask", c)

    def test_commands_after_the_first_end_of_a_heredoc_are_read(self):
        # The shell ends a heredoc at the first line holding only its marker; what follows inside $( ) runs.
        run = "python3 %s/scripts/cli.py approve --hook x" % ROOT
        for middle in ("echo '%s' | sh", "C='%s'; eval \"$C\"", "printf -v C '%%s' '%s'; $C", "sh <<< '%s'"):
            c = "git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n" + middle % run + "\ncat <<'EOF'\nEOF\n)\""
            self.assertEqual(bash(c), "ask", c)

    def test_a_line_continuation_at_the_end_of_a_comment_does_not_hide_the_next_line(self):
        run = "python3 %s/scripts/cli.py approve --hook x" % ROOT
        for pre in ("true # \\\n", "ls # see \\\n", "ls # it's \\\n"):
            self.assertEqual(bash(pre + run), "ask", pre)

    def test_quotes_in_comments_or_ansi_c_strings_do_not_hide_a_pipe(self):
        run = "python3 %s/scripts/cli.py approve --hook x" % ROOT
        cfg = "python3 %s/scripts/cfgtool.py set sandbox off" % ROOT
        for r in (run, cfg):
            for c in ("echo hi # it's\necho \"%s\" | sh\n# that's all", "echo $'\\''; echo \"%s\" | sh; echo 'z'",
                      "echo $'a\\'b'; echo \"%s\" | sh; echo 'z'"):
                self.assertEqual(bash(c % r), "ask", c)
        self.assertEqual(bash("echo hi # it's fine\n" + CLI + " scan"), "allow")
        self.assertEqual(bash("grep -c '#' f | head # it's a count"), "allow")

    def test_a_cat_defined_through_eval_or_any_function_reads_the_heredoc_as_commands(self):
        run = "python3 %s/scripts/cli.py approve --hook x" % ROOT
        body = "git commit --allow-empty -m \"$(cat <<'EOF'\n%s\nEOF\n)\"" % run
        for pre in ('eval "c""at() { sh; }"; ', 'X=c; eval "${X}at() { sh; }"; ', "eval 'c''at() { sh; }'; ",
                    "c\\at() { sh; }; ", "source ./f; "):
            self.assertEqual(bash(pre + body), "ask", pre)

    def test_an_expansion_counted_up_or_down_in_arithmetic_asks(self):
        run = CLI + " replay --pack p.json"
        for line in ("set -a; V=CLAUDE_PLUGIN_; V+=DATA; (( ++$V )); %s", "V=X; (( x = --$V )); %s",
                     "V=X; : $(( ++$V )); %s", "V=X; let ++$V; %s", "V=X; a[++$V]=1; %s", "V=x; (( ++${V^^} )); %s",
                     "V=HO; a[x[1],${V}ME=0]=1; %s", "V=HO; : ${a[x[1],${V}ME=0]}; %s"):
            c = line % run
            self.assertEqual(bash(c), "ask", c)
        self.assertEqual(bash("(( i++ )); " + run), "ask")  # Any arithmetic asks (a read value may name HOME).

    def test_a_very_long_line_asks_quickly(self):
        run = "\npython3 %s/scripts/cli.py scan" % ROOT
        for pad in ("`" * 240000, "a[" * 400000, "x " * 200000):
            started = time.monotonic()
            self.assertEqual(bash(pad + run), "ask")
            self.assertLess(time.monotonic() - started, 1.0)

    def test_sourcing_anywhere_a_command_can_stand_reads_the_heredoc_as_commands(self):
        msg = "git commit -m \"$(cat <<'EOF'\npython3 %s/scripts/cli.py approve --hook x\nEOF\n)\"" % ROOT
        for pre in ("{ . ./env.sh; }; ", "if . ./env.sh; then :; fi; ", "command . ./env.sh; ",
                    "builtin . ./env.sh; ", "time . ./env.sh; ", "! . ./env.sh; ", "for f in a; do . ./env.sh; done; ",
                    "x=1 . ./env.sh; ", "x=1 source ./env.sh; "):
            self.assertEqual(bash(pre + msg), "ask", pre)

    def test_home_built_in_old_arithmetic_substring_bounds_or_an_integer_variable_asks(self):
        for pre in ("V=HO; : $[${V}ME=7]", "V=HO; : $[ ${V}ME++ ]", "V=HO; x=abc; : ${x:${V}ME=1}",
                    "V=HO; x=abc; : ${x:0:${V}ME=1}", "V=HO; declare -i x; x=${V}ME=9", "V=HO; typeset -i x; x+=${V}ME=9",
                    "V=HO; local -ri x=${V}ME=9"):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_sourcing_after_a_redirect_an_option_a_case_pattern_or_an_element_asks(self):
        msg = "git commit -m \"$(cat <<'EOF'\npython3 %s/scripts/cli.py approve --hook x\nEOF\n)\"" % ROOT
        for pre in ("2>/dev/null . ./env.sh; ", "</dev/null . ./env.sh; ", "< /dev/null . ./env.sh; ",
                    "time -p . ./env.sh; ", "command -p . ./env.sh; ", "case a in a) . ./env.sh;; esac; ",
                    "x[0]=1 . ./env.sh; ", "'.' ./env.sh; "):
            self.assertEqual(bash(pre + msg), "ask", pre)
        for pre in ("make -C . && ", "find . -name x; ", "rsync -a . dest/; "):
            self.assertEqual(bash(pre + msg.replace("python3", "run")), "allow", pre)
        # A case statement is not a plain line, so the message is read as words that may run (an over-ask).
        self.assertEqual(bash("case a in a) git add .;; esac; " + msg.replace("python3", "run")), "ask")

    def test_substring_bounds_of_any_parameter_and_quoted_declare_ask(self):
        for pre in ("V=HO; : ${@:${V}ME=1}", "V=HO; : ${*:${V}ME=1}", "V=HO; a=(x y); : ${a[0]:${V}ME=1}",
                    "V=HO; x=y; r=x; : ${!r:${V}ME=1}", "V=HO; \"declare\" -i x; x=${V}ME=9",
                    "V=HO; d\\eclare -i x; x=${V}ME=9", "V=HO; 'typeset' -i x; x=${V}ME=9"):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_substring_bounds_of_special_parameters_and_test_arithmetic_ask(self):
        for pre in ("V=HO; : ${$:${V}ME=1}", "V=HO; : ${-:${V}ME=1}", "V=HO; : ${?:${V}ME=1}",
                    "V=HO; : ${!:${V}ME=1}", "V=HO; : ${#:${V}ME=1}",
                    "V=HO; a=(0); [[ a[0] -eq ${V}ME[0]=5 ]]", "V=HO; x=]; [[ 1 -lt ${V}ME=5 ]]"):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_sourcing_in_a_subshell_or_through_a_built_name_asks(self):
        msg = "git commit -m \"$(cat <<'EOF'\npython3 %s/scripts/cli.py approve --hook x\nEOF\n)\"" % ROOT
        for pre in ("( . ./env.sh; ", 'x="a b" . ./env.sh; ', "2>'a b' . ./env.sh; ", "{fd}>/dev/null . ./env.sh; ",
                    "$'\\x2e' ./env.sh; ", "D=.; $D ./env.sh; ", "sou${Z}rce ./env.sh; "):
            c = pre + msg + (" )" if pre.startswith("(") else "")
            self.assertEqual(bash(c), "ask", pre)

    def test_a_numeric_test_with_a_quoted_or_later_operand_asks(self):
        for pre in ('V=HO; [[ "${V}ME = 5" -eq 5 ]]', 'V=HO; [[ 1 -eq 1 && 0 -eq "${V}ME = 5" ]]',
                    "V=HO; [[ ! ${V}ME=5 -gt 1 || 1 ]]"):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_sourcing_after_a_descriptor_redirect_a_brace_word_or_a_trap_asks(self):
        msg = "git commit -m \"$(cat <<'EOF'\npython3 %s/scripts/cli.py approve --hook x\nEOF\n)\"" % ROOT
        for pre in ("2>&1 . ./env.sh; ", ">&2 . ./env.sh; ", "<&0 . ./env.sh; ", "x=1 2>&1 . ./env.sh; ",
                    "2>&1 $D ./env.sh; ", "{.,} ./env.sh; ", "{,.} ./env.sh; ", "x=1 {.,} ./env.sh; ",
                    "trap '. ./env.sh' DEBUG; ", 'trap ". ./env.sh" DEBUG; ', "mapfile -C . -c 1 < l; "):
            self.assertEqual(bash(pre + msg), "ask", pre)
        self.assertEqual(bash("make 2>&1 | tee log; " + msg.replace("approve --hook x", "is great")), "allow")

    def test_a_setter_after_an_escaped_redirect_a_prefix_or_through_a_pattern_asks(self):
        for pre in ('V=HO; echo \\>& let "${V}ME = 5"', "echo \\>& . <(printf 'HO%sE=/x' M)",
                    "echo \\>& declare -i x; V=HO; x=${V}ME=9", 'V=HO; >/dev/null let "${V}ME = 5"',
                    'V=HO; 2>&1 let "${V}ME = 5"', 'V=HO; x=1 let "${V}ME = 5"',
                    ">/dev/null . <(printf 'HO%sE=/x' M)", '>/dev/null declare -i x; V=HO; x="${V}ME = 9"',
                    'V=HO; {let,} "${V}ME = 5"', 'V=HO; l[e]t "${V}ME = 5"',
                    'V=HO; [[ x == "]]" || "${V}ME = 5" -eq 5 ]]', 'V=HO; [[ $(echo ]]) == x || "${V}ME = 5" -eq 5 ]]',
                    'V=HO; [[ x =~ (]]) || "${V}ME = 5" -eq 5 ]]'):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)
        # Arithmetic reads values as expressions, so it asks on a line that runs dryfire, even when harmless.
        self.assertEqual(bash(">/dev/null let n=n+1; " + CLI + " scan"), "ask")

    def test_a_pattern_command_word_may_source(self):
        msg = "git commit -m \"$(cat <<'EOF'\npython3 %s/scripts/cli.py approve --hook x\nEOF\n)\"" % ROOT
        for pre in ("sourc[e] ./e; ", "sourc? ./e; ", "sour* ./e; "):
            self.assertEqual(bash(pre + msg), "ask", pre)

    def test_a_setter_in_a_funsub_a_quoted_joiner_a_quoted_prefix_or_a_case_branch_asks(self):
        for pre in ('V=HO; echo ${ let "${V}ME = 5"; }', 'V=HO; x=${ let "${V}ME = 5"; }',
                    'V=HO; echo ${ declare -i x; x="${V}ME = 9"; }', "echo ${ . <(printf 'HO%sE=/x' M); }",
                    'V=HO; echo ${| let "${V}ME = 5"; }',
                    'V=HO; [[ "${V}ME = 5 | 0" -eq 5 ]]', 'V=HO; [[ "${V}ME = 5 || 1" -eq 1 ]]',
                    'V=HO; [[ "${V}ME = 1 && 1" -eq 1 ]]', 'V=HO; x="a b" let "${V}ME = 5"',
                    "x='a b' . <(printf 'HO%sE=/x' M)", 'V=HO; >| f let "${V}ME = 5"',
                    ">| f . <(printf 'HO%sE=/x' M)", "V=HO; 2>'a b' let \"${V}ME = 5\"",
                    'V=HO; case x in x) let "${V}ME = 5";; esac', "case x in x) . <(printf 'HO%sE=/x' M);; esac",
                    "{declare,} -i x; V=HO; x=${V}ME=9"):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_a_setter_in_a_function_body_or_a_subshell_asks(self):
        for pre in ('V=HO; f() { let "${V}ME = 5"; }; f', 'V=HO; function f { let "${V}ME = 5"; }; f',
                    'V=HO; f() (let "${V}ME = 5"); f', 'V=HO; (let "${V}ME = 5")', "(. <(printf 'HO%sE=/x' M))",
                    "function f { . <(printf 'HO%sE=/x' M); }; f"):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_an_unknown_command_word_given_a_built_name_asks(self):
        for pre in ("{read,} HO${Z}ME <<< /x", "rea[d] HO${Z}ME <<< /x", "{printf,} -v HO${Z}ME /x",
                    "C=read; $C HO${Z}ME <<< /x", "C=declare; $C -n R=HO${Z}ME; R=/x", "C=getopts; $C a: ${V}ME",
                    'C=let; $C "${V}ME++"', 'C=let; $C "${V^^}++"'):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_a_numeric_test_hidden_by_a_steered_clause_or_a_joiner_in_an_expansion_asks(self):
        for pre in ('V=HO; [ x ] & [[ "${V}ME = 7" -eq 7 ]] > ]', 'V=HO; [ x ] & [[ "${V}ME = 7" -eq 7 ]] 2> ]',
                    'V=HO; [[ "${V}ME = 5"$(:;) -eq 5 ]]', 'V=HO; x=; [[ "${V}ME = 6"${x-;} -eq 6 ]]',
                    'V=HO; [[ "${V}ME = 5"${x//|/} -eq 5 ]]'):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_a_setter_after_a_glued_pattern_or_an_escaped_prefix_asks(self):
        for pre in ('V=HO; f(){ let "${V}ME = 5"; }; f', "f(){ . <(printf 'HO%sE=/x' M); }; f",
                    'V=HO; case x in x)let "${V}ME = 5";; esac', 'case x in x)source <(printf "HO%sE=/x" M);; esac',
                    'V=HO; case a$ in a$) let "${V}ME = 5";; esac', 'V=HO; case "a>" in a\\>) let "${V}ME = 5";; esac',
                    'V=HO; x=a\\ b let "${V}ME = 5"', 'V=HO; x="a \\" b" let "${V}ME = 5"',
                    'V=HO; x="a $(echo ")") b" let "${V}ME = 5"', "x=a\\ b source <(printf 'HO%sE=/x' M)"):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_a_setter_after_an_unreadable_part_or_a_dollar_quote_asks(self):
        for pre in ("echo $'it\\'s'; HOME=/tmp/h", "echo $'it\\'s'; V=HO; let \"${V}ME = 5\";",
                    "V=HO; x=$'a\\'' let \"${V}ME = 5\";", "V=HO; >$'a\\'' let \"${V}ME = 5\";",
                    "x=$'a\\'' source <(printf 'HO%sE=/x' M);"):
            c = pre + " " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_an_unknown_command_word_given_a_lone_expansion_as_a_name_asks(self):
        for pre in ("V=HOM; V+=E; {read,} ${V} <<< /x", "C=read; $C $V <<< /x", "{printf,} -v $V /x",
                    "{declare,} -n R=$V; R=/x", "{getopts,} a: $V"):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_a_name_built_by_an_escaped_quote_a_glob_a_brace_list_or_any_expansion_asks(self):
        for pre in ("V=HO; x=\\$'\\' let \"${V}ME = 5\"", "x=\\$'\\' source <(printf 'HO%sE=/x' M)",
                    "V=HOM; V+=E; x=\\$'\\' {read,} $V <<< /x", "V=HO; >$$'\\' let \"${V}ME = 5\"",
                    "C=read; Z=M; $C -r x(.) HO${Z}E <<< 'a /x'", "Z=M; {read,} @(x) HO${Z}E <<< 'a /x'",
                    "C=read; V=hom; V+=e; $C ${V^^} <<< /x", "$C ${!R}", "$C ${V%x}", "$C ${V:-x}", "$C ${a[0]}",
                    'set -- $V; $C "$@"', "{printf,} -v${V} /x", "export {HO,}ME=/x", "declare {HO,}ME=/x",
                    "read {HO,}ME <<< /x", "touch HOME=x; export HOM?=x", "eval \"$(printf 'SE9NRT0veA==')\"",
                    "base64 -d < f > g; . ./g"):
            c = pre + "; " + CLI + " scan"
            self.assertEqual(bash(c), "ask", c)

    def test_text_the_shell_reads_again_or_a_child_shell_given_the_run_asks(self):
        run = "python3 %s/scripts/cli.py scan" % ROOT
        for c in ("trap 'HO\\\nME=/x' DEBUG; " + run, "emulate sh -c 'HO\\\nME=/x'; " + run,
                  "e''val 'HO\\\nME=/x'; " + run, "sour''ce /dev/stdin <<<'HO\\\nME=/x'; " + run,
                  "ev\\al x; " + run, ": /(e:'HO\\\nME=/x':); " + run,
                  "printf -v n 'HO%sME=0' ''; (( n )); " + run, "declare -u n=home=0; (( n )); " + run,
                  "typeset -u n=home=0; let n; " + run, "local -u n=home=0; (( n )); " + run):
            self.assertEqual(bash(c), "ask", c)

    def test_a_text_command_redefined_on_the_line_is_read_as_a_run(self):
        script = "python3 %s/scripts/cli.py" % ROOT
        for c in ('git() { shift; "$@"; }; git log %s approve --hook x',
                  'git() { shift; "$@"; }; git log HOME=/x %s scan',
                  'grep() { "$@"; }; grep %s approve --hook x', 'function cat { "$@"; }; cat %s approve --hook x',
                  'alias g=x; eval \'git() { "$@"; }\'; git log %s approve --hook x'):
            self.assertEqual(bash(c % script), "ask", c)

    def test_text_that_sets_home_piped_into_a_shell_asks(self):
        script = "python3 %s/scripts/cli.py" % ROOT
        for c in ("echo 'HOME=/x %s scan' | sh", "echo HOME=/x %s scan | bash",
                  "cat <<'X' | sh\nHOME=/x %s scan\nX", "echo 'cd %s && HOME=/x python3 cli.py scan' | sh"):
            arg = ROOT + "/scripts" if "cd %s" in c else script
            self.assertEqual(bash(c % arg), "ask", c)
        self.assertEqual(bash("grep -n 'HOME=' %s/scripts/cli.py | head" % ROOT), "allow")

    def test_a_value_read_at_run_time_and_used_in_arithmetic_asks(self):
        run = CLI + " scan"
        for c in ("echo 0=EMOH | rev | (read n; (( n )); %s)", "rev <<< 0=EMOH | (read n; let n; %s)",
                  "read n < v; (( n )); %s", "mapfile -t a < v; %s"):
            self.assertEqual(bash(c % run), "ask", c)

    def test_a_line_that_may_change_what_a_text_command_runs_reads_it_as_a_run(self):
        script = "python3 %s/scripts/cli.py" % ROOT
        for c in ('echo \\;#; git() { shift; "$@"; }; git log %s approve --hook x',
                  'noglob eval \'git() { shift; "$@"; }\'; git log %s approve --hook x',
                  'repeat 1 eval \'git() { shift; "$@"; }\'; git log %s approve --hook x',
                  "BASH_CMDS[cat]=/usr/bin/env; cat %s approve --hook x",
                  "BASH_CMDS[grep]=/usr/bin/env; grep HOME=/x %s scan",
                  "shopt -s expand_aliases\nBASH_ALIASES[cat]=env\ncat %s approve --hook x",
                  "read PATH < f && cat %s approve --hook x", "read PATH < f && cat HOME=/x %s scan",
                  "d/cat HOME=/x %s scan", "echo \\;# ; echo 'HOME=/x %s scan' | sh"):
            self.assertEqual(bash(c % script), "ask", c)

    def test_a_quoted_heredoc_fed_to_a_shell_is_not_a_commit_message(self):
        run = "HOME=/x python3 %s/scripts/cli.py scan" % ROOT
        for c in ("echo \"$(cat <<'EOF'\n%s\nEOF\n)\" | sh", "sh -c \"$(cat <<'EOF'\n%s\nEOF\n)\"",
                  "bash <<< \"$(cat <<'EOF'\n%s\nEOF\n)\""):
            self.assertEqual(bash(c % run), "ask", c)

    def test_a_pipe_through_a_folder_named_dryfire_that_runs_nothing_passes(self):
        for c in ("ls ~/src/dryfire/*.md | sort", "git -C ~/src/dryfire log --oneline | awk '{print $1}'",
                  "grep -rn HOME ~/src/dryfire/plugins | sort", "find ~/src/dryfire -name '*.py' | xargs wc -l",
                  "cd ~/src/dryfire && rg -l select | sort"):
            self.assertEqual(bash(c), "allow", c)

    def test_a_substitution_that_runs_inside_double_quotes_asks(self):
        script = "python3 %s/scripts/cli.py" % ROOT
        for c in ('echo "${(e):-\\$""(%s approve --hook x)}"', 'git commit -m "${(e):-\\$""(%s approve --hook x)}"',
                  'echo "${ %s approve --hook x; }"', 'echo "${| %s approve --hook x; }"',
                  "test -v 'a[${ %s approve --hook x; }]'", 'make "${(e):-\\$""(HOME=/x %s scan)}"',
                  'make "${ HOME=/x %s scan; }"', "v='$(%s approve --hook x)'; echo \"${v@P}\""):
            self.assertEqual(bash(c % script), "ask", c)

    def test_a_builtin_that_sets_a_variable_is_not_a_text_command(self):
        script = "python3 %s/scripts/cli.py" % ROOT
        for c in ("printf '-v' 'BASH_CMDS[cat]' %%s /usr/bin/env; cat %s approve --hook x",
                  "printf '-v' 'BASH_CMDS[cat]' %%s /usr/bin/env; cat HOME=/x %s scan",
                  "printf '-v' 'commands[cat]' %%s /usr/bin/env; cat %s approve --hook x",
                  "printf \\-v 'BASH_CMDS[cat]' %%s /usr/bin/env; cat %s approve --hook x"):
            self.assertEqual(bash(c % script), "ask", c)

    def test_a_heredoc_inside_single_quotes_or_a_comment_is_not_stripped(self):
        run = "HOME=/x python3 %s/scripts/cli.py scan" % ROOT
        for c in ("echo '$(cat <<'EOF'\nx' ; echo '%s' | sh ; echo '\nEOF\n)'",
                  "echo hi # $(cat <<'EOF'\n( echo '%s' | sh\nEOF\n)"):
            self.assertEqual(bash(c % run), "ask", c)

    def test_a_zsh_glob_flag_after_a_parenthesis_is_not_a_comment(self):
        run = "HOME=/x python3 %s/scripts/cli.py scan" % ROOT
        for c in ("echo /(#|b)in ; %s", "echo /(#|b)in ; echo '%s' | sh"):
            self.assertEqual(bash(c % run), "ask", c)

    def test_a_commit_message_piped_into_text_commands_passes(self):
        for tail in (" 2>&1 | tail -3", " | cat", " |& grep -v x | head"):
            c = "git commit -m \"$(cat <<'EOF'\ncli.py: read the config once, dryfire?\nEOF\n)\"" + tail
            self.assertEqual(bash(c), "allow", c)

    def test_a_comment_after_an_array_assignment_hides_nothing(self):
        run = "HOME=/x python3 %s/scripts/cli.py scan" % ROOT
        for c in ("a=(#'\n)\necho '%s' | sh\nb=(#'\n)", "a=(#\\\n); %s", "a+=(# x\n); %s"):
            self.assertEqual(bash(c % run), "ask", c)

    def test_an_array_like_argument_after_a_command_is_not_a_comment(self):
        run = "HOME=/x python3 %s/scripts/cli.py scan" % ROOT
        for c in ("echo x=(#i)y '%s' | sh", "touch x=#iy; echo x=(#i)y '%s' | sh", "a=1 echo b=(#i)y '%s' | sh"):
            self.assertEqual(bash(c % run), "ask", c)

    def test_a_glob_flag_hides_nothing_from_the_parser(self):
        for c in ("ls -d /(#|)tmp; rm -rf ~/.claude/dryfire", "ls /(#i)x; echo hi > %s/scripts/cli.py" % ROOT):
            self.assertEqual(bash(c), "deny", c)
        self.assertEqual(bash("ls /(#i)x; python3 %s/scripts/cli.py replay --data /tmp/evil" % ROOT), "ask")

    def test_a_data_variable_in_text_a_command_reads_asks(self):
        run = "HOME=/x python3 %s/scripts/cli.py scan" % ROOT
        for c in ("bash -ce \"$x\"", "zsh -cx \"$x\"", "bash -c -e \"$x\"", "sh -c -- \"$x\"",
                  "sh -c 'eval \"$1\"' _ \"$x\"", "env $x", "$x", "perl -e \"system('$x')\""):
            self.assertEqual(bash("x='%s'; " % run + c), "ask", c)
        self.assertEqual(bash("x='%s' sh -c 'eval \"$x\"'" % run), "ask")
        self.assertEqual(bash("export x='%s'; sh -c 'eval \"$x\"'" % run), "ask")

    def test_searching_dryfire_for_its_own_words_passes(self):
        cli = "%s/scripts/cli.py" % ROOT
        for c in ('grep -c "approve" ' + cli, 'git log -S "approve" -- ' + cli,
                  'git log -S"def approve" --oneline -- %s | head' % cli, "grep -rn 'approve' %s | grep -c eval" % cli,
                  "grep -n approve %s; echo let" % cli, "grep -n HOME %s | wc -l" % cli):
            self.assertEqual(bash(c), "allow", c)
        run = "python3 %s approve --hook x" % cli
        for c in ("x=1 eval \"$y\"; %s", "builtin eval \"$y\"; %s", "if true; then eval \"$y\"; fi; %s"):
            self.assertEqual(bash(c % run), "ask", c)

    def test_a_hash_after_a_parenthesis_near_dryfire_is_never_trusted(self):
        approve = "cd %s/scripts; python3 cli.py appro\"\"ve --hook z" % ROOT
        for pre in ("x=1 a=(", "{ a=(", "if true; then a=(", "declare -a a=(", "export a=(", "! a=("):
            for run in ("cd ~/.claude; echo x > dryfire/approvals.json", approve):
                c = pre + "# it's\n); " + run + "; x=1 b=(# '\n)"
                self.assertNotEqual(bash(c), "allow", c)
        for c in ("ls (#i)x; rm -rf ~/.claude/dryfire", "ls (#i)x; cd ~/.claude; echo x > dryfire/approvals.json"):
            self.assertNotEqual(bash(c), "allow", c)
        self.assertEqual(bash('git commit -m "Fix the scan (#12) in dryfire"'), "allow")
        self.assertEqual(bash("ls (#i)readme*"), "allow")

    def test_eval_after_a_redirect_option_or_prefix_still_runs_text(self):
        x = "Z=OM; x=\"H${Z}E=/x python3 %s/scripts/cli.py scan\"; " % ROOT
        for pre in ("2>/dev/null ", ">&2 ", "time -p ", "command -p ", "command -- ", "a[0]=1 ", "repeat 1 ", "- "):
            self.assertEqual(bash(x + pre + 'eval "$x"'), "ask", pre)
        self.assertEqual(bash(x + '2>/dev/null trap "$x" EXIT'), "ask")

    def test_a_dash_c_word_built_from_pieces_is_read_whole(self):
        x = "x='OME=/x python3 %s/scripts/cli.py scan'; " % ROOT
        for c in ('bash -c "H""$x"', 'zsh -c "H"$x'):
            self.assertEqual(bash(x + c), "ask", c)

    def test_git_with_a_folder_option_is_still_a_text_command(self):
        self.assertEqual(bash("git -C ~/src/dryfire log -S HOME -- %s/scripts/cli.py" % ROOT), "allow")
        self.assertEqual(bash("git -c core.pager=sh -C . log -S HOME -- %s/scripts/cli.py" % ROOT), "ask")

    def test_eval_spelled_through_a_variable_quotes_or_a_backslash_still_runs_text(self):
        x = "X=HO; c='ME=/tmp/h python3 %s/scripts/cli.py scan'; " % ROOT
        for c in ('E=eval; $E "$X$c"', '\\eval "$X$c"', "e''val \"$X$c\"", "$'eval' \"$X$c\"",
                  'builtin \\eval "$X$c"'):
            self.assertEqual(bash(x + c), "ask", c)

    def test_any_dash_c_word_that_expands_is_read(self):
        x = "X=HO; c='ME=/tmp/h python3 %s/scripts/cli.py scan'; " % ROOT
        for c in ("sh -c ''\"$X$c\"", "sh -c ':;'\"$X$c\"", "sh -c :\\;\"$X$c\"", "sh -c 'eval \"$0\"' \"$X$c\""):
            self.assertEqual(bash(x + c), "ask", c)

    def test_a_zsh_pattern_run_from_the_data_folder_hides_nothing(self):
        for c in ("ls (#i)x ; echo hi > approvals.json", "ls (#i)x ; rm -f approvals.json"):
            self.assertNotEqual(decide("Bash", {"command": c}, cwd=DATA), "allow", c)
            self.assertEqual(decide("Bash", {"command": c}, cwd=HOME + "/.claude/dryfire"), "deny", c)

    def test_text_stored_in_a_variable_and_run_later_asks(self):
        run = "HOME=/x python3 %s/scripts/cli.py scan" % ROOT
        n = "n=x[$'\\x24'\"(%s)\"]; " % run
        for c in ("x='%s'; eval \"$x\"" % run, "x='%s'; sh -c \"$x\"" % run, "x='%s'; bash -c \"$x\"" % run,
                  "x='%s'; env -S \"$x\"" % run, "x='%s'; command eval \"$x\"" % run, "trap '%s' EXIT" % run,
                  "x='%s'; . <(echo \"$x\")" % run, n + "(( n ))", n + "let n", n + "[[ n -eq 0 ]]",
                  n + "echo ${v:n}", n + "echo ${a[n]}", n + "v=n; echo ${!v}"):
            self.assertEqual(bash(c), "ask", c)

    def test_code_running_braces_in_single_quotes_are_text(self):
        c = "git commit -m 'selfguard: read ${ cmd; } and ${v@P}; cli.py approve asks'"
        self.assertEqual(bash(c), "allow")

    def test_many_printf_words_are_read_quickly(self):
        import time
        started = time.monotonic()
        bash(("printf " * 4600)[:32000])
        self.assertLess(time.monotonic() - started, 0.5)

    def test_many_braces_in_single_quotes_or_a_comment_are_read_quickly(self):
        import time
        for c in ("'" + "${!" * 10000 + "'", "'" + "${ " * 10000 + "'", "# " + "${!" * 10000):
            started = time.monotonic()
            bash(c)
            self.assertLess(time.monotonic() - started, 0.5, c[:4])

    def test_text_about_dryfire_that_runs_nothing_passes(self):
        script = "%s/scripts/cli.py" % ROOT
        for c in ('git commit -m "dryfire: fix cli.py parse(x)"', 'git commit -m "dryfire: why does cli.py fail?"',
                  "git commit -am 'dryfire: CLAUDE_PLUGIN_DATA wins over HOME'", "grep -n 'def main(' " + script,
                  "grep -rn 'source' " + script, "grep -n 'HOME=' " + script, "wc -l " + script,
                  "git log -S HOME --oneline -- " + script):
            self.assertEqual(bash(c), "allow", c)

    def test_a_line_naming_its_own_variables_or_none_runs_dryfire_without_asking(self):
        for c in (CLI + ' scan --data "${CLAUDE_PLUGIN_DATA}"', CLI + " scan --data $CLAUDE_PLUGIN_DATA",
                  'cd "$HOME/w" && ' + CLI + " scan", "getopts a: opt; " + CLI + " scan",
                  "git status && " + CLI + " detect --json"):
            self.assertEqual(bash(c), "allow", c)
        # A line that does not run dryfire may expand anything.
        for c in ("$CC -o out main.c -DFOO=$BAR", "export {A,B}=1", "source \"$VIRTUAL_ENV/bin/activate\""):
            self.assertEqual(bash(c), "allow", c)

    def test_an_unreadable_line_run_from_the_plugin_folder_that_sets_home_asks(self):
        for c in ("echo $'it\\'s'; HOME=/tmp/h; python3 cli.py scan", "echo $'it\\'s'; HOME=/tmp/h; ./cli.py scan",
                  "echo $'it\\'s'; HOME=/tmp/h; python3 -m cli scan"):
            self.assertEqual(decide("Bash", {"command": c}, cwd=ROOT + "/scripts"), "ask", c)

    def test_input_too_deep_to_parse_is_asked_about(self):
        out = io.StringIO()
        text = ('{"tool_name":"Bash","permission_mode":"bypassPermissions","tool_input":{"command":"ls"},"x":'
                + "[" * 300000 + "]" * 300000 + "}")
        selfguard.main(io.StringIO(text), out)
        self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_a_check_that_fails_in_an_unattended_mode_is_refused(self):
        from unittest import mock
        out = io.StringIO()
        payload = {"tool_name": "Bash", "permission_mode": "bypassPermissions", "tool_input": {"command": "ls"}}
        with mock.patch.object(selfguard, "check_bash", side_effect=RecursionError):
            selfguard.main(io.StringIO(json.dumps(payload)), out)
        self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_a_commit_after_adding_files_is_text(self):
        msg = "git commit -m \"$(cat <<'EOF'\nBind cli.py approve to the dryfire hook file hash\nEOF\n)\""
        for pre in ("git add . && ", "git add docs/source/x.md && ", "git add -A; "):
            self.assertEqual(bash(pre + msg), "allow", pre)
        self.assertEqual(bash(". ./env.sh; " + msg.replace("Bind", "python3 %s/scripts/cli.py approve" % ROOT)), "ask")

    def test_words_in_a_commit_message_do_not_make_it_ask(self):
        for text in ("Bind cli.py approve to the dryfire hook file hash", "dryfire: cli.py approve keeps PATH only",
                     "Explain eval, alias and source() in the docs"):
            msg = "git commit -m \"$(cat <<'EOF'\n%s\nEOF\n)\"" % text
            self.assertEqual(bash(msg), "allow", text)

    def test_a_heredoc_ended_by_its_marker_and_a_parenthesis_hides_nothing(self):
        run = "python3 %s/scripts/cli.py approve --hook x" % ROOT
        c = ("x=\"$(cat <<'EOF'\nmsg\nEOF)\"; printf -v C '%%s' '%s'; $C; y=\"$(cat <<'EOF'\nEOF\n)\"" % run)
        self.assertEqual(bash(c), "ask")

    def test_a_cat_changed_on_the_line_reads_the_heredoc_as_commands(self):
        run = "python3 %s/scripts/cli.py approve --hook x" % ROOT
        msg = "git commit --allow-empty -m \"$(cat <<'EOF'\n%s\nEOF\n)\"" % run
        for pre in ("cat() { sh; }; ", "function cat { sh; }; ", "alias cat=sh; ", "PATH=/tmp/x:$PATH; ",
                    "hash -p /bin/sh cat; ", "export PATH=/tmp/x; "):
            self.assertEqual(bash(pre + msg), "ask", pre)

    def test_arithmetic_setting_home_anywhere_in_a_statement_asks(self):
        scan = CLI + " scan"
        for c in ("V=HO; if (( ${V}ME = 0 )); then %s; fi", "V=HO; while (( ${V}ME = 0 )); do %s; done",
                  "V=HO; ! (( ${V}ME = 0 )); %s", "V=HO; { (( ${V}ME = 0 )); }; %s",
                  "V=HO; case a in a) (( ${V}ME = 0 ));; esac; %s", "V=HO; for (( ${V}ME = 0; 0; )); do :; done; %s",
                  "V=HO; until ! (( ${V}ME = 0 )); do :; done; %s", "(( HO$(printf M)E = 0 )); %s"):
            self.assertEqual(bash(c % scan), "ask", c)

    def test_an_expansion_assigned_to_in_arithmetic_or_a_subscript_asks(self):
        for line in ("V=H; V+=OME; (( $V = 0 )); %s", "V=H; V+=OME; : $(( $V = 0 )); %s",
                     "V=hoME; (( ${V^^} = 0 )); %s", "IFS=; V=(HO ME); (( ${V[*]} = 0 )); %s",
                     "set -- HO ME; IFS=; (( $* = 0 )); %s", "V=hoME; if (( ${V^^} = 0 )); then %s; fi",
                     "V=hoME; (( n = 1, ${V^^} <<= 1 )); %s", "V=hoME; (( ${V^^}++ )); %s",
                     "a[$(printf HO)ME=0]=1; %s", "V=HO; a[${V}ME=0]=1; %s", "V=HO; : ${a[${V}ME=0]}; %s",
                     "V=hoME; x=( [${V^^}=0]=1 ); %s"):
            c = line % (CLI + " scan")
            self.assertEqual(bash(c), "ask", c)

    def test_any_expansion_on_a_line_that_runs_dryfire_asks(self):
        # Asking costs one confirmation; telling which of these can build a name has no end. dryfire's own
        # commands name only its folders and HOME, so they never meet this.
        run = "; " + CLI + " replay --pack p.json"
        for pre in ('curl "$U?a=b" -o p.json', 'read -p "$P" ans', 'eval "$(ssh-agent -s)"', "$CC -o out main.c",
                    "rg -n 'foo(bar)?' $(pwd)", "echo ${P:-default}", "[[ $# -eq 0 ]]", "n=$(( n + 1 ))",
                    'source "$VIRTUAL_ENV/bin/activate"', "source ./env.sh", ". ./env.sh", "ls a[0]", "ls *.json",
                    "echo {a,b}"):
            self.assertEqual(bash(pre + run), "ask", pre)
        self.assertEqual(bash("grep localhost x" + run), "allow")

    def test_rg_with_a_preprocessor_is_read(self):
        c = 'rg --pre "python3 %s/scripts/cli.py approve --hook x" foo' % ROOT
        self.assertEqual(bash(c), "ask")

    def test_git_commit_text_naming_dryfire_passes(self):
        self.assertEqual(bash('git commit -m "dryfire: cli.py approve now asks"'), "allow")

    def test_a_hash_inside_a_word_starts_no_comment(self):
        c = "cd %s/scripts && echo a#b; env -S 'python3 -Bm cli approve --hook x'" % ROOT
        self.assertEqual(bash(c), "ask")

    def test_a_run_with_no_subcommand_on_the_line_asks(self):
        # xargs, or anything else that adds the words when the line runs, supplies the subcommand.
        script = '"$CLAUDE_PLUGIN_ROOT/scripts/cli.py"'
        for c in ("printf 'appr''ove\\n--hook\\nx' | xargs python3 " + script,
                  "printf '\\x61pprove --hook x' | xargs python3 " + script,
                  "xargs python3 %s < /tmp/args" % script, "xargs " + CFG + " --data /tmp/d < /tmp/args"):
            self.assertEqual(bash(c), "ask", c)
        for c in (CLI + " --version", CLI + " --help", CFG + " -h"):
            self.assertEqual(bash(c), "allow", c)

    def test_reading_or_recording_dryfire_text_does_not_ask(self):
        for c in ("grep -rn approve ~/src/dryfire/cli.py", "echo 'dryfire: init cli.py tests' >> notes.md",
                  "git log -p -- plugins/dryfire/scripts/cli.py | grep approve"):
            self.assertEqual(bash(c), "allow", c)

    def test_git_can_run_a_command_line_so_it_is_not_text(self):
        script = "%s/scripts/cli.py" % ROOT
        for c in ("git -c alias.x='!python3 %s approve --hook h' x" % script,
                  "git config alias.x '!python3 %s init' && git x" % script):
            self.assertEqual(bash(c), "ask", c)

    def test_another_packages_cli_module_is_not_dryfire(self):
        for c in ("python3 -m myapp.cli serve", "python3 -m myapp.cli", "python3 -m tool.cfgtool set x"):
            self.assertEqual(bash(c), "allow", c)
        self.assertEqual(bash('PYTHONPATH="$CLAUDE_PLUGIN_ROOT" python3 -m scripts.cli approve --hook x'), "ask")

    def test_env_long_option_prefixes_and_split_string_escapes_are_read(self):
        script = "%s/scripts/cli.py" % ROOT
        hidden = 'python3 %s appro""ve --hook h' % script
        for c in ("env --split='%s'" % hidden, "env --spl '%s'" % hidden, "env --s='%s'" % hidden,
                  "env --un FOO -S '%s'" % hidden, "env --ch /tmp -S '%s'" % hidden, "env -a x -S '%s'" % hidden,
                  "env -S 'python3 %s\\_approve\\_--hook\\_h'" % script,
                  "env -S 'python3 %s\\tinit'" % script):
            self.assertEqual(bash(c), "ask", c)
        self.assertEqual(selfguard._env_unescape("a\\_b\\tc\\\\_d\\c e"), "a b c\\\\_d")

    def test_a_missing_subcommand_is_named_as_missing(self):
        verdict = selfguard.check({"tool_name": "Bash", "tool_input": {
            "command": "xargs python3 %s/scripts/cli.py < /tmp/args" % ROOT}, "cwd": "/w"}, HOME, ENV, ROOT)
        self.assertIn("no subcommand on the line", verdict.reason)

    def test_known_subcommands_match_the_scripts(self):
        from dryfire import cfgtool, main
        for script, parser in (("cli.py", main.parser()), ("cfgtool.py", cfgtool.parser())):
            choices = [a for a in parser._actions if a.dest == "command"][0].choices
            self.assertEqual(sorted(choices), sorted(selfguard.SUBCOMMANDS[script]), script)

    def test_a_same_named_script_elsewhere_gets_no_exemption(self):
        self.assertEqual(bash("python3 /tmp/cli.py approve --hook x"), "allow")
        self.assertEqual(bash("python3 /tmp/cli.py run --data %s" % DATA), "deny")

    def test_odd_input_asks(self):
        self.assertEqual(selfguard.check("x", HOME, ENV, ROOT).decision, "ask")
        self.assertEqual(decide("Bash", "not a dict"), "ask")
        self.assertEqual(decide("Bash", {"command": None}), "ask")

    def test_other_tools_pass(self):
        self.assertEqual(decide("Read", {"file_path": DATA + "/approvals.json"}), "allow")


class ScriptTest(unittest.TestCase):
    def run_hook(self, payload, env=None):
        e = dict(os.environ)
        e.update(env or {})
        return helpers.run_script("selfguard.py", json.dumps(payload), env=e)

    def test_allow_prints_nothing_and_exits_0(self):
        r = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/"})
        self.assertEqual((r.returncode, r.stdout), (0, b""))

    def test_deny_is_hook_json(self):
        r = self.run_hook({"tool_name": "Write", "tool_input": {"file_path": helpers.PLUGIN + "/hooks/x.json"},
                           "cwd": "/"})
        self.assertEqual(r.returncode, 0)
        out = json.loads(r.stdout)["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")

    def test_broken_input_asks(self):
        r = helpers.run_script("selfguard.py", "{nope")
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_crash_asks(self):
        out = io.StringIO()
        orig = selfguard.check
        selfguard.check = lambda p: 1 / 0
        try:
            selfguard.main(io.StringIO("{}"), out)
        finally:
            selfguard.check = orig
        self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_runs_under_100_ms(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status && ls -la | wc -l"},
                              "cwd": "/"}).encode()
        script = os.path.join(helpers.SCRIPTS, "selfguard.py")
        subprocess.run([sys.executable, script], input=payload, stdout=subprocess.PIPE)  # Warm the cache.
        # The median, not the mean: one slow run on a busy machine says nothing about the hook.
        times = []
        for _ in range(11):
            started = time.monotonic()
            subprocess.run([sys.executable, script], input=payload, stdout=subprocess.PIPE, check=True)
            times.append(time.monotonic() - started)
        median = sorted(times)[len(times) // 2]
        self.assertLess(median, 0.1, "selfguard took %.0f ms (median)" % (median * 1000))


if __name__ == "__main__":
    unittest.main()
