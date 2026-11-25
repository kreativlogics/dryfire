import json
import unittest

import helpers
from dryfire import redact, report, replay, transcripts
from dryfire.hookio import ASK, DENY, ERROR, NONE, Outcome
from dryfire.guards import Guard


class CleanTest(unittest.TestCase):
    def setUp(self):
        self.r = redact.Redactor(home="/Users/someone")

    def test_every_fake_secret_kind_is_masked(self):
        for kind in helpers.SECRET_KINDS:
            text = "deploy %s now" % helpers.fake(kind)
            out = self.r.clean(text)
            self.assertNotIn(helpers.secret_core(kind), out, kind)
            self.assertIn("deploy", out)

    def test_references_are_kept(self):
        for text in ("export GH_TOKEN=$GH_TOKEN", "curl -H 'Authorization: Bearer ${TOKEN}'",
                     "mysql -p$DB_PASS", "--password=$(cat f)"):
            self.assertNotIn("hidden", self.r.clean(text), text)

    def test_named_values_tools_and_quoted_phrases(self):
        # Each value is assembled here so no secret-looking string sits in the file whole.
        pw = "Qm7" + "rT2vX"
        aws = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfi" + "CYzQ9kLmN3"
        cases = [
            ("curl -H 'X-Api-Key: %s' https://x.test" % pw, pw),
            ("export MY_SECRET_THING='%s def ghi'" % pw, "def ghi"),
            ('export CLIENT_SECRET="%s two words"' % pw, "two words"),
            ("aws configure set aws_secret_access_key %s" % aws, "K7MDENG"),
            ("gh secret set GITHUB_TOKEN %s" % pw, pw),
            ("sshpass -p %s ssh host" % pw, pw),
            ("sshpass -p%s ssh host" % pw, pw),
            ("docker login -u me -p %s registry.test" % pw, pw),
            ("redis-cli -h db -a %s ping" % pw, pw),
            ("openssl enc -aes-256-cbc -k %s -in f" % pw, pw),
            ("openssl rsa -in k.pem -passin pass:%s" % pw, pw),
            ("htpasswd -b .htpasswd admin %s" % pw, pw),
            ("htpasswd -cb .htpasswd admin %s" % pw, pw),
            ("echo %s" % aws, "K7MDENG"),
        ]
        for text, core in cases:
            out = self.r.clean(text)
            self.assertNotIn(core, out, text)
            self.assertIn("hidden", out, text)

    def test_quoted_values_and_more_password_flags(self):
        pw = "Hu" + "nter2" + "Qx"
        cases = [
            "sshpass -p '%s' ssh h", "docker login -p '%s' registry.test", 'redis-cli -a "%s" ping',
            "curl --user=me:%s x.test", "curl -u :%s x.test", "MYSQL_PWD=%s mysql -u root",
            "ldapsearch -x -D cn=admin -w %s", "zip -P %s out.zip f", "unzip -P %s out.zip",
            "7z x -p%s a.7z", "7z a -p %s a.7z f", "sqlcmd -S db -U sa -P %s", "mongo -u me -p %s",
            "mongosh -u me -p '%s'", "keytool -list -keystore k.jks -storepass %s", "smbclient //h/s -U me%%%s",
            "vault login %s", "mytool --password $'%s more'", "mytool --password '%s'", "mytool --token=\"%s\"",
            "openssl enc -aes-256-cbc -pass pass:%s -in f",
        ]
        for text in cases:
            text = text % pw
            out = self.r.clean(text)
            self.assertNotIn(pw, out, text)
            self.assertNotIn("]]", out, text)
            self.assertEqual(out.count("[hidden"), 1, (text, out))

    def test_every_password_flag_and_attached_form_is_masked(self):
        pw, pw2 = "Hu" + "nter2" + "Qx", "Sw" + "ordf1sh" + "Zq"
        for text in ("keytool -importkeystore -srcstorepass %s -deststorepass %s",
                     "openssl pkcs12 -in a.p12 -passin pass:%s -passout pass:%s",
                     "keytool -genkeypair -alias x -storepass %s -keypass %s"):
            out = self.r.clean(text % (pw, pw2))
            self.assertNotIn(pw, out, text)
            self.assertNotIn(pw2, out, text)
        for text in ("htpasswd -nb admin %s", "htpasswd -nbB admin %s", "htpasswd -b -c .htpasswd admin %s",
                     "ldapwhoami -x -w%s", "unzip -P%s a.zip", "sqlcmd -U sa -P%s", "mongosh -u a -p%s",
                     "smbclient -U 'user%%%s' //h/s", "celery -A app -b redis://:%s@h:6379/0 worker",
                     "psql postgres://:%s@h/db", "curl -uadmin:%s http://x.test", "curl -su admin:%s x.test",
                     "docker login --username u -p%s", "docker login -u u -p=%s r.test",
                     "openssl enc -aes-256-cbc -passout=pass:%s -in f"):
            out = self.r.clean(text % pw)
            self.assertNotIn(pw, out, text)
            self.assertEqual(out.count("[hidden"), 1, (text, out))
        # The second keytool starts inside the first one's 500 characters; its flag lies beyond them.
        out = self.r.clean("keytool -list " + "-v " * 90 + "keytool " + "-v " * 100 + "-storepass %s" % pw)
        self.assertNotIn(pw, out)
        for text in ("htpasswd -b f admin '%s x'", 'htpasswd -nb admin "%s x"', "htpasswd -bBC 10 f admin %s",
                     "htpasswd -b -C 12 -c f admin %s", "htpasswd -nbB -C 8 admin %s", "htpasswd -bB -C10 f u %s",
                     "htpasswd -b -- f u %s", "htpasswd -b f u pa'ss w'%s"):
            out = self.r.clean(text % pw)
            self.assertNotIn(pw, out, text)
            self.assertTrue(out.endswith("[hidden: password]"), (text, out))
        out = self.r.clean("htpasswd -nb admin %s | tee .htpasswd" % pw)
        self.assertNotIn(pw, out)
        self.assertTrue(out.endswith("| tee .htpasswd"), out)

    def test_a_user_password_quoted_after_the_colon_or_around_the_user_is_masked(self):
        pw = "hunter" + "2xy"
        for c in ('curl -u admin:"my %s" https://x', "curl -u admin:$'my %s' https://x",
                  "curl -u 'admin':%s https://x", 'curl -u "admin":%s https://x', 'curl -u "admin:%s" https://x'):
            out = self.r.clean(c % pw)
            self.assertNotIn(pw, out, c)
            self.assertIn("admin", out, c)

    def test_a_password_in_any_shell_quoting_is_masked(self):
        pw = "Wq7" + "zLp4"
        for c in ("curl -u $'admin:%s' x.test", 'curl -u "admin:pa\\"ss %s" x.test',
                  "curl -u 'admin:pa'\"'\"'%s' x.test", "curl -u admin:pa\\ %s x.test", "curl -u admin:${E}%s x.test",
                  'mytool --password $"%s"', 'mytool --password "$X"%s', "mytool --token=$X-%s",
                  "curl -su admin:%s x.test", "curl --user=admin:%s x.test"):
            out = self.r.clean(c % pw)
            self.assertNotIn(pw, out, c)
            self.assertNotIn(pw[3:], out, c)

    def test_text_joined_after_a_command_substitution_is_masked(self):
        pw = "Wq7" + "zLp4"
        for c in ("mytool --password=$(true)%s", "curl -u admin:$(true)%s x.test", 'mytool --password "$(true)%s"',
                  "TOKEN=$(true)%s cmd"):
            out = self.r.clean(c % pw)
            self.assertNotIn(pw[3:], out, c)

    def test_a_parenthesis_in_text_after_a_substitution_does_not_keep_it(self):
        pw = "Wq7" + "zLp4"
        for c in ("mytool --password=$(true)'%s('", 'mytool --password "$(true)%s("', "TOKEN=$(true)'%s(' cmd",
                  "curl -u admin:$(true)'%s(' x.test", "mytool --password=$(true)%s\\("):
            out = self.r.clean(c % pw)
            self.assertNotIn(pw[3:], out, c)

    def test_text_printed_by_any_form_of_echo_or_a_here_string_is_masked(self):
        pw = "Wq7" + "zLp4"
        for c in ("mytool --password $(command echo %s)", "mytool --password $(\\echo %s)",
                  "mytool --password=$( (echo %s) )", "curl -u admin:$(cat <<<%s) x.test"):
            out = self.r.clean(c % pw)
            self.assertNotIn(pw[3:], out, c)

    def test_a_secret_named_value_joined_to_a_reference_is_masked(self):
        pw = "Wq7" + "zLp4"
        for c in ("TOKEN=$(true)'%s' cmd", 'TOKEN="$(true)"%s cmd', "export API_KEY=$P'%s'", "TOKEN=${P}'%s' cmd"):
            out = self.r.clean(c % pw)
            self.assertNotIn(pw[3:], out, c)
        for c in ('TOKEN="$P" cmd', "export API_KEY=$(cat f)", "TOKEN=${P} cmd"):
            self.assertEqual(self.r.clean(c), c)

    def test_a_value_cut_by_the_length_bound_is_masked_to_the_end_of_its_line(self):
        pw = "Wq7" + "zLp4"
        for text in ("TOKEN=" + "x'y'" * 255 + "zz" + "\\ " + pw + " cmd",
                     "TOKEN=" + "a" * 900 + '"' + pw + " " + "b" * 113 + '\\c" cmd',
                     "TOKEN=" + "a" * 900 + "$'" + pw + " " + "b" * 112 + "\\c' cmd"):
            self.assertNotIn(pw[3:], self.r.clean(text))

    def test_a_substitution_that_can_print_its_own_words_is_masked(self):
        pw = "Wq7" + "zLp4"
        for inner in ("/bin/echo %s", "env echo %s", "'echo' %s", '"echo" %s', "e\\cho %s", "eval echo %s",
                      "true; echo %s", ":; echo %s", "\necho %s\n", "cat <<EOF\n%s\nEOF\n", "echo \\\n%s",
                      "true && echo %s", "echo %s | cat"):
            for c in ("TOKEN=$(%s) cmd" % inner, "curl -u admin:$(%s) x.test" % inner, "TOKEN=`%s` cmd" % inner):
                out = self.r.clean(c % pw)
                self.assertNotIn(pw[3:], out, c)

    def test_a_quoted_value_cut_by_the_bound_at_a_space_is_masked(self):
        pw = "Wq7" + "zLp4"
        for q in ('"', "'"):
            for sep in (" ", "\t", ";", "&", "|"):
                c = "TOKEN=" + q + "a" * 1022 + sep + pw + q + " cmd"
                self.assertNotIn(pw, self.r.clean(c), (q, sep))
        self.assertNotIn(pw, self.r.clean("TOKEN=$'" + "a" * 1022 + " " + pw + "' cmd"))

    def test_a_substitution_whose_commands_are_not_plain_names_is_masked(self):
        pw = "Wq7" + "zLp4"
        for inner in ("ech${x}o %s", "e{c,}ho %s", "/bin/ech? %s", "ech$'o' %s", "basename %s", "dirname %s/x",
                      "expr %s", "yes %s | head -1", "cat f | xargs echo %s", "cat f & basename %s"):
            for c in ("TOKEN=$(%s) cmd", "TOKEN=`%s` cmd", "curl -u admin:$(%s) x.test",
                      'mytool --password "$(%s)"'):
                line = c % (inner % pw)
                self.assertNotIn(pw, self.r.clean(line), line)

    def test_substitutions_with_quoted_arguments_or_reading_a_file_are_kept(self):
        for c in ('TOKEN="$(op read "op://v/i/f")" cmd', 'TOKEN="$(cat "$HOME/.tok")" cmd', "TOKEN=$(< f) cmd",
                  "TOKEN=$(cat ~/.config/echo/token) cmd", "TOKEN=$(cat f | head -1) cmd"):
            self.assertEqual(self.r.clean(c), c)

    def test_a_substitution_run_through_another_program_is_masked(self):
        pw = "Wq7" + "zLp4"
        for inner in ("timeout 5 echo %s", "nice echo %s", "stdbuf -oL echo %s", "caffeinate -i echo %s",
                      "busybox echo %s", "dash -c 'echo %s'", "ksh -c 'echo %s'", "fish -c 'echo %s'", "date +%s",
                      "perl -e 'print \"%s\"'", "jq -rn '\"%s\"'", "cat f | jq -r '\"%s\"'",
                      "jq -r --arg x %s .a f"):
            for c in ("TOKEN=$(%s) cmd", "curl -u admin:$(%s) x.test", 'mytool --password "$(%s)"'):
                line = c % (inner % pw)
                self.assertNotIn(pw, self.r.clean(line), line)

    def test_common_fetcher_options_are_kept(self):
        for c in ("TOKEN=$(pass show x | head -n 1) cmd", "TOKEN=$(tail -n 1 f) cmd",
                  "TOKEN=$(kubectl -n prod get secret x -o jsonpath={.data.token}) cmd",
                  "TOKEN=$(op read -n op://v/i/f) cmd", "TOKEN=$(cat ~/.token 2>/dev/null) cmd",
                  "TOKEN=$(kubectl get secret x -n prod -o jsonpath='{.data.token}' | base64 -d) cmd",
                  "TOKEN=$(aws secretsmanager get-secret-value --secret-id prod/db --query SecretString) cmd",
                  "TOKEN=$(cat ~/.token 2>&1) cmd", "TOKEN=$(gh auth token |& head -1) cmd",
                  "TOKEN=$(vault kv get -field=password s/a) cmd"):
            self.assertEqual(self.r.clean(c), c)

    def test_a_secret_given_to_a_fetcher_is_masked(self):
        pw = "Wq7" + "zLp4"
        for inner in ("gpg --batch --passphrase %s -d f", "bw unlock %s --raw",
                      "security add-generic-password -a u -s x -w %s", "kubectl create secret generic x "
                      "--from-literal=k=%s -o name", "gh secret set X --body %s", "doppler secrets set X=%s",
                      "op item create pw=%s", "aws ssm put-parameter --name x --value %s --type SecureString",
                      "security unlock-keychain -p %s login.keychain", "security set-generic-password-partition-list "
                      "-S apple: -k %s", "vault kv patch s/a k=%s", "heroku config:set API=%s",
                      "gh api -X PUT x -f value=%s", "vault token lookup %s", "gh api x -fvalue=%s",
                      "gh api x -Fvalue=%s", "gh api x -ifk=%s", "gh api -XPUT x -fvalue=%s",
                      "gh api --method=PUT x -fk=%s", "gh api --input f --method=PUT x/%s",
                      "gh 'api' -XPUT x -fk=%s", 'gh "api" x -fvalue=%s', "gh api x -Hk:%s"):
            for c in ("TOKEN=$(%s) cmd", "curl -u admin:$(%s) x.test", 'mytool --password "$(%s)"'):
                line = c % (inner % pw)
                self.assertNotIn(pw, self.r.clean(line), line)

    def test_substitutions_that_fetch_a_secret_are_kept(self):
        for c in ("TOKEN=$(gh auth token) cmd", 'TOKEN="$(op read op://v/i/f)" cmd', "TOKEN=`cat f` cmd",
                  "curl -u admin:$(cat f) x.test", "mytool --password $(pass show x)"):
            self.assertEqual(self.r.clean(c), c)

    def test_many_secret_names_in_one_word_are_read_quickly(self):
        import time
        for text in ("TOKEN=$(" * 8000, "a=TOKEN=$(" * 6000):
            started = time.monotonic()
            self.r.clean(text)
            self.assertLess(time.monotonic() - started, 0.6, text[:12])

    def test_a_long_secret_named_value_is_masked_to_its_end(self):
        pw = ("Wq7" + "zLp4") * 1500
        out = self.r.clean("TOKEN=%s cmd" % pw)
        self.assertNotIn(pw[-20:], out)
        self.assertTrue(out.startswith("TOKEN="))

    def test_unclosed_quotes_continued_lines_defaults_and_echoes_are_masked(self):
        pw = "Wq7" + "zLp4"
        for c in ("curl -u 'admin:%s", 'curl -u "admin:%s', "curl -u admin:\\\n%s x.test", "mytool --password '%s",
                  'mytool --password "%s', 'mytool --password "${P:-%s}"', "curl -u admin:$(echo %s) x.test",
                  "mytool --password $(printf %s)", "mytool --password=\"$(echo %s)\""):
            out = self.r.clean(c % pw)
            self.assertNotIn(pw[3:], out, c)

    def test_whole_references_in_a_user_password_are_kept(self):
        for c in ('curl -u "$U:$P" x.test', "curl -u admin:$P x.test", 'curl -u "admin:${P}" x.test',
                  "curl -u admin:$(cat f) x.test", "sort -u names.txt"):
            self.assertEqual(self.r.clean(c), c)

    def test_a_long_quoted_user_password_is_masked_to_its_end(self):
        tail = "LEAK" + "TAIL"
        out = self.r.clean('curl -u "admin:%s%s" https://x' % ("a" * 1005, tail), limit=0)
        self.assertNotIn(tail, out)

    def test_a_value_joining_plain_and_quoted_parts_is_masked_whole(self):
        pw = "Sup3r" + "S3cret"
        for text in ('openssl enc -aes256 -passin pass:"%s" -in a', "openssl pkcs12 -export -passout pass:'%s'",
                     'curl -u "admin:my %s pass" x.test', "curl --user 'admin:my %s' x.test",
                     'curl --user "admin:my %s"', 'mytool --password pa"%s"x', "mytool --token=a$'%s'"):
            self.assertNotIn(pw, self.r.clean(text % pw), text)
        self.assertEqual(self.r.clean('curl -u "admin" x.test'), 'curl -u "admin" x.test')

    def test_password_pointers_are_kept_only_for_openssl(self):
        pw = "file:" + "Qm7rT2"
        for text in ("mysql -p%s db" % pw, "sshpass -p %s ssh h" % pw, "redis-cli -a env:%s" % pw[5:]):
            self.assertIn("hidden", self.r.clean(text), text)
        self.assertNotIn("hidden", self.r.clean("openssl enc -passin %s -in a" % pw))
        for text in ("openssl enc -k %s -in a" % pw, "openssl enc -k env:Qm7rT2 -in a", "openssl enc -k stdin"):
            self.assertIn("hidden", self.r.clean(text), text)

    def test_ordinary_flags_named_like_secrets_are_kept(self):
        for text in ('git commit --author="Jane Doe" -m fix', "git log --author=alice",
                     "pip install tokenizers==0.15.2", "docker run -d --name mongo -p 27017:27017 mongo:7",
                     "sudo -u root ls", "openssl x509 -in a.pem -passin env:PW -noout", "htpasswd -v f u"):
            self.assertNotIn("hidden", self.r.clean(text), text)

    def test_names_inside_other_words_and_dotted_names(self):
        pw = "Qm7" + "rT2vX9"
        for text in ("curl --header=api_key:%s x.test" % pw, "config.api_key=%s" % pw, "a=GH_TOKEN=%s" % pw):
            self.assertNotIn(pw, self.r.clean(text), text)
        self.assertEqual(self.r.clean("grep -n x api_key.txt: found it"), "grep -n x api_key.txt: found it")

    def test_masking_is_fast_on_hostile_input(self):
        # Each line repeats what one rule looks for, so a rule that rescans the line per hit shows up here.
        import time
        for piece in ("api_key_", "a_", "ab-", "x", "a/", "A-b.", "MY_SECRET=", "GH_TOKEN ", "a.api_key ",
                      "api_key=\"", "api_key='", "sshpass ", "docker login ", "mysql ", "openssl ", "redis-cli ",
                      "htpasswd -b ", "a://b:", "-u x:", "authorization: ", "bearer ", "--password ", "\x1b[",
                      "htpasswd -b -C1 ", "htpasswd -b f u 'a", "-su ", "-uu", "docker login -p", "openssl -passin=",
                      "(?x)"):
            text = piece * (60000 // len(piece))
            started = time.monotonic()
            self.r.clean(text, limit=0)
            self.assertLess(time.monotonic() - started, 1.0, repr(piece))
        # A client name cut short by a separator, over and over: each must not rescan the rest of the line.
        for piece in ("mongo;", "keytool;", "zip|", "smbclient&", "sshpass\n", "mysql -p;"):
            text = piece * (120000 // len(piece))
            started = time.monotonic()
            self.r.clean(text, limit=0, oneline=False)
            self.assertLess(time.monotonic() - started, 1.0, repr(piece))
        for text in ("Authorization:" + " " * 60000 + "x", ("Authorization:" + " " * 3000 + "x ") * 20,
                     "bearer" + " " * 60000 + "x", "-u" + " " * 60000 + "x", "--password" + " " * 60000 + "x",
                     " -" + "u" * 60000, " -s" + "u" * 60000 + " x"):
            started = time.monotonic()
            self.r.clean(text, limit=0)
            self.assertLess(time.monotonic() - started, 1.0, repr(text[:20]))

    def test_prose_and_paths_with_secret_words_are_kept(self):
        for text in ("git commit -m 'fix password reset flow'", "grep -r api_key src/",
                     "ls frontend/components/LoginForm2/PasswordField.vue",
                     "cat /Users/someone/Sites/app/node_modules/pkg/dist/index.js",
                     "docker login registry.test", "redis-cli -a $REDIS_PASS ping"):
            self.assertNotIn("hidden", self.r.clean(text), text)

    def test_ordinary_long_words_are_kept(self):
        for text in ("git checkout feature/very-long-branch-name-for-something", "sha 3f2a9c0e" + "1" * 32):
            self.assertNotIn("hidden", self.r.clean(text), text)

    def test_slow_pattern_shapes(self):
        for p in ("(a+)+", "(a*)*b", "(?:x|xy)+", "((ab)+)+", "(a{2,})*", "(?:[a-z]+\\.)+com", "a*a*a*b",
                  "\\w+\\s+\\w*x+", "(a?){25}a{25}", "((ab)?){10}", "(a?b?)+",
                  "[ab]{1,200}[ab]{1,200}[ab]{1,200}c", "a{0,99}a{0,99}a{0,99}a{0,99}c", "a?a?a?a?a?aaaaa",
                  "(?x)(a+) +c", "(?x) (a+) + c", "(?ix:(a+) +)c", "(?x)(a+)#c\n+c",
                  "(a+)(?#c)+b", "(a|a)(?#)*b"):
            self.assertTrue(redact.slow_pattern(p), p)
        for p in ("tok_[A-Za-z0-9]{20}", "(abc)+", "\\(a+\\)+", "[(a+)]+", "(?:ab)?c+", "(x|y)", "a{3}b{1,2}",
                  "(\\d{3})-\\d+", "(?i)tok_[a-z]{20}", "\\(?x\\)(a+)"):
            self.assertFalse(redact.slow_pattern(p), p)

    def test_custom_patterns_see_only_what_the_report_shows(self):
        import time
        r = redact.Redactor(home="/h", patterns=["a+b"])  # Seconds on 100,000 characters, nothing on 556.
        started = time.monotonic()
        self.assertTrue(r.clean("a" * 100000).endswith("(+99700 chars)"))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_home_becomes_tilde_but_not_a_longer_name(self):
        self.assertEqual(self.r.clean("cat /Users/someone/a"), "cat ~/a")
        self.assertEqual(self.r.clean("cat /Users/someoneelse/a"), "cat /Users/someoneelse/a")

    def test_home_kept_when_asked(self):
        self.assertIn("/Users/someone", redact.Redactor("/Users/someone", redact_home=False).clean("/Users/someone/a"))

    def test_control_bidi_and_ansi_removed(self):
        out = self.r.clean("a\x1b[31mred\x1b[0m\u202eb\x07c\nd")
        self.assertEqual(out, "ared bc ⏎ d".replace(" bc", "bc"))

    def test_cap(self):
        out = self.r.clean("x" * 50, limit=10)
        self.assertTrue(out.startswith("x" * 10) and "+40 chars" in out)

    def test_custom_patterns_and_bad_pattern(self):
        r = redact.Redactor(patterns=[r"acme-\d+", "("])
        self.assertEqual(r.clean("id acme-42"), "id [hidden: custom pattern]")
        self.assertEqual(len(r.errors), 1)


class StubGuard(Guard):
    def __init__(self, name, decide):
        Guard.__init__(self, name)
        self.decide = decide

    def evaluate(self, tool, tool_input, mode):
        return self.decide(tool_input.get("command", ""))


def calls_for(commands):
    out = []
    for i, c in enumerate(commands):
        out.append(transcripts.Call("id%d" % i, "Bash", {"command": c},
                                    transcripts.parse_ts("2026-11-2%dT10:00:00Z" % (i % 3)), "/Users/someone/w", "s",
                                    "default", "/p"))
    return out


RUN = {"since": "2026-11-01", "until": "2026-11-25", "window_days": 24, "sandbox_text": "none",
       "permission_mode": "default", "notes": [], "skipped_distinct": 0, "skipped_calls": 0,
       "reader": {"files": 1, "files_skipped_old": 0}}


def summarize(commands, guards_list):
    uniques = list(replay.collect(calls_for(commands)).values())
    results = replay.run(guards_list, uniques)
    return report.build(dict(RUN), guards_list, uniques, results, redact.Redactor("/Users/someone"))


class ReportTest(unittest.TestCase):
    def test_headline_counts_every_occurrence(self):
        g = StubGuard("pack", lambda c: Outcome(DENY, "no rm") if c.startswith("rm") else Outcome(NONE))
        s = summarize(["rm -rf a", "rm -rf a", "ls", "ls", "ls"], [g])
        self.assertEqual(report.headline(s, s["guards"][0]),
                         "pack would have blocked 2 of 5 of your commands (40.0%)")
        self.assertEqual(s["distinct_calls"], 2)

    def test_headline_says_how_often_the_hook_failed(self):
        g = StubGuard("hook", lambda c: Outcome(ERROR, "", detail="timed out") if c == "ls" else Outcome(NONE))
        s = summarize(["rm a", "ls", "ls", "pwd"], [g])
        self.assertEqual(report.headline(s, s["guards"][0]),
                         "hook would have blocked 0 of 4 of your commands (0.0%), but it failed or timed out on 2")
        self.assertIn("failed or timed out on 2 of the 4 calls it saw (50.0%)", report.markdown(s))
        s = summarize(["rm a"] * 19 + ["ls"], [g])  # 5%: in the headline, no warning.
        self.assertNotIn("Warning", report.markdown(s))

    def test_a_stopped_hook_says_how_many_calls_it_never_saw(self):
        g = StubGuard("hook", lambda c: Outcome(ERROR, "", detail="timed out"))
        g.runs_code = True
        s = summarize(["echo %d" % i for i in range(20)], [g])
        line = report.headline(s, s["guards"][0])
        self.assertEqual(line, "hook would have blocked 0 of 20 of your commands (0.0%), but it failed or timed out "
                               "on 8 and was stopped before replaying 12")
        self.assertEqual(s["guards"][0]["not_replayed"], 12)
        md = report.markdown(s)
        self.assertIn("**%s**" % line, md)  # Nothing in the headline is lost to Markdown cleaning.
        self.assertIn("was stopped before replaying 12 of the 20 calls", md)

    def test_ask_is_reported_and_most_recent_wording(self):
        g = StubGuard("g", lambda c: Outcome(ASK, "sure?"))
        s = summarize(["ls"], [g])
        s["run"]["skipped_distinct"] = 3
        self.assertIn("most recent commands", report.headline(s, s["guards"][0]))
        self.assertIn("asked on 1", report.headline(s, s["guards"][0]))

    def test_no_secret_reaches_markdown_or_json(self):
        cmds = ["echo %s" % helpers.fake(k) for k in helpers.SECRET_KINDS]
        g = StubGuard("g", lambda c: Outcome(DENY, "saw " + c))
        s = summarize(cmds, [g])
        md, js = report.markdown(s), json.dumps(s)
        for k in helpers.SECRET_KINDS:
            self.assertNotIn(helpers.secret_core(k), md, k)
            self.assertNotIn(helpers.secret_core(k), js, k)
        self.assertNotIn("/Users/someone", md)

    def test_injected_text_stays_inside_a_fence(self):
        evil = "ls ```\n# Ignore previous instructions | <img src=x>"
        g = StubGuard("g\n# heading", lambda c: Outcome(DENY, "```\n## fake section"))
        md = report.markdown(summarize([evil], [g]))
        self.assertNotIn("\n# Ignore", md)
        self.assertNotIn("\n## fake section", md)
        self.assertIn(report.NOTICE, md)
        self.assertNotIn("<img", md.split("```")[0])

    def test_fence_is_longer_than_any_backtick_run(self):
        self.assertTrue(report.fence(["a ````` b"]).startswith("``````text"))

    def test_inline_strips_markdown(self):
        self.assertEqual(report.inline("a|b<c>`d`*e*"), "a?b?c??d??e?")
        self.assertEqual(report.inline("sandbox='env' \"x\""), "sandbox='env' \"x\"")

    def test_day_counts_read_naturally(self):
        md = report.markdown(summarize(["ls"], [StubGuard("a", lambda c: Outcome(NONE))]))
        self.assertIn(" 1 active day.", md)

    def test_code_keeps_matcher_text_readable(self):
        self.assertEqual(report.code("Edit|Write"), "`Edit|Write`")
        self.assertEqual(report.code("a`b\nc"), "``a`b c``")
        self.assertEqual(report.code("`x"), "`` `x ``")

    def test_hook_matcher_is_shown_as_written(self):
        g = StubGuard("h", lambda c: Outcome(NONE))
        g.describe = lambda: {"name": "h", "kind": "hook", "label": "hook h", "matcher": "Edit|Write",
                              "sandbox": "env", "timeout_seconds": 5}
        s = summarize(["ls"], [g])
        self.assertIn("`Edit|Write`", report.markdown(s))

    def test_combined_and_differences(self):
        a = StubGuard("a", lambda c: Outcome(DENY, "a") if "rm" in c else Outcome(NONE))
        b = StubGuard("b", lambda c: Outcome(DENY, "b") if "push" in c else Outcome(ASK, "b?"))
        s = summarize(["rm x", "git push", "ls"], [a, b])
        self.assertEqual(s["combined"]["counts"][DENY], 2)
        self.assertEqual(s["combined"]["counts"][ASK], 1)
        d = s["differences"][0]
        self.assertEqual((d["only_a_blocks"], d["only_b_blocks"]), (1, 1))
        self.assertIn("Where the guards disagree", report.markdown(s))


if __name__ == "__main__":
    unittest.main()
