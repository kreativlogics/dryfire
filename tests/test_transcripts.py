import datetime
import json
import os
import time
import unittest

import helpers
from dryfire import transcripts

UTC = datetime.timezone.utc


def ts(text):
    return transcripts.parse_ts(text)


class ReaderTest(unittest.TestCase):
    def setUp(self):
        self.t = helpers.Transcripts()

    def tearDown(self):
        self.t.close()

    def read(self, **kw):
        stats = transcripts.Stats()
        calls = list(transcripts.read_calls([self.t.projects], stats=stats, **kw))
        return calls, stats

    def test_reads_tool_use_blocks_with_their_context(self):
        self.t.write([self.t.user("acceptEdits"), self.t.bash("git status", cwd="/w/app")])
        calls, stats = self.read()
        self.assertEqual(len(calls), 1)
        c = calls[0]
        self.assertEqual((c.tool, c.input["command"], c.cwd, c.mode), ("Bash", "git status", "/w/app", "acceptEdits"))
        self.assertEqual(c.day, "2026-11-20")
        self.assertEqual(stats.files, 1)

    def test_same_tool_use_id_counts_once(self):
        rec = self.t.bash("ls", tid="toolu_same")
        self.t.write([rec, rec])
        self.t.write([rec], session="s2")
        calls, stats = self.read()
        self.assertEqual(len(calls), 1)
        self.assertEqual(stats.duplicates, 2)

    def test_several_tool_uses_in_one_message(self):
        extra = {"type": "tool_use", "id": "toolu_a", "name": "Read", "input": {"file_path": "/x"}}
        self.t.write([self.t.bash("pwd", extra_blocks=[extra, {"type": "text", "text": "hi"}])])
        calls, _ = self.read()
        self.assertEqual(sorted(c.tool for c in calls), ["Bash", "Read"])

    def test_window_by_call_timestamp(self):
        self.t.write([self.t.bash("old", ts="2026-01-01T00:00:00Z"), self.t.bash("new", ts="2026-11-20T00:00:00Z")])
        calls, stats = self.read(since=ts("2026-11-01T00:00:00Z"), until=ts("2026-11-25T00:00:00Z"))
        self.assertEqual([c.input["command"] for c in calls], ["new"])
        self.assertEqual(stats.out_of_window, 1)

    def test_files_older_than_window_are_not_opened(self):
        path = self.t.write([self.t.bash("ls")])
        old = time.time() - 90 * 86400
        os.utime(path, (old, old))
        calls, stats = self.read(since=datetime.datetime.now(UTC) - datetime.timedelta(days=30))
        self.assertEqual(calls, [])
        self.assertEqual(stats.files_skipped_old, 1)

    def test_partial_last_line_is_skipped_and_counted(self):
        self.t.write([self.t.bash("ok")], raw_tail=b'{"type": "assistant", "message": {"content": [{"type": "tool_u')
        calls, stats = self.read()
        self.assertEqual(len(calls), 1)
        self.assertEqual(stats.partial_lines, 1)

    def test_bad_json_line_is_counted_not_fatal(self):
        self.t.write(['{"type": "assistant", "tool_use" nope', self.t.bash("ok")])
        calls, stats = self.read()
        self.assertEqual(len(calls), 1)
        self.assertEqual(stats.bad_lines, 1)

    def test_subagent_transcripts_are_included(self):
        self.t.write([self.t.bash("main")])
        self.t.write([self.t.bash("inner")], session="agent-1", sub=os.path.join("s1", "subagents"))
        calls, _ = self.read()
        self.assertEqual(sorted(c.input["command"] for c in calls), ["inner", "main"])

    def test_symlinked_file_is_not_followed(self):
        outside = os.path.join(self.t.root, "outside.jsonl")
        with open(outside, "w") as fh:
            fh.write(json.dumps(self.t.bash("secret elsewhere")) + "\n")
        folder = os.path.join(self.t.projects, "p")
        os.makedirs(folder)
        os.symlink(outside, os.path.join(folder, "link.jsonl"))
        calls, stats = self.read()
        self.assertEqual(calls, [])
        self.assertEqual(stats.files_outside_root, 1)

    def test_symlinked_folder_is_not_walked(self):
        other = os.path.join(self.t.root, "other")
        os.makedirs(other)
        with open(os.path.join(other, "x.jsonl"), "w") as fh:
            fh.write(json.dumps(self.t.bash("elsewhere")) + "\n")
        os.symlink(other, os.path.join(self.t.projects, "linked"))
        calls, _ = self.read()
        self.assertEqual(calls, [])

    def test_project_scope_keeps_calls_made_in_or_below_the_project(self):
        p = self.t.project_dir
        self.t.write([self.t.bash("in", cwd=p), self.t.bash("below", cwd=p + "/src"),
                      self.t.bash("sibling", cwd=p + "-other"), self.t.bash("away", cwd="/elsewhere")])
        calls, stats = self.read(project_dir=p)
        self.assertEqual(sorted(c.input["command"] for c in calls), ["below", "in"])
        self.assertEqual(stats.out_of_scope, 2)

    def test_oversized_input_is_skipped(self):
        self.t.write([self.t.bash("x" * 5000), self.t.bash("small")])
        calls, stats = self.read(max_input=1000)
        self.assertEqual([c.input["command"] for c in calls], ["small"])
        self.assertEqual(stats.oversized, 1)

    def test_accept_tool_filters_before_window(self):
        self.t.write([self.t.call("Read", {"file_path": "/a"}), self.t.bash("ls")])
        calls, stats = self.read(accept_tool=lambda t: t == "Bash")
        self.assertEqual([c.tool for c in calls], ["Bash"])
        self.assertEqual(stats.not_matched, 1)

    def test_permission_mode_follows_the_latest_user_record(self):
        self.t.write([self.t.user("plan"), self.t.bash("a"), self.t.user("bypassPermissions"), self.t.bash("b")])
        calls, _ = self.read()
        self.assertEqual([c.mode for c in calls], ["plan", "bypassPermissions"])

    def test_user_records_with_tool_use_text_are_not_calls(self):
        self.t.write([{"type": "user", "message": {"content": [{"type": "tool_use", "id": "x", "name": "Bash",
                                                                "input": {"command": "rm -rf /"}}]}}])
        calls, _ = self.read()
        self.assertEqual(calls, [])

    def test_reader_never_writes_into_transcript_folders(self):
        path = self.t.write([self.t.bash("ls")])
        before = (os.stat(path).st_mtime, sorted(os.listdir(os.path.dirname(path))))
        self.read()
        self.assertEqual(before, (os.stat(path).st_mtime, sorted(os.listdir(os.path.dirname(path)))))


class TimestampTest(unittest.TestCase):
    def test_z_suffix_and_odd_fraction_lengths(self):
        for text in ("2026-11-20T10:00:00Z", "2026-11-20T10:00:00.1Z", "2026-11-20T10:00:00.12345Z",
                     "2026-11-20T10:00:00.123456789Z", "2026-11-20T10:00:00+00:00"):
            dt = transcripts.parse_ts(text)
            self.assertIsNotNone(dt, text)
            self.assertEqual(dt.tzinfo, UTC)

    def test_garbage_is_none(self):
        for text in (None, "", "yesterday", 12, "2026-13-45T00:00:00Z"):
            self.assertIsNone(transcripts.parse_ts(text))

    def test_offsets_convert_to_utc(self):
        self.assertEqual(transcripts.parse_ts("2026-11-20T01:00:00-07:00").hour, 8)


class RootsTest(unittest.TestCase):
    def test_config_dir_and_home_both_used_and_deduplicated(self):
        t = helpers.Transcripts()
        try:
            alt = os.path.join(t.root, "alt")
            os.makedirs(os.path.join(alt, "projects"))
            roots = transcripts.default_roots(t.home, {"CLAUDE_CONFIG_DIR": alt})
            self.assertEqual(roots, [os.path.join(alt, "projects"), t.projects])
            same = transcripts.default_roots(t.home, {"CLAUDE_CONFIG_DIR": os.path.join(t.home, ".claude")})
            self.assertEqual(len(same), 1)
        finally:
            t.close()

    def test_encode_project_matches_claude_code_folder_names(self):
        self.assertEqual(transcripts.encode_project("/Users/a.b/my_app"), "-Users-a-b-my-app")


if __name__ == "__main__":
    unittest.main()
