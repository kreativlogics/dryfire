import json
import unittest

import helpers  # noqa: F401
from dryfire import hookio
from dryfire.hookio import ALLOW, ASK, DEFER, DENY, ERROR, NONE, Outcome


def j(**kw):
    return json.dumps(kw)


def hso(decision, reason="r", **extra):
    d = {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}
    d.update(extra)
    return json.dumps({"hookSpecificOutput": d})


class InterpretTest(unittest.TestCase):
    def test_exit_2_blocks_with_stderr_as_reason(self):
        o = hookio.interpret(2, "", "no force push\n")
        self.assertEqual((o.decision, o.reason), (DENY, "no force push"))

    def test_exit_2_json_reason_wins_over_stderr(self):
        o = hookio.interpret(2, hso("deny", "from json"), "from stderr")
        self.assertEqual((o.decision, o.reason), (DENY, "from json"))

    def test_exit_2_json_allow_does_not_unblock(self):
        self.assertEqual(hookio.interpret(2, hso("allow"), "").decision, DENY)

    def test_exit_0_json_decisions(self):
        for d in (DENY, ASK, ALLOW, DEFER):
            self.assertEqual(hookio.interpret(0, hso(d), "").decision, d)

    def test_json_object_on_other_exit_code_decides(self):
        self.assertEqual(hookio.interpret(1, hso("ask"), "").decision, ASK)

    def test_legacy_decision_field(self):
        self.assertEqual(hookio.interpret(0, j(decision="block", reason="old"), "").decision, DENY)
        self.assertEqual(hookio.interpret(0, j(decision="approve"), "").decision, ALLOW)

    def test_updated_input_marks_modified(self):
        o = hookio.interpret(0, hso("allow", updatedInput={"command": "ls"}), "")
        self.assertTrue(o.modified)

    def test_continue_false_does_not_block(self):
        o = hookio.interpret(0, j(**{"continue": False, "stopReason": "stop"}), "")
        self.assertNotEqual(o.decision, DENY)
        self.assertTrue(o.stopped)

    def test_exit_0_plain_text_is_no_decision(self):
        self.assertEqual(hookio.interpret(0, "all good\n", "").decision, NONE)

    def test_other_exit_code_plain_output_is_a_non_blocking_error(self):
        o = hookio.interpret(1, "", "boom")
        self.assertEqual(o.decision, ERROR)
        self.assertIn("1", o.detail)

    def test_broken_json_is_an_error(self):
        self.assertEqual(hookio.interpret(0, '{"hookSpecificOutput": ', "").decision, ERROR)

    def test_timeout_and_start_failure_are_errors(self):
        self.assertEqual(hookio.interpret(None, "", "", timed_out=True).decision, ERROR)
        self.assertEqual(hookio.interpret(None, "", "", start_error="No such file").decision, ERROR)

    def test_on_failure_block_turns_errors_into_deny(self):
        self.assertEqual(hookio.interpret(None, "", "", timed_out=True, on_failure=True).decision, DENY)
        self.assertEqual(hookio.interpret(1, "", "x", on_failure=True).decision, DENY)
        self.assertEqual(hookio.interpret(0, "", "", on_failure=True).decision, NONE)

    def test_unknown_permission_decision_is_an_error(self):
        self.assertEqual(hookio.interpret(0, hso("maybe"), "").decision, ERROR)


class MergeTest(unittest.TestCase):
    def test_deny_beats_defer_beats_ask_beats_allow(self):
        m = hookio.merge
        self.assertEqual(m([Outcome(ALLOW), Outcome(ASK), Outcome(DENY)]).decision, DENY)
        self.assertEqual(m([Outcome(ALLOW), Outcome(DEFER), Outcome(ASK)]).decision, DEFER)
        self.assertEqual(m([Outcome(ALLOW), Outcome(ASK)]).decision, ASK)
        self.assertEqual(m([Outcome(NONE), Outcome(ALLOW)]).decision, ALLOW)
        self.assertEqual(m([Outcome(NONE), Outcome(ERROR)]).decision, NONE)

    def test_payload_shape(self):
        p = hookio.payload("Bash", {"command": "ls"}, "/w", "/t.jsonl", None, "s", "id")
        self.assertEqual(p["hook_event_name"], "PreToolUse")
        self.assertEqual(p["permission_mode"], "default")
        self.assertEqual(p["tool_input"], {"command": "ls"})


if __name__ == "__main__":
    unittest.main()
