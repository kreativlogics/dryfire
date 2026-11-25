import os
import sys
import threading
import time
import unittest

import helpers
from dryfire import replay, sandbox, transcripts
from dryfire.guards import Guard, HookGuard, HookSpec
from dryfire.hookio import ERROR, NONE, Outcome


class SlowGuard(Guard):
    """Runs code like a hook: each call takes `delay` seconds, and `first` decides the first call."""

    runs_code = True

    def __init__(self, delay=0.0, outcome=None, first=None):
        Guard.__init__(self, "slow")
        self.label = "slow"
        self.delay = delay
        self.outcome = outcome or Outcome(NONE)
        self.first = first
        self.calls = 0
        self.lock = threading.Lock()

    def evaluate(self, tool, tool_input, mode):
        with self.lock:
            self.calls += 1
            n = self.calls
        if n == 1 and self.first:
            return self.first()
        time.sleep(self.delay)
        return self.outcome


def uniques(n):
    calls = [transcripts.Call("id%d" % i, "Bash", {"command": "echo %d" % i},
                              transcripts.parse_ts("2026-11-20T10:00:00Z"), "/w", "s", "default", "/p")
             for i in range(n)]
    return list(replay.collect(calls).values())


def interrupt():
    raise KeyboardInterrupt


class RunTest(unittest.TestCase):
    def test_interrupt_does_not_wait_for_the_queued_calls(self):
        # 40 calls of 1 s on 4 workers would take 10 s if the queue were drained after Ctrl-C.
        g = SlowGuard(delay=1.0, first=interrupt)
        started = time.monotonic()
        with self.assertRaises(KeyboardInterrupt):
            replay.run([g], uniques(40), workers=4)
        self.assertLess(time.monotonic() - started, 4.0)
        self.assertLess(g.calls, 12)

    def test_a_hook_that_keeps_timing_out_is_stopped(self):
        g = SlowGuard(outcome=Outcome(ERROR, "", detail="timed out"))
        results = replay.run([g], uniques(30), workers=1)
        self.assertEqual(len(results["slow"]), replay.STOP_AFTER_TIMEOUTS)
        self.assertTrue(any("timed out" in n and "not replayed" in n for n in g.notes), g.notes)

    def test_one_answer_resets_the_streak(self):
        answers = [Outcome(ERROR, "", detail="timed out")] * 5 + [Outcome(NONE)]
        g = SlowGuard()
        g.evaluate = lambda tool, tool_input, mode: answers[int(tool_input["command"].split()[1]) % 6]
        results = replay.run([g], uniques(30), workers=1)
        self.assertEqual(len(results["slow"]), 30)
        self.assertEqual(g.notes, [])


# A hook that starts a process in a new session, which leaves the hook's process group.
DAEMON = ("import os, time\n"
          "if os.fork() == 0:\n"
          "    os.setsid()\n"
          "    fd = os.open(os.devnull, os.O_RDWR)\n"
          "    for n in (0, 1, 2):\n"
          "        os.dup2(fd, n)\n"
          "    time.sleep(1.5)\n"
          "    open(%r, 'w').close()\n"
          "    os._exit(0)\n")


def calls_of(commands):
    return [transcripts.Call("id%d" % i, "Bash", {"command": c},
                             transcripts.parse_ts("2026-11-2%dT10:00:00Z" % (i % 9)), "/w", "s", "default", "/p")
            for i, c in enumerate(commands)]


class TwoReadTest(unittest.TestCase):
    def test_first_read_keeps_no_inputs(self):
        uniques = replay.collect(calls_of(["ls", "ls", "pwd"]), keep_inputs=False)
        self.assertEqual(sorted(u.count for u in uniques.values()), [1, 2])
        self.assertTrue(all(u.input is None for u in uniques.values()))

    def test_second_read_fills_only_the_kept_calls(self):
        commands = ["echo %d" % i for i in range(5)]
        uniques = replay.collect(calls_of(commands), keep_inputs=False)
        kept, _, _ = replay.select(uniques, 2)
        missing = replay.fill_inputs(kept, calls_of(commands))
        self.assertEqual(missing, [])
        self.assertEqual(sorted(u.input["command"] for u in kept), ["echo 3", "echo 4"])
        self.assertEqual(sum(u.input is not None for u in uniques.values()), 2)

    def test_a_call_gone_by_the_second_read_is_reported_missing(self):
        uniques = replay.collect(calls_of(["ls", "pwd"]), keep_inputs=False)
        kept, _, _ = replay.select(uniques, 0)
        missing = replay.fill_inputs(kept, calls_of(["ls"]))
        self.assertEqual(len(missing), 1)


class LeftoverProcessTest(helpers.TempCase):
    def test_a_process_that_left_the_group_is_ended_and_reported(self):
        marker = os.path.join(self.t.root, "daemon-alive")
        spec = HookSpec(command=helpers.py_hook(DAEMON % marker), matcher="Bash")
        g = HookGuard("h", spec, self.t.home, timeout=10, sandbox_mode="env")
        replay.run([g], uniques(1), workers=1)
        time.sleep(2.5)
        self.assertFalse(os.path.exists(marker), "a process the hook started outlived the replay")
        self.assertTrue(any("left 1 process running" in n for n in g.notes), g.notes)

    def test_sweep_leaves_other_processes_alone(self):
        self.assertEqual(sandbox.sweep(), 0)


class SandboxStopTest(unittest.TestCase):
    def tearDown(self):
        sandbox.STOP.clear()

    def test_stop_ends_a_running_hook_at_once(self):
        timer = threading.Timer(0.3, sandbox.STOP.set)
        timer.start()
        started = time.monotonic()
        res = sandbox.run([sys.executable, "-c", "import time; time.sleep(30)"], b"", None, "/", 20)
        timer.cancel()
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertTrue(res.timed_out)


if __name__ == "__main__":
    unittest.main()
