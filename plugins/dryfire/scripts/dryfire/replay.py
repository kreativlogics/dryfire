"""Replay past calls through guards and keep the decisions.

Identical calls (same tool and input, and the same permission mode when
modes are replayed as recorded) are judged once and counted as often as
they happened, so the headline counts what you actually ran.
"""

import concurrent.futures
import hashlib
import json
import sys
import time

from . import sandbox
from .hookio import ERROR, Outcome


class Unique(object):
    """One distinct call and every time it happened."""

    __slots__ = ("key", "tool", "input", "mode", "count", "days", "projects", "first", "last")

    def __init__(self, key, tool, tool_input, mode):
        self.key = key
        self.tool = tool
        self.input = tool_input
        self.mode = mode
        self.count = 0
        self.days = {}
        self.projects = {}
        self.first = None
        self.last = None

    def add(self, call):
        self.count += 1
        day = call.day
        if day:
            self.days[day] = self.days.get(day, 0) + 1
        place = call.cwd or call.project or "?"
        self.projects[place] = self.projects.get(place, 0) + 1
        if call.ts is not None:
            if self.first is None or call.ts < self.first:
                self.first = call.ts
            if self.last is None or call.ts > self.last:
                self.last = call.ts


def key_of(tool, tool_input, mode=None):
    blob = json.dumps([tool, tool_input, mode], sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def collect(calls, permission_mode="default", keep_inputs=True):
    """Group calls into Unique; permission_mode 'as-recorded' keeps each call's own mode.

    With keep_inputs False only keys and counts are kept, so a long history costs little memory;
    fill_inputs then reads the inputs of the calls that select() kept.
    """
    uniques = {}
    for call in calls:
        mode, k = _mode_and_key(call, permission_mode)
        u = uniques.get(k)
        if u is None:
            u = uniques[k] = Unique(k, call.tool, call.input if keep_inputs else None, mode)
        u.add(call)
    return uniques


def fill_inputs(kept, calls, permission_mode="default"):
    """Give each kept call without an input its input from a second read; returns the ones not found."""
    want = {u.key: u for u in kept if u.input is None}
    for call in calls:
        if not want:
            break
        u = want.pop(_mode_and_key(call, permission_mode)[1], None)
        if u is not None:
            u.input = call.input
    return list(want.values())


def _mode_and_key(call, permission_mode):
    if permission_mode == "as-recorded":
        mode = call.mode or "default"
        return mode, key_of(call.tool, call.input, mode)
    return permission_mode, key_of(call.tool, call.input, None)


def select(uniques, max_calls):
    """Keep at most max_calls distinct calls, the most recently used first."""
    items = sorted(uniques.values(), key=lambda u: (u.last.timestamp() if u.last else 0.0, u.count), reverse=True)
    if not max_calls or len(items) <= max_calls:
        return items, 0, 0
    kept, dropped = items[:max_calls], items[max_calls:]
    return kept, len(dropped), sum(u.count for u in dropped)


def _folders(unique):
    """The absolute folders a distinct call was made from (for path patterns in a hook's 'if')."""
    return [p for p in unique.projects if p.startswith("/")]


# A hook that times out on this many calls in a row, or fails on this many, is stopped: replaying the
# rest would take timeout x calls / workers and tell you nothing new.
STOP_AFTER_TIMEOUTS = 8
STOP_AFTER_ERRORS = 50


def run(guards, uniques, workers=4, progress=None):
    """{guard name: {unique key: Outcome}} for the calls each guard accepts."""
    sandbox.STOP.clear()
    results = {}
    for g in guards:
        todo = [u for u in uniques if g.accepts(u.tool, u.input, _folders(u))]
        if not g.runs_code:
            results[g.name] = {u.key: _safe_eval(g, u) for u in todo}
            continue
        results[g.name] = _run_code(g, todo, workers, progress)
    return results


def _run_code(g, todo, workers, progress):
    out = {}
    started = last_note = time.monotonic()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = {pool.submit(_safe_eval, g, u): u for u in todo}
        streak = _Streak()
        for fut in concurrent.futures.as_completed(futures):
            outcome = fut.result()
            out[futures[fut].key] = outcome
            stop = streak.add(outcome)
            if stop:
                for f in futures:
                    f.cancel()
                g.not_replayed = {u.key for u in todo if u.key not in out}
                g.notes.append("stopped after %s in a row; %d of %d distinct calls were not replayed" % (
                    stop, len(todo) - len(out), len(todo)))
                break
            now = time.monotonic()
            if progress and now - last_note >= 5:
                last_note = now
                progress("%s: %d of %d distinct calls replayed (%.0f s)" % (g.label, len(out), len(todo),
                                                                           now - started))
    except BaseException:
        # Ctrl-C: drop the queue and end the hooks already running instead of waiting for them.
        sandbox.STOP.set()
        pool.shutdown(wait=False, cancel_futures=True)
        sandbox.sweep()
        raise
    pool.shutdown(wait=True)
    left = sandbox.sweep()
    if left:
        g.notes.append("it left %s running after its calls (in a new session, outside the hook's process "
                       "group); dryfire ended %s" % (_count(left, "process", "processes"),
                                                     "it" if left == 1 else "them"))
    if progress and todo:
        progress("%s: %d distinct calls replayed in %.1f s" % (g.label, len(out), time.monotonic() - started))
    return out


def _count(n, one, many):
    return "%d %s" % (n, one if n == 1 else many)


class _Streak(object):
    """Counts timeouts and failures in a row; any other answer starts the count again."""

    def __init__(self):
        self.timeouts = self.errors = 0

    def add(self, outcome):
        failed = outcome.decision == ERROR
        timed_out = failed and outcome.detail == "timed out"
        self.timeouts = self.timeouts + 1 if timed_out else 0
        self.errors = self.errors + 1 if failed else 0
        if self.timeouts >= STOP_AFTER_TIMEOUTS:
            return "%d calls that timed out" % self.timeouts
        if self.errors >= STOP_AFTER_ERRORS:
            return "%d calls that failed" % self.errors
        return ""


def _safe_eval(guard, unique):
    try:
        return guard.evaluate(unique.tool, unique.input, unique.mode)
    except Exception as exc:  # A broken guard must not stop the whole replay.
        return Outcome(ERROR, "", detail="dryfire could not evaluate this call: %s" % type(exc).__name__)


def stderr_progress(message):
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
