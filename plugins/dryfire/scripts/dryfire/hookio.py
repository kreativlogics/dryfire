"""The PreToolUse hook protocol, read the way Claude Code reads it.

Input: one JSON object on stdin. Output, in order of precedence:

- Exit code 2 blocks the call. If stdout is a JSON object its reason is used,
  otherwise stderr is the reason. A JSON "allow" does not undo the block.
- Any other exit code with a JSON object on stdout: the fields decide and the
  exit code is ignored. hookSpecificOutput.permissionDecision is one of allow,
  ask, deny, defer; the older top-level "decision": "approve" | "block" maps to
  allow | deny. updatedInput replaces the tool input. "continue": false stops
  the session but does not block the tool call by itself.
- Exit 0 with no JSON: no decision. Output starting with "{" that does not
  parse as an object, a permissionDecision outside the four values, or
  another exit code with plain output: a non-blocking error.
- A timeout or a hook that cannot start: a non-blocking error.
- on_failure "block" (the hook's onFailure setting) turns errors and timeouts
  into a block.

Several hooks on one call merge as deny > defer > ask > allow.
"""

import json

DENY, DEFER, ASK, ALLOW, NONE, ERROR = "deny", "defer", "ask", "allow", "none", "error"
# Rule packs only: the guard would let the call through but warn, or only log it.
WARN, LOG = "warn", "log"
DECISIONS = (DENY, DEFER, ASK, ALLOW)
_RANK = {DENY: 6, DEFER: 5, ASK: 4, ALLOW: 3, WARN: 2, LOG: 1, NONE: 0, ERROR: 0}


class Outcome(object):
    """What one guard decided for one call."""

    __slots__ = ("decision", "reason", "modified", "detail", "rule", "stopped")

    def __init__(self, decision, reason="", modified=False, detail="", rule="", stopped=False):
        self.decision = decision
        self.reason = reason or ""
        self.modified = modified
        self.detail = detail  # For errors: exit code, timeout, bad JSON. For others: empty.
        self.rule = rule  # Rule id when the guard names one.
        self.stopped = stopped

    def as_dict(self):
        return {"decision": self.decision, "reason": self.reason, "modified": self.modified,
                "detail": self.detail, "rule": self.rule, "stopped": self.stopped}

    def __repr__(self):
        return "Outcome(%s, %r, rule=%r, detail=%r)" % (self.decision, self.reason[:60], self.rule, self.detail)


def payload(tool, tool_input, cwd, transcript_path, mode, session_id, tool_use_id):
    """The stdin object a PreToolUse hook receives."""
    return {
        "session_id": session_id,
        "transcript_path": transcript_path,
        "cwd": cwd,
        "permission_mode": mode or "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": tool_use_id,
    }


def _json_object(stdout):
    text = (stdout or "").strip()
    if not text.startswith("{"):
        return None, False
    try:
        obj = json.loads(text)
    except ValueError:
        return None, True
    if not isinstance(obj, dict):
        return None, True
    return obj, True


def _fields(obj):
    """(decision or None, reason, modified, stopped) from a parsed JSON object."""
    decision, reason = None, ""
    spec = obj.get("hookSpecificOutput")
    if isinstance(spec, dict) and spec.get("hookEventName") in (None, "PreToolUse"):
        d = spec.get("permissionDecision")
        if d is not None and d not in DECISIONS:
            raise ValueError("permissionDecision %r is not one of %s" % (d, ", ".join(DECISIONS)))
        if d in DECISIONS:
            decision = d
            reason = spec.get("permissionDecisionReason") or ""
        modified = isinstance(spec.get("updatedInput"), dict)
    else:
        modified = False
    if decision is None:
        legacy = obj.get("decision")
        if legacy == "block":
            decision = DENY
        elif legacy == "approve":
            decision = ALLOW
        if decision is not None:
            reason = obj.get("reason") or ""
    if not reason and isinstance(obj.get("reason"), str):
        reason = obj["reason"]
    stopped = obj.get("continue") is False
    if not isinstance(reason, str):
        reason = json.dumps(reason)
    return decision, reason, modified, stopped


def interpret(rc, stdout, stderr, timed_out=False, start_error="", truncated=False, on_failure=False):
    """Turn one hook run into an Outcome."""
    def failed(detail):
        if on_failure:
            return Outcome(DENY, "hook failed and its onFailure is block: " + detail, detail=detail)
        return Outcome(ERROR, (stderr or "").strip()[:2000], detail=detail)

    if start_error:
        return failed("could not start: " + start_error)
    if timed_out:
        return failed("timed out")
    obj, looked_json = _json_object(stdout)
    if rc == 2:
        reason = (stderr or "").strip()
        if obj is not None:
            try:
                _d, json_reason, _m, stopped = _fields(obj)
            except ValueError:
                json_reason, stopped = "", False
            return Outcome(DENY, json_reason or reason, detail="exit 2", stopped=stopped)
        return Outcome(DENY, reason, detail="exit 2")
    if obj is not None:
        try:
            decision, reason, modified, stopped = _fields(obj)
        except ValueError as exc:
            return failed("output did not match the hook format: %s" % exc)
        return Outcome(decision or NONE, reason, modified=modified, stopped=stopped)
    if looked_json:
        return failed("output looked like JSON but did not parse" + (" (output was cut at the size cap)"
                                                                       if truncated else ""))
    if rc == 0:
        return Outcome(NONE)
    return failed("exit %s" % rc)


def merge(outcomes):
    """Claude Code's merge of several hooks on one call: deny > defer > ask > allow."""
    best = Outcome(NONE)
    for o in outcomes:
        if o is not None and _RANK.get(o.decision, 0) > _RANK.get(best.decision, 0):
            best = o
    return best


def blocks(decision):
    return decision == DENY
