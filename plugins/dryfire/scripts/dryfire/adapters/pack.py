"""dryfire's own rule pack: a JSON file of regexes, for drafting a rule before
writing a hook.

{
  "version": 1,
  "name": "my-draft",
  "rules": [
    {"id": "no-force-push", "pattern": "git\\s+push\\s+.*--force", "decision": "deny",
     "reason": "Force push", "scope": "segment"},
    {"id": "env-files", "tool": "Write|Edit", "field": "file_path", "pattern": "\\.env$",
     "decision": "ask"}
  ]
}

tool is a hook matcher (default "Bash"). field is the tool_input field to
match (default "command"). scope "command" (default) matches the whole
field; "segment" matches each simple command of a Bash command after
wrappers are removed. The first matching rule decides.
"""

import json
import re

from .. import shell
from ..guards import Guard, matcher_accepts, matcher_error
from ..hookio import ASK, DENY, NONE, Outcome

ID_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
RULE_KEYS = {"id", "pattern", "decision", "reason", "scope", "tool", "field", "ignore_case"}
MAX_FIELD = 20000


class PackRule(object):
    __slots__ = ("id", "rx", "decision", "reason", "scope", "tool", "field")


def load(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return from_data(data, path)


def from_data(data, source="pack"):
    """(name, rules, errors)."""
    errors = []
    if not isinstance(data, dict):
        return "?", [], ["%s: a pack must be a JSON object" % source]
    if data.get("version") != 1:
        errors.append("%s: version must be 1" % source)
    name = data.get("name") if isinstance(data.get("name"), str) else "pack"
    rules = []
    seen = set()
    for i, r in enumerate(data.get("rules") or []):
        where = "%s: rules[%d]" % (source, i)
        if not isinstance(r, dict):
            errors.append(where + " must be an object")
            continue
        unknown = sorted(set(r) - RULE_KEYS)
        if unknown:
            errors.append("%s: unknown field(s) %s" % (where, ", ".join(unknown)))
        rid = r.get("id")
        if not isinstance(rid, str) or not ID_RX.match(rid) or rid in seen:
            errors.append(where + ": id must be a unique short name")
            continue
        seen.add(rid)
        decision = r.get("decision", DENY)
        if decision not in (DENY, ASK):
            errors.append("%s (%s): decision must be deny or ask" % (where, rid))
            continue
        scope = r.get("scope", "command")
        if scope not in ("command", "segment"):
            errors.append("%s (%s): scope must be command or segment" % (where, rid))
            continue
        tool = r.get("tool", "Bash")
        if not isinstance(tool, str) or matcher_error(tool):
            errors.append("%s (%s): tool is not a valid matcher" % (where, rid))
            continue
        field = r.get("field", "command")
        if not isinstance(field, str) or not field:
            errors.append("%s (%s): field must be a name" % (where, rid))
            continue
        pattern = r.get("pattern")
        try:
            rx = re.compile(pattern, re.I if r.get("ignore_case") else 0)
        except (re.error, TypeError) as exc:
            errors.append("%s (%s): pattern does not compile (%s)" % (where, rid, exc))
            continue
        rule = PackRule()
        rule.id, rule.rx, rule.decision, rule.scope, rule.tool, rule.field = rid, rx, decision, scope, tool, field
        rule.reason = r.get("reason") if isinstance(r.get("reason"), str) else rid
        rules.append(rule)
    return name, rules, errors


class PackGuard(Guard):
    kind = "pack"

    def __init__(self, name, rules, errors=()):
        Guard.__init__(self, name)
        self.rules = rules
        self.notes.extend(errors)
        self.label = "pack %s" % name

    def accepts(self, tool, tool_input=None, cwds=()):
        return any(matcher_accepts(r.tool, tool) for r in self.rules)

    def evaluate(self, tool, tool_input, mode):
        for r in self.rules:
            if not matcher_accepts(r.tool, tool):
                continue
            value = tool_input.get(r.field) if isinstance(tool_input, dict) else None
            if not isinstance(value, str):
                continue
            value = value[:MAX_FIELD]
            if r.scope == "segment" and tool == "Bash" and r.field == "command":
                texts = [" ".join(c.argv) for c in shell.parse(value).cmds]
            else:
                texts = [value]
            if any(r.rx.search(t) for t in texts):
                return Outcome(r.decision, r.reason, rule=r.id)
        return Outcome(NONE)
