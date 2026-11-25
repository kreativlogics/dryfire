"""Secret detection. Results name the kind and the line, never the value.

High-confidence patterns are token formats with a fixed prefix or structure.
Generic patterns (quoted values assigned to secret-sounding names, passwords in
connection strings) also need enough randomness and must not look like a
placeholder. SEC03 can hand the staged diff to gitleaks instead.
"""

import math
import re

HIGH = "high"
GENERIC = "generic"

# (id, label, regex, confidence, group index holding the value, min entropy)
_PATTERNS = [
    ("private-key", "private key block",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", HIGH, 0, 0.0),
    ("aws-access-key-id", "AWS access key ID", r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b", HIGH, 1, 3.0),
    ("aws-secret-key", "AWS secret access key",
     r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b", HIGH, 1, 3.5),
    ("github-token", "GitHub token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", HIGH, 1, 3.0),
    ("github-pat", "GitHub fine-grained token", r"\b(github_pat_[A-Za-z0-9_]{60,255})\b", HIGH, 1, 3.0),
    ("gitlab-token", "GitLab token", r"\b(gl(?:pat|dt|rt|ptt|cbt|oas)-[A-Za-z0-9_\-]{20,})", HIGH, 1, 3.0),
    ("slack-token", "Slack token", r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b", HIGH, 1, 3.0),
    ("slack-webhook", "Slack webhook URL",
     r"(https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9+/_-]{20,})", HIGH, 1, 3.0),
    ("stripe-live", "Stripe live key", r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b", HIGH, 1, 3.0),
    ("anthropic-key", "Anthropic API key", r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{30,})", HIGH, 1, 3.0),
    ("openai-key", "OpenAI API key",
     r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})", HIGH, 1, 3.0),
    ("google-api-key", "Google API key", r"\b(AIza[0-9A-Za-z_\-]{35})\b", HIGH, 1, 3.0),
    ("npm-token", "npm token", r"\b(npm_[A-Za-z0-9]{36})\b", HIGH, 1, 3.0),
    ("pypi-token", "PyPI token", r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})", HIGH, 1, 3.0),
    ("sendgrid-key", "SendGrid key", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", HIGH, 1, 3.0),
    ("jwt", "JSON web token",
     r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,})", HIGH, 1, 3.0),
    ("url-password", "password inside a connection URL",
     r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@\"'`]{1,64}:([^\s@/\"'`]{6,128})@[A-Za-z0-9.\-\[\]]", GENERIC, 1, 2.5),
    ("assigned-secret", "secret assigned in code or config",
     r"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|private[_\-]?key)"
     r"[\"']?\s*(?::|=|=>|:=)\s*[\"']([^\"'\s]{8,200})[\"']", GENERIC, 1, 3.0),
]

PATTERNS = [(pid, label, re.compile(rx), conf, grp, ent) for pid, label, rx, conf, grp, ent in _PATTERNS]

_PLACEHOLDER_WORDS = (
    "example", "sample", "dummy", "placeholder", "changeme", "change_me", "your", "redacted",
    "fake", "xxxxx", "*****", "<", ">", "${", "{{", "%s", "todo", "replace", "insert", "foobar",
    "secret123", "password", "passw0rd", "12345678", "abcdefgh", "test", "demo", "mock",
)
_HIGH_PLACEHOLDER_WORDS = ("example", "sample", "dummy", "placeholder", "redacted", "fake", "xxxxxxxx")
_REFERENCE_PREFIXES = ("$", "process.env", "os.environ", "env(", "getenv", "env.", "secrets.", "vars.", "%")


def entropy(value):
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def _looks_placeholder(value, confidence):
    low = value.lower()
    words = _HIGH_PLACEHOLDER_WORDS if confidence == HIGH else _PLACEHOLDER_WORDS
    if any(w in low for w in words):
        return True
    if confidence != HIGH and low.startswith(_REFERENCE_PREFIXES):
        return True
    if len(set(value)) <= 3:
        return True
    return False


class Hit(object):
    __slots__ = ("kind", "label", "line", "confidence")

    def __init__(self, kind, label, line, confidence):
        self.kind = kind
        self.label = label
        self.line = line
        self.confidence = confidence

    def describe(self):
        return "%s (line %d)" % (self.label, self.line) if self.line else self.label


def scan_text(text, high_only=False, first_line=1):
    """Return a list of Hit for secrets found in text. Values are never kept."""
    hits = []
    if not text:
        return hits
    seen = set()
    for offset, line in enumerate(text.splitlines()):
        if len(line) > 20000:
            line = line[:20000]
        for pid, label, rx, conf, grp, min_ent in PATTERNS:
            if high_only and conf != HIGH:
                continue
            for m in rx.finditer(line):
                value = m.group(grp)
                if _looks_placeholder(value, conf):
                    continue
                if min_ent and entropy(value) < min_ent:
                    continue
                key = (offset, m.start(grp))
                if key in seen:
                    continue
                seen.add(key)
                hits.append(Hit(pid, label, first_line + offset, conf))
    return hits


def mask(text):
    """Replace secret values in text with [hidden: kind] for display."""
    if not text:
        return text
    out = text
    for pid, label, rx, conf, grp, min_ent in PATTERNS:
        def repl(m, label=label, conf=conf, grp=grp, min_ent=min_ent):
            value = m.group(grp)
            if _looks_placeholder(value, conf) or (min_ent and entropy(value) < min_ent):
                return m.group(0)
            whole = m.group(0)
            start = m.start(grp) - m.start(0)
            return whole[:start] + "[hidden: %s]" % label + whole[start + len(value):]
        out = rx.sub(repl, out)
    return out


def added_lines(old, new):
    """Lines of new that are not in old, as (line_number, text)."""
    old_counts = {}
    for line in (old or "").splitlines():
        old_counts[line] = old_counts.get(line, 0) + 1
    added = []
    for idx, line in enumerate((new or "").splitlines(), 1):
        if old_counts.get(line, 0) > 0:
            old_counts[line] -= 1
            continue
        added.append((idx, line))
    return added


def scan_added(old, new, high_only=False):
    hits = []
    for number, line in added_lines(old, new):
        for hit in scan_text(line, high_only=high_only, first_line=number):
            hits.append(hit)
    return hits
