"""Read tool calls out of Claude Code transcripts.

Read-only and local: files are opened for reading only and nothing here talks
to the network. Transcript text is untrusted data; it is parsed as JSON and
never executed, formatted into a shell command or followed.

A transcript is JSON Lines. Assistant records carry message.content[], where a
tool call is {"type": "tool_use", "id", "name", "input"}. The same call can be
written more than once (streamed updates, resumed sessions), so calls are
deduplicated by id. Subagent transcripts are included.
"""

import datetime
import json
import os
import re

_TOOL_USE = b'"tool_use"'
_ASSISTANT = b'"assistant"'
_MODE_RX = re.compile(rb'"permissionMode"\s*:\s*"([A-Za-z]{1,32})"')

DEFAULT_MAX_INPUT = 65536


class Call(object):
    """One past tool call."""

    __slots__ = ("id", "tool", "input", "ts", "cwd", "session", "mode", "project")

    def __init__(self, id, tool, input, ts, cwd, session, mode, project):
        self.id = id
        self.tool = tool
        self.input = input
        self.ts = ts  # datetime in UTC, or None when the record had no usable timestamp.
        self.cwd = cwd
        self.session = session
        self.mode = mode
        self.project = project  # The transcript folder name under projects/.

    @property
    def day(self):
        return self.ts.strftime("%Y-%m-%d") if self.ts else ""


class Stats(object):
    """Counters that make the report honest about what was not read."""

    FIELDS = ("roots", "files", "files_skipped_old", "files_unreadable", "files_outside_root", "lines",
              "bad_lines", "partial_lines", "tool_uses", "duplicates", "out_of_window", "no_timestamp",
              "oversized", "not_matched", "out_of_scope", "bytes")

    def __init__(self):
        for f in self.FIELDS:
            setattr(self, f, 0)

    def as_dict(self):
        return {f: getattr(self, f) for f in self.FIELDS}


def encode_project(path):
    """Claude Code's folder name for a project path (every non-alphanumeric becomes '-')."""
    return re.sub(r"[^A-Za-z0-9]", "-", path)


def default_roots(home, env=None):
    env = os.environ if env is None else env
    out = []
    cfg = (env.get("CLAUDE_CONFIG_DIR") or "").strip()
    if cfg:
        out.append(os.path.join(os.path.expanduser(cfg), "projects"))
    out.append(os.path.join(home, ".claude", "projects"))
    seen, result = set(), []
    for r in out:
        real = os.path.realpath(r)
        if real not in seen and os.path.isdir(real):
            seen.add(real)
            result.append(r)
    return result


def parse_ts(value):
    """ISO-8601 timestamp to an aware UTC datetime, or None."""
    if not isinstance(value, str) or len(value) < 10:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Python 3.9's fromisoformat takes 0, 3 or 6 fraction digits only.
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", text)
    if m:
        frac = (m.group(2) or "")[1:7]
        frac = ("." + frac.ljust(6, "0")) if frac else ""
        text = m.group(1) + frac + m.group(3)
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def iter_files(roots, since=None, project_folder=None, stats=None):
    """Yield (root, path) for .jsonl transcripts under roots.

    Symlinks are not followed, and a file whose real path leaves its root is
    skipped. Files last written before `since` are skipped without opening.
    """
    stats = stats or Stats()
    since_epoch = since.timestamp() if since else None
    for root in roots:
        stats.roots += 1
        real_root = os.path.realpath(root)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            if project_folder and os.path.normpath(dirpath) == os.path.normpath(root):
                dirnames[:] = [d for d in dirnames if d.startswith(project_folder)]
                filenames = []
            for name in sorted(filenames):
                if not name.endswith(".jsonl"):
                    continue
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    stats.files_outside_root += 1
                    continue
                real = os.path.realpath(path)
                if not (real == real_root or real.startswith(real_root.rstrip(os.sep) + os.sep)):
                    stats.files_outside_root += 1
                    continue
                try:
                    st = os.stat(path)
                except OSError:
                    stats.files_unreadable += 1
                    continue
                if since_epoch is not None and st.st_mtime < since_epoch:
                    stats.files_skipped_old += 1
                    continue
                stats.files += 1
                stats.bytes += st.st_size
                yield root, path


def _project_of(root, path):
    rel = os.path.relpath(path, root)
    return rel.split(os.sep, 1)[0] if os.sep in rel else ""


def read_calls(roots, since=None, until=None, accept_tool=None, max_input=DEFAULT_MAX_INPUT,
               project_dir=None, stats=None, seen_ids=None):
    """Yield Call for every distinct past tool call that passes the filters.

    accept_tool: a function tool_name -> bool (the hook matcher); None accepts all.
    project_dir: when set, only calls made in that folder (or below it) count.
    """
    stats = stats if stats is not None else Stats()
    seen = seen_ids if seen_ids is not None else set()
    folder = encode_project(project_dir) if project_dir else None
    for root, path in iter_files(roots, since=since, project_folder=folder, stats=stats):
        project = _project_of(root, path)
        try:
            fh = open(path, "rb")
        except OSError:
            stats.files_unreadable += 1
            continue
        with fh:
            mode = ""
            for raw in fh:
                stats.lines += 1
                if not raw.endswith(b"\n"):
                    # The last line of a file that is still being written.
                    stats.partial_lines += 1
                    continue
                if b"permissionMode" in raw:
                    m = _MODE_RX.search(raw)
                    if m:
                        mode = m.group(1).decode("ascii", "replace")
                if _TOOL_USE not in raw or _ASSISTANT not in raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    stats.bad_lines += 1
                    continue
                for call in _calls_in(rec, mode, project, stats):
                    if call.id in seen:
                        stats.duplicates += 1
                        continue
                    seen.add(call.id)
                    if accept_tool is not None and not accept_tool(call.tool):
                        stats.not_matched += 1
                        continue
                    if call.ts is None:
                        stats.no_timestamp += 1
                        if since is not None:
                            continue
                    elif (since is not None and call.ts < since) or (until is not None and call.ts >= until):
                        stats.out_of_window += 1
                        continue
                    if project_dir and not _within(call.cwd, project_dir):
                        stats.out_of_scope += 1
                        continue
                    try:
                        size = len(json.dumps(call.input, ensure_ascii=False))
                    except (TypeError, ValueError):
                        stats.bad_lines += 1
                        continue
                    if max_input and size > max_input:
                        stats.oversized += 1
                        continue
                    yield call


def _within(cwd, project_dir):
    if not cwd:
        return False
    a = os.path.normpath(cwd)
    b = os.path.normpath(project_dir)
    return a == b or a.startswith(b.rstrip(os.sep) + os.sep)


def _calls_in(rec, mode, project, stats):
    if not isinstance(rec, dict) or rec.get("type") != "assistant":
        return
    msg = rec.get("message")
    content = msg.get("content") if isinstance(msg, dict) else None
    if not isinstance(content, list):
        return
    ts = parse_ts(rec.get("timestamp"))
    cwd = rec.get("cwd") if isinstance(rec.get("cwd"), str) else ""
    session = rec.get("sessionId") if isinstance(rec.get("sessionId"), str) else ""
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        name = block.get("name")
        tid = block.get("id")
        tinput = block.get("input")
        if not isinstance(name, str) or not name or not isinstance(tinput, dict):
            stats.bad_lines += 1
            continue
        stats.tool_uses += 1
        if not isinstance(tid, str) or not tid:
            tid = "noid:" + json.dumps([session, rec.get("uuid"), name, tinput], sort_keys=True, default=str)
        yield Call(tid, name, tinput, ts, cwd, session, mode, project)
