"""Find what can be replayed, without running any of it.

Looks at transcript folders, PreToolUse hooks in Claude Code settings files
and installed plugins, and the config files of checkrein,
destructive_command_guard and cc-safety-net. Reads files only.
"""

import json
import os
import shutil

from . import transcripts
from .guards import HookSpec


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def settings_paths(home, project_dir):
    out = [("user", os.path.join(home, ".claude", "settings.json")),
           ("user-local", os.path.join(home, ".claude", "settings.local.json"))]
    if project_dir:
        out.append(("project", os.path.join(project_dir, ".claude", "settings.json")))
        out.append(("project-local", os.path.join(project_dir, ".claude", "settings.local.json")))
    out.append(("managed", "/Library/Application Support/ClaudeCode/managed-settings.json"))
    out.append(("managed", "/etc/claude-code/managed-settings.json"))
    return out


def pre_tool_hooks(hooks_obj, plugin_root=None, source=""):
    """HookSpec for every command hook under PreToolUse in a settings or hooks.json object."""
    specs = []
    if not isinstance(hooks_obj, dict):
        return specs
    groups = hooks_obj.get("PreToolUse")
    if not isinstance(groups, list):
        return specs
    for gi, group in enumerate(groups):
        if not isinstance(group, dict):
            continue
        matcher = group.get("matcher", "*")
        for hi, h in enumerate(group.get("hooks") or []):
            if not isinstance(h, dict) or h.get("type", "command") != "command":
                continue
            if not h.get("command") and not h.get("args"):
                continue
            spec = HookSpec(command=h.get("command") or "", args=h.get("args"), matcher=matcher,
                            plugin_root=plugin_root, on_failure=h.get("onFailure") == "block",
                            if_rule=h.get("if", ""), source="%s#%d.%d" % (source, gi, hi))
            spec.declared_timeout = h.get("timeout")
            specs.append(spec)
    return specs


def plugin_hooks(plugin_root):
    data = _load_json(os.path.join(plugin_root, "hooks", "hooks.json"))
    if not isinstance(data, dict):
        return []
    return pre_tool_hooks(data.get("hooks"), plugin_root=plugin_root, source="plugin:%s" % os.path.basename(
        plugin_root.rstrip("/")))


def installed_plugins(home):
    """(name, install path) from Claude Code's installed_plugins.json."""
    data = _load_json(os.path.join(home, ".claude", "plugins", "installed_plugins.json"))
    out = []
    if not isinstance(data, dict) or not isinstance(data.get("plugins"), dict):
        return out
    for key, entries in sorted(data["plugins"].items()):
        if not isinstance(entries, list):
            continue
        for e in entries:
            path = e.get("installPath") if isinstance(e, dict) else None
            if isinstance(path, str) and os.path.isdir(path):
                out.append((key, path))
    return out


def configured_hooks(home, project_dir):
    """[(id, HookSpec)] for every PreToolUse command hook found in settings and installed plugins."""
    found = []
    for scope, path in settings_paths(home, project_dir):
        data = _load_json(path)
        if isinstance(data, dict):
            for spec in pre_tool_hooks(data.get("hooks"), source="settings:%s" % scope):
                found.append((spec.source, spec))
    for key, path in installed_plugins(home):
        for spec in plugin_hooks(path):
            spec.source = "plugin:%s%s" % (key, spec.source[spec.source.index("#"):])
            found.append((spec.source, spec))
    return found


def checkrein_roots(home):
    """Installed checkrein plugin folders."""
    return [path for key, path in installed_plugins(home) if key.split("@", 1)[0] == "checkrein"]


def transcript_summary(roots):
    out = []
    for root in roots:
        files, size, first, last = 0, 0, None, None
        for dirpath, _dirs, names in os.walk(root, followlinks=False):
            for n in names:
                if not n.endswith(".jsonl"):
                    continue
                try:
                    st = os.lstat(os.path.join(dirpath, n))
                except OSError:
                    continue
                files += 1
                size += st.st_size
                first = st.st_mtime if first is None else min(first, st.st_mtime)
                last = st.st_mtime if last is None else max(last, st.st_mtime)
        out.append({"root": root, "files": files, "bytes": size, "oldest_write": first, "newest_write": last})
    return out


def dcg_info(home):
    cfg_dir = os.path.join(home, ".config", "dcg")
    packs = []
    if os.path.isdir(cfg_dir):
        for dirpath, _dirs, names in os.walk(cfg_dir, followlinks=False):
            packs.extend(os.path.join(dirpath, n) for n in sorted(names) if n.endswith((".yaml", ".yml")))
    return {"binary": shutil.which("dcg"), "config": os.path.join(cfg_dir, "config.toml")
            if os.path.isfile(os.path.join(cfg_dir, "config.toml")) else None, "packs": packs}


def safetynet_info(home, project_dir):
    out = {"binary": shutil.which("cc-safety-net"), "rule_files": [], "rulebooks": [], "legacy": []}
    for base in [os.path.join(home, ".cc-safety-net")] + ([os.path.join(project_dir, ".cc-safety-net")]
                                                           if project_dir else []):
        rule = os.path.join(base, "rules", "rule.json")
        if os.path.isfile(rule):
            out["rule_files"].append(rule)
        rules_dir = os.path.join(base, "rules")
        if os.path.isdir(rules_dir):
            for name in sorted(os.listdir(rules_dir)):
                book = os.path.join(rules_dir, name, "rulebook.json")
                if os.path.isfile(book):
                    out["rulebooks"].append(book)
    for legacy in [os.path.join(home, ".cc-safety-net", "config.json")] + (
            [os.path.join(project_dir, ".safety-net.json")] if project_dir else []):
        if os.path.isfile(legacy):
            out["legacy"].append(legacy)
    return out


def detect(home, project_dir, roots=None):
    roots = roots if roots is not None else transcripts.default_roots(home)
    hooks = configured_hooks(home, project_dir)
    return {
        "transcripts": transcript_summary(roots),
        "hooks": [{"id": hid, "matcher": spec.matcher, "command": spec.command, "args": spec.args,
                   "plugin_root": spec.plugin_root} for hid, spec in hooks],
        "checkrein": checkrein_roots(home),
        "dcg": dcg_info(home),
        "safetynet": safetynet_info(home, project_dir),
    }
