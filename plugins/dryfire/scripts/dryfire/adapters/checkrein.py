"""checkrein: build its PreToolUse hook from a checkrein folder and read its rule ids.

The folder can be the repository (with plugins/checkrein inside), the plugin
folder itself, or an installed copy. The hook is replayed like any other hook
(sandboxed, approval needed); this adapter only fills in the command, the
preset option and the rule-id pattern of checkrein's reasons
("checkrein GIT01 (deny): ...").
"""

import os
import re

from .. import detect
from ..guards import HookGuard

PRESETS = ("relaxed", "standard", "strict")
RULE_RX = re.compile(r"\bcheckrein ([A-Z]{2,5}\d{2,3}) \((?:ask|deny)\)")


def plugin_root(path):
    """The checkrein plugin folder inside path, or None."""
    if not path:
        return None
    path = os.path.realpath(os.path.expanduser(path))
    for candidate in (path, os.path.join(path, "plugins", "checkrein")):
        if os.path.isfile(os.path.join(candidate, "scripts", "guard.py")) and \
                os.path.isfile(os.path.join(candidate, "hooks", "hooks.json")):
            return candidate
    return None


def find(path, home):
    """Resolve a user-given path, or the newest installed copy when path is empty."""
    if path:
        return plugin_root(path)
    roots = [plugin_root(p) for p in detect.checkrein_roots(home)]
    roots = [r for r in roots if r]
    return sorted(roots, key=lambda r: os.path.getmtime(r))[-1] if roots else None


def specs(root, preset, config_file=None):
    """HookSpecs for checkrein's PreToolUse hook at the given preset."""
    out = detect.plugin_hooks(root)
    for spec in out:
        spec.options["preset"] = preset
        spec.options.setdefault("fail_mode", "ask")
        if config_file:
            spec.seed_files["config.json"] = config_file
    return out


def guards(root, presets, home, timeout, sandbox_mode, allow_read=(), config_file=None):
    result = []
    for preset in presets:
        if preset not in PRESETS:
            raise ValueError("checkrein preset %r is not one of %s" % (preset, ", ".join(PRESETS)))
        for i, spec in enumerate(specs(root, preset, config_file)):
            name = "checkrein-%s" % preset + ("" if i == 0 else "-%d" % i)
            g = HookGuard(name, spec, home, timeout=timeout, sandbox_mode=sandbox_mode, allow_read=allow_read,
                          rule_rx=RULE_RX, label="checkrein (%s)" % preset)
            result.append(g)
    return result
