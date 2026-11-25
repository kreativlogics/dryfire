"""dryfire's settings: defaults < preset < user < project < this run.

- User layer: the plugin's userConfig values (CLAUDE_PLUGIN_OPTION_*) and
  config.json in the plugin data folder.
- Project layer: .dryfire/config.json in the project. A project can make
  things safer and pick preferences, but cannot loosen a safety key, add
  transcript folders, or run a hook nobody approved.
- Run flags: like the project layer (they come from whoever runs the
  command, which may be the agent), so they too can only tighten.

Key classes:
  meta              version
  preference        any layer, normal precedence
  safety-min        lower wins (timeout_seconds)
  safety-order      the stricter value wins (sandbox, scope, redact_home)
  safety-union      lists add up (redact_patterns)
  loosen-user       user layer only (transcript_roots)
  loosen-approved   project values need an approval (allow_read)
  exec              runs code; every hook needs an approval (hooks)
"""

import difflib
import json
import os
import re

from . import approve, ledger, redact, secrets

VERSION = 1

PRESETS = {
    "quick": {"window_days": 7, "max_calls": 2000},
    "standard": {"window_days": 30, "max_calls": 20000},
    "deep": {"window_days": 365, "max_calls": 100000},
}

ORDERS = {
    "sandbox": ["env", "auto", "required"],
    "scope": ["all", "project"],
    "redact_home": [False, True],
}

SCHEMA = {
    "version": {"cls": "meta", "type": int, "default": VERSION,
                "help": "Config format version."},
    "preset": {"cls": "preference", "type": str, "default": "standard", "choices": sorted(PRESETS),
               "help": "quick: 7 days, 2,000 distinct calls. standard: 30 days, 20,000. deep: 365 days, 100,000."},
    "window_days": {"cls": "preference", "type": int, "min": 1, "max": 3650,
                    "help": "How many days of history to replay (default from the preset)."},
    "max_calls": {"cls": "preference", "type": int, "min": 1, "max": 1000000,
                  "help": "Most distinct calls a hook is run on; the most recently used are kept (default from "
                          "the preset). Rule packs always see every call."},
    "workers": {"cls": "preference", "type": int, "min": 1, "max": 32,
                "help": "Hooks run in parallel by this many workers (default: CPUs, at most 8)."},
    "samples": {"cls": "preference", "type": int, "default": 3, "min": 0, "max": 20,
                "help": "Sample calls shown per rule."},
    "permission_mode": {"cls": "preference", "type": str, "default": "default",
                        "choices": ["default", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions",
                                    "as-recorded"],
                        "help": "permission_mode sent to hooks; as-recorded uses the mode the transcript last noted."},
    "timeout_seconds": {"cls": "safety-min", "type": int, "default": 10, "min": 1, "max": 120,
                        "help": "Per-call time limit for a hook under test. Project and run can only lower it."},
    "sandbox": {"cls": "safety-order", "type": str, "default": "auto", "choices": ORDERS["sandbox"],
                "help": "env: temp HOME and clean environment only. auto: also the macOS sandbox when available. "
                        "required: refuse to run hooks without the OS sandbox."},
    "scope": {"cls": "safety-order", "type": str, "default": "all", "choices": ORDERS["scope"],
              "help": "all: every project's transcripts. project: only calls made in this project."},
    "redact_home": {"cls": "safety-order", "type": bool, "default": True,
                    "help": "Show the home folder as ~ in reports."},
    "redact_patterns": {"cls": "safety-union", "type": list, "default": [],
                        "help": "Extra regular expressions masked in every report."},
    "transcript_roots": {"cls": "loosen-user", "type": list, "default": [],
                         "help": "Extra transcript folders to read (user config only)."},
    "allow_read": {"cls": "loosen-approved", "type": list, "default": [],
                   "help": "Extra paths in your home folder a hook may read inside the macOS sandbox."},
    "hooks": {"cls": "exec", "type": dict, "default": {},
              "help": "Named hooks to replay: {name: {command | args, matcher, plugin_root, options, if, "
                      "on_failure}}. Each needs approval before it runs."},
}

OPTION_KEYS = ("preset", "sandbox", "timeout_seconds")


class ConfigError(Exception):
    pass


def user_path(data_dir):
    return os.path.join(data_dir, "config.json")


def project_path(project_dir):
    return os.path.join(project_dir, ".dryfire", "config.json")


def _type_name(t):
    return {int: "a whole number", str: "text", bool: "true or false", list: "a list", dict: "an object"}[t]


def _hint(key):
    """The schema key a misspelt key most likely meant, or ""."""
    keys = [k for k in SCHEMA if k != "version"]
    low = str(key).lower()
    for k in keys:
        if k.startswith(low) or low.startswith(k.split("_")[0]) and len(low) >= 4:
            return k
    close = difflib.get_close_matches(low, keys, n=1, cutoff=0.5)
    if not close:
        heads = {k.split("_")[0]: k for k in keys}
        close = [heads[h] for h in difflib.get_close_matches(low, list(heads), n=1, cutoff=0.6)]
    return close[0] if close else ""


def validate(data, where):
    """Problems as text; each names the key, what was expected and what was found."""
    errs = []
    if not isinstance(data, dict):
        return ["%s: must be a JSON object" % where]
    v = data.get("version", VERSION)
    if isinstance(v, int) and v > VERSION:
        errs.append("%s: version %d is newer than this dryfire understands (%d); update the plugin" % (
            where, v, VERSION))
    for key, value in data.items():
        spec = SCHEMA.get(key)
        if spec is None:
            hint = _hint(key)
            errs.append("%s: unknown key %r%s" % (where, key, " (did you mean %r?)" % hint if hint else ""))
            continue
        t = spec["type"]
        if t is int and (isinstance(value, bool) or not isinstance(value, int)) or \
                t is not int and not isinstance(value, t):
            errs.append("%s: %s must be %s, got %s" % (where, key, _type_name(t), json.dumps(value)[:60]))
            continue
        if "choices" in spec and value not in spec["choices"]:
            errs.append("%s: %s must be one of %s, got %r" % (where, key, ", ".join(spec["choices"]), value))
        if t is int and ("min" in spec and value < spec["min"] or "max" in spec and value > spec["max"]):
            errs.append("%s: %s must be between %d and %d, got %d" % (where, key, spec["min"], spec["max"], value))
        if t is list and not all(isinstance(x, str) for x in value):
            errs.append("%s: %s must be a list of text values" % (where, key))
        if key == "redact_patterns":
            for p in value:
                try:
                    re.compile(p)
                except (re.error, TypeError) as exc:
                    errs.append("%s: redact_patterns entry %r does not compile (%s)" % (where, p, exc))
        if key == "hooks":
            errs.extend(_validate_hooks(value, where))
    blob = json.dumps(data)
    if secrets.scan_text(blob, high_only=True):
        errs.append("%s: holds a value that looks like a secret; keep secrets out of dryfire's config" % where)
    return errs


_HOOK_KEYS = {"command", "args", "matcher", "plugin_root", "options", "if", "on_failure"}


def _validate_hooks(hooks, where):
    errs = []
    for name, h in hooks.items():
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$", name):
            errs.append("%s: hook name %r must be a short name (letters, digits, . _ -)" % (where, name))
        if not isinstance(h, dict):
            errs.append("%s: hooks.%s must be an object" % (where, name))
            continue
        for k in sorted(set(h) - _HOOK_KEYS):
            errs.append("%s: hooks.%s has unknown key %r" % (where, name, k))
        has_cmd = isinstance(h.get("command"), str) and h["command"].strip()
        has_args = isinstance(h.get("args"), list) and h["args"] and all(isinstance(a, str) for a in h["args"])
        if not has_cmd and not has_args:
            errs.append("%s: hooks.%s needs a command (text) or args (list of text)" % (where, name))
        if "options" in h and not isinstance(h["options"], dict):
            errs.append("%s: hooks.%s.options must be an object" % (where, name))
        if "on_failure" in h and h["on_failure"] not in ("block", "ignore"):
            errs.append("%s: hooks.%s.on_failure must be block or ignore" % (where, name))
    return errs


def _read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise ConfigError("%s: cannot read (%s)" % (path, exc))


def _options(env):
    out = {}
    for key in OPTION_KEYS:
        raw = (env.get("CLAUDE_PLUGIN_OPTION_" + key.upper()) or "").strip()
        if not raw:
            continue
        if SCHEMA[key]["type"] is int:
            try:
                out[key] = int(raw)
            except ValueError:
                continue
        else:
            out[key] = raw
    return out


class Effective(object):
    def __init__(self):
        self.values = {}
        self.source = {}
        self.notes = []
        self.hooks = {}  # name -> (hook dict, layer, project_dir or "")


def _stricter(key, a, b):
    order = ORDERS[key]
    return a if order.index(a) >= order.index(b) else b


def resolve(data_dir, project_dir, flags=None, env=None):
    env = os.environ if env is None else env
    eff = Effective()
    v = eff.values
    for key, spec in SCHEMA.items():
        if "default" in spec:
            v[key] = spec["default"]
            eff.source[key] = "default"

    opts = _options(env)
    errs = validate(opts, "plugin options")
    if errs:
        raise ConfigError("; ".join(errs))
    user = {}
    file_user = _read(user_path(data_dir)) if data_dir else None
    if file_user is not None:
        errs = validate(file_user, user_path(data_dir))
        if errs:
            raise ConfigError("; ".join(errs))
        user = file_user
    project = {}
    if project_dir:
        p = _read(project_path(project_dir))
        if p is not None:
            errs = validate(p, project_path(project_dir))
            if errs:
                raise ConfigError("; ".join(errs))
            project = p
    flags = {k: val for k, val in (flags or {}).items() if val is not None}
    errs = validate(flags, "run options")
    if errs:
        raise ConfigError("; ".join(errs))

    preset = flags.get("preset") or project.get("preset") or user.get("preset") or opts.get("preset") or v["preset"]
    v["preset"] = preset
    for key, val in PRESETS[preset].items():
        v[key] = val
        eff.source[key] = "preset %s" % preset
    v["workers"] = max(1, min(8, os.cpu_count() or 1))
    eff.source["workers"] = "default"

    # Plugin options arrive in the environment of whoever runs the CLI, which may be the agent, so like the
    # project and run layers they can only tighten. Only your config file loosens.
    for layer_name, layer in (("options", opts), ("user", user), ("project", project), ("run", flags)):
        loose = layer_name != "user"
        for key, val in layer.items():
            if key in ("version", "preset"):
                continue
            cls = SCHEMA[key]["cls"]
            if cls == "preference":
                v[key] = val
                eff.source[key] = layer_name
            elif cls == "safety-min":
                if not loose or val < v[key]:
                    v[key] = val
                    eff.source[key] = layer_name
                elif val > v[key]:
                    eff.notes.append("%s %s=%s ignored: it can only lower the value (now %s)" % (
                        layer_name, key, val, v[key]))
            elif cls == "safety-order":
                new = val if not loose else _stricter(key, val, v[key])
                if loose and new != val:
                    eff.notes.append("%s %s=%s ignored: it can only make this stricter (now %s)" % (
                        layer_name, key, json.dumps(val), json.dumps(v[key])))
                if new != v[key] or not loose:
                    v[key] = new
                    eff.source[key] = layer_name
            elif cls == "safety-union":
                if loose:
                    for p in [p for p in val if redact.slow_pattern(p)]:
                        eff.notes.append("%s redact_patterns entry %r ignored: its shape (a repeated group that "
                                         "repeats or has alternatives, or more than two open-ended repeats) can "
                                         "take minutes on some lines; add it to your user config if you trust "
                                         "it" % (layer_name, p))
                    val = [p for p in val if not redact.slow_pattern(p)]
                v[key] = list(dict.fromkeys(list(v[key]) + list(val)))
                eff.source[key] = "merged"
            elif cls == "loosen-user":
                if loose:
                    eff.notes.append("%s %s ignored: only your user config can set it" % (layer_name, key))
                else:
                    v[key] = val
                    eff.source[key] = layer_name
            elif cls == "loosen-approved":
                if layer_name == "project":
                    granted = [x for x in val if approve.is_approved(data_dir, project_dir, key, x)]
                    for x in val:
                        if x not in granted:
                            eff.notes.append("project allow_read %r needs approval: /dryfire:config approve "
                                             "allow_read" % x)
                    v[key] = list(dict.fromkeys(list(v[key]) + granted))
                elif layer_name == "run":
                    eff.notes.append("run allow_read ignored: set it in the user config")
                else:
                    v[key] = val
                eff.source[key] = layer_name
            elif cls == "exec":
                for name, h in val.items():
                    if layer_name == "project" and name in eff.hooks:
                        # A cloned project must not take over the name of a hook you set up.
                        eff.notes.append("project hook %r has the same name as one of yours; it is "
                                         "project:%s" % (name, name))
                        name = "project:" + name
                    eff.hooks[name] = (h, layer_name, project_dir if layer_name == "project" else "")
    return eff


def write_layer(path, data):
    errs = validate(data, path)
    if errs:
        raise ConfigError("; ".join(errs))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ledger.write_json_atomic(path, data)


def parse_value(key, text):
    """A command-line value for key, as JSON when it parses, else as text."""
    spec = SCHEMA.get(key)
    if spec is None:
        hint = _hint(key)
        raise ConfigError("unknown key %r%s" % (key, " (did you mean %r?)" % hint if hint else ""))
    if spec["type"] is str:
        return text
    try:
        return json.loads(text)
    except ValueError:
        raise ConfigError("%s needs %s, e.g. %s" % (key, _type_name(spec["type"]),
                                                     {int: "10", bool: "true", list: '["a"]', dict: "{}"}[spec["type"]]))
