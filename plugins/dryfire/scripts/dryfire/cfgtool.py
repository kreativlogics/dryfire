"""dryfire's settings tool: show, explain, set, unset, init, approve, doctor."""

import argparse
import json
import os
import sys

from . import __version__, approve, cfg, ledger, redact, sandbox, transcripts
from .adapters import checkrein

STARTER = {"version": cfg.VERSION, "preset": "standard"}


def _env(args, environ):
    home = os.path.expanduser("~")
    data = (args.data or "").strip() or (environ.get("CLAUDE_PLUGIN_DATA") or "").strip()
    data_dir = os.path.abspath(os.path.expanduser(data)) if data else os.path.join(home, ".claude", "dryfire")
    project = (args.project or "").strip() or (environ.get("CLAUDE_PROJECT_DIR") or "").strip() or os.getcwd()
    return home, data_dir, os.path.realpath(os.path.expanduser(project))


def _layer_path(args, data_dir, project_dir):
    return cfg.project_path(project_dir) if args.project_layer else cfg.user_path(data_dir)


def _read_layer(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise cfg.ConfigError("%s: cannot read (%s)" % (path, exc))
    if not isinstance(data, dict):
        raise cfg.ConfigError("%s: must be a JSON object" % path)
    return data


def cmd_show(args, home, data_dir, project_dir, environ, out):
    eff = cfg.resolve(data_dir, project_dir, None, environ)
    clean = redact.Redactor.for_settings(home, eff.values).clean
    values = dict(eff.values)
    hooks = {n: {"layer": layer, "command": clean(h.get("command") or " ".join(h.get("args") or []))}
             for n, (h, layer, _p) in sorted(eff.hooks.items())}
    if args.json:
        values = _cleaned(values, clean)
        values["hooks"] = _with_clean_keys(hooks, clean)  # The commands are clean already: cut them once.
        notes = [clean(n, limit=300) for n in eff.notes]
        out.write(json.dumps({"values": values, "source": eff.source, "notes": notes,
                              "files": {"user": clean(cfg.user_path(data_dir)),
                                        "project": clean(cfg.project_path(project_dir))}}, indent=2) + "\n")
        return 0
    values["hooks"] = hooks
    out.write("dryfire settings (user file %s, project file %s)\n\n" % (
        clean(cfg.user_path(data_dir)), clean(cfg.project_path(project_dir))))
    for key in sorted(values):
        if key == "version":
            continue
        shown = json.dumps(values[key]) if key != "hooks" else ", ".join(
            "%s (%s)" % (n, h["layer"]) for n, h in values[key].items()) or "none"
        out.write("  %-16s %s  [%s]\n" % (key, clean(shown, limit=200), eff.source.get(key, "default")))
    for note in eff.notes:
        out.write("note: %s\n" % clean(note, limit=300))
    return 0


def _cleaned(value, clean):
    """value with every string in it masked the way the text view masks it."""
    if isinstance(value, str):
        return clean(value, limit=300)
    if isinstance(value, list):
        return [_cleaned(v, clean) for v in value]
    if isinstance(value, dict):
        return _with_clean_keys({k: _cleaned(v, clean) for k, v in value.items()}, clean)
    return value


def _with_clean_keys(mapping, clean):
    """mapping with masked keys; two keys that mask alike are both kept (the second as 'key (2)')."""
    out = {}
    for k, v in mapping.items():
        key, n = clean(k, limit=200), 1
        while key in out:
            n += 1
            key = "%s (%d)" % (clean(k, limit=200), n)
        out[key] = v
    return out


def cmd_explain(args, out):
    keys = [args.key] if args.key else sorted(k for k in cfg.SCHEMA if k != "version")
    for key in keys:
        spec = cfg.SCHEMA.get(key)
        if spec is None:
            raise cfg.ConfigError("unknown key %r" % key)
        extra = ""
        if "choices" in spec:
            extra = " Choices: %s." % ", ".join(spec["choices"])
        elif "min" in spec:
            extra = " Range: %d to %d." % (spec["min"], spec["max"])
        out.write("%s (%s): %s%s\n" % (key, spec["cls"], spec["help"], extra))
    return 0


def cmd_set(args, home, data_dir, project_dir, out):
    path = _layer_path(args, data_dir, project_dir)
    # Held over the read and the write, so two changes at once can't drop one of them.
    with ledger.locked(data_dir, "config"):
        data = _read_layer(path)
        _apply_set(data, args)
        cfg.write_layer(path, data)
    key = args.key
    out.write("Set %s in %s\n" % (key, redact.Redactor(home).clean(path)))
    if key.startswith("hooks."):
        out.write("A hook in the config still needs approval before it runs: "
                  "cli.py approve --use %s\n" % key[len("hooks."):])
    return 0


def _apply_set(data, args):
    data.setdefault("version", cfg.VERSION)
    key = args.key
    if key.startswith("hooks."):
        name = key[len("hooks."):]
        try:
            value = json.loads(args.value)
        except ValueError:
            raise cfg.ConfigError("hooks.%s needs a JSON object, e.g. '{\"command\": \"...\", \"matcher\": "
                                  "\"Bash\"}'" % name)
        hooks = dict(data.get("hooks") or {})
        hooks[name] = value
        data["hooks"] = hooks
    else:
        data[key] = cfg.parse_value(key, args.value)


def cmd_unset(args, home, data_dir, project_dir, out):
    path = _layer_path(args, data_dir, project_dir)
    key = args.key
    with ledger.locked(data_dir, "config"):
        data = _read_layer(path)
        if key.startswith("hooks."):
            hooks = dict(data.get("hooks") or {})
            if hooks.pop(key[len("hooks."):], None) is None:
                raise cfg.ConfigError("%s is not set in %s" % (key, path))
            data["hooks"] = hooks
        elif data.pop(key, None) is None:
            raise cfg.ConfigError("%s is not set in %s" % (key, path))
        cfg.write_layer(path, data)
    out.write("Removed %s from %s\n" % (key, redact.Redactor(home).clean(path)))
    return 0


def cmd_init(args, home, data_dir, project_dir, out):
    path = _layer_path(args, data_dir, project_dir)
    if os.path.exists(path):
        raise cfg.ConfigError("%s already exists" % path)
    cfg.write_layer(path, dict(STARTER))
    out.write("Wrote %s\n" % redact.Redactor(home).clean(path))
    return 0


def cmd_approve(args, home, data_dir, project_dir, out):
    if args.key != "allow_read":
        raise cfg.ConfigError("only project allow_read values are approved here; hooks are approved with "
                              "cli.py approve")
    data = _read_layer(cfg.project_path(project_dir))
    values = data.get("allow_read") or []
    if not values:
        out.write("This project's config sets no allow_read.\n")
        return 0
    clean = redact.Redactor(home).clean
    for v in values:
        approve.grant(data_dir, project_dir, "allow_read", v)
        out.write("Approved allow_read %s for this project\n" % clean(v))
    return 0


def cmd_doctor(home, data_dir, project_dir, environ, out):
    clean = redact.Redactor(home).clean
    ok = True
    lines = ["dryfire %s, Python %s" % (__version__, sys.version.split()[0])]
    if sys.version_info < (3, 9):
        ok = False
        lines.append("FAIL Python 3.9 or newer is needed")
    lines.append("%s OS sandbox: %s" % ("ok  " if sandbox.os_sandbox_available() else "warn",
                                        "macOS sandbox-exec" if sandbox.os_sandbox_available() else
                                        "none (hooks run with a temp HOME and clean environment only)"))
    roots = transcripts.default_roots(home, environ)
    lines.append("%s transcripts: %s" % ("ok  " if roots else "FAIL", ", ".join(clean(r) for r in roots) or
                                         "none found under ~/.claude/projects"))
    ok = ok and bool(roots)
    try:
        eff = cfg.resolve(data_dir, project_dir, None, environ)
        lines.append("ok   config: preset %s, %d days, timeout %d s, sandbox %s" % (
            eff.values["preset"], eff.values["window_days"], eff.values["timeout_seconds"], eff.values["sandbox"]))
        for n in eff.notes:
            lines.append("note %s" % clean(n, limit=300))
    except cfg.ConfigError as exc:
        ok = False
        lines.append("FAIL config: %s" % clean(str(exc), limit=400))
    lines.append("ok   approvals: %d" % len(approve.load(data_dir)))
    root = checkrein.find("", home)
    lines.append("info checkrein: %s" % (clean(root) if root else "not installed"))
    out.write("\n".join(lines) + "\n")
    return 0 if ok else 1


def parser():
    # No abbreviated options, as in cli.py: selfguard reads --data and --project by their full names.
    ap = argparse.ArgumentParser(prog="dryfire-config", description="Show and change dryfire's settings.",
                                 allow_abbrev=False)
    ap.add_argument("--data", default="", help="dryfire's data folder")
    ap.add_argument("--project", default="", help="the project folder (default: CLAUDE_PROJECT_DIR or here)")
    sub = ap.add_subparsers(dest="command")
    p = sub.add_parser("show", allow_abbrev=False, help="effective settings and where each comes from")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("explain", allow_abbrev=False, help="what a key does")
    p.add_argument("key", nargs="?")
    for name, helptext in (("set", "set a key"), ("unset", "remove a key"), ("init", "write a starter file")):
        p = sub.add_parser(name, allow_abbrev=False, help=helptext)
        if name != "init":
            p.add_argument("key")
        if name == "set":
            p.add_argument("value")
        p.add_argument("--project-layer", action="store_true", help="change the project file, not yours")
    p = sub.add_parser("approve", allow_abbrev=False, help="approve this project's allow_read values")
    p.add_argument("key")
    sub.add_parser("doctor", allow_abbrev=False, help="check the setup")
    return ap


def main(argv=None, out=None, err=None, environ=None):
    out = out or sys.stdout
    err = err or sys.stderr
    environ = os.environ if environ is None else environ
    ap = parser()
    args = ap.parse_args(argv)
    if not args.command:
        ap.print_help(err)
        return 2
    home, data_dir, project_dir = _env(args, environ)
    try:
        if args.command == "show":
            return cmd_show(args, home, data_dir, project_dir, environ, out)
        if args.command == "explain":
            return cmd_explain(args, out)
        if args.command == "set":
            return cmd_set(args, home, data_dir, project_dir, out)
        if args.command == "unset":
            return cmd_unset(args, home, data_dir, project_dir, out)
        if args.command == "init":
            return cmd_init(args, home, data_dir, project_dir, out)
        if args.command == "approve":
            return cmd_approve(args, home, data_dir, project_dir, out)
        return cmd_doctor(home, data_dir, project_dir, environ, out)
    except cfg.ConfigError as exc:
        # The message quotes config values, and a config file is not ours to trust: mask it like a report.
        err.write("dryfire: config: %s\n" % redact.Redactor(home).clean(str(exc), limit=2000))
        return 1
