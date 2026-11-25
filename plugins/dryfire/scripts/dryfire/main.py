"""dryfire's command line: detect, scan, replay and approve.

Nothing here opens a network connection. Transcripts are read, never
written; the only files dryfire writes are its own approvals and config in
its data folder, the temp folders hooks run in, and a report file when you
pass --out.
"""

import argparse
import datetime
import json
import os
import shlex
import sys

from . import __version__, approve, cfg, context, detect, ledger, redact, replay, report, sandbox, selfguard, transcripts
from .adapters import checkrein, dcg, pack, safetynet
from .guards import (MAX_HASHED_BYTES, HookGuard, HookSpec, describe_hook_for_approval, matcher_error,
                     unbound_files)

EXIT_ERROR = 1
EXIT_UNAPPROVED = 3
EXIT_SANDBOX = 4

CLI = os.path.join(selfguard.PLUGIN_ROOT, "scripts", "cli.py")


class Fail(Exception):
    def __init__(self, message, code=EXIT_ERROR):
        Exception.__init__(self, message)
        self.code = code


class Env(object):
    """Where this run lives: home, data folder, project, environment."""

    def __init__(self, args, environ=None):
        self.environ = os.environ if environ is None else environ
        self.home = os.path.expanduser("~")
        data = (getattr(args, "data", "") or "").strip() or (self.environ.get("CLAUDE_PLUGIN_DATA") or "").strip()
        self.data_dir = os.path.abspath(os.path.expanduser(data)) if data else \
            os.path.join(self.home, ".claude", "dryfire")
        project = (getattr(args, "project", "") or "").strip() or \
            (self.environ.get("CLAUDE_PROJECT_DIR") or "").strip() or os.getcwd()
        self.project_dir = os.path.realpath(os.path.expanduser(project))


# Selecting guards.

class Selected(object):
    def __init__(self):
        self.hooks = []  # (name, spec, approval project dir, label, rule_rx)
        self.rule_guards = []
        self.notes = []


def _unique_name(name, taken):
    base, n = name, 2
    while name in taken:
        name = "%s-%d" % (base, n)
        n += 1
    taken.add(name)
    return name


def select_hooks(args, env, eff):
    """Every hook the arguments ask for, not yet approved or built."""
    sel = Selected()
    taken = set()
    for i, command in enumerate(args.hook or [], 1):
        matcher = args.matcher if args.matcher is not None else "Bash"
        err = matcher_error(matcher)
        if err:
            raise Fail("--matcher: " + err)
        # A relative script path means the folder you typed it in, as it would in your shell.
        spec = HookSpec(command=command, matcher=matcher, plugin_root=args.plugin_root,
                        source="command line").pinned(os.getcwd(), env.project_dir)
        name = _unique_name("hook-%d" % i, taken)
        sel.hooks.append((name, spec, "", "hook %d" % i, None))
    wanted = args.use or []
    if wanted:
        names = sorted(eff.hooks) if "all" in wanted else wanted
        for name in names:
            if name not in eff.hooks:
                raise Fail("no hook named %r in your dryfire config (configured: %s)" % (
                    name, ", ".join(sorted(eff.hooks)) or "none"))
            h, layer, pdir = eff.hooks[name]
            # Claude Code runs hooks from the project folder, so that is where a relative path points.
            spec = HookSpec.from_dict(h, source="config:%s" % layer)
            spec.pinned(pdir or env.project_dir, env.project_dir)
            sel.hooks.append((_unique_name(name, taken), spec, pdir, name, None))
    if args.detected:
        found = detect.configured_hooks(env.home, env.project_dir)
        ids = [hid for hid, _ in found] if "all" in args.detected else args.detected
        by_id = dict(found)
        for hid in ids:
            if hid not in by_id:
                raise Fail("no detected hook with id %r; run detect to list them" % hid)
            spec = by_id[hid].pinned(env.project_dir, env.project_dir)
            sel.hooks.append((_unique_name(hid.replace(":", "-").replace("#", "-"), taken), spec, "", hid, None))
    if args.checkrein is not None:
        root = checkrein.find(args.checkrein, env.home)
        if not root:
            raise Fail("checkrein not found%s; pass the folder of a checkrein checkout or install" % (
                " at %s" % args.checkrein if args.checkrein else " among installed plugins"))
        presets = [p.strip() for p in (args.checkrein_preset or "standard").split(",") if p.strip()]
        for p in presets:
            if p not in checkrein.PRESETS:
                raise Fail("--checkrein-preset: %r is not one of %s" % (p, ", ".join(checkrein.PRESETS)))
        cfg_file = os.path.abspath(os.path.expanduser(args.checkrein_config)) if args.checkrein_config else None
        if cfg_file and not os.path.isfile(cfg_file):
            raise Fail("--checkrein-config: %s is not a file" % cfg_file)
        for p in presets:
            for j, spec in enumerate(checkrein.specs(root, p, cfg_file)):
                name = _unique_name("checkrein-%s" % p + ("" if j == 0 else "-%d" % j), taken)
                sel.hooks.append((name, spec, "", "checkrein (%s)" % p, checkrein.RULE_RX))
    return sel


def select_rules(args, env, sel):
    packs = []
    if args.dcg:
        packs.extend(detect.dcg_info(env.home)["packs"])
        if not packs:
            raise Fail("--dcg: no packs found under ~/.config/dcg; pass --dcg-pack FILE")
    packs.extend(args.dcg_pack or [])
    if packs:
        loaded = [dcg.load(os.path.expanduser(p)) for p in packs]
        if not any(p.valid for p in loaded):
            raise Fail("no usable destructive_command_guard pack:\n  " + "\n  ".join(
                "%s: %s" % (p.source, "; ".join(p.errors)) for p in loaded))
        sel.rule_guards.append(dcg.DcgGuard("dcg", loaded))
    if args.safetynet is not None:
        if args.safetynet:
            paths = [os.path.expanduser(args.safetynet)]
        else:
            info = detect.safetynet_info(env.home, env.project_dir)
            paths = []
            for base in (os.path.join(env.home, ".cc-safety-net"), os.path.join(env.project_dir, ".cc-safety-net")):
                if os.path.isdir(base):
                    paths.append(base)
            paths += [p for p in info["legacy"] if os.path.basename(p) != "config.json"]
            if not paths:
                raise Fail("--safetynet: no cc-safety-net config found in ~/.cc-safety-net or this project; "
                           "pass a rulebook.json, rule.json or config path")
        for p in paths:
            if not os.path.exists(p):
                raise Fail("--safetynet: %s does not exist" % p)
        setups = [safetynet.load_path(p) for p in paths]
        if not any(s.books for s in setups):
            raise Fail("no cc-safety-net rules loaded:\n  " + "\n  ".join(
                e for s in setups for e in (s.errors + s.notes)))
        sel.rule_guards.append(safetynet.SafetyNetGuard("safetynet", setups))
    for i, path in enumerate(args.pack or [], 1):
        try:
            name, rules, errors = pack.load(os.path.expanduser(path))
        except (OSError, ValueError) as exc:
            raise Fail("--pack %s: cannot read (%s)" % (path, exc))
        if not rules:
            raise Fail("--pack %s has no usable rules:\n  %s" % (path, "\n  ".join(errors) or "rules is empty"))
        sel.rule_guards.append(pack.PackGuard(name if i == 1 else "%s-%d" % (name, i), rules, errors))


def unapproved(sel, env):
    out = []
    for name, spec, pdir, _label, _rx in sel.hooks:
        value = spec.approval_value(env.home)
        if unbound_files(value) or not approve.is_approved(env.data_dir, pdir, "hook", value):
            out.append((name, spec, pdir))
    return out


def _selection_flags(args):
    """The guard-selection flags of this run, to repeat in an approve command."""
    out = []
    for c in args.hook or []:
        out += ["--hook", c]
    if args.hook and args.matcher is not None:
        out += ["--matcher", args.matcher]
    if args.hook and args.plugin_root:
        out += ["--plugin-root", args.plugin_root]
    for u in args.use or []:
        out += ["--use", u]
    for d in args.detected or []:
        out += ["--detected", d]
    if args.checkrein is not None:
        out += ["--checkrein"] + ([args.checkrein] if args.checkrein else [])
        if args.checkrein_preset:
            out += ["--checkrein-preset", args.checkrein_preset]
    return out


def approval_help(missing, args, env, redactor):
    clean = redactor.clean
    lines = ["dryfire runs a hook only after you approve it. Not approved yet:"]
    for name, spec, pdir in missing:
        d = describe_hook_for_approval(spec, env.home)
        what = d["runs_as"] or " ".join(d["args"] or [])
        fp = approve.fingerprint(pdir, "hook", spec.approval_value(env.home))[:12]
        lines.append("  - %s: %s  [%s]%s" % (name, clean(what, limit=200), fp,
                                             "  (from %s's config)" % clean(pdir) if pdir else ""))
    lines.append("Each runs once per distinct past call, in a temp folder with a temp HOME and a time limit, "
                 "and never sees your real files when the macOS sandbox is on.")
    words = ["python3", CLI, "approve", "--data", env.data_dir] + _selection_flags(args)
    cmd = " ".join(shlex.quote(w) for w in words)
    # Home stays spelled out here: a ~ inside quotes would not expand when the command is pasted.
    shown = redactor.keeping_home().clean(cmd, limit=4000, oneline=False)  # A longer one gets the note.
    if shown != cmd:
        lines.append("To approve, run 'approve' yourself with --data %s and the same --hook, --pack or --use "
                     "options as this run. The full command is not shown because part of it is masked, and a "
                     "masked one would approve something else." % clean(env.data_dir, limit=0))
    else:
        lines.append("To approve, run this yourself (or confirm it when asked):")
        lines.append("  " + shown)
    return "\n".join(lines)


# Commands.

def cmd_detect(args, env, out):
    try:
        clean = redact.Redactor.for_settings(env.home, cfg.resolve(env.data_dir, env.project_dir, None,
                                                                   env.environ).values).clean
    except cfg.ConfigError:  # detect also helps when the config is broken; it masks the default way then.
        clean = redact.Redactor(env.home).clean
    found = detect.detect(env.home, env.project_dir, _roots(env, None))
    for h in found["hooks"]:
        spec = HookSpec(command=h["command"], args=h["args"], plugin_root=h["plugin_root"])
        spec.pinned(env.project_dir, env.project_dir)
        value = spec.approval_value(env.home)
        h["approved"] = not unbound_files(value) and approve.is_approved(env.data_dir, "", "hook", value)
        h["command"] = clean(h["command"], limit=300) if h["command"] else None
        h["args"] = [clean(a, limit=200) for a in h["args"]] if h["args"] else None
        h["plugin_root"] = clean(h["plugin_root"]) if h["plugin_root"] else None
        h["matcher"] = clean(str(h["matcher"]), limit=200)
        h["id"] = clean(h["id"], limit=200)
    found["os_sandbox"] = sandbox.os_sandbox_available()
    found["data_dir"] = clean(env.data_dir)
    for t in found["transcripts"]:
        t["root"] = clean(t["root"])
    for key in ("checkrein", "dcg", "safetynet"):
        found[key] = _clean_strings(found[key], clean)
    if args.json:
        out.write(json.dumps(found, indent=2, default=str) + "\n")
        return 0
    L = ["# dryfire detect", ""]
    for t in found["transcripts"]:
        L.append("Transcripts: %s, %s files, %.1f MB." % (t["root"], "{:,}".format(t["files"]),
                                                        t["bytes"] / 1e6))
    if not found["transcripts"]:
        L.append("Transcripts: none found.")
    L.append("OS sandbox: %s." % ("macOS sandbox-exec available" if found["os_sandbox"] else
                                  "not available (hooks run with a temp HOME and clean environment only)"))
    L += ["", "## PreToolUse hooks (replay with --detected ID)", ""]
    if not found["hooks"]:
        L.append("None configured.")
    for h in found["hooks"]:
        L.append("- %s  matcher=%s  %s" % (report.inline(h["id"]), report.code(h["matcher"]),
                                           "approved" if h["approved"] else "not approved"))
        L.append(report.fence([h["command"] or " ".join(h["args"] or [])]))
    L += ["", "## Guards dryfire can read", ""]
    L.append("- checkrein installs: %d (replay with --checkrein)" % len(found["checkrein"]))
    L.append("- destructive_command_guard packs: %d (replay with --dcg or --dcg-pack FILE)" %
             len(found["dcg"]["packs"]))
    sn = found["safetynet"]
    L.append("- cc-safety-net: %d rule.json, %d rulebooks, %d inline configs (replay with --safetynet)" % (
        len(sn["rule_files"]), len(sn["rulebooks"]), len(sn["legacy"])))
    out.write("\n".join(L) + "\n")
    return 0


def _clean_strings(value, clean):
    """value with every string in it (lists and dict values, at any depth) passed through clean."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, list):
        return [_clean_strings(v, clean) for v in value]
    if isinstance(value, dict):
        return {k: _clean_strings(v, clean) for k, v in value.items()}
    return value


def _roots(env, eff):
    roots = transcripts.default_roots(env.home, env.environ)
    if eff is not None:
        for extra in eff.values.get("transcript_roots") or []:
            p = os.path.expanduser(extra)
            if os.path.isdir(p) and os.path.realpath(p) not in {os.path.realpath(r) for r in roots}:
                roots.append(p)
    return roots


def _window(eff):
    until = datetime.datetime.now(datetime.timezone.utc)
    since = until - datetime.timedelta(days=eff.values["window_days"])
    return since, until


def cmd_scan(args, env, out, eff):
    roots = _roots(env, eff)
    if not roots:
        raise Fail("no transcripts found under ~/.claude/projects")
    since, until = _window(eff)
    stats = transcripts.Stats()
    scope = env.project_dir if eff.values["scope"] == "project" else None
    by_tool, days, places, distinct = {}, set(), set(), set()
    total = 0
    clean, names = redact.Redactor.for_settings(env.home, eff.values).clean, {}
    for call in transcripts.read_calls(roots, since=since, until=until, project_dir=scope, stats=stats):
        total += 1
        if call.tool not in names:
            names[call.tool] = clean(call.tool, limit=80)  # Tool names come from transcripts: untrusted.
        tool = names[call.tool]
        by_tool[tool] = by_tool.get(tool, 0) + 1
        if call.day:
            days.add(call.day)
        places.add(call.cwd or call.project)
        distinct.add(replay.key_of(call.tool, call.input))
    summary = {"window_days": eff.values["window_days"], "since": since.strftime("%Y-%m-%d"),
               "until": until.strftime("%Y-%m-%d"), "calls": total, "distinct_calls": len(distinct),
               "active_days": len(days), "folders": len(places),
               "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -kv[1])), "reader": stats.as_dict()}
    if args.json:
        out.write(json.dumps(summary, indent=2) + "\n")
        return 0
    L = ["# dryfire scan", "",
         "%s tool calls (%s distinct) on %s active days in %s folders, %s to %s." % (
             "{:,}".format(total), "{:,}".format(len(distinct)), len(days), len(places), summary["since"],
             summary["until"]), "",
         "| Tool | Calls |", "|---|---:|"]
    for tool, n in list(summary["by_tool"].items())[:25]:
        L.append("| %s | %s |" % (report.inline(tool, 80), "{:,}".format(n)))
    out.write("\n".join(L) + "\n")
    return 0


def _sandbox_text(mode, any_hooks):
    if not any_hooks:
        return "not needed (no hook code runs)"
    if mode == "os":
        return "macOS sandbox (no network, writes only to a temp folder, no reads of your home folder) " \
               "with a temp HOME and clean environment"
    return "temp HOME and clean environment only (no OS sandbox)"


def build_guards(args, env, eff):
    sel = select_hooks(args, env, eff)
    select_rules(args, env, sel)
    if not sel.hooks and not sel.rule_guards:
        raise Fail("choose at least one guard: --hook CMD, --use NAME, --detected ID, --checkrein [PATH], "
                   "--dcg-pack FILE, --safetynet [PATH] or --pack FILE (run detect to see what is installed)")
    return sel


def cmd_replay(args, env, out, eff):
    sel = build_guards(args, env, eff)
    redactor = redact.Redactor.for_settings(env.home, eff.values)
    missing = unapproved(sel, env)
    if missing:
        raise Fail(approval_help(missing, args, env, redactor), EXIT_UNAPPROVED)
    mode = "env"
    if sel.hooks:
        try:
            mode = sandbox.mode_for(eff.values["sandbox"])
        except sandbox.SandboxUnavailable as exc:
            raise Fail(str(exc), EXIT_SANDBOX)
    guards = list(sel.rule_guards)
    for name, spec, _pdir, label, rx in sel.hooks:
        guards.append(HookGuard(name, spec, env.home, timeout=eff.values["timeout_seconds"], sandbox_mode=mode,
                                allow_read=eff.values["allow_read"], rule_rx=rx, label=label))
    guards.sort(key=lambda g: g.runs_code)
    if args.out:
        _check_out(args.out, env, args.force)
    roots = _roots(env, eff)
    if not roots:
        raise Fail("no transcripts found under ~/.claude/projects")
    since, until = _window(eff)
    stats = transcripts.Stats()
    scope = env.project_dir if eff.values["scope"] == "project" else None
    progress = None if args.quiet else replay.stderr_progress
    if progress:
        progress("dryfire: reading %d days of transcripts..." % eff.values["window_days"])

    def read(stats):
        return transcripts.read_calls(roots, since=since, until=until,
                                      accept_tool=lambda t: any(g.accepts(t) for g in guards),
                                      project_dir=scope, stats=stats)

    pmode = eff.values["permission_mode"]
    # max_calls bounds how much hook code runs; rules cost little, so a rules-only run reads everything.
    # With hooks, the first read keeps only keys and counts and a second read fetches the inputs of the
    # calls kept, so a year of large Write calls is never loaded together.
    uniques = replay.collect(read(stats), pmode, keep_inputs=not sel.hooks)
    kept, skipped_distinct, skipped_calls = replay.select(uniques, eff.values["max_calls"] if sel.hooks else 0)
    del uniques
    if sel.hooks:
        gone = replay.fill_inputs(kept, read(transcripts.Stats()), pmode)
        if gone:
            kept = [u for u in kept if u.input is not None]
            sel.notes.append("%d distinct calls were left out: their transcripts changed while dryfire read "
                             "them" % len(gone))
    if progress:
        progress("dryfire: %s calls, %s distinct; replaying..." % (
            "{:,}".format(sum(u.count for u in kept)), "{:,}".format(len(kept))))
    results = replay.run(guards, kept, eff.values["workers"], progress)
    run_info = {
        "dryfire": __version__,
        "since": since.strftime("%Y-%m-%d"), "until": until.strftime("%Y-%m-%d"),
        "window_days": eff.values["window_days"], "preset": eff.values["preset"],
        "scope": eff.values["scope"],
        "sandbox_text": _sandbox_text(mode, bool(sel.hooks)), "permission_mode": eff.values["permission_mode"],
        "skipped_distinct": skipped_distinct, "skipped_calls": skipped_calls, "reader": stats.as_dict(),
        "notes": [redactor.clean(n, limit=400) for n in eff.notes + sel.notes + redactor.errors],
    }
    summary = report.build(run_info, guards, kept, results, redactor, eff.values["samples"])
    text = json.dumps(summary, indent=2) + "\n" if args.json else report.markdown(summary)
    if args.out:
        _write_out(args.out, text)
        for g in summary["guards"]:
            out.write(report.inline(report.headline(summary, g), 400) + "\n")
            warning = report.failure_warning(g)
            if warning:
                out.write(report.inline(warning, 400) + "\n")
        out.write("Report written to %s\n" % redactor.clean(os.path.abspath(os.path.expanduser(args.out))))
    else:
        out.write(text)
    return 0


def _protected(env):
    return [env.data_dir, os.path.join(env.home, ".claude", "dryfire"), selfguard.PLUGIN_ROOT]


def _check_out(path, env, force):
    full = os.path.abspath(os.path.expanduser(path))
    real = os.path.realpath(full)
    for d in _protected(env):
        if context.inside(full, d) or context.inside(real, os.path.realpath(d)):
            raise Fail("--out: dryfire does not write reports into its own folder (%s)" % d)
    if not os.path.isdir(os.path.dirname(full)):
        raise Fail("--out: folder %s does not exist" % os.path.dirname(full))
    if os.path.exists(full) and not force:
        raise Fail("--out: %s exists; pass --force to replace it" % full)


def _write_out(path, text):
    """Write through a new temp file of our own, so nothing planted beside the target is followed."""
    import tempfile

    full = os.path.abspath(os.path.expanduser(path))
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(full) + ".", suffix=".dryfire-tmp",
                               dir=os.path.dirname(full))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, full)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def cmd_approve(args, env, out, eff):
    clean = redact.Redactor.for_settings(env.home, eff.values).clean
    if args.list:
        data = approve.load(env.data_dir)
        if not data:
            out.write("Nothing is approved yet.\n")
        for fp, e in sorted(data.items(), key=lambda kv: kv[1].get("approved_at", "")):
            value = e.get("value")
            shown = value.get("command") or " ".join(value.get("args") or []) if isinstance(value, dict) else value
            out.write("%s  %s  %s  %s%s\n" % (fp[:12], e.get("approved_at", "?"), e.get("key", "?"),
                                              clean(str(shown), limit=200),
                                              "  (project %s)" % clean(e["project"]) if e.get("project") else ""))
        return 0
    if args.revoke:
        target = args.revoke
        if target != "all" and len(target) < 8:
            raise Fail("--revoke needs at least 8 characters of a fingerprint (see approve --list), or all")
        # The same lock grant() holds, so a revoke and an approval at the same time can't undo each other.
        with ledger.locked(env.data_dir, "approvals"):
            data = approve.load(env.data_dir)
            gone = [fp for fp in data if target == "all" or fp.startswith(target)]
            if not gone:
                raise Fail("nothing approved matches %r" % target)
            for fp in gone:
                del data[fp]
            ledger.write_json_atomic(os.path.join(env.data_dir, "approvals.json"), data)
        out.write("Revoked %d approval(s).\n" % len(gone))
        return 0
    sel = select_hooks(args, env, eff)
    if not sel.hooks:
        raise Fail("approve needs the hooks to approve: --hook CMD, --use NAME, --detected ID or --checkrein")
    for name, spec, pdir, _label, _rx in sel.hooks:
        d = describe_hook_for_approval(spec, env.home)
        value = spec.approval_value(env.home)  # Checked and granted as one value, so nothing changes between.
        unbound = unbound_files(value)
        if unbound:
            raise Fail("%s names more file content than one approval can bind (%d MB in all), so it was not "
                       "approved: %s" % (name, MAX_HASHED_BYTES >> 20, clean(", ".join(unbound), limit=300)))
        fp = approve.grant(env.data_dir, pdir, "hook", value)
        out.write("Approved %s [%s]: %s\n" % (name, fp[:12],
                                             clean(d["runs_as"] or " ".join(d["args"] or []), limit=300)))
    return 0


# Arguments.

def _add_common(p):
    p.add_argument("--data", default="", help="dryfire's data folder (approvals, config)")
    p.add_argument("--project", default="", help="the project folder (default: CLAUDE_PROJECT_DIR or here)")
    p.add_argument("--json", action="store_true", help="JSON instead of Markdown")


def _add_window(p):
    p.add_argument("--preset", choices=sorted(cfg.PRESETS), help="quick, standard or deep")
    p.add_argument("--window-days", type=int, help="days of history to read")
    p.add_argument("--scope", choices=cfg.ORDERS["scope"], help="all projects, or only this project")


def _add_selection(p):
    g = p.add_argument_group("hooks (each needs your approval before it runs)")
    g.add_argument("--hook", action="append", metavar="CMD", help="a hook command, as in settings.json")
    g.add_argument("--matcher", help="matcher for --hook (default: Bash)")
    g.add_argument("--plugin-root", help="CLAUDE_PLUGIN_ROOT for --hook")
    g.add_argument("--use", action="append", metavar="NAME", help="a hook from dryfire's config, or all")
    g.add_argument("--detected", action="append", metavar="ID", help="a hook found by detect, or all")
    g.add_argument("--checkrein", nargs="?", const="", metavar="PATH",
                   help="checkrein's hook (installed copy, or a checkout folder)")
    g.add_argument("--checkrein-preset", metavar="LIST", help="relaxed, standard, strict (comma list)")
    g.add_argument("--checkrein-config", metavar="FILE", help="a checkrein config.json to replay with")


def parser():
    # No abbreviated options: selfguard reads --data by its full name, so '--dat X' must not mean --data.
    ap = argparse.ArgumentParser(prog="dryfire", description="Replay a guard against your past tool calls.",
                                 allow_abbrev=False)
    ap.add_argument("--version", action="version", version="dryfire " + __version__)
    sub = ap.add_subparsers(dest="command")
    p = sub.add_parser("detect", allow_abbrev=False, help="list transcripts, hooks and rule files dryfire can replay")
    _add_common(p)
    p = sub.add_parser("scan", allow_abbrev=False, help="count past tool calls (no commands shown)")
    _add_common(p)
    _add_window(p)
    p = sub.add_parser("replay", allow_abbrev=False, help="replay guards against past calls and report what they would do")
    _add_common(p)
    _add_window(p)
    _add_selection(p)
    r = p.add_argument_group("rules (evaluated by dryfire, nothing runs)")
    r.add_argument("--dcg", action="store_true", help="destructive_command_guard packs in ~/.config/dcg")
    r.add_argument("--dcg-pack", action="append", metavar="FILE", help="a destructive_command_guard YAML pack")
    r.add_argument("--safetynet", nargs="?", const="", metavar="PATH",
                   help="cc-safety-net rules (found automatically, or a rulebook/rule.json/config path)")
    r.add_argument("--pack", action="append", metavar="FILE", help="a dryfire JSON rule pack")
    o = p.add_argument_group("run")
    o.add_argument("--max-calls", type=int, help="most distinct calls to replay (most recent kept)")
    o.add_argument("--timeout", type=int, help="seconds per hook call (can only lower the configured value)")
    o.add_argument("--sandbox", choices=cfg.ORDERS["sandbox"], help="can only make the sandbox stricter")
    o.add_argument("--workers", type=int, help="hooks run in parallel")
    o.add_argument("--samples", type=int, help="sample calls per rule")
    o.add_argument("--permission-mode", help="permission_mode sent to hooks, or as-recorded")
    o.add_argument("--out", help="write the report to this file and print only the headline")
    o.add_argument("--force", action="store_true", help="replace an existing --out file")
    o.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    p = sub.add_parser("approve", allow_abbrev=False, help="approve hooks to run (or list and revoke approvals)")
    _add_common(p)
    _add_selection(p)
    p.add_argument("--list", action="store_true", help="list approvals")
    p.add_argument("--revoke", metavar="FINGERPRINT", help="revoke an approval (8+ characters), or all")
    return ap


def _flags(args):
    names = {"preset": "preset", "window_days": "window_days", "scope": "scope", "max_calls": "max_calls",
             "timeout": "timeout_seconds", "sandbox": "sandbox", "workers": "workers", "samples": "samples",
             "permission_mode": "permission_mode"}
    return {key: getattr(args, attr) for attr, key in names.items() if getattr(args, attr, None) is not None}


def main(argv=None, out=None, err=None):
    out = out or sys.stdout
    err = err or sys.stderr
    ap = parser()
    args = ap.parse_args(argv)
    if not args.command:
        ap.print_help(err)
        return 2
    env = Env(args)
    try:
        if args.command == "detect":
            return cmd_detect(args, env, out)
        eff = cfg.resolve(env.data_dir, env.project_dir, _flags(args), env.environ)
        if args.command == "scan":
            return cmd_scan(args, env, out, eff)
        if args.command == "replay":
            return cmd_replay(args, env, out, eff)
        return cmd_approve(args, env, out, eff)
    except cfg.ConfigError as exc:
        # The message quotes config values, and a config file is not ours to trust: mask it like a report.
        err.write("dryfire: config: %s\n" % redact.Redactor(env.home).clean(str(exc), limit=2000))
        return EXIT_ERROR
    except Fail as exc:
        err.write("dryfire: %s\n" % exc)
        return exc.code
    except KeyboardInterrupt:
        err.write("dryfire: stopped\n")
        return 130
