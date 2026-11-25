"""Approvals for project-config values that run a command or loosen a rule.

An approval is bound to the project folder, the key and the exact value, so a
changed value needs a new approval. Approvals live in the plugin data folder,
which the SLF01 rule protects from edits by the agent.
"""

import hashlib
import json
import os
import time

from . import ledger


def _path(data_dir):
    return os.path.join(data_dir, "approvals.json")


def fingerprint(project_dir, key, value):
    root = os.path.realpath(project_dir) if project_dir else ""
    blob = json.dumps([root, key, value], sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def load(data_dir):
    if not data_dir:
        return {}
    try:
        with open(_path(data_dir)) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except ValueError:
        return {}  # A corrupt file approves nothing.
    return data if isinstance(data, dict) else {}


def is_approved(data_dir, project_dir, key, value):
    return fingerprint(project_dir, key, value) in load(data_dir)


def grant(data_dir, project_dir, key, value):
    fp = fingerprint(project_dir, key, value)
    os.makedirs(data_dir, exist_ok=True)
    with ledger.locked(data_dir, "approvals"):
        data = load(data_dir)
        data[fp] = {
            "key": key,
            "value": value,
            "project": os.path.realpath(project_dir) if project_dir else "",
            "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        ledger.write_json_atomic(_path(data_dir), data)
    return fp
