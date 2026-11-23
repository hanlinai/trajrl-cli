"""Read-only smoke test against a real platform, with the real trajrl.

Runs only with TRAJRL_SMOKE=1, on a machine whose trajrl (TRAJRL_BIN, or
on PATH) is set up for an account with a sandbox TRAJRL_SMOKE_SANDBOX
(default web). It lists, shows, and asks status and doctor: it starts,
unlocks or creates nothing.

    TRAJRL_SMOKE=1 python -m pytest tests/test_smoke_stage.py -s
"""

import json
import os

import pytest

from trajrl import Client

pytestmark = pytest.mark.skipif(os.environ.get("TRAJRL_SMOKE") != "1", reason="TRAJRL_SMOKE=1 runs it")


def test_read_only_smoke():
    name = os.environ.get("TRAJRL_SMOKE_SANDBOX", "web")
    c = Client(timeout=120)
    print(f"\n{c!r}, min_entry {c.min_entry!r}")

    sbs = c.sandboxes.list()
    print("list:", sbs)
    assert name in [s.name for s in sbs]

    sb = c.sandboxes.get(name)
    print("get:", sb, sb.id, sb.data.get("reason"))
    assert sb.name == name and sb.state

    st = c.status()
    print("status:", json.dumps(st)[:600])
    assert st["configured"] is True
    assert name in [s["name"] for s in st["sandboxes"]]

    doc = c.doctor()
    for check in doc["checks"]:
        print(f"doctor: {check['status']:4}  {check['name']:12}  {check['message']}")
    assert isinstance(doc["ok"], bool)
