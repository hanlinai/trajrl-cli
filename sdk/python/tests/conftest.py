import json
import os
import stat
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"

VERSION = {"version": "0.2.0", "min_entry": "0.2.0"}


def fixture(name):
    """A JSON fixture. ls.json and show-web.json are the Go goldens
    internal/control/testdata/plain/ls-json.txt and show-web-json.txt, their
    placeholders filled in; the others are the shapes of cmd/trajrl's
    status/doctor, internal/cli/verifycmd's Verdict, and the contract's
    new/start/unlock answer."""
    return json.loads((FIXTURES / name).read_text())


class Fake:
    """A fake trajrl: bin is its path (named trajrl, in a directory of its
    own); on() gives the answer to an argv; calls() are its runs."""

    def __init__(self, tmp_path, monkeypatch):
        self.dir = tmp_path / "bin"
        self.dir.mkdir()
        self.bin = self.dir / "trajrl"
        self.bin.write_text(
            "#!" + sys.executable + "\n" + (HERE / "fake_trajrl.py").read_text()
        )
        self.bin.chmod(self.bin.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.log = tmp_path / "calls.ndjson"
        self.answers_file = tmp_path / "answers.json"
        self.answers = {}
        monkeypatch.setenv("FAKE_TRAJRL_LOG", str(self.log))
        monkeypatch.setenv("FAKE_TRAJRL_ANSWERS", str(self.answers_file))
        monkeypatch.delenv("TRAJRL_BIN", raising=False)
        monkeypatch.delenv("TRAJRL_PASSPHRASE_FILE", raising=False)
        self.on("version", "--json", json=VERSION)

    def on(self, *argv, json=None, **answer):
        if json is not None:
            answer["stdout"] = _dumps(json)
        self.answers[" ".join(str(a) for a in argv)] = answer
        self.answers_file.write_text(_dumps(self.answers))

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def argvs(self):
        return [c["argv"] for c in self.calls()]

    def client(self, **kw):
        from trajrl import Client

        return Client(trajrl_bin=str(self.bin), **kw)


def _dumps(v):
    return json.dumps(v)


@pytest.fixture
def fake(tmp_path, monkeypatch):
    return Fake(tmp_path, monkeypatch)


@pytest.fixture
def client(fake):
    return fake.client()


@pytest.fixture
def web(fake, client):
    fake.on("show", "web", "--json", json=fixture("show-web.json"))
    return client.sandboxes.get("web")
