"""Finding trajrl, its version, and the argv of the account-wide calls."""

import os

import pytest

import trajrl
from trajrl import Client, Sandbox, TrajrlNotFound

from conftest import VERSION, fixture


def test_version_is_checked_first(fake):
    c = fake.client()
    assert c.version == "0.2.0" and c.min_entry == "0.2.0"
    assert c.trajrl_bin == str(fake.bin)
    assert fake.argvs() == [["version", "--json"]]


def test_one_version():
    assert trajrl.__version__ == "0.4.0"


# The missing binary.


def test_no_trajrl_on_path(fake, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    with pytest.raises(TrajrlNotFound, match="not on PATH: install it"):
        Client()


def test_trajrl_bin_not_there(fake, tmp_path):
    with pytest.raises(TrajrlNotFound, match="not an executable file"):
        Client(trajrl_bin=tmp_path / "nowhere" / "trajrl")


def test_trajrl_bin_env_not_there(fake, monkeypatch, tmp_path):
    monkeypatch.setenv("TRAJRL_BIN", str(tmp_path / "nowhere"))
    with pytest.raises(TrajrlNotFound, match=r"\$TRAJRL_BIN"):
        Client()


def test_found_on_path(fake, monkeypatch):
    monkeypatch.setenv("PATH", str(fake.dir) + os.pathsep + os.environ["PATH"])
    assert Client().trajrl_bin == str(fake.dir / "trajrl")


def test_trajrl_bin_env_before_path(fake, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setenv("TRAJRL_BIN", str(fake.bin))
    assert Client().trajrl_bin == str(fake.bin)


def test_argument_before_env(fake, monkeypatch):
    monkeypatch.setenv("TRAJRL_BIN", "/nonexistent/trajrl")
    assert Client(trajrl_bin=fake.bin).version == "0.2.0"


def test_a_trajrl_without_json(fake):
    # trajrl 0.2.0 before --json: "trajrl 0.2.0" on stdout.
    fake.on("version", "--json", stdout="trajrl 0.2.0\n")
    with pytest.raises(TrajrlNotFound, match="did not answer version --json"):
        fake.client()


def test_another_program_named_trajrl(fake):
    # PyPI's "trajrl" is another project's CLI; it refuses --json.
    fake.on("version", "--json", stderr="Error: No such option: --json\n", exit=2)
    with pytest.raises(TrajrlNotFound, match="No such option"):
        fake.client()


# Account-wide calls.


def test_status(fake, client):
    fake.on("status", "--json", json=fixture("status.json"))
    st = client.status()
    assert st["configured"] is True
    assert st["sandboxes"][0]["next"] == "trajrl unlock web"


def test_status_not_set_up_is_a_report(fake, client):
    # trajrl status --json exits 1 on a machine not set up, with the report.
    fake.on("status", "--json", json=fixture("status-not-set-up.json"), exit=1)
    assert client.status()["configured"] is False


def test_doctor_failing_check_is_a_report(fake, client):
    fake.on("doctor", "--json", json=fixture("doctor.json"), exit=1)
    rep = client.doctor()
    assert rep["ok"] is False and rep["checks"][2]["fix"]


def test_doctor_transport_raises(fake, client):
    fake.on("doctor", "--json", stderr='{"error": "cannot read config", "code": 255}\n', exit=255)
    with pytest.raises(trajrl.TransportError):
        client.doctor()


def test_list(fake, client):
    fake.on("ls", "--json", json=fixture("ls.json"))
    sbs = client.sandboxes.list()
    assert [(s.name, s.state) for s in sbs] == [("web", "running"), ("web2", "running")]
    assert all(isinstance(s, Sandbox) for s in sbs)
    assert sbs[0].data["host_key"] == "ssh-ed25519 AAAAguestkey"
    assert sbs[0].id == "sbx-0000000000000001"


def test_get_and_refresh(fake, client):
    fake.on("show", "web", "--json", json=fixture("show-web.json"))
    sb = client.sandboxes.get("web")
    assert sb.name == "web" and sb.state == "running"
    fake.on("show", "web", "--json", json=dict(fixture("show-web.json"), state="stopped"))
    assert sb.refresh().state == "stopped"
    assert fake.argvs()[1:] == [["show", "web", "--json"]] * 2


@pytest.mark.parametrize("name", ["", "-rf", "two words", "tab\tname", None])
def test_names_that_are_not_one_word(client, name):
    with pytest.raises(ValueError):
        client.sandboxes.get(name)


def test_create(fake, client):
    fake.on("new", "web", "--size", "small", "--disk", "16", "--image", "stable", "--json", json=fixture("boot.json"))
    sb = client.sandboxes.create("web", size="small", disk=16, image="stable")
    assert (sb.name, sb.state) == ("web", "running")
    assert sb.last_boot["verified"] is True and sb.last_boot["boot"] == 1


def test_create_defaults(fake, client):
    fake.on("new", "web", "--json", json=dict(fixture("boot.json"), state=None, verified=None))
    sb = client.sandboxes.create("web")
    assert sb.state is None and sb.last_boot["verified"] is None
    assert fake.argvs()[-1] == ["new", "web", "--json"]


def test_stdin_is_devnull(fake, client):
    fake.on("ls", "--json", json=[])
    client.sandboxes.list()
    assert all(c["stdin_devnull"] for c in fake.calls())
