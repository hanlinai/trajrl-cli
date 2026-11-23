"""A sandbox's commands: their argv, exec's NDJSON, cp, the passphrase file."""

import base64
import os

import pytest

from trajrl import CommandFailed, ExecEvent, ExecResult, NeedsOwner, TrajrlError, TransportError, UsageError

from conftest import fixture


def b64(s):
    return base64.b64encode(s if isinstance(s, bytes) else s.encode()).decode()


# Lifecycle argv.


def test_lifecycle_argv(fake, web):
    fake.on("start", "web", "--json", json=fixture("boot.json"))
    fake.on("unlock", "web", "--json", json=fixture("boot.json"))
    stopped = dict(fixture("show-web.json"), state="stopped")
    fake.on("stop", "web", "--json", json=stopped)
    fake.on("wait", "web", "--json", json=fixture("show-web.json"))
    fake.on("wait", "web", "--json", "--timeout", "90s", json=fixture("show-web.json"))
    fake.on("rm", "web", "--yes", "--json", json={"removed": "web", "note": "its disk and VM are deleted"})

    assert web.stop()["state"] == "stopped" and web.state == "stopped"
    assert web.start()["verified"] is True and web.state == "running"
    assert web.last_boot["host_key_sha256"].startswith("SHA256:")
    assert web.unlock()["boot"] == 1
    assert web.wait()["state"] == "running"
    web.wait(timeout=90)
    assert web.remove() == {"removed": "web", "note": "its disk and VM are deleted"}
    assert fake.argvs()[2:] == [
        ["stop", "web", "--json"],
        ["start", "web", "--json"],
        ["unlock", "web", "--json"],
        ["wait", "web", "--json"],
        ["wait", "web", "--json", "--timeout", "90s"],
        ["rm", "web", "--yes", "--json"],
    ]


# The passphrase file.


def test_passphrase_file_argument(fake, tmp_path):
    pf = tmp_path / "pass"
    pf.write_text("secret\n")
    c = fake.client(passphrase_file=pf)
    fake.on("show", "web", "--json", json=fixture("show-web.json"))
    fake.on("unlock", "web", "--json", json=fixture("boot.json"))
    c.sandboxes.get("web").unlock()
    assert {x["passphrase_file"] for x in fake.calls()} == {str(pf)}


def test_passphrase_file_relative_is_made_absolute(fake, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fake.client(passphrase_file="pass")
    assert fake.calls()[-1]["passphrase_file"] == str(tmp_path / "pass")


def test_passphrase_file_from_environment(fake, monkeypatch):
    monkeypatch.setenv("TRAJRL_PASSPHRASE_FILE", "/home/owner/.trajrl-pass")
    fake.client()
    assert fake.calls()[-1]["passphrase_file"] == "/home/owner/.trajrl-pass"


def test_passphrase_file_argument_wins(fake, monkeypatch, tmp_path):
    monkeypatch.setenv("TRAJRL_PASSPHRASE_FILE", "/home/owner/.trajrl-pass")
    fake.client(passphrase_file=tmp_path / "other")
    assert fake.calls()[-1]["passphrase_file"] == str(tmp_path / "other")


def test_no_passphrase_file(fake):
    fake.client()
    assert fake.calls()[-1]["passphrase_file"] is None


def test_missing_passphrase_needs_owner(fake, web):
    # docs/cli.md, "The owner key's passphrase".
    msg = "the owner key needs its passphrase: give -passphrase-file or TRAJRL_PASSPHRASE_FILE"
    fake.on("start", "web", "--json", stderr='{"error": "%s", "code": 3}\n' % msg, exit=3)
    with pytest.raises(NeedsOwner) as e:
        web.start()
    assert e.value.message == msg and e.value.error_code == 3


# exec: argv, NDJSON.


def test_exec_argv_no_shell(fake, web):
    cmd = ["sh", "-c", "echo $HOME; ls * | wc -l", "--json", "-timeout"]
    fake.on("exec", "web", "--json", "-cwd", "/srv", "-e", "A=1", "-e", "B=x y=z", "-timeout", "30", "--", *cmd,
            lines=[{"exit_code": 0}])
    web.exec(cmd, cwd="/srv", env={"A": "1", "B": "x y=z"}, timeout=30)
    call = fake.calls()[-1]
    assert call["argv"] == ["exec", "web", "--json", "-cwd", "/srv", "-e", "A=1", "-e", "B=x y=z",
                            "-timeout", "30", "--", *cmd]
    assert call["stdin_devnull"]


def test_exec_minimal_argv(fake, web):
    fake.on("exec", "web", "--json", "--", "true", lines=[{"exit_code": 0}])
    assert web.exec(["true"]) == ExecResult(b"", b"", 0, None)


def test_exec_documented_lines(fake, web):
    # docs/cli.md, "For programs": trajrl exits with the command's status.
    fake.on("exec", "web", "--json", "--", "sh", "-c", "x", stdout=(
        '{"stdout":"aGVsbG8K"}\n{"stderr":"YSB3YXJuaW5nCg=="}\n{"exit_code":7}\n'), exit=7)
    assert web.exec(["sh", "-c", "x"]) == ExecResult(b"hello\n", b"a warning\n", 7, None)


def test_exec_decodes_base64(fake, web):
    fake.on("exec", "web", "--json", "--", "make", lines=[
        {"stdout": b64("building\n")},
        {"stderr": b64(b"warn\xff\n")},
        {"stdout": b64("done\n")},
        {"exit_code": 2},
    ])
    r = web.exec(["make"])
    assert r == ExecResult(b"building\ndone\n", b"warn\xff\n", 2, None)


def test_exec_stream_events(fake, web):
    fake.on("exec", "web", "--json", "--", "sleep", "999", lines=[
        {"stdout": b64("a")},
        {"stderr": b64("b")},
        {"error": "the command ran out of time (300s) and was killed"},
        {"exit_code": 137},
    ])
    events = list(web.exec_stream(["sleep", "999"]))
    assert events == [
        ExecEvent("stdout", b"a"),
        ExecEvent("stderr", b"b"),
        ExecEvent("error", "the command ran out of time (300s) and was killed"),
        ExecEvent("exit", 137),
    ]
    assert events[-1] == ("exit", 137)
    r = web.exec(["sleep", "999"])
    assert r.exit_code == 137 and r.error.startswith("the command ran out")


def test_exec_nonzero_exit_status_of_trajrl_is_the_command(fake, web):
    # trajrl exits with the command's code; the exit_code line says it is one.
    fake.on("exec", "web", "--json", "--", "false", lines=[{"exit_code": 255}], exit=255)
    assert web.exec(["false"]).exit_code == 255


def test_exec_stdin(fake, web):
    fake.on("exec", "web", "--json", "-stdin", "--", "cat", echo_stdin=True, lines=[{"exit_code": 0}])
    assert web.exec(["cat"], stdin=b"hello\x00world").stdout == b"hello\x00world"
    assert web.exec(["cat"], stdin="text").stdout == b"text"
    call = fake.calls()[-1]
    assert not call["stdin_devnull"] and call["stdin"] == "text"


def test_exec_api_unreachable(fake, web):
    fake.on("exec", "web", "--json", "--", "true",
            stderr='{"error": "dial tcp: connect: connection refused", "code": 255}\n', exit=255)
    with pytest.raises(TransportError, match="connection refused"):
        web.exec(["true"])


def test_exec_no_pin_is_a_failure(fake, web):
    # A refusal or a missing pin is 1, not 255.
    fake.on("exec", "web", "--json", "--", "true",
            stderr='{"error": "web: no record of its host key: run trajrl verify web", "code": 1}\n', exit=1)
    with pytest.raises(CommandFailed, match="run trajrl verify web"):
        web.exec(["true"])


def test_exec_sandbox_waiting_for_its_owner(fake, web):
    fake.on("exec", "web", "--json", "--", "true",
            stderr='{"error": "web waits for its owner\'s key: run trajrl unlock web", "code": 3}\n', exit=3)
    with pytest.raises(NeedsOwner):
        web.exec(["true"])


def test_exec_usage_error(fake, web):
    fake.on("exec", "web", "--json", "-timeout", "900", "--", "true",
            stderr='{"error": "-timeout: at most 300", "code": 2}\n', exit=2)
    with pytest.raises(UsageError):
        list(web.exec_stream(["true"], timeout=900))


def test_exec_reply_without_exit_code(fake, web):
    fake.on("exec", "web", "--json", "--", "true", lines=[{"stdout": b64("x")}])
    with pytest.raises(TransportError, match="without an exit code"):
        web.exec(["true"])


def test_exec_bad_lines(fake, web):
    fake.on("exec", "web", "--json", "--", "a", stdout="not json\n")
    with pytest.raises(TrajrlError, match="not JSON"):
        web.exec(["a"])
    fake.on("exec", "web", "--json", "--", "b", lines=[{"stdout": "%%%"}, {"exit_code": 0}])
    with pytest.raises(TrajrlError, match="not base64"):
        web.exec(["b"])


def test_exec_timeout(fake, tmp_path):
    c = fake.client(timeout=0.5)
    fake.on("show", "web", "--json", json=fixture("show-web.json"))
    fake.on("exec", "web", "--json", "--", "x", lines=[{"stdout": b64("early")}], sleep=5)
    with pytest.raises(TransportError, match="did not finish within 0.5s"):
        c.sandboxes.get("web").exec(["x"])


def test_exec_stream_stopped_early(fake, web):
    fake.on("exec", "web", "--json", "--", "yes", lines=[{"stdout": b64("y\n")}] * 3 + [{"exit_code": 0}])
    it = web.exec_stream(["yes"])
    assert next(it) == ("stdout", b"y\n")
    it.close()  # ends the trajrl process


def test_exec_argv_must_be_a_list(web):
    with pytest.raises(TypeError, match="list of words"):
        web.exec("ls -l")
    with pytest.raises(ValueError):
        web.exec([])
    with pytest.raises(ValueError):
        web.exec(["env"], env={"A=B": "1"})


# cp.


def test_upload(fake, web, tmp_path):
    local = tmp_path / "app.tar"
    local.write_bytes(b"x" * 10)
    fake.on("cp", str(local), "web:/srv/app.tar", "--json", json={"direction": "in", "path": "/srv/app.tar", "bytes": 10})
    assert web.upload(local, "/srv/app.tar") == 10


def test_download(fake, web, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fake.on("cp", "web:/var/log/app.log", str(tmp_path / "app.log"), "--json",
            json={"direction": "out", "path": str(tmp_path / "app.log"), "bytes": 5},
            write={"path": str(tmp_path / "app.log"), "data": "hello"})
    assert web.download("/var/log/app.log", "app.log") == 5  # relative: made absolute
    assert (tmp_path / "app.log").read_text() == "hello"


def test_cp_paths(web, tmp_path):
    with pytest.raises(ValueError, match="absolute"):
        web.upload(tmp_path / "f", "relative/path")
    with pytest.raises(ValueError, match="path in a sandbox"):
        web.download("/etc/hosts", "/tmp/x:/y")


def test_cp_failure(fake, web, tmp_path):
    fake.on("cp", "web:/nope", str(tmp_path / "out"), "--json",
            stderr='{"error": "/nope: no such file", "code": 1}\n', exit=1)
    with pytest.raises(TrajrlError, match="no such file"):
        web.download("/nope", tmp_path / "out")
    assert not os.path.exists(tmp_path / "out")
