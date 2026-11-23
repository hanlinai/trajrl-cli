"""trajrl's exit status and error, as exceptions."""

import pytest

from trajrl import (
    CommandFailed,
    NeedsOwner,
    NotVerified,
    SandboxNotFound,
    SandboxNotRunning,
    TransportError,
    TrajrlError,
    UsageError,
)

from conftest import fixture


@pytest.mark.parametrize(
    "status, cls",
    [(1, CommandFailed), (2, UsageError), (3, NeedsOwner), (255, TransportError), (7, CommandFailed)],
)
def test_exit_status(fake, web, status, cls):
    fake.on("start", "web", "--json", stderr='{"error": "it went wrong", "code": "x"}\n', exit=status)
    with pytest.raises(cls) as e:
        web.start()
    assert type(e.value) is cls
    assert e.value.code == status
    assert e.value.message == "it went wrong"
    assert e.value.error_code == "x"
    assert e.value.argv == [str(fake.bin), "start", "web", "--json"]


def test_json_error_among_human_text(fake, web):
    fake.on(
        "unlock", "web", "--json",
        stderr='checking the TD of web...\n{"error": "the key file\'s passphrase: no terminal; give TRAJRL_PASSPHRASE_FILE", "code": 3}\n',
        exit=3,
    )
    with pytest.raises(NeedsOwner) as e:
        web.unlock()
    assert "passphrase" in e.value.message
    assert "checking the TD" in e.value.stderr


def test_platform_text_not_found(fake, client):
    # internal/control/testdata/plain/show-nosuch.txt
    fake.on("show", "nosuch", "--json", stderr='show: sandbox "nosuch": not found\n', exit=1)
    with pytest.raises(SandboxNotFound) as e:
        client.sandboxes.get("nosuch")
    assert e.value.message == 'show: sandbox "nosuch": not found'
    assert isinstance(e.value, CommandFailed)


def test_platform_text_not_running(fake, web):
    fake.on("stop", "web", "--json", stderr="stop: the sandbox is not running\n", exit=1)
    with pytest.raises(SandboxNotRunning):
        web.stop()


def test_wait_for_the_owner(fake, web):
    # internal/control/testdata/plain/owner-wait.txt: the platform's text.
    view = dict(fixture("show-web.json"), state="waiting for its owner's key")
    fake.on(
        "wait", "web", "--json", "--timeout", "1s",
        json=view,
        stderr="wait: web is waiting for its owner's key, which only its owner can give: run on your own machine: trajrl unlock web. Waiting for that.\n"
        "wait: web is still waiting for its owner's key after 1s: run on your own machine: trajrl unlock web\n",
        exit=1,
    )
    with pytest.raises(NeedsOwner) as e:
        web.wait(timeout=1)
    assert e.value.result["state"] == "waiting for its owner's key"


def test_other_failure_keeps_stdout(fake, web):
    fake.on("rm", "web", "--yes", "--json", stdout="", stderr="rm: the host did not answer\n", exit=1)
    with pytest.raises(CommandFailed) as e:
        web.remove()
    assert type(e.value) is CommandFailed and e.value.result is None


def test_silent_failure(fake, web):
    fake.on("stop", "web", "--json", exit=1)
    with pytest.raises(CommandFailed, match="exited with status 1"):
        web.stop()


def test_no_json_on_success(fake, web):
    fake.on("stop", "web", "--json", stdout="web stopped\n")
    with pytest.raises(TrajrlError, match="printed no JSON"):
        web.stop()


def test_timeout(fake):
    c = fake.client(timeout=0.5)
    fake.on("ls", "--json", json=[], sleep=5)
    with pytest.raises(TransportError, match="did not finish within 0.5s"):
        c.sandboxes.list()


# verify fails closed.


def test_verified(fake, web):
    fake.on("verify", "web", "--json", json=fixture("verify-verified.json"))
    assert web.verify()["quote"]["platform_tcb"] == "UpToDate"


def test_not_verified(fake, web):
    fake.on("verify", "web", "--json", json=fixture("verify-refused.json"),
            stderr="NOT VERIFIED: quote authenticity/TCB: ...\n", exit=1)
    with pytest.raises(NotVerified) as e:
        web.verify()
    assert e.value.result["verdict"] == "NOT VERIFIED"
    assert "OutOfDate" in e.value.message
    assert e.value.code == 1


def test_not_verified_with_status_zero(fake, web):
    # A rehearsal build: NOT VERIFIED, status 0.
    fake.on("verify", "web", "--json", json={"verdict": "NOT VERIFIED", "reason": "rehearsal", "sandbox_id": "x", "quote": None})
    with pytest.raises(NotVerified, match="rehearsal"):
        web.verify()


def test_verify_of_a_stopped_sandbox(fake, web):
    fake.on("verify", "web", "--json", stderr="verify: the sandbox is not running\n", exit=1)
    with pytest.raises(SandboxNotRunning):
        web.verify()
