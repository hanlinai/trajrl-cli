"""A sandbox, and what trajrl does with one."""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union

from ._cli import Cli, PathLike
from .errors import CommandFailed, NotVerified, TrajrlError

# exec's flags, as trajrl exec --json takes them.
_EXEC_CWD = "-cwd"
_EXEC_ENV = "-e"
_EXEC_TIMEOUT = "-timeout"
_EXEC_STDIN = "-stdin"

# How much longer than a command's own time limit trajrl may take for it.
_GRACE = 60.0


class ExecEvent(NamedTuple):
    """One event of Sandbox.exec_stream: ("stdout", bytes), ("stderr", bytes),
    ("error", str) when the sandbox's API reports one (a command stopped at
    its time limit), and last ("exit", int)."""

    kind: str
    data: Union[bytes, str, int]


@dataclass
class ExecResult:
    """What Sandbox.exec ran gave: its output, its exit code, and the error
    the sandbox's API reported, if any (a command stopped at its time limit
    exits 137 with one)."""

    stdout: bytes
    stderr: bytes
    exit_code: int
    error: Optional[str] = None


def check_name(name: str) -> str:
    if not isinstance(name, str) or not name or name.startswith("-") or any(c.isspace() for c in name):
        raise ValueError(f"not a sandbox name: {name!r}")
    return name


def _remote_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError(f"a path in the sandbox is absolute: {path!r}")
    return path


def _local_path(path: PathLike) -> str:
    p = os.path.abspath(os.fspath(path))
    # trajrl cp takes NAME:/PATH for the sandbox's side.
    _, colon, rest = p.partition(":")
    if colon and rest.startswith("/"):
        raise ValueError(f"trajrl cp would read {p!r} as a path in a sandbox")
    return p


def _bytes(field: str, value: Any) -> bytes:
    if not isinstance(value, str):
        raise TrajrlError(f"exec's {field} is not a string: {value!r}")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise TrajrlError(f"exec's {field} is not base64: {value[:80]!r}") from None


class Sandbox:
    """A sandbox of the account trajrl is set up for, as trajrl last saw it.

    data is the platform's object for it (trajrl ls --json / show --json);
    refresh() asks again. Every method runs one trajrl command and returns
    what it printed, parsed; one that changes the sandbox also updates data
    where trajrl's answer says. last_boot is the answer of the last create,
    start or unlock made through this object.
    """

    def __init__(self, cli: Cli, data: Mapping[str, Any]) -> None:
        self._cli = cli
        self.data: Dict[str, Any] = dict(data)
        self.last_boot: Optional[Dict[str, Any]] = None
        check_name(self.name)

    @property
    def name(self) -> str:
        return self.data["name"]

    @property
    def state(self) -> Optional[str]:
        return self.data.get("state")

    @property
    def id(self) -> Optional[str]:
        return self.data.get("id")

    def __repr__(self) -> str:
        return f"Sandbox(name={self.name!r}, state={self.state!r})"

    def _booted(self, result: Any) -> None:
        self.last_boot = result
        if isinstance(result, dict) and result.get("state") is not None:
            self.data["state"] = result["state"]

    def refresh(self) -> "Sandbox":
        """Ask the platform for it again (trajrl show NAME --json)."""
        self.data = dict(self._cli.run(["show", self.name, "--json"]))
        return self

    # Starting and stopping.

    def start(self) -> Dict[str, Any]:
        """trajrl start NAME --json: start it, verify its TD, unlock it with
        your disk key. Returns {"name", "state", "verified",
        "host_key_sha256", "boot"}."""
        r = self._cli.run(["start", self.name, "--json"])
        self._booted(r)
        return r

    def unlock(self) -> Dict[str, Any]:
        """trajrl unlock NAME --json: verify the TD that waits for your key and
        unlock it. Returns what start returns."""
        r = self._cli.run(["unlock", self.name, "--json"])
        self._booted(r)
        return r

    def stop(self) -> Dict[str, Any]:
        """trajrl stop NAME --json (the platform's): returns the sandbox."""
        r = self._cli.run(["stop", self.name, "--json"])
        self.data = dict(r)
        return r

    def remove(self) -> Dict[str, Any]:
        """trajrl rm NAME --yes --json: destroy it and its disk, for good.
        Returns {"removed": NAME} and, where owners hold the keys, a "note"."""
        return self._cli.run(["rm", self.name, "--yes", "--json"])

    def wait(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """trajrl wait NAME --json: until it is running, or has failed (the
        platform gives up after timeout seconds; its default is 30 minutes).
        Returns the sandbox. A sandbox that waits for its owner's key raises
        NeedsOwner when the wait ends: unlock() it."""
        args = ["wait", self.name, "--json"]
        if timeout is not None:
            args += ["--timeout", f"{int(timeout)}s"]
        r = self._cli.run(args, timeout=self._cli.deadline(None if timeout is None else timeout + _GRACE))
        self.data = dict(r)
        return r

    def verify(self) -> Dict[str, Any]:
        """trajrl verify NAME --json: check that it is a genuine Intel TDX
        guest running the image you expect, and that its SSH host key is the
        one in its quote. Returns the verdict, {"verdict": "VERIFIED", ...};
        any other verdict raises NotVerified (its result is the verdict)."""
        try:
            r = self._cli.run(["verify", self.name, "--json"])
        except CommandFailed as e:
            if isinstance(e.result, dict) and "verdict" in e.result:
                raise NotVerified(
                    e.result.get("reason") or e.message,
                    code=e.code,
                    stderr=e.stderr,
                    error_code=e.error_code,
                    result=e.result,
                    argv=e.argv,
                ) from None
            raise
        if not isinstance(r, dict) or r.get("verdict") != "VERIFIED":
            reason = r.get("reason") if isinstance(r, dict) else None
            raise NotVerified(reason or f"not verified: {r!r}", code=0, result=r)
        return r

    # Commands and files, over the sandbox's own API (TLS that ends in the
    # TD, its host key pinned on this machine).

    def _exec_args(
        self,
        argv: Sequence[str],
        cwd: Optional[str],
        env: Optional[Mapping[str, str]],
        stdin: Optional[Union[bytes, str]],
        timeout: Optional[int],
    ) -> Tuple[List[str], Optional[bytes]]:
        if isinstance(argv, (str, bytes)):
            raise TypeError("argv is a list of words, run without a shell: ['sh', '-c', '...'] for a shell")
        words = [str(w) for w in argv]
        if not words:
            raise ValueError("argv is empty")
        args = ["exec", self.name, "--json"]
        if cwd is not None:
            args += [_EXEC_CWD, cwd]
        for k, v in (env or {}).items():
            if not k or "=" in k:
                raise ValueError(f"not an environment variable's name: {k!r}")
            args += [_EXEC_ENV, f"{k}={v}"]
        if timeout is not None:
            args += [_EXEC_TIMEOUT, str(int(timeout))]
        data: Optional[bytes] = None
        if stdin is not None:
            data = stdin.encode("utf-8") if isinstance(stdin, str) else bytes(stdin)
            args.append(_EXEC_STDIN)
        args.append("--")
        args += words
        return args, data

    def exec_stream(
        self,
        argv: Sequence[str],
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        stdin: Optional[Union[bytes, str]] = None,
        timeout: Optional[int] = None,
    ) -> Iterator[ExecEvent]:
        """Run argv in the sandbox (trajrl exec NAME --json ... -- ARGV) and
        yield its output as it comes: ExecEvent("stdout"|"stderr", bytes), an
        ExecEvent("error", str) if the API reports one, then
        ExecEvent("exit", code). timeout is the command's limit in seconds
        (trajrl's default 60, at most 300); stdin is sent whole before it
        starts. A non-zero exit code is an event, not an exception."""
        args, data = self._exec_args(argv, cwd, env, stdin, timeout)
        limit = self._cli.deadline(None if timeout is None else timeout + _GRACE)
        code: Optional[int] = None
        with self._cli.stream(args, stdin=data, timeout=limit) as s:
            for line in s:
                if "stdout" in line:
                    yield ExecEvent("stdout", _bytes("stdout", line["stdout"]))
                elif "stderr" in line:
                    yield ExecEvent("stderr", _bytes("stderr", line["stderr"]))
                elif "error" in line:
                    yield ExecEvent("error", str(line["error"]))
                elif "exit_code" in line:
                    code = int(line["exit_code"])
        if code is None:
            raise s.error()
        yield ExecEvent("exit", code)

    def exec(
        self,
        argv: Sequence[str],
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        stdin: Optional[Union[bytes, str]] = None,
        timeout: Optional[int] = None,
    ) -> ExecResult:
        """exec_stream, collected: ExecResult(stdout, stderr, exit_code,
        error)."""
        out: List[bytes] = []
        err: List[bytes] = []
        errors: List[str] = []
        code = -1
        for kind, data in self.exec_stream(argv, cwd=cwd, env=env, stdin=stdin, timeout=timeout):
            if kind == "stdout":
                out.append(data)  # type: ignore[arg-type]
            elif kind == "stderr":
                err.append(data)  # type: ignore[arg-type]
            elif kind == "error":
                errors.append(data)  # type: ignore[arg-type]
            elif kind == "exit":
                code = data  # type: ignore[assignment]
        return ExecResult(b"".join(out), b"".join(err), code, "; ".join(errors) or None)

    def upload(self, local: PathLike, remote: str) -> int:
        """trajrl cp LOCAL NAME:/PATH --json: copy a file in. Returns its
        size in bytes."""
        r = self._cli.run(["cp", _local_path(local), f"{self.name}:{_remote_path(remote)}", "--json"])
        return int(r["bytes"])

    def download(self, remote: str, local: PathLike) -> int:
        """trajrl cp NAME:/PATH LOCAL --json: copy a file out. Returns its
        size in bytes."""
        r = self._cli.run(["cp", f"{self.name}:{_remote_path(remote)}", _local_path(local), "--json"])
        return int(r["bytes"])
