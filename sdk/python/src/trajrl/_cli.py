"""Running trajrl: finding the program, running it, its JSON and its errors.

Every call is one trajrl process with an argument list (never a shell), its
stdin /dev/null unless the caller gives bytes for it, so trajrl never waits
for a prompt. Its stdout is JSON; on failure its stderr says why, as
{"error": ..., "code": ...} or as text.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from typing import IO, Any, Dict, Iterator, List, Optional, Sequence, Tuple, Type, Union

from .errors import (
    CommandFailed,
    NeedsOwner,
    SandboxNotFound,
    SandboxNotRunning,
    TransportError,
    TrajrlError,
    TrajrlNotFound,
    UsageError,
)

PathLike = Union[str, "os.PathLike[str]"]

EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_NEEDS_OWNER = 3
EXIT_TRANSPORT = 255

INSTALL_HINT = (
    "install it: brew install trajrl (after brew tap hanlinai/trajrl-cli "
    "https://github.com/hanlinai/trajrl-cli), "
    "curl -fsSL https://sandbox.trajrl.com/trajrl/install.sh | sh, "
    "or scoop install trajrl; or pass trajrl_bin= or set $TRAJRL_BIN"
)


def find_trajrl(trajrl_bin: Optional[PathLike] = None) -> str:
    """The trajrl program: trajrl_bin, else $TRAJRL_BIN, else trajrl on PATH.
    A value with no directory in it is looked up on PATH."""
    if trajrl_bin is not None:
        given, where = os.fspath(trajrl_bin), "trajrl_bin"
    elif os.environ.get("TRAJRL_BIN"):
        given, where = os.environ["TRAJRL_BIN"], "$TRAJRL_BIN"
    else:
        found = shutil.which("trajrl")
        if found is None:
            raise TrajrlNotFound("trajrl is not on PATH: " + INSTALL_HINT)
        return found
    if os.sep in given or (os.altsep and os.altsep in given):
        if os.path.isfile(given) and os.access(given, os.X_OK):
            return given
        raise TrajrlNotFound(f"{where} is {given!r}, which is not an executable file")
    found = shutil.which(given)
    if found is None:
        raise TrajrlNotFound(f"{where} is {given!r}, which is not on PATH")
    return found


def _json_or_none(data: bytes) -> Any:
    try:
        return json.loads(data) if data.strip() else None
    except ValueError:
        return None


def _what_went_wrong(stderr: str) -> Tuple[str, Any]:
    """The error trajrl reported: the last {"error", "code"} line of stderr,
    else its last line of text."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and "error" in obj:
                return str(obj["error"]), obj.get("code")
    return (lines[-1] if lines else ""), None


def error_for(argv: Sequence[str], status: int, stdout: bytes, stderr: bytes) -> TrajrlError:
    """The exception for a trajrl run that ended with a non-zero status."""
    text = stderr.decode("utf-8", "replace")
    message, error_code = _what_went_wrong(text)
    if not message:
        message = f"trajrl {' '.join(argv[1:2])} exited with status {status}"
    cls: Type[TrajrlError]
    if status == EXIT_USAGE:
        cls = UsageError
    elif status == EXIT_NEEDS_OWNER:
        cls = NeedsOwner
    elif status == EXIT_TRANSPORT:
        cls = TransportError
    else:
        # A forwarded command's errors are the platform's text.
        low = message.lower()
        if "waiting for its owner's key" in low:
            cls = NeedsOwner
        elif "not running" in low:
            cls = SandboxNotRunning
        elif "not found" in low:
            cls = SandboxNotFound
        else:
            cls = CommandFailed
    return cls(
        message,
        code=status,
        stderr=text,
        error_code=error_code,
        result=_json_or_none(stdout),
        argv=argv,
    )


class Cli:
    """One trajrl program and how it is run: the environment (with
    TRAJRL_PASSPHRASE_FILE if a passphrase file was given) and the default
    time limit of a call, in seconds (None: none)."""

    def __init__(
        self,
        path: str,
        passphrase_file: Optional[PathLike] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self.path = path
        self.passphrase_file = (
            os.path.abspath(os.fspath(passphrase_file)) if passphrase_file is not None else None
        )
        self.timeout = timeout

    def env(self) -> Dict[str, str]:
        env = dict(os.environ)
        if self.passphrase_file is not None:
            env["TRAJRL_PASSPHRASE_FILE"] = self.passphrase_file
        return env

    def deadline(self, at_least: Optional[float] = None) -> Optional[float]:
        """The time limit of a call that may itself take at_least seconds:
        the client's, raised to that if it is shorter."""
        if at_least is None:
            return self.timeout
        if self.timeout is None:
            return at_least
        return max(self.timeout, at_least)

    def run(
        self,
        args: Sequence[str],
        *,
        stdin: Optional[bytes] = None,
        timeout: Optional[float] = None,
        report_on_failure: bool = False,
    ) -> Any:
        """Run trajrl ARGS and return its stdout as JSON. A non-zero status
        raises, unless report_on_failure and it is 1 with JSON on stdout (a
        report that says what is wrong: status, doctor)."""
        argv = [self.path, *args]
        try:
            proc = subprocess.run(
                argv,
                input=stdin,
                stdin=None if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env(),
                timeout=timeout if timeout is not None else self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise TransportError(
                f"trajrl {' '.join(args[:1])} did not finish within {e.timeout:g}s",
                stderr=(e.stderr or b"").decode("utf-8", "replace"),
                argv=argv,
            ) from None
        except OSError as e:
            raise TrajrlNotFound(f"cannot run {self.path}: {e}", argv=argv) from e
        if proc.returncode != 0:
            if report_on_failure and proc.returncode == EXIT_FAILED:
                report = _json_or_none(proc.stdout)
                if report is not None:
                    return report
            raise error_for(argv, proc.returncode, proc.stdout, proc.stderr)
        try:
            return json.loads(proc.stdout)
        except ValueError:
            raise TrajrlError(
                f"trajrl {' '.join(args[:1])} printed no JSON on stdout: "
                f"{proc.stdout[:200].decode('utf-8', 'replace')!r}",
                code=0,
                stderr=proc.stderr.decode("utf-8", "replace"),
                argv=argv,
            ) from None

    def stream(
        self, args: Sequence[str], *, stdin: Optional[bytes] = None, timeout: Optional[float] = None
    ) -> "Stream":
        return Stream([self.path, *args], self.env(), stdin, timeout)


class Stream:
    """A trajrl process whose stdout is NDJSON, read a line at a time. Use it
    as a context manager: leaving it ends the process (killed if it is still
    running) and sets status, stderr and timed_out."""

    def __init__(
        self, argv: List[str], env: Dict[str, str], stdin: Optional[bytes], timeout: Optional[float]
    ) -> None:
        self.argv = argv
        self.status: Optional[int] = None
        self.timed_out = False
        self._eof = False
        self._stderr: List[bytes] = []
        try:
            self._proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
        except OSError as e:
            raise TrajrlNotFound(f"cannot run {argv[0]}: {e}", argv=argv) from e
        self._threads = [
            threading.Thread(target=self._read_stderr, args=(self._proc.stderr,), daemon=True)
        ]
        if stdin is not None:
            self._threads.append(
                threading.Thread(target=self._write_stdin, args=(self._proc.stdin, stdin), daemon=True)
            )
        for t in self._threads:
            t.start()
        self._timer: Optional[threading.Timer] = None
        if timeout is not None:
            self._timer = threading.Timer(timeout, self._time_out)
            self._timer.daemon = True
            self._timer.start()
        self.timeout = timeout

    def _read_stderr(self, f: IO[bytes]) -> None:
        for chunk in iter(lambda: f.read(8192), b""):
            self._stderr.append(chunk)

    @staticmethod
    def _write_stdin(f: IO[bytes], data: bytes) -> None:
        try:
            f.write(data)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                f.close()
            except OSError:
                pass

    def _time_out(self) -> None:
        if self._proc.poll() is None:
            self.timed_out = True
            self._proc.kill()

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        assert self._proc.stdout is not None
        for raw in self._proc.stdout:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                raise TrajrlError(
                    f"trajrl printed a line that is not JSON: {line[:200].decode('utf-8', 'replace')!r}",
                    argv=self.argv,
                ) from None
            if not isinstance(obj, dict):
                raise TrajrlError(f"trajrl printed a JSON line that is not an object: {obj!r}", argv=self.argv)
            yield obj
        self._eof = True

    def __enter__(self) -> "Stream":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self.status is not None:
            return
        if not self._eof and self._proc.poll() is None:
            # Left before the end of its output: the process is not needed.
            self._proc.kill()
        self.status = self._proc.wait()
        if self._timer is not None:
            self._timer.cancel()
        for t in self._threads:
            t.join()
        for f in (self._proc.stdout, self._proc.stderr):
            if f is not None:
                f.close()

    @property
    def stderr(self) -> bytes:
        return b"".join(self._stderr)

    def error(self) -> TrajrlError:
        """The exception for a run that ended without its answer."""
        if self.timed_out:
            return TransportError(
                f"trajrl {' '.join(self.argv[1:2])} did not finish within {self.timeout:g}s",
                stderr=self.stderr.decode("utf-8", "replace"),
                argv=self.argv,
            )
        if self.status == 0:
            return TransportError(
                "trajrl's reply ended without an exit code",
                code=0,
                stderr=self.stderr.decode("utf-8", "replace"),
                argv=self.argv,
            )
        return error_for(self.argv, self.status if self.status is not None else -1, b"", self.stderr)
