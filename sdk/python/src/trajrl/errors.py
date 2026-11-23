"""The exceptions the SDK raises.

Each is a TrajrlError. Which one is chosen from trajrl's exit status:

    0    ok
    1    CommandFailed (or a subclass, from what the error says)
    2    UsageError
    3    NeedsOwner
    255  TransportError

and a non-zero status of a command trajrl forwards to the platform is
CommandFailed too. Sandbox.exec never raises for the exit code of the command
it ran: it returns it.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence


class TrajrlError(Exception):
    """Something trajrl did not do.

    code is trajrl's exit status (None when it did not run, or was stopped);
    message is what it said went wrong; stderr is everything it wrote there;
    error_code is the "code" of its JSON error, if it wrote one; result is its
    JSON stdout when it printed one anyway (verify's verdict, wait's sandbox);
    argv is the command line.
    """

    def __init__(
        self,
        message: str,
        *,
        code: Optional[int] = None,
        stderr: str = "",
        error_code: Any = None,
        result: Any = None,
        argv: Optional[Sequence[str]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.stderr = stderr
        self.error_code = error_code
        self.result = result
        self.argv = list(argv) if argv is not None else None


class TrajrlNotFound(TrajrlError):
    """No trajrl program: not on PATH, or not where trajrl_bin or $TRAJRL_BIN
    said, or the program there is not TrajRL's trajrl with --json."""


class UsageError(TrajrlError):
    """trajrl refused the command line (exit status 2)."""


class NeedsOwner(TrajrlError):
    """Only the owner can go on (exit status 3): the key file's passphrase is
    missing (give passphrase_file= or $TRAJRL_PASSPHRASE_FILE), or the sandbox
    waits for its owner's key (Sandbox.unlock)."""


class TransportError(TrajrlError):
    """trajrl reached neither the platform nor the sandbox, or the connection
    broke (exit status 255), or the call took longer than its timeout."""


class CommandFailed(TrajrlError):
    """The command failed (exit status 1, or another non-zero status of a
    command forwarded to the platform)."""


class SandboxNotFound(CommandFailed):
    """The platform has no sandbox of that name in this account."""


class SandboxNotRunning(CommandFailed):
    """The sandbox exists but is not running."""


class NotVerified(CommandFailed):
    """trajrl verify did not vouch for the sandbox. result is its verdict:
    {"verdict": "NOT VERIFIED", "reason": ..., "quote": ...}."""
