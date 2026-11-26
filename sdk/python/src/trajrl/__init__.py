"""TrajRL's TDX sandboxes from Python, on the owner's machine.

The SDK runs the trajrl command line (trajrl ... --json): the disk key, the
verification of a sandbox's TD and the pinned host keys stay with trajrl, on
this machine. It holds no key itself and needs nothing but trajrl.

    from trajrl import Client
    c = Client()
    sb = c.sandboxes.get("web")
    print(sb.exec(["uname", "-a"]).stdout.decode())
"""

from .client import Client, Sandboxes
from .errors import (
    CommandFailed,
    NeedsOwner,
    NotVerified,
    SandboxNotFound,
    SandboxNotRunning,
    TransportError,
    TrajrlError,
    TrajrlNotFound,
    UsageError,
)
from .sandbox import ExecEvent, ExecResult, Sandbox

__version__ = "0.4.0"

__all__ = [
    "Client",
    "CommandFailed",
    "ExecEvent",
    "ExecResult",
    "NeedsOwner",
    "NotVerified",
    "Sandbox",
    "SandboxNotFound",
    "SandboxNotRunning",
    "Sandboxes",
    "TransportError",
    "TrajrlError",
    "TrajrlNotFound",
    "UsageError",
    "__version__",
]
