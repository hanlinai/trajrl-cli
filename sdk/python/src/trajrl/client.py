"""The client: one trajrl program on this machine."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ._cli import Cli, PathLike, find_trajrl
from .errors import TrajrlError, TrajrlNotFound
from .sandbox import Sandbox, check_name


class Client:
    """TrajRL's sandboxes, through the trajrl command line on this machine.

    trajrl is trajrl_bin, else $TRAJRL_BIN, else trajrl on PATH; it must
    answer trajrl version --json. passphrase_file is the file holding your
    key file's passphrase, given to trajrl as TRAJRL_PASSPHRASE_FILE (without
    it, trajrl takes $TRAJRL_PASSPHRASE_FILE from this process's
    environment; it never prompts). timeout is the time limit of each trajrl
    call, in seconds (None: none; starting a sandbox can take minutes).
    """

    def __init__(
        self,
        trajrl_bin: Optional[PathLike] = None,
        passphrase_file: Optional[PathLike] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self._cli = Cli(find_trajrl(trajrl_bin), passphrase_file, timeout)
        try:
            v = self._cli.run(["version", "--json"])
        except TrajrlError as e:
            raise TrajrlNotFound(
                f"{self._cli.path} did not answer version --json ({e.message}): "
                "this SDK needs TrajRL's trajrl, a release with --json",
                code=e.code,
                stderr=e.stderr,
                argv=e.argv,
            ) from e
        if not isinstance(v, dict) or not isinstance(v.get("version"), str):
            raise TrajrlNotFound(f"{self._cli.path} version --json printed {v!r}, not trajrl's version")
        #: trajrl's version, and the oldest entry point it works with.
        self.version: str = v["version"]
        self.min_entry: Optional[str] = v.get("min_entry")
        self.sandboxes = Sandboxes(self._cli)

    @property
    def trajrl_bin(self) -> str:
        """The trajrl program this client runs."""
        return self._cli.path

    def __repr__(self) -> str:
        return f"Client(trajrl_bin={self._cli.path!r}, version={self.version!r})"

    def status(self) -> Dict[str, Any]:
        """trajrl status --json: the account's sandboxes with what this
        machine verified, and what to run next. On a machine trajrl is not set
        up on, {"configured": false, "message": ...}."""
        return self._cli.run(["status", "--json"], report_on_failure=True)

    def doctor(self) -> Dict[str, Any]:
        """trajrl doctor --json: {"ok": bool, "checks": [{"name", "status",
        "message", "fix"}]}; a failing check is in the report, not raised."""
        return self._cli.run(["doctor", "--json"], report_on_failure=True)


class Sandboxes:
    """The account's sandboxes (Client.sandboxes)."""

    def __init__(self, cli: Cli) -> None:
        self._cli = cli

    def list(self) -> List[Sandbox]:
        """trajrl ls --json."""
        return [Sandbox(self._cli, v) for v in self._cli.run(["ls", "--json"])]

    def get(self, name: str) -> Sandbox:
        """trajrl show NAME --json. SandboxNotFound if there is none."""
        return Sandbox(self._cli, self._cli.run(["show", check_name(name), "--json"]))

    def create(
        self,
        name: str,
        size: Optional[str] = None,
        disk: Optional[int] = None,
        image: Optional[str] = None,
    ) -> Sandbox:
        """trajrl new NAME --json: create it, verify its TD and unlock its
        first boot with your disk key. size is one of the platform's sizes,
        disk its disk in GiB, image the platform's image to boot. The
        Sandbox's last_boot is trajrl's answer: {"name", "state", "verified",
        "host_key_sha256", "boot"}."""
        args = ["new", check_name(name)]
        if size is not None:
            args += ["--size", str(size)]
        if disk is not None:
            args += ["--disk", str(int(disk))]
        if image is not None:
            args += ["--image", str(image)]
        args.append("--json")
        r = self._cli.run(args)
        sb = Sandbox(self._cli, {"name": r.get("name") or name})
        sb._booted(r)
        return sb
