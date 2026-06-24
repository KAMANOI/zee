"""Isolation backends for the behavioural sandbox.

A backend knows how to wrap a command so it runs contained: writes
confined to the sandbox HOME, network denied except one loopback port.
The contract is feature-based, not OS-named, so Docker / bubblewrap /
gVisor are later additions behind the same interface — a new class, not
a rewrite.

Hard rule (I2/I7): ``detect_backend()`` returns ``None`` when nothing
real is available. The runner treats ``None`` as "do not execute" — it
never falls back to running untrusted code on the bare host.
"""

from __future__ import annotations

import platform
import shutil
from abc import ABC, abstractmethod
from pathlib import Path

from .profile import build_profile


class IsolationBackend(ABC):
    """Wraps a command so it executes inside an isolation boundary."""

    name: str = "isolation"

    @abstractmethod
    def available(self) -> bool:
        """True only if this backend can actually contain a process here."""

    @abstractmethod
    def wrap(
        self,
        command: list[str],
        *,
        workhome: Path,
        loopback_port: int,
        profile_dir: Path,
    ) -> list[str]:
        """Return the argv that runs ``command`` under isolation.

        ``workhome`` is the sandbox HOME (writes are confined to it).
        ``loopback_port`` is the only reachable network destination.
        ``profile_dir`` is a private scratch dir the backend may use for
        a generated profile file.
        """


class MacosSandboxExec(IsolationBackend):
    """macOS native ``sandbox-exec`` (Seatbelt / SBPL).

    Deprecated by Apple but present and functional on every supported
    macOS, which is exactly the "zero install, works out of the box"
    property the gate wants for its default behavioural backend.
    """

    name = "sandbox-exec"

    def available(self) -> bool:
        return (
            platform.system() == "Darwin"
            and shutil.which("sandbox-exec") is not None
        )

    def wrap(
        self,
        command: list[str],
        *,
        workhome: Path,
        loopback_port: int,
        profile_dir: Path,
    ) -> list[str]:
        # sandbox-exec matches the *resolved* path — pass WORKHOME as a
        # realpath or writes inside it are silently denied.
        real_home = str(Path(workhome).resolve())
        profile_path = Path(profile_dir) / "profile.sb"
        profile_path.write_text(build_profile(loopback_port), encoding="utf-8")
        return [
            "sandbox-exec",
            "-D",
            f"WORKHOME={real_home}",
            "-f",
            str(profile_path),
            *command,
        ]


# Ordered by preference. The first available one wins. macOS-native is
# first because it needs no install on the owner's machine; Docker /
# bubblewrap backends slot in here later for Linux and cross-platform.
_BACKENDS: tuple[IsolationBackend, ...] = (MacosSandboxExec(),)


def detect_backend() -> IsolationBackend | None:
    """Return the preferred available backend, or None (interlock: the
    runner must then skip execution, never run on the bare host)."""
    for backend in _BACKENDS:
        if backend.available():
            return backend
    return None


def available_backends() -> list[str]:
    """Names of all backends that are usable on this machine right now."""
    return [b.name for b in _BACKENDS if b.available()]
