"""macOS sandbox profile (SBPL) generation for the behavioural runner.

The profile denies everything by default and re-grants only what an
install hook legitimately needs to run while staying contained:

  * read system paths (so the interpreter can load its libraries) and
    the sandbox HOME, but NOT the real user homes — ``/Users`` and
    ``/private/var/root`` are explicitly read-denied so a detonated hook
    cannot read the host's real ``~/.ssh`` / ``~/.aws`` / source and
    exfiltrate it. The bait the hook *should* find lives in the sandbox
    HOME instead,
  * write only under the disposable sandbox HOME (the artifact's own
    work copy + the seeded fake credentials live here; a write to the
    real ``~/.zshrc`` is therefore denied and observable as a failure),
  * no network at all, except a single loopback port — the local
    FakeNet sink the runner controls. Any real outbound the artifact
    tries either rides the proxy into the sink (observed) or is denied
    by the kernel (contained).

Honest limits (invariant I5): this contains *writes* and *network* and
blocks reads of the real user homes, but it is not a formal proof. A
determined hook can still read world-readable system files; and TLS sent
straight through a CONNECT tunnel is contained but its body is opaque to
the sink. This is layered risk reduction, not complete detection.

Two facts learned empirically and encoded here (don't "fix" them away):
  1. ``sandbox-exec`` matches the *resolved* path, so WORKHOME must be a
     realpath (``/private/var/...`` not ``/var/...``); the runner passes
     it resolved.
  2. The network host literal must be ``localhost`` (an IP literal like
     ``127.0.0.1`` is rejected by the profile parser); a port filter
     ``localhost:<port>`` is accepted and used to scope the allow.
  3. ``(allow file-read*)`` then ``(deny file-read* (subpath "/Users") …)``
     — last matching rule wins in SBPL, so the deny narrows the allow.
     A metadata/data split was tried and rejected: denying read-data on
     the dyld shared cache makes the interpreter abort (SIGABRT).

This is best-effort containment, not a formal proof (invariant I5).
"""

from __future__ import annotations


def build_profile(loopback_port: int) -> str:
    """Return the SBPL text for a behavioural run.

    ``loopback_port`` is the port the runner's FakeNet sink listens on;
    it is the only network destination the sandboxed process may reach.
    ``WORKHOME`` is supplied at launch via ``-D WORKHOME=<realpath>``.
    """
    if not isinstance(loopback_port, int) or not (0 < loopback_port < 65536):
        raise ValueError(f"loopback_port out of range: {loopback_port!r}")
    return f"""(version 1)
(deny default)
(allow process-fork)
(allow process-exec*)
(allow signal (target self))
(allow sysctl-read)
(allow mach-lookup)
(allow file-read*)
(deny file-read*
    (subpath "/Users")
    (subpath "/private/var/root"))
(allow file-write* (subpath (param "WORKHOME")))
(allow file-write-data
    (literal "/dev/null")
    (literal "/dev/zero")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/tty")
    (literal "/dev/stdout")
    (literal "/dev/stderr"))
(allow file-ioctl (literal "/dev/tty"))
(deny network*)
(allow network-outbound (remote ip "localhost:{loopback_port}"))
"""
