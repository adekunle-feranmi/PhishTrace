"""Bounded, shell-free execution of third-party OSINT tools.

Threat-intel tooling is usually a pile of Python and Go binaries that expect to
be run by a human: they write report files into the current directory, inherit
whatever environment is present, and happily stream gigabytes to stdout.  This
runner makes those tools usable from a service inside a fixed envelope:

* **No shell.**  ``asyncio.create_subprocess_exec`` receives an argv list, so a
  selector can never be interpreted as shell syntax.
* **No option injection.**  Every selector is validated before it reaches argv
  (``-flag``-looking values, whitespace and control characters are rejected).
* **No inherited secrets.**  The child gets a minimal environment (``PATH``,
  ``HOME`` inside a scratch dir, locale, ``TZ``) instead of ``os.environ``, so
  an API key exported for an HTTP provider cannot leak into a subprocess and a
  ``*_proxy`` variable cannot silently reroute its traffic.
* **Bounded output and time.**  Stdout/stderr are drained with a hard byte cap;
  the process group is killed on timeout or when the cap is hit.  Tools that
  spawn children (theharvester, spiderfoot) die with the group.
* **Scratch cwd.**  Each run gets its own directory, removed afterwards.  Tools
  that insist on writing ``<target>.json`` next to the binary still work.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

#: Selectors are ASCII in this codebase (IDNs are punycoded by the normalizer).
_TARGET_RE = re.compile(r"^[\x21-\x7e]{1,512}$")
_DENY_PREFIX = "-"

DEFAULT_MAX_OUTPUT = 4_000_000  # 4 MB per stream
DEFAULT_TIMEOUT = 120.0
_READ_CHUNK = 65_536
_KILL_GRACE = 3.0


class ToolNotAvailable(RuntimeError):
    """The configured binary is missing or not executable."""


class ToolTargetError(ValueError):
    """A selector would be unsafe to place in an argv position."""


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    ok: bool
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    truncated: bool = False
    workdir: str | None = None
    files: dict[str, bytes] = field(default_factory=dict)
    evidence_id: str | None = None
    reason: str | None = None

    def json_stdout(self) -> Any:
        """Best-effort JSON parse of stdout; ``None`` when it is not JSON."""
        import json

        text = self.stdout.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def json_lines(self) -> list[Any]:
        import json

        rows: list[Any] = []
        for line in self.stdout.splitlines():
            line = line.strip()
            if not line or line[0] not in "[{":
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        return rows

    def summary(self) -> str:
        bits = [f"{self.tool}: exit={self.exit_code}"]
        if self.timed_out:
            bits.append("timed out")
        if self.truncated:
            bits.append("output truncated")
        if self.reason:
            bits.append(self.reason)
        return ", ".join(bits)


def validate_target(value: Any, *, field_name: str = "target") -> str:
    """Reject anything that could be read as an option or break argv hygiene."""
    text = str(value or "").strip()
    if not text:
        raise ToolTargetError(f"{field_name} must not be empty")
    if len(text) > 512:
        raise ToolTargetError(f"{field_name} is longer than 512 characters")
    if text.startswith(_DENY_PREFIX):
        raise ToolTargetError(f"{field_name} must not start with '-'")
    if not _TARGET_RE.match(text):
        raise ToolTargetError(f"{field_name} contains whitespace, control or non-ASCII characters")
    return text


def _safe_env(workdir: Path) -> dict[str, str]:
    path = os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin"
    # Keep the search path, drop everything else: credentials, proxies and
    # tool-specific variables stay in the parent process.
    return {
        "PATH": path,
        "HOME": str(workdir),
        "TMPDIR": str(workdir),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONIOENCODING": "utf-8",
        "NO_COLOR": "1",
    }


def _resolve_binary(name: str, configured: str | None) -> str:
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
        resolved = shutil.which(configured)
        if resolved:
            return resolved
        raise ToolNotAvailable(f"configured path for '{name}' is not executable: {configured}")
    resolved = shutil.which(name)
    if not resolved:
        raise ToolNotAvailable(f"'{name}' is not installed or not on PATH")
    return resolved


async def _drain(stream: asyncio.StreamReader | None, cap: int, on_exceed) -> tuple[str, bool]:
    """Read a stream up to ``cap`` bytes, then stop storing but keep draining."""
    if stream is None:
        return "", False
    chunks: list[bytes] = []
    total = 0
    truncated = False
    while True:
        chunk = await stream.read(_READ_CHUNK)
        if not chunk:
            break
        if total < cap:
            keep = chunk[: cap - total]
            chunks.append(keep)
            total += len(keep)
            if len(keep) < len(chunk):
                truncated = True
                on_exceed()
        else:
            truncated = True
            on_exceed()
    return b"".join(chunks).decode("utf-8", errors="replace"), truncated


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            proc.terminate()
        except ProcessLookupError:
            return
    try:
        await asyncio.wait_for(proc.wait(), _KILL_GRACE)
        return
    except asyncio.TimeoutError:
        pass
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            return
    try:
        await asyncio.wait_for(proc.wait(), _KILL_GRACE)
    except asyncio.TimeoutError:
        pass


class ToolRunner:
    """Run one external tool with a fixed safety envelope."""

    def __init__(
        self,
        tool: str,
        *,
        path: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_output: int = DEFAULT_MAX_OUTPUT,
        env: Mapping[str, str] | None = None,
    ):
        self.tool = tool
        self.binary = _resolve_binary(tool, path)
        self.timeout = max(1.0, float(timeout))
        self.max_output = max(4096, int(max_output))
        self.extra_env = {str(k): str(v) for k, v in (env or {}).items()}
        self._scratch: Path | None = None

    # ------------------------------------------------------------------ helpers
    @property
    def display_command(self) -> str:
        return os.path.basename(self.binary)

    def available(self) -> bool:
        return bool(self.binary)

    def _cleanup(self, workdir: Path | None) -> None:
        if workdir is None:
            return
        for path in sorted(workdir.rglob("*"), reverse=True):
            try:
                if path.is_file() or path.is_symlink():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            except OSError:
                continue
        try:
            workdir.rmdir()
        except OSError:
            pass

    # ----------------------------------------------------------------- execution
    async def run(
        self,
        args: Iterable[str],
        *,
        collect: Iterable[str] = (),
        collect_json: bool = False,
        timeout: float | None = None,
    ) -> ToolResult:
        argv = [str(arg) for arg in args]
        workdir: Path | None = None
        started = time.monotonic()
        try:
            import tempfile

            workdir = Path(tempfile.mkdtemp(prefix="phishtrace-tool-"))
            env = _safe_env(workdir)
            env.update(self.extra_env)
            proc = await asyncio.create_subprocess_exec(
                self.binary,
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(workdir),
                env=env,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            self._cleanup(workdir)
            return ToolResult(
                tool=self.tool, command=[self.binary, *argv], ok=False, exit_code=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason=f"binary disappeared before start: {exc}",
            )
        except OSError as exc:
            self._cleanup(workdir)
            return ToolResult(
                tool=self.tool, command=[self.binary, *argv], ok=False, exit_code=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                reason=f"could not start tool: {exc}",
            )

        exceeded = {"hit": False}

        def on_exceed() -> None:
            if exceeded["hit"]:
                return
            exceeded["hit"] = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

        out_task = asyncio.create_task(_drain(proc.stdout, self.max_output, on_exceed))
        err_task = asyncio.create_task(_drain(proc.stderr, self.max_output, on_exceed))
        limit = max(1.0, float(timeout or self.timeout))
        timed_out = False
        try:
            await asyncio.wait_for(proc.wait(), limit)
        except asyncio.TimeoutError:
            timed_out = True
            await _terminate(proc)
        finally:
            stdout, out_trunc = await out_task
            stderr, err_trunc = await err_task

        files: dict[str, bytes] = {}
        if workdir is not None:
            names = [str(name) for name in collect]
            if collect_json:
                # Tool report filenames change between releases (sherlock writes
                # <user>.json, maigret report_<user>.json, ghunt a chosen name),
                # so pick up any JSON report the tool left behind.
                names.extend(
                    str(path.relative_to(workdir))
                    for path in sorted(workdir.rglob("*.json"))[:20]
                    if path.is_file()
                )
            total = 0
            for name in names:
                candidate = (workdir / name).resolve()
                try:
                    candidate.relative_to(workdir.resolve())
                except ValueError:
                    continue
                try:
                    size = candidate.stat().st_size if candidate.is_file() else -1
                except OSError:
                    continue
                if 0 <= size <= self.max_output and total + size <= 8_000_000:
                    try:
                        files[name] = candidate.read_bytes()
                        total += size
                    except OSError:
                        continue

        exit_code = proc.returncode
        ok = exit_code == 0 and not timed_out
        reason = None
        if timed_out:
            reason = f"timed out after {limit:.0f}s"
        elif exceeded["hit"]:
            reason = f"output exceeded {self.max_output} bytes"
        elif exit_code not in (0, None):
            tail = " ".join(stderr.split())[-300:]
            reason = f"exit code {exit_code}" + (f": {tail}" if tail else "")

        result = ToolResult(
            tool=self.tool,
            command=[os.path.basename(self.binary), *argv],
            ok=ok,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=int((time.monotonic() - started) * 1000),
            timed_out=timed_out,
            truncated=out_trunc or err_trunc or exceeded["hit"],
            workdir=str(workdir) if workdir else None,
            files=files,
            reason=reason,
        )
        self._cleanup(workdir)
        return result
