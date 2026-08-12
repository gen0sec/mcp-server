#!/usr/bin/env python3
"""
Launcher for the Gen0Sec WAF Rule Generation MCP server.

Resolution order for dependencies:

1. Bundled deps, IF they import under this interpreter. Two layouts are
   supported:
     - Multi-ABI (offline bundle): `server/lib/<abi-tag>/`, one dir per
       interpreter target (e.g. `server/lib/cpython-312-darwin-arm64/`). The
       host selects the dir matching `_abi_tag()`.
     - Flat (single-platform local `make vendor`, or the Docker image):
       packages live directly under `server/lib`.
   The thin released `.mcpb` carries neither and relies on (2).
2. Per-interpreter venv at `<extension_dir>/.venv-<pyX.Y>-<platform>`. Built on
   first run when (1) is absent or ABI-incompatible.

A single bundle cannot carry native extensions for every Python ABI + OS +
arch, so a bundled dir is used only when it actually imports on the host;
otherwise we fall back to (2). The host Python is never modified. We do not use
`--user`, `--break-system-packages`, or any global install.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REQUIREMENTS = PROJECT_ROOT / "requirements.txt"
# The manifest sets PYTHONPATH=${__dirname}/server/lib. When populated, that
# directory holds vendored wheels including native extensions (pydantic_core,
# ...) built for ONE Python ABI + OS + arch.
BUNDLED_LIB = SCRIPT_DIR / "lib"
# Set before re-execing into the fallback venv so a broken venv can't loop.
_BOOTSTRAP_FLAG = "GEN0SEC_MCP_BOOTSTRAPPED"


def _venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _env_tag() -> str:
    """A venv key unique to this interpreter's ABI + OS + arch.

    Keying only by ``pyX.Y`` (the old scheme) collided across architectures —
    e.g. an arm64 and an x86_64 (Rosetta) launch of the same Python minor would
    share, and reuse, an incompatible venv.
    """
    plat = re.sub(r"[^A-Za-z0-9._-]+", "_", sysconfig.get_platform())
    return f"py{sys.version_info.major}.{sys.version_info.minor}-{plat}"


def _abi_tag() -> str:
    """Self-computable key for THIS interpreter's binary-wheel compatibility.

    The SAME logic runs at build time (to name each ``server/lib/<tag>/`` in the
    offline bundle) and here (to pick the matching one), so one bundle can carry
    native wheels for several interpreters and each host selects its own — no
    third-party package (``packaging``) required, which we couldn't import before
    deps exist anyway. Example: ``cpython-312-darwin-arm64``.
    """
    import platform

    impl = sys.implementation.cache_tag or (
        f"{sys.implementation.name}-{sys.version_info.major}{sys.version_info.minor}"
    )
    machine = platform.machine() or "unknown"
    return f"{impl}-{sys.platform}-{machine}".lower()


def _bundled_dir() -> "Path | None":
    """The vendored-deps directory for this interpreter, if the bundle has one.

    Prefers the multi-ABI layout (``server/lib/<abi-tag>/``); falls back to the
    flat layout (packages directly under ``server/lib``). Presence of the ``mcp``
    package is the sentinel that a directory is actually populated.
    """
    tagged = BUNDLED_LIB / _abi_tag()
    if (tagged / "mcp").is_dir():
        return tagged
    if (BUNDLED_LIB / "mcp").is_dir():
        return BUNDLED_LIB
    return None


def _prepend_to_path(directory: Path) -> None:
    """Put ``directory`` first on sys.path and PYTHONPATH (for any subprocess)."""
    entry = str(directory)
    if entry not in sys.path:
        sys.path.insert(0, entry)
    current = os.environ.get("PYTHONPATH", "")
    parts = [entry] + ([current] if current else [])
    os.environ["PYTHONPATH"] = os.pathsep.join(parts)


def _purge_bundled_from_path() -> None:
    """Remove the vendored ``server/lib`` from ``sys.path`` and ``PYTHONPATH``.

    The bundled wheels include native extensions built for one Python ABI + OS
    + arch. When the host Python doesn't match, they fail to import. Because the
    manifest pins ``PYTHONPATH=${__dirname}/server/lib`` ahead of everything,
    those broken wheels would also SHADOW the correctly-built packages in our
    fallback venv — defeating the fallback. Drop server/lib (and any
    ``server/lib/<abi-tag>`` we added) so the venv wins.
    """
    root = BUNDLED_LIB.resolve()

    def _is_bundled(entry: str) -> bool:
        try:
            return bool(entry) and Path(entry).resolve().is_relative_to(root)
        except OSError:
            return False

    sys.path[:] = [p for p in sys.path if not _is_bundled(p)]

    current = os.environ.get("PYTHONPATH", "")
    if current:
        parts = [p for p in current.split(os.pathsep) if not _is_bundled(p)]
        if parts:
            os.environ["PYTHONPATH"] = os.pathsep.join(parts)
        else:
            os.environ.pop("PYTHONPATH", None)


def _bundled_deps_importable() -> bool:
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


def _build_venv(venv_dir: Path) -> Path:
    """Create a venv with the current interpreter and install requirements.

    The venv is built in a sibling temp directory and atomically published with
    ``os.replace`` so a crash mid-build, or two Claude Desktop launches racing
    on first run, can never leave a half-built venv at ``venv_dir``.
    """
    if not REQUIREMENTS.exists():
        print(f"[gen0sec-mcp] requirements.txt not found at {REQUIREMENTS}", file=sys.stderr)
        sys.exit(1)

    print(
        f"[gen0sec-mcp] Bundled deps unavailable for {_env_tag()}; "
        f"creating isolated venv at {venv_dir} (one-time setup)...",
        file=sys.stderr,
    )

    tmp_dir = venv_dir.parent / f"{venv_dir.name}.tmp-{os.getpid()}"
    shutil.rmtree(tmp_dir, ignore_errors=True)
    try:
        import venv as _venv
        _venv.EnvBuilder(with_pip=True, symlinks=(sys.platform != "win32")).create(str(tmp_dir))

        subprocess.check_call(
            [str(_venv_python(tmp_dir)), "-m", "pip", "install", "--no-warn-script-location",
             "--disable-pip-version-check", "-r", str(REQUIREMENTS)],
        )

        # Publish atomically. If a concurrent builder won the race, os.replace
        # onto their non-empty dir fails — fall back to their finished venv.
        try:
            os.replace(tmp_dir, venv_dir)
        except OSError:
            if not _venv_python(venv_dir).exists():
                raise
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return _venv_python(venv_dir)


def _ensure_runtime() -> None:
    """Guarantee `import mcp` will succeed, re-execing into a venv if needed."""
    # Once we've re-exec'd into the fallback venv, that venv is authoritative:
    # do NOT re-discover a bundled dir here, or an incompatible server/lib would
    # be prepended again and shadow the venv (import fails → false "venv broken").
    already_bootstrapped = os.environ.get(_BOOTSTRAP_FLAG) == "1"
    if not already_bootstrapped:
        # Multi-ABI bundle: the manifest's PYTHONPATH=server/lib holds no
        # packages directly, so add the subdir matching this interpreter.
        bundled = _bundled_dir()
        if bundled is not None:
            _prepend_to_path(bundled)

    if _bundled_deps_importable():
        return

    # We re-exec into a fallback venv below. If we've already done so and deps
    # STILL don't import, the venv itself is broken — stop, don't loop.
    if already_bootstrapped:
        print(
            "[gen0sec-mcp] Dependencies still unavailable after venv bootstrap. "
            "The fallback venv did not provide 'mcp'.\n"
            "  Check network/pip access for the one-time dependency install, or "
            "point python_path at an interpreter that already has requirements.txt "
            "installed.",
            file=sys.stderr,
        )
        sys.exit(1)

    # A bundle is present but doesn't match this interpreter (ABI/OS/arch), or is
    # absent. Emit a one-line diagnostic so an unexpected fallback (e.g. a tag
    # that doesn't match the vendored dir name) is debuggable from the logs.
    if BUNDLED_LIB.is_dir():
        try:
            present = sorted(p.name for p in BUNDLED_LIB.iterdir() if p.is_dir())
        except OSError:
            present = []
        tagged = BUNDLED_LIB / _abi_tag()
        try:
            inside = sorted(p.name for p in tagged.iterdir())[:12] if tagged.is_dir() else "<no such dir>"
        except OSError as e:
            inside = f"<err {e}>"
        print(
            f"[gen0sec-mcp] No bundled deps for abi tag '{_abi_tag()}'. "
            f"server/lib dirs: {present}; tagged.is_dir={tagged.is_dir()}; "
            f"mcp.is_dir={(tagged / 'mcp').is_dir()}; contents={inside}",
            file=sys.stderr,
        )

    # Stop the broken/absent server/lib from shadowing the fallback venv — both
    # now and across the re-exec — then build/use the venv.
    _purge_bundled_from_path()

    venv_dir = PROJECT_ROOT / f".venv-{_env_tag()}"
    venv_py = _venv_python(venv_dir)

    if not venv_py.exists():
        try:
            venv_py = _build_venv(venv_dir)
        except (subprocess.CalledProcessError, OSError) as e:
            print(
                f"[gen0sec-mcp] Failed to create dependency venv: {e}\n"
                f"  Tried: {venv_dir}\n"
                "  The extension needs a one-time network install of "
                "requirements.txt, or a python_path pointing at an interpreter "
                "that already has them installed.",
                file=sys.stderr,
            )
            sys.exit(1)

    # Re-exec into the venv interpreter so imports come from there. The flag (and
    # the purged PYTHONPATH) are inherited by the new process image.
    os.environ[_BOOTSTRAP_FLAG] = "1"
    os.execv(str(venv_py), [str(venv_py), str(Path(__file__).resolve()), *sys.argv[1:]])


def _run_main() -> None:
    os.chdir(SCRIPT_DIR)
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))

    main_script = SCRIPT_DIR / "main.py"
    import runpy
    original_argv = sys.argv[:]
    sys.argv = [str(main_script), *sys.argv[1:]]
    try:
        runpy.run_path(str(main_script), run_name="__main__")
    finally:
        sys.argv = original_argv


if __name__ == "__main__":
    # Build-time hook: CI names each offline-bundle dir with this value, so the
    # naming can never drift from the runtime selection logic above.
    if "--print-abi-tag" in sys.argv[1:]:
        # No trailing newline: on Windows a printed "\n" becomes "\r\n", and a
        # shell $(...) keeps the stray "\r", corrupting the dir name CI derives.
        sys.stdout.write(_abi_tag())
        sys.stdout.flush()
        raise SystemExit(0)
    _ensure_runtime()
    _run_main()
