#!/usr/bin/env python3
"""
Launcher for the Gen0Sec WAF Rule Generation MCP server.

Resolution order for dependencies:

1. Bundled `server/lib`, IF it imports under this interpreter. The released
   `.mcpb` is deliberately "thin" (no vendored wheels) because a single bundle
   cannot carry native extensions for every Python ABI + OS + arch. A populated
   `server/lib` only exists for a single-platform local/offline build
   (`make vendor`) or the Docker image — and it is used only when it actually
   imports on the host.
2. Per-interpreter venv at `<extension_dir>/.venv-<pyX.Y>-<platform>`. Built on
   first run when (1) is absent or ABI-incompatible. This is the normal path
   for the released bundle.

The host Python is never modified. We do not use `--user`, `--break-
system-packages`, or any global install.
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


def _purge_bundled_from_path() -> None:
    """Remove the vendored ``server/lib`` from ``sys.path`` and ``PYTHONPATH``.

    The bundled wheels include native extensions built for one Python ABI + OS
    + arch. When the host Python doesn't match, they fail to import. Because the
    manifest pins ``PYTHONPATH=${__dirname}/server/lib`` ahead of everything,
    those broken wheels would also SHADOW the correctly-built packages in our
    fallback venv — defeating the fallback. Drop server/lib so the venv wins.
    """
    target = BUNDLED_LIB.resolve()

    def _is_bundled(entry: str) -> bool:
        try:
            return bool(entry) and Path(entry).resolve() == target
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
    if _bundled_deps_importable():
        return

    # We re-exec into a fallback venv below. If we've already done so and deps
    # STILL don't import, the venv itself is broken — stop, don't loop.
    if os.environ.get(_BOOTSTRAP_FLAG) == "1":
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
    # absent. Stop the broken/absent server/lib from shadowing the fallback venv
    # — both now and across the re-exec — then build/use the venv.
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
    _ensure_runtime()
    _run_main()
