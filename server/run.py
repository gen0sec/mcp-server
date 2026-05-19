#!/usr/bin/env python3
"""
Launcher for the Gen0Sec WAF Rule Generation MCP server.

Resolution order for dependencies:

1. Bundled `server/lib` (preferred). `make pack` vendors deps here and the
   manifest sets PYTHONPATH=${__dirname}/server/lib, so imports just work.
2. Per-interpreter venv at `<extension_dir>/.venv-pyX.Y`. Only created if (1)
   fails — e.g. user configured a Python whose ABI doesn't match the
   bundled wheels, or the bundle is absent (running unpacked from source).

The host Python is never modified. We do not use `--user`, `--break-
system-packages`, or any global install.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REQUIREMENTS = PROJECT_ROOT / "requirements.txt"


def _venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _bundled_deps_importable() -> bool:
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


def _build_venv(venv_dir: Path) -> Path:
    """Create a venv with the current interpreter and install requirements."""
    py_tag = f"{sys.version_info.major}.{sys.version_info.minor}"
    print(
        f"[gen0sec-mcp] Bundled deps unavailable for Python {py_tag}; "
        f"creating isolated venv at {venv_dir} (one-time setup)...",
        file=sys.stderr,
    )
    if venv_dir.exists():
        shutil.rmtree(venv_dir, ignore_errors=True)

    import venv as _venv
    _venv.EnvBuilder(with_pip=True, symlinks=(sys.platform != "win32")).create(str(venv_dir))

    py = _venv_python(venv_dir)
    if not REQUIREMENTS.exists():
        print(f"[gen0sec-mcp] requirements.txt not found at {REQUIREMENTS}", file=sys.stderr)
        sys.exit(1)

    subprocess.check_call(
        [str(py), "-m", "pip", "install", "--no-warn-script-location",
         "--disable-pip-version-check", "-r", str(REQUIREMENTS)],
    )
    return py


def _ensure_runtime() -> None:
    """Guarantee `import mcp` will succeed, re-execing into a venv if needed."""
    if _bundled_deps_importable():
        return

    py_tag = f"{sys.version_info.major}.{sys.version_info.minor}"
    venv_dir = PROJECT_ROOT / f".venv-py{py_tag}"
    venv_py = _venv_python(venv_dir)

    if not venv_py.exists():
        try:
            venv_py = _build_venv(venv_dir)
        except (subprocess.CalledProcessError, OSError) as e:
            print(
                f"[gen0sec-mcp] Failed to create dependency venv: {e}\n"
                f"  Tried: {venv_dir}\n"
                "  Rebuild the extension with 'make pack' so deps are bundled, "
                "or install requirements.txt into a Python that the extension "
                "is configured to use.",
                file=sys.stderr,
            )
            sys.exit(1)

    # Re-exec into the venv interpreter so imports come from there.
    if Path(sys.executable).resolve() != venv_py.resolve():
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
