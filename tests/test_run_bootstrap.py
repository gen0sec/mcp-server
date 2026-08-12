"""Unit tests for server/run.py bootstrap helpers (no network, always run).

Regression guard for the fallback-shadowing bug: the manifest pins
PYTHONPATH=${__dirname}/server/lib ahead of everything, so if the bundled
native wheels don't match the host interpreter (ABI/OS/arch), they must be
removed from sys.path AND PYTHONPATH before the per-interpreter venv is used —
otherwise the broken bundle shadows the venv and the fallback silently fails.
"""
import importlib.util
import os
import sys
from pathlib import Path

RUN_PY = Path(__file__).resolve().parent.parent / "server" / "run.py"


def _load_run():
    spec = importlib.util.spec_from_file_location("run_under_test", RUN_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_purge_removes_bundled_lib_but_keeps_others(monkeypatch):
    run = _load_run()
    lib = str(run.BUNDLED_LIB)
    other = "/usr/local/lib/python3.99/site-packages"

    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([lib, other]))
    monkeypatch.setattr(sys, "path", list(sys.path) + [lib, other])

    run._purge_bundled_from_path()

    assert lib not in sys.path
    assert other in sys.path
    pp = os.environ["PYTHONPATH"].split(os.pathsep)
    assert lib not in pp
    assert other in pp


def test_purge_pops_pythonpath_when_bundled_is_sole_entry(monkeypatch):
    run = _load_run()
    monkeypatch.setenv("PYTHONPATH", str(run.BUNDLED_LIB))
    monkeypatch.setattr(sys, "path", list(sys.path))

    run._purge_bundled_from_path()

    assert "PYTHONPATH" not in os.environ


def test_purge_is_a_noop_when_nothing_bundled(monkeypatch):
    run = _load_run()
    monkeypatch.delenv("PYTHONPATH", raising=False)
    before = list(sys.path)
    monkeypatch.setattr(sys, "path", list(before))

    run._purge_bundled_from_path()

    assert sys.path == before
    assert "PYTHONPATH" not in os.environ
