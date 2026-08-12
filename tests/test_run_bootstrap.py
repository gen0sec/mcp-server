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


def test_purge_also_removes_multiabi_subdir(monkeypatch):
    # The multi-ABI layout puts packages in server/lib/<abi-tag>/; the purge must
    # drop those subdir entries too, not just the flat server/lib root.
    run = _load_run()
    tagged = str(run.BUNDLED_LIB / "cpython-312-linux-x86_64")
    other = "/usr/local/lib/python3.99/site-packages"

    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([tagged, other]))
    monkeypatch.setattr(sys, "path", list(sys.path) + [tagged, other])

    run._purge_bundled_from_path()

    assert tagged not in sys.path
    assert other in sys.path
    assert tagged not in os.environ["PYTHONPATH"].split(os.pathsep)


def test_abi_tag_is_stable_and_self_describing():
    run = _load_run()
    tag = run._abi_tag()
    assert tag == tag.lower()
    assert sys.platform in tag
    # Interpreter family + version, e.g. cpython-312-...
    assert tag.startswith((sys.implementation.name, "cpython", "pypy"))
    # Same interpreter must always compute the same key (build == runtime).
    assert run._abi_tag() == tag


def test_bundled_dir_none_when_unpopulated(monkeypatch, tmp_path):
    run = _load_run()
    # Point BUNDLED_LIB at an empty dir: neither a matching <tag>/mcp nor a flat
    # mcp exists, so there is no usable bundled dir.
    monkeypatch.setattr(run, "BUNDLED_LIB", tmp_path)
    assert run._bundled_dir() is None


def test_ensure_runtime_skips_bundled_after_bootstrap(monkeypatch):
    # Regression: once re-exec'd into the fallback venv, _ensure_runtime must NOT
    # re-prepend a bundled dir — an incompatible server/lib would shadow the venv
    # and make the venv look "broken".
    run = _load_run()
    calls = []
    monkeypatch.setattr(run, "_prepend_to_path", lambda d: calls.append(d))
    monkeypatch.setattr(run, "_bundled_dir", lambda: run.BUNDLED_LIB / "sometag")
    monkeypatch.setattr(run, "_bundled_deps_importable", lambda: True)
    monkeypatch.setenv("GEN0SEC_MCP_BOOTSTRAPPED", "1")

    run._ensure_runtime()

    assert calls == []


def test_ensure_runtime_prepends_bundled_before_bootstrap(monkeypatch):
    run = _load_run()
    calls = []
    tag_dir = run.BUNDLED_LIB / "sometag"
    monkeypatch.setattr(run, "_prepend_to_path", lambda d: calls.append(d))
    monkeypatch.setattr(run, "_bundled_dir", lambda: tag_dir)
    monkeypatch.setattr(run, "_bundled_deps_importable", lambda: True)
    monkeypatch.delenv("GEN0SEC_MCP_BOOTSTRAPPED", raising=False)

    run._ensure_runtime()

    assert calls == [tag_dir]
