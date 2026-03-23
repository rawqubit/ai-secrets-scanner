"""Tests for ai-secrets-scanner."""
import sys
import os
import subprocess
import pytest


def run(*args):
    env = os.environ.copy()
    env.setdefault('OPENAI_API_KEY', 'sk-dummy')
    return subprocess.run(
        [sys.executable, "main.py"] + list(args),
        capture_output=True, text=True, env=env
    )


def test_help():
    r = run("--help")
    assert r.returncode == 0
    assert len(r.stdout) > 0


def test_no_args_fails():
    """Calling with no arguments must fail (required argument missing)."""
    r = run()
    assert r.returncode != 0

def test_module_compiles():
    r = subprocess.run(
        [sys.executable, "-m", "py_compile", "main.py"],
        capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr
