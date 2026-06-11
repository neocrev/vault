#!/usr/bin/env python3
"""Tests for vault — each test gets its own temp directory."""

import os, sys, json, shutil, tempfile
from pathlib import Path

PYTHON = "/usr/bin/python3"
SCRIPT = str(Path(__file__).parent / "vault.py")

class VaultTest:
    def __init__(self):
        self.td = Path(tempfile.mkdtemp(prefix="vault_test_"))

    def run(self, *args, inp=""):
        import subprocess
        result = subprocess.run(
            [PYTHON, SCRIPT] + list(args),
            capture_output=True, text=True, input=inp,
            cwd=str(self.td), env={**os.environ, "HOME": str(self.td)}
        )
        return result

    def cleanup(self):
        shutil.rmtree(self.td)

def test_init_creates_store():
    t = VaultTest()
    r = t.run("init", inp="secret123\nsecret123\n")
    assert r.returncode == 0, f"stderr: {r.stderr}"
    assert (t.td / ".vault" / "store.enc").exists()
    assert (t.td / ".vault" / "salt").exists()
    t.cleanup()

def test_init_twice_fails():
    t = VaultTest()
    t.run("init", inp="secret123\nsecret123\n")
    r = t.run("init", inp="secret123\nsecret123\n")
    assert r.returncode == 0
    assert "already exists" in r.stdout
    t.cleanup()

def test_set_and_get():
    t = VaultTest()
    t.run("init", inp="secret123\nsecret123\n")
    r = t.run("set", "apikey", "sk-abc123", inp="secret123\n")
    assert r.returncode == 0, f"stderr: {r.stderr}"
    r = t.run("get", "apikey", inp="secret123\n")
    assert r.returncode == 0, f"stderr: {r.stderr}"
    assert "sk-abc123" in r.stdout
    t.cleanup()

def test_list_keys():
    t = VaultTest()
    t.run("init", inp="secret123\nsecret123\n")
    t.run("set", "k1", "v1", inp="secret123\n")
    t.run("set", "k2", "v2", inp="secret123\n")
    r = t.run("list", inp="secret123\n")
    assert r.returncode == 0, f"stderr: {r.stderr}"
    assert "k1" in r.stdout
    assert "k2" in r.stdout
    t.cleanup()

def test_rm_key():
    t = VaultTest()
    t.run("init", inp="secret123\nsecret123\n")
    t.run("set", "todelete", "value", inp="secret123\n")
    r = t.run("rm", "todelete", inp="secret123\n")
    assert r.returncode == 0, f"stderr: {r.stderr}"
    assert "removed" in r.stdout
    r = t.run("get", "todelete", inp="secret123\n")
    assert r.returncode != 0
    t.cleanup()

def test_export():
    t = VaultTest()
    t.run("init", inp="secret123\nsecret123\n")
    t.run("set", "tk", "tv", inp="secret123\n")
    r = t.run("export", inp="secret123\n")
    assert r.returncode == 0, f"stderr: {r.stderr}"
    data = json.loads(r.stdout)
    assert "tk" in data
    assert data["tk"]["value"] == "tv"
    t.cleanup()

def test_wrong_password():
    t = VaultTest()
    t.run("init", inp="secret123\nsecret123\n")
    r = t.run("list", inp="wrongpass\n")
    assert r.returncode != 0
    assert "wrong password" in r.stderr
    t.cleanup()

def test_empty_list():
    t = VaultTest()
    t.run("init", inp="secret123\nsecret123\n")
    r = t.run("list", inp="secret123\n")
    assert r.returncode == 0
    assert "empty" in r.stdout
    t.cleanup()

def test_password_mismatch():
    t = VaultTest()
    r = t.run("init", inp="secret123\nnomatch\n")
    assert r.returncode != 0
    assert "do not match" in r.stderr
    t.cleanup()

def test_short_password():
    t = VaultTest()
    r = t.run("init", inp="ab\nab\n")
    assert r.returncode != 0
    assert "at least 4" in r.stderr
    t.cleanup()

def test_many_keys():
    t = VaultTest()
    t.run("init", inp="secret123\nsecret123\n")
    for i in range(10):
        t.run("set", f"key{i}", f"val{i}", inp="secret123\n")
    r = t.run("list", inp="secret123\n")
    assert r.returncode == 0
    for i in range(10):
        assert f"key{i}" in r.stdout
    t.cleanup()

if __name__ == "__main__":
    tests = [f for f in dir() if f.startswith("test_")]
    passed, failed = 0, 0
    for name in sorted(tests):
        try:
            globals()[name]()
            print(f"  PASS  {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1
    print(f"\n{passed}/{passed+failed} tests passed")
    sys.exit(0 if failed == 0 else 1)
