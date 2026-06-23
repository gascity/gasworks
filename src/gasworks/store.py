"""Credential store: ~/.config/gasworks/credentials.json (0600), atomic + cross-process locked.

Holds the Keycloak refresh token, the per-org STS session + its DPoP key (PEM), and an EIA
cache. A stolen credentials file is co-located-key vulnerable (the token scheme's acknowledged
limit — DPoP binds the key, not the file); OS-keyring storage is a documented follow-up.
"""

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict


def config_dir() -> Path:
    override = os.environ.get("GASWORKS_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "gasworks"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return (Path(xdg) if xdg else Path.home() / ".config") / "gasworks"


def _creds_path() -> Path:
    return config_dir() / "credentials.json"


def _ensure_dir() -> Path:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    return d


@contextmanager
def _locked():
    """Hold an exclusive lock around the read-modify-write of credentials.json so two
    concurrent getToken invocations cannot lose each other's session/key."""
    d = _ensure_dir()
    fd = os.open(str(d / ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "posix":
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            try:
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            except OSError:
                pass  # best-effort on Windows
        yield
    finally:
        if os.name == "posix":
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def load() -> Dict[str, Any]:
    try:
        with open(_creds_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, OSError):
        # A corrupt/unreadable file degrades to "logged out" (re-login), never a crash.
        return {}


def save(data: Dict[str, Any]) -> None:
    """Atomically write credentials.json, 0600 from creation (mkstemp is O_EXCL+0600)."""
    d = _ensure_dir()
    fd, tmp = tempfile.mkstemp(dir=str(d), prefix=".cred-", suffix=".tmp")
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(_creds_path()))  # atomic on POSIX and Windows
        if os.name == "nt":
            _win_lockdown(_creds_path())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextmanager
def update():
    """Locked read-modify-write: `with store.update() as data: data[...] = ...`."""
    with _locked():
        data = load()
        yield data
        save(data)


def clear() -> None:
    with _locked():
        try:
            os.unlink(_creds_path())
        except FileNotFoundError:
            pass


def _win_lockdown(path: Path) -> None:
    # 0600 is a no-op on Windows; best-effort restrict the file to the current user.
    user = os.environ.get("USERNAME")
    if not user:
        return
    import subprocess

    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            check=False,
            capture_output=True,
        )
    except OSError:
        pass
