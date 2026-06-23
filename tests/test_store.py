import os
import stat

import gasworks.store as store


def test_save_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("GASWORKS_CONFIG_DIR", str(tmp_path / "cfg"))
    data = {"refresh_token": "rt", "sessions": {"org_a": {"token": "t", "dpop_pem": "..."}}}
    store.save(data)
    assert store.load() == data


def test_creds_file_is_0600(tmp_path, monkeypatch):
    if os.name != "posix":
        return
    monkeypatch.setenv("GASWORKS_CONFIG_DIR", str(tmp_path / "cfg"))
    store.save({"x": 1})
    mode = stat.S_IMODE(os.stat(store._creds_path()).st_mode)
    assert mode == 0o600, oct(mode)


def test_update_is_read_modify_write(tmp_path, monkeypatch):
    monkeypatch.setenv("GASWORKS_CONFIG_DIR", str(tmp_path / "cfg"))
    store.save({"a": 1})
    with store.update() as data:
        data["b"] = 2
    assert store.load() == {"a": 1, "b": 2}


def test_load_missing_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("GASWORKS_CONFIG_DIR", str(tmp_path / "nope"))
    assert store.load() == {}


def test_clear_removes(tmp_path, monkeypatch):
    monkeypatch.setenv("GASWORKS_CONFIG_DIR", str(tmp_path / "cfg"))
    store.save({"x": 1})
    store.clear()
    assert store.load() == {}


def test_corrupt_file_degrades_to_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("GASWORKS_CONFIG_DIR", str(tmp_path / "cfg"))
    store.save({"x": 1})
    store._creds_path().write_text("{not valid json", encoding="utf-8")
    assert store.load() == {}
