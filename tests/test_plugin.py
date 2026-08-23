"""Tests for Proxmox VE configuration without importing or instantiating GTK."""

import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(__file__)
MISSING = object()
USE_STORED_SECRET = object()


def _load():
    spec = importlib.util.spec_from_file_location(
        "proxmox_plugin", os.path.join(HERE, "..", "__init__.py")
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    return mod


class _Settings:
    def __init__(
        self,
        value=MISSING,
        *,
        fail_get=False,
        fail_set=False,
        operation_log=None,
    ):
        self.value = value
        self.fail_get = fail_get
        self.fail_set = fail_set
        self.operation_log = operation_log
        self.get_calls = []
        self.set_calls = []

    def get(self, key, default=None):
        self.get_calls.append((key, default))
        if self.fail_get:
            raise RuntimeError("settings unavailable")
        return default if self.value is MISSING else self.value

    def set(self, key, value):
        self.set_calls.append((key, value))
        if self.operation_log is not None:
            self.operation_log.append(("settings.set", key))
        if self.fail_set:
            raise RuntimeError("settings unavailable")
        self.value = value


class _Secrets:
    def __init__(
        self,
        *,
        readback=USE_STORED_SECRET,
        fail_set=False,
        fail_get=False,
        operation_log=None,
    ):
        self.readback = readback
        self.fail_set = fail_set
        self.fail_get = fail_get
        self.operation_log = operation_log
        self.stored = None
        self.calls = []

    def set(self, key, value):
        self.calls.append(("set", key, value))
        if self.operation_log is not None:
            self.operation_log.append(("secrets.set", key))
        if self.fail_set:
            raise RuntimeError("secure storage unavailable")
        self.stored = value

    def get(self, key):
        self.calls.append(("get", key))
        if self.operation_log is not None:
            self.operation_log.append(("secrets.get", key))
        if self.fail_get:
            raise RuntimeError("secure storage unavailable")
        return self.stored if self.readback is USE_STORED_SECRET else self.readback

    def delete(self, key):
        self.calls.append(("delete", key))
        return False


class _Ctx:
    def __init__(self):
        self.pages = []
        self.ui = self
        self.settings = _Settings()
        self.secrets = _Secrets()

    def register_page(self, page_id, title, icon, factory):
        self.pages.append((page_id, title, icon, factory))


def test_activate_registers_one_proxmox_page_without_importing_gtk():
    mod = _load()
    ctx = _Ctx()

    mod.Plugin().activate(ctx)

    assert len(ctx.pages) == 1
    page_id, title, _icon, factory = ctx.pages[0]
    assert page_id == "proxmox"
    assert title == "Proxmox VE"
    assert callable(factory)
    assert "gi" not in mod.__dict__


def test_manifest_declares_only_required_permissions():
    with open(os.path.join(HERE, "..", "plugin.json"), encoding="utf-8") as manifest:
        data = json.load(manifest)

    assert data["permissions"] == ["ui", "settings", "keyring"]


def test_load_configuration_defaults_when_absent():
    mod = _load()

    assert mod.load_configuration(_Settings()) == {
        "server_url": "",
        "token_user": "",
        "token_id": "",
    }


def test_load_configuration_accepts_valid_configuration():
    mod = _load()
    stored = {
        "server_url": "https://pve.example.test:8006",
        "token_user": "automation@pve",
        "token_id": "sshpilot",
    }

    assert mod.load_configuration(_Settings(stored)) == stored


@pytest.mark.parametrize("stored", [None, "invalid", ["invalid"]])
def test_load_configuration_rejects_non_dictionary_roots(stored):
    mod = _load()

    assert mod.load_configuration(_Settings(stored)) == {
        "server_url": "",
        "token_user": "",
        "token_id": "",
    }


def test_load_configuration_defaults_missing_properties():
    mod = _load()

    assert mod.load_configuration(_Settings({"server_url": "https://pve.test"})) == {
        "server_url": "https://pve.test",
        "token_user": "",
        "token_id": "",
    }


def test_load_configuration_rejects_properties_with_wrong_types():
    mod = _load()
    stored = {"server_url": 42, "token_user": [], "token_id": None}

    assert mod.load_configuration(_Settings(stored)) == {
        "server_url": "",
        "token_user": "",
        "token_id": "",
    }


def test_load_configuration_handles_settings_errors():
    mod = _load()

    assert mod.load_configuration(_Settings(fail_get=True)) == {
        "server_url": "",
        "token_user": "",
        "token_id": "",
    }


def test_save_without_new_secret_only_writes_stripped_configuration():
    mod = _load()
    settings = _Settings()
    secrets = _Secrets()
    configuration = mod.build_configuration(
        "  https://pve.example.test:8006  ",
        "  automation@pve ",
        " sshpilot  ",
    )

    result = mod.save_configuration(settings, secrets, configuration, "")

    assert settings.set_calls == [
        (
            "configuration",
            {
                "server_url": "https://pve.example.test:8006",
                "token_user": "automation@pve",
                "token_id": "sshpilot",
            },
        )
    ]
    assert secrets.calls == []
    assert result.success is True
    assert result.partial is False
    assert result.clear_secret is False


def test_save_with_new_secret_stores_and_verifies_it():
    mod = _load()
    operation_log = []
    settings = _Settings(operation_log=operation_log)
    secrets = _Secrets(operation_log=operation_log)
    configuration = mod.build_configuration("https://pve.test", "user@pve", "plugin")
    secret = "new-token-secret"

    result = mod.save_configuration(settings, secrets, configuration, secret)

    assert secrets.calls == [
        ("set", "api_token_secret", secret),
        ("get", "api_token_secret"),
    ]
    assert operation_log == [
        ("settings.set", "configuration"),
        ("secrets.set", "api_token_secret"),
        ("secrets.get", "api_token_secret"),
    ]
    assert settings.value == configuration
    assert secret not in repr(settings.value)
    assert result.success is True
    assert result.partial is False
    assert result.clear_secret is True
    assert secret not in result.message


@pytest.mark.parametrize("readback", [None, "different-secret"])
def test_save_does_not_confirm_missing_or_mismatched_secret(readback):
    mod = _load()
    settings = _Settings()
    secrets = _Secrets(readback=readback)
    secret = "new-token-secret"

    result = mod.save_configuration(settings, secrets, {}, secret)

    assert settings.set_calls == [("configuration", {})]
    assert secrets.calls == [
        ("set", "api_token_secret", secret),
        ("get", "api_token_secret"),
    ]
    assert result.success is False
    assert result.partial is True
    assert result.clear_secret is False
    assert secret not in result.message


def test_settings_failure_prevents_secret_write():
    mod = _load()
    settings = _Settings(fail_set=True)
    secrets = _Secrets()
    secret = "new-token-secret"

    result = mod.save_configuration(settings, secrets, {}, secret)

    assert secrets.calls == []
    assert result.success is False
    assert result.partial is False
    assert result.clear_secret is False
    assert secret not in result.message


def test_secret_write_failure_reports_partial_save_without_revealing_secret():
    mod = _load()
    settings = _Settings()
    secrets = _Secrets(fail_set=True)
    secret = "new-token-secret"

    result = mod.save_configuration(settings, secrets, {}, secret)

    assert settings.set_calls == [("configuration", {})]
    assert secrets.calls == [("set", "api_token_secret", secret)]
    assert result.success is False
    assert result.partial is True
    assert result.clear_secret is False
    assert secret not in result.message


def test_secret_read_failure_reports_partial_save_without_revealing_secret():
    mod = _load()
    settings = _Settings()
    secrets = _Secrets(fail_get=True)
    configuration = mod.build_configuration("https://pve.test", "user@pve", "plugin")
    secret = "new-token-secret"

    result = mod.save_configuration(settings, secrets, configuration, secret)

    assert settings.set_calls == [("configuration", configuration)]
    assert secrets.calls == [
        ("set", "api_token_secret", secret),
        ("get", "api_token_secret"),
    ]
    assert result.success is False
    assert result.partial is True
    assert result.clear_secret is False
    assert secret not in result.message
    assert secret not in repr(result)


class _ForbiddenWidget:
    def __getattr__(self, name):
        raise AssertionError(f"stale callback accessed new page widget method {name}")


def test_stale_save_callback_does_not_touch_rebuilt_page_widgets():
    mod = _load()
    plugin = mod.Plugin()
    page_a_token = object()
    plugin._page_token = object()
    plugin._secret_row = _ForbiddenWidget()
    plugin._save_button = _ForbiddenWidget()
    plugin._status_label = _ForbiddenWidget()
    result = mod.SaveResult(
        success=True,
        partial=False,
        clear_secret=True,
        message="Configuration and token secret saved.",
    )

    plugin._finish_save(result, page_a_token)
