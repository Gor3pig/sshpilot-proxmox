"""Tests for Proxmox VE configuration without importing or instantiating GTK."""

import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
MISSING = object()
USE_STORED_SECRET = object()


def _load():
    module_name = "proxmox_plugin"
    for name in tuple(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(ROOT, "__init__.py"),
        submodule_search_locations=[ROOT],
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
        if self.operation_log is not None:
            self.operation_log.append(("settings.get", key))
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
        self.ui_thread_calls = []
        self.ui = self
        self.settings = _Settings()
        self.secrets = _Secrets()

    def register_page(self, page_id, title, icon, factory):
        self.pages.append((page_id, title, icon, factory))

    def run_on_ui_thread(self, callback, *args):
        self.ui_thread_calls.append((callback, args))


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

    assert data["permissions"] == ["ui", "settings", "keyring", "network"]


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


class _FakeClient:
    def __init__(self, result, operation_log=None):
        self.result = result
        self.operation_log = operation_log
        self.calls = []

    def test_connection(self, configuration, secret):
        self.calls.append((configuration, secret))
        if self.operation_log is not None:
            self.operation_log.append(("client.test_connection", configuration.endpoint_url))
        return self.result


def test_connection_uses_saved_settings_then_secret_in_worker_logic():
    mod = _load()
    operation_log = []
    stored = {
        "server_url": "https://pve.example.test:8006/",
        "token_user": "automation@pve",
        "token_id": "sshpilot",
    }
    settings = _Settings(stored, operation_log=operation_log)
    secrets = _Secrets(readback="stored-secret", operation_log=operation_log)
    expected = mod.connection_test_result("success")
    client = _FakeClient(expected, operation_log)

    result = mod.run_connection_test(settings, secrets, lambda: client)

    assert result is expected
    assert settings.get_calls == [("configuration", {})]
    assert secrets.calls == [("get", "api_token_secret")]
    assert len(client.calls) == 1
    configuration, secret = client.calls[0]
    assert configuration.server_url == "https://pve.example.test:8006"
    assert configuration.token_user == "automation@pve"
    assert configuration.token_id == "sshpilot"
    assert secret == "stored-secret"
    assert operation_log == [
        ("settings.get", "configuration"),
        ("secrets.get", "api_token_secret"),
        (
            "client.test_connection",
            "https://pve.example.test:8006/api2/json/access/permissions",
        ),
    ]


@pytest.mark.parametrize(
    "stored",
    [
        {},
        {"server_url": "https://pve.test", "token_user": "", "token_id": "id"},
        {"server_url": "http://pve.test", "token_user": "user", "token_id": "id"},
    ],
)
def test_connection_does_not_read_secret_or_create_client_for_invalid_config(stored):
    mod = _load()
    settings = _Settings(stored)
    secrets = _Secrets(readback="stored-secret")

    def forbidden_factory():
        raise AssertionError("client created for invalid configuration")

    result = mod.run_connection_test(settings, secrets, forbidden_factory)

    assert result.category in {"invalid_configuration", "invalid_url"}
    assert secrets.calls == []


def test_connection_does_not_create_client_when_secret_is_missing():
    mod = _load()
    settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        }
    )
    secrets = _Secrets(readback=None)

    def forbidden_factory():
        raise AssertionError("client created without a secret")

    result = mod.run_connection_test(settings, secrets, forbidden_factory)

    assert result.category == "missing_secret"
    assert secrets.calls == [("get", "api_token_secret")]


def test_connection_reports_secret_backend_failure_without_creating_client():
    mod = _load()
    settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        }
    )
    secrets = _Secrets(fail_get=True)

    def forbidden_factory():
        raise AssertionError("client created after secret backend failure")

    result = mod.run_connection_test(settings, secrets, forbidden_factory)

    assert result.category == "secret_unavailable"
    assert result.message == (
        "The API token secret could not be read from secure storage."
    )


def test_connection_hides_secret_from_unexpected_client_failure():
    mod = _load()
    secret = "worker-secret-sentinel"
    settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        }
    )
    secrets = _Secrets(readback=secret)

    class _FailingClient:
        def test_connection(self, _configuration, supplied_secret):
            raise RuntimeError(f"client exposed {supplied_secret}")

    result = mod.run_connection_test(settings, secrets, _FailingClient)

    assert result.category == "unexpected_error"
    assert secret not in result.message
    assert secret not in repr(result)


class _Button:
    def __init__(self):
        self.sensitive_calls = []

    def set_sensitive(self, sensitive):
        self.sensitive_calls.append(sensitive)


class _StatusLabel:
    def __init__(self):
        self.label = ""
        self.css_classes = set()

    def remove_css_class(self, css_class):
        self.css_classes.discard(css_class)

    def set_label(self, label):
        self.label = label

    def add_css_class(self, css_class):
        self.css_classes.add(css_class)


class _TextRow:
    def __init__(self, text):
        self.text = text

    def get_text(self):
        return self.text


class _DeferredThread:
    created = []

    def __init__(self, *, target, args, daemon):
        self.target = target
        self.args = args
        self.daemon = daemon
        self.started = False
        self.created.append(self)

    def start(self):
        self.started = True


def _headless_plugin(mod, ctx):
    plugin = mod.Plugin()
    plugin.activate(ctx)
    plugin._page_token = object()
    plugin._save_button = _Button()
    plugin._test_button = _Button()
    plugin._status_label = _StatusLabel()
    return plugin


def test_test_button_starts_worker_and_uses_ui_thread_callback(monkeypatch):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    ctx = _Ctx()
    ctx.settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        }
    )
    ctx.secrets = _Secrets(readback="stored-secret")
    plugin = _headless_plugin(mod, ctx)
    expected = mod.connection_test_result("success")
    client = _FakeClient(expected)
    plugin._client_factory = lambda: client
    plugin._server_url_row = _ForbiddenWidget()
    plugin._token_user_row = _ForbiddenWidget()
    plugin._token_id_row = _ForbiddenWidget()
    plugin._secret_row = _ForbiddenWidget()
    page_token = plugin._page_token

    plugin._on_test_clicked(None)

    assert len(_DeferredThread.created) == 1
    worker = _DeferredThread.created[0]
    assert worker.started is True
    assert worker.target == plugin._test_worker
    assert worker.args == (page_token,)
    assert plugin._operation_in_progress is True
    assert plugin._save_button.sensitive_calls == [False]
    assert plugin._test_button.sensitive_calls == [False]
    assert plugin._status_label.label == "Testing connection…"
    assert ctx.settings.get_calls == []

    worker.target(*worker.args)

    assert len(ctx.ui_thread_calls) == 1
    callback, args = ctx.ui_thread_calls[0]
    assert callback == plugin._finish_test
    assert args == (expected, page_token)
    assert ctx.settings.get_calls == [("configuration", {})]
    assert ctx.secrets.calls == [("get", "api_token_secret")]

    callback(*args)

    assert plugin._operation_in_progress is False
    assert plugin._save_button.sensitive_calls == [False, True]
    assert plugin._test_button.sensitive_calls == [False, True]
    assert plugin._status_label.label == expected.message
    assert plugin._status_label.css_classes == {"success"}


def test_save_and_test_are_mutually_exclusive_on_one_page(monkeypatch):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    plugin = _headless_plugin(mod, _Ctx())
    plugin._server_url_row = _TextRow("https://pve.test")
    plugin._token_user_row = _TextRow("user@pve")
    plugin._token_id_row = _TextRow("id")
    plugin._secret_row = _TextRow("new-secret")

    plugin._on_save_clicked(None)
    plugin._on_test_clicked(None)

    assert len(_DeferredThread.created) == 1
    assert _DeferredThread.created[0].target == plugin._save_worker
    assert plugin._operation_in_progress is True
    assert plugin._save_button.sensitive_calls == [False]
    assert plugin._test_button.sensitive_calls == [False]


def test_stale_test_callback_does_not_touch_rebuilt_page_widgets():
    mod = _load()
    plugin = mod.Plugin()
    page_a_token = object()
    plugin._page_token = object()
    plugin._save_button = _ForbiddenWidget()
    plugin._test_button = _ForbiddenWidget()
    plugin._status_label = _ForbiddenWidget()

    plugin._finish_test(mod.connection_test_result("success"), page_a_token)


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
