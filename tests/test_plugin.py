"""Tests for Proxmox VE configuration without importing or instantiating GTK."""

import importlib.util
import json
import os
import sys
import types

import pytest

from ui_fakes import (
    _AdwActionRow,
    _AdwPreferencesGroup,
    _Button,
    _install_fake_gi,
)

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
        custom_ca_enabled=MISSING,
    ):
        self.value = value
        self.fail_get = fail_get
        self.fail_set = fail_set
        self.operation_log = operation_log
        self.custom_ca_enabled = custom_ca_enabled
        self.get_calls = []
        self.set_calls = []

    def get(self, key, default=None):
        self.get_calls.append((key, default))
        if self.operation_log is not None:
            self.operation_log.append(("settings.get", key))
        if self.fail_get:
            raise RuntimeError("settings unavailable")
        if key == "custom_ca_enabled":
            return (
                default
                if self.custom_ca_enabled is MISSING
                else self.custom_ca_enabled
            )
        return default if self.value is MISSING else self.value

    def set(self, key, value):
        self.set_calls.append((key, value))
        if self.operation_log is not None:
            self.operation_log.append(("settings.set", key))
        if self.fail_set:
            raise RuntimeError("settings unavailable")
        if key == "custom_ca_enabled":
            self.custom_ca_enabled = value
        else:
            self.value = value


class _Files:
    def __init__(self, root=None, *, fail_path=False, fail_read=False):
        self.root = root
        self.fail_path = fail_path
        self.fail_read = fail_read
        self.path_calls = []
        self.read_calls = []

    def path(self, relative):
        self.path_calls.append(relative)
        if self.fail_path or self.root is None:
            raise OSError("private storage unavailable")
        return os.path.join(self.root, relative)

    def read_bytes(self, relative):
        self.read_calls.append(relative)
        if self.fail_read:
            raise OSError("private storage unavailable")
        with open(self.path(relative), "rb") as stored:
            return stored.read()


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


class _KeyedSettings:
    def __init__(
        self,
        values=None,
        *,
        fail_get_once=None,
        fail_set_once=None,
        set_then_fail_once=None,
        get_sequences=None,
    ):
        self.values = dict(values or {})
        self.fail_get_once = set(fail_get_once or ())
        self.fail_set_once = set(fail_set_once or ())
        self.set_then_fail_once = set(set_then_fail_once or ())
        self.get_sequences = {
            key: list(sequence) for key, sequence in (get_sequences or {}).items()
        }
        self.get_calls = []
        self.set_calls = []

    def get(self, key, default=None):
        self.get_calls.append((key, default))
        if key in self.fail_get_once:
            self.fail_get_once.remove(key)
            raise RuntimeError("settings unavailable")
        sequence = self.get_sequences.get(key)
        if sequence:
            value = sequence.pop(0)
            return default if value is MISSING else value
        return self.values.get(key, default)

    def set(self, key, value):
        self.set_calls.append((key, value))
        if key in self.fail_set_once:
            self.fail_set_once.remove(key)
            raise RuntimeError("settings unavailable")
        self.values[key] = value
        if key in self.set_then_fail_once:
            self.set_then_fail_once.remove(key)
            raise RuntimeError("settings readback unavailable")


class _KeyedSecrets:
    def __init__(self, values=None, *, fail_set_once=None, get_sequences=None):
        self.values = dict(values or {})
        self.fail_set_once = set(fail_set_once or ())
        self.get_sequences = {
            key: list(sequence) for key, sequence in (get_sequences or {}).items()
        }
        self.calls = []

    def get(self, key):
        self.calls.append(("get", key))
        sequence = self.get_sequences.get(key)
        if sequence:
            return sequence.pop(0)
        return self.values.get(key)

    def set(self, key, value):
        self.calls.append(("set", key, value))
        if key in self.fail_set_once:
            self.fail_set_once.remove(key)
            raise RuntimeError("secure storage unavailable")
        self.values[key] = value

    def delete(self, key):
        self.calls.append(("delete", key))
        return self.values.pop(key, None) is not None


def _endpoint_model(
    mod,
    endpoint_id="b" * 32,
    *,
    active_endpoint_id=None,
    configuration=None,
    custom_ca_enabled=False,
    secret_source=None,
):
    if configuration is None:
        configuration = {
            "server_url": "https://pve.example.test:8006",
            "token_user": "automation@pve",
            "token_id": "sshpilot",
        }
    if secret_source is None:
        secret_source = mod.ENDPOINT_SECRET_SOURCE_LEGACY
    return {
        "schema_version": mod.ENDPOINT_SCHEMA_VERSION,
        "active_endpoint_id": active_endpoint_id or endpoint_id,
        "endpoints": [
            {
                "endpoint_id": endpoint_id,
                "configuration": configuration,
                "custom_ca_enabled": custom_ca_enabled,
                "secret_source": secret_source,
            }
        ],
    }


class _Ctx:
    def __init__(self):
        self.pages = []
        self.ui_thread_calls = []
        self.ui = self
        self.settings = _Settings()
        self.secrets = _Secrets()
        self.files = _Files()
        self.connections = []
        self.connection_calls = []
        self.fail_list_connections = False
        self.fail_add_connection = False
        self.fail_open_connection = False

    def register_page(self, page_id, title, icon, factory):
        self.pages.append((page_id, title, icon, factory))

    def run_on_ui_thread(self, callback, *args):
        self.ui_thread_calls.append((callback, args))

    def list_connections(self):
        self.connection_calls.append(("list",))
        if self.fail_list_connections:
            raise RuntimeError("connections unavailable")
        return list(self.connections)

    def add_connection(self, data):
        self.connection_calls.append(("add", dict(data)))
        if self.fail_add_connection:
            raise RuntimeError("connection creation detail")
        connection = types.SimpleNamespace(
            nickname=data["nickname"],
            host=data["hostname"],
            username=data.get("username", ""),
            port=data.get("port", 22),
            protocol=data.get("protocol", "ssh"),
        )
        self.connections.append(connection)
        return connection

    def open_connection(self, nickname):
        self.connection_calls.append(("open", nickname))
        if self.fail_open_connection:
            raise RuntimeError("connection open detail")
        return any(connection.nickname == nickname for connection in self.connections)


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

    assert data["permissions"] == [
        "ui",
        "settings",
        "keyring",
        "network",
        "filesystem",
        "connections",
    ]


def test_custom_ca_disabled_uses_system_trust_without_reading_private_files():
    mod = _load()
    files = _Files(fail_read=True)

    assert mod.load_custom_ca_pem(_Settings(), files) is None
    assert files.read_calls == []


def test_custom_ca_enabled_accepts_only_missing_or_exact_boolean_values():
    mod = _load()

    assert mod._custom_ca_enabled(_Settings()) is False
    assert mod._custom_ca_enabled(_Settings(custom_ca_enabled=False)) is False
    assert mod._custom_ca_enabled(_Settings(custom_ca_enabled=True)) is True


@pytest.mark.parametrize("value", ["true", 1, 0, None])
def test_custom_ca_enabled_rejects_non_boolean_values(value):
    mod = _load()

    with pytest.raises(mod.ProxmoxValidationError) as raised:
        mod._custom_ca_enabled(_Settings(custom_ca_enabled=value))

    assert raised.value.category == "custom_ca_error"
    assert repr(value) not in str(raised.value)


def test_custom_ca_enabled_loads_and_validates_private_copy(tmp_path, monkeypatch):
    mod = _load()
    stored = b"private-copy-ca"
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(stored)
    files = _Files(str(tmp_path))
    seen = []
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: seen.append(value) or value.decode("ascii"),
    )

    result = mod.load_custom_ca_pem(
        _Settings(custom_ca_enabled=True),
        files,
    )

    assert result == stored.decode("ascii")
    assert seen == [stored]
    assert files.read_calls == [mod.CUSTOM_CA_FILE]


def test_custom_ca_enabled_fails_closed_when_private_copy_is_missing(tmp_path):
    mod = _load()

    with pytest.raises(mod.ProxmoxValidationError) as raised:
        mod.load_custom_ca_pem(
            _Settings(custom_ca_enabled=True),
            _Files(str(tmp_path)),
        )

    assert raised.value.category == "custom_ca_error"
    assert str(tmp_path) not in str(raised.value)


def test_custom_ca_enabled_fails_closed_when_private_copy_is_invalid(tmp_path):
    mod = _load()
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(b"not a certificate")

    with pytest.raises(mod.ProxmoxValidationError) as raised:
        mod.load_custom_ca_pem(
            _Settings(custom_ca_enabled=True),
            _Files(str(tmp_path)),
        )

    assert raised.value.category == "custom_ca_error"
    assert "not a certificate" not in str(raised.value)


def test_disabled_custom_ca_ignores_an_orphaned_private_copy(tmp_path):
    mod = _load()
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(b"orphaned-invalid-data")
    files = _Files(str(tmp_path))

    assert mod.load_custom_ca_pem(
        _Settings(custom_ca_enabled=False),
        files,
    ) is None
    assert files.read_calls == []


def test_import_custom_ca_copies_validated_data_and_enables_setting(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    source = tmp_path / "selected-source.pem"
    source.write_bytes(b"selected-ca")
    private_root = tmp_path / "private"
    private_root.mkdir()
    settings = _Settings(custom_ca_enabled=False)
    files = _Files(str(private_root))
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii"),
    )

    result = mod.import_custom_ca(settings, files, str(source))

    assert result == mod.CustomCAResult(
        True,
        True,
        "Custom CA certificate imported.",
    )
    stored = private_root / mod.CUSTOM_CA_FILE
    assert stored.read_bytes() == b"selected-ca"
    assert stored.stat().st_mode & 0o777 == 0o600
    assert settings.set_calls == [(mod.CUSTOM_CA_ENABLED_KEY, True)]
    assert str(source) not in repr(settings.set_calls)
    assert sorted(path.name for path in private_root.iterdir()) == [
        mod.CUSTOM_CA_FILE
    ]


def test_import_replaces_an_active_ca_without_toggling_setting(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    source = tmp_path / "replacement.pem"
    source.write_bytes(b"replacement-ca")
    private_root = tmp_path / "private"
    private_root.mkdir()
    (private_root / mod.CUSTOM_CA_FILE).write_bytes(b"previous-ca")
    settings = _Settings(custom_ca_enabled=True)
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii"),
    )

    result = mod.import_custom_ca(
        settings,
        _Files(str(private_root)),
        str(source),
    )

    assert result.success is True
    assert result.enabled is True
    assert settings.set_calls == []
    assert (private_root / mod.CUSTOM_CA_FILE).read_bytes() == b"replacement-ca"


@pytest.mark.parametrize(
    "data, expected_message",
    [
        (b"", "The selected file is not a valid CA certificate bundle."),
        (b"\xff", "The selected file is not a valid CA certificate bundle."),
        (
            b"-----BEGIN PRIVATE KEY-----\nmaterial\n-----END PRIVATE KEY-----\n",
            "The selected file contains private key material and was not imported.",
        ),
        (
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
            "The selected file is not a valid CA certificate bundle.",
        ),
    ],
)
def test_import_rejects_invalid_ca_content(tmp_path, data, expected_message):
    mod = _load()
    source = tmp_path / "selected.pem"
    source.write_bytes(data)
    private_root = tmp_path / "private"
    private_root.mkdir()
    settings = _Settings(custom_ca_enabled=False)

    result = mod.import_custom_ca(
        settings,
        _Files(str(private_root)),
        str(source),
    )

    assert result.success is False
    assert result.enabled is False
    assert result.message == expected_message
    assert settings.set_calls == []
    assert list(private_root.iterdir()) == []
    assert str(source) not in result.message


def test_import_rejects_files_larger_than_one_mib(tmp_path):
    mod = _load()
    source = tmp_path / "oversized.pem"
    source.write_bytes(b"x" * (mod.MAX_CUSTOM_CA_BYTES + 1))
    private_root = tmp_path / "private"
    private_root.mkdir()

    result = mod.import_custom_ca(
        _Settings(custom_ca_enabled=False),
        _Files(str(private_root)),
        str(source),
    )

    assert result.success is False
    assert result.message == "The selected CA certificate file is too large."
    assert list(private_root.iterdir()) == []


def test_import_accepts_a_file_exactly_at_the_one_mib_limit(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    source = tmp_path / "maximum.pem"
    source.write_bytes(b"x" * mod.MAX_CUSTOM_CA_BYTES)
    private_root = tmp_path / "private"
    private_root.mkdir()
    monkeypatch.setattr(mod, "validate_custom_ca_pem", lambda _value: "valid-ca")

    result = mod.import_custom_ca(
        _Settings(custom_ca_enabled=False),
        _Files(str(private_root)),
        str(source),
    )

    assert result.success is True
    assert (private_root / mod.CUSTOM_CA_FILE).read_bytes() == b"valid-ca"


def test_import_storage_error_is_sanitized(tmp_path, monkeypatch):
    mod = _load()
    source = tmp_path / "selected.pem"
    source.write_bytes(b"selected-ca")
    monkeypatch.setattr(mod, "validate_custom_ca_pem", lambda value: "valid-ca")

    result = mod.import_custom_ca(
        _Settings(custom_ca_enabled=False),
        _Files(fail_path=True),
        str(source),
    )

    assert result.success is False
    assert result.message == "The custom CA certificate could not be saved."
    assert str(source) not in result.message


def test_import_replace_failure_preserves_active_copy_and_removes_temporary(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    source = tmp_path / "selected.pem"
    source.write_bytes(b"replacement-ca")
    private_root = tmp_path / "private"
    private_root.mkdir()
    stored = private_root / mod.CUSTOM_CA_FILE
    stored.write_bytes(b"previous-ca")
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii"),
    )
    monkeypatch.setattr(
        mod.os,
        "replace",
        lambda _source, _target: (_ for _ in ()).throw(OSError()),
    )

    result = mod.import_custom_ca(
        _Settings(custom_ca_enabled=True),
        _Files(str(private_root)),
        str(source),
    )

    assert result.success is False
    assert result.enabled is True
    assert stored.read_bytes() == b"previous-ca"
    assert sorted(path.name for path in private_root.iterdir()) == [
        mod.CUSTOM_CA_FILE
    ]


def test_import_setting_error_leaves_ca_disabled_and_cleans_copy(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    source = tmp_path / "selected.pem"
    source.write_bytes(b"selected-ca")
    private_root = tmp_path / "private"
    private_root.mkdir()
    settings = _Settings(custom_ca_enabled=False, fail_set=True)
    monkeypatch.setattr(mod, "validate_custom_ca_pem", lambda value: "valid-ca")

    result = mod.import_custom_ca(
        settings,
        _Files(str(private_root)),
        str(source),
    )

    assert result.success is False
    assert result.enabled is False
    assert settings.custom_ca_enabled is False
    assert not (private_root / mod.CUSTOM_CA_FILE).exists()


def test_remove_custom_ca_disables_then_deletes_private_copy(tmp_path):
    mod = _load()
    stored = tmp_path / mod.CUSTOM_CA_FILE
    stored.write_bytes(b"stored-ca")
    settings = _Settings(custom_ca_enabled=True)

    result = mod.remove_custom_ca(settings, _Files(str(tmp_path)))

    assert result == mod.CustomCAResult(True, False, "System trust store restored.")
    assert settings.set_calls == [(mod.CUSTOM_CA_ENABLED_KEY, False)]
    assert not stored.exists()


def test_remove_custom_ca_accepts_an_already_missing_file(tmp_path):
    mod = _load()

    result = mod.remove_custom_ca(
        _Settings(custom_ca_enabled=True),
        _Files(str(tmp_path)),
    )

    assert result.success is True
    assert result.enabled is False


def test_remove_settings_error_preserves_private_copy(tmp_path):
    mod = _load()
    stored = tmp_path / mod.CUSTOM_CA_FILE
    stored.write_bytes(b"stored-ca")

    result = mod.remove_custom_ca(
        _Settings(custom_ca_enabled=True, fail_set=True),
        _Files(str(tmp_path)),
    )

    assert result.success is False
    assert result.enabled is None
    assert stored.read_bytes() == b"stored-ca"


def test_remove_cleanup_error_keeps_system_trust_enabled(tmp_path, monkeypatch):
    mod = _load()
    stored = tmp_path / mod.CUSTOM_CA_FILE
    stored.write_bytes(b"stored-ca")
    settings = _Settings(custom_ca_enabled=True)
    monkeypatch.setattr(mod.os, "unlink", lambda _path: (_ for _ in ()).throw(OSError()))

    result = mod.remove_custom_ca(settings, _Files(str(tmp_path)))

    assert result.success is False
    assert result.enabled is False
    assert settings.custom_ca_enabled is False
    assert stored.exists()
    assert result.message == (
        "System trust was restored, but the stored custom CA could not be removed."
    )


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


def test_endpoint_store_materializes_legacy_metadata_without_secret_or_ca(
    tmp_path,
):
    mod = _load()
    configuration = {
        "server_url": "https://pve.example.test:8006",
        "token_user": "automation@pve",
        "token_id": "sshpilot",
    }
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: configuration,
            mod.CUSTOM_CA_ENABLED_KEY: False,
        }
    )
    secrets = _KeyedSecrets()
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
    )

    collection = store.materialize_legacy()
    endpoint_id = collection.active_endpoint_id

    assert mod._ENDPOINT_ID.fullmatch(endpoint_id)
    assert collection.active_endpoint_id == endpoint_id
    assert collection.active_endpoint.configuration == configuration
    assert collection.active_endpoint.custom_ca_enabled is False
    assert collection.active_endpoint.secret_source == (
        mod.ENDPOINT_SECRET_SOURCE_LEGACY
    )
    assert settings.values[mod.ENDPOINTS_KEY] == {
        "schema_version": 1,
        "active_endpoint_id": endpoint_id,
        "endpoints": [
            {
                "endpoint_id": endpoint_id,
                "configuration": configuration,
                "custom_ca_enabled": False,
                "secret_source": mod.ENDPOINT_SECRET_SOURCE_LEGACY,
            }
        ],
    }
    assert settings.values[mod.CONFIGURATION_KEY] == configuration
    assert settings.values[mod.CUSTOM_CA_ENABLED_KEY] is False
    assert secrets.values == {}
    assert mod.SECRET_KEY not in repr(settings.values[mod.ENDPOINTS_KEY])
    json.dumps(settings.values[mod.ENDPOINTS_KEY])
    set_calls = list(settings.set_calls)

    assert store.materialize_legacy() == collection
    assert settings.set_calls == set_calls


def test_endpoint_store_materializes_legacy_secret_and_custom_ca(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    endpoint_id = "2" * 32
    secret = "legacy-token-secret"
    ca = b"public-ca"
    configuration = {
        "server_url": "https://pve.example.test:8006",
        "token_user": "automation@pve",
        "token_id": "sshpilot",
    }
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: configuration,
            mod.CUSTOM_CA_ENABLED_KEY: True,
        }
    )
    secrets = _KeyedSecrets({mod.SECRET_KEY: secret})
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(ca)
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii") if isinstance(value, bytes) else value,
    )
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: endpoint_id,
    )

    collection = store.materialize_legacy()

    assert collection.active_endpoint.custom_ca_enabled is True
    assert collection.active_endpoint.secret_source == (
        mod.ENDPOINT_SECRET_SOURCE_ENDPOINT
    )
    assert secrets.values[mod.SECRET_KEY] == secret
    assert secrets.values[store.secret_key(endpoint_id)] == secret
    assert (tmp_path / mod.CUSTOM_CA_FILE).read_bytes() == ca
    endpoint_ca = tmp_path / store.custom_ca_file(endpoint_id)
    assert endpoint_ca.read_bytes() == ca
    assert endpoint_ca.stat().st_mode & 0o777 == 0o600
    assert secret not in repr(settings.values)


def test_endpoint_store_reuses_existing_model_without_repeating_migration(
    tmp_path,
):
    mod = _load()
    endpoint_id = "3" * 32
    persisted = _endpoint_model(
        mod,
        endpoint_id,
        configuration={
            "server_url": "https://new.example.test:8006",
            "token_user": "new@pve",
            "token_id": "new-token",
        },
    )
    settings = _KeyedSettings(
        {
            mod.ENDPOINTS_KEY: persisted,
            mod.CONFIGURATION_KEY: {
                "server_url": "https://legacy.example.test:8006",
            },
        }
    )
    secrets = _KeyedSecrets({mod.SECRET_KEY: "legacy-secret"})
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: pytest.fail("an existing model must not allocate an id"),
    )

    first = store.materialize_legacy()
    second = store.materialize_legacy()

    assert first == second
    assert first.active_endpoint.server_url == "https://new.example.test:8006"
    assert settings.set_calls == []
    assert secrets.calls == []


def test_endpoint_url_can_change_without_changing_opaque_endpoint_id(tmp_path):
    mod = _load()
    endpoint_id = "4" * 32
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {
                "server_url": "https://old.example.test:8006",
                "token_user": "automation@pve",
                "token_id": "sshpilot",
            },
            mod.CUSTOM_CA_ENABLED_KEY: False,
        }
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=lambda: endpoint_id,
    )
    store.materialize_legacy()

    updated = store.update_configuration(
        endpoint_id,
        {
            "server_url": "https://new.example.test:8006",
            "token_user": "automation@pve",
            "token_id": "sshpilot",
        },
    )

    assert updated.active_endpoint_id == endpoint_id
    assert updated.active_endpoint.endpoint_id == endpoint_id
    assert updated.active_endpoint.server_url == "https://new.example.test:8006"


def test_endpoint_secret_and_custom_ca_storage_are_isolated(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    first_id = "5" * 32
    second_id = "6" * 32
    secrets = _KeyedSecrets()
    store = mod.EndpointStore(
        _KeyedSettings(),
        secrets,
        _Files(str(tmp_path)),
    )
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii") if isinstance(value, bytes) else value,
    )

    store.set_secret(first_id, "first-secret")
    store.set_secret(second_id, "second-secret")
    store.write_custom_ca(first_id, b"first-ca")
    store.write_custom_ca(second_id, b"second-ca")

    assert store.get_secret(first_id) == "first-secret"
    assert store.get_secret(second_id) == "second-secret"
    assert store.read_custom_ca(first_id) == "first-ca"
    assert store.read_custom_ca(second_id) == "second-ca"
    assert store.secret_key(first_id) != store.secret_key(second_id)
    assert store.custom_ca_file(first_id) != store.custom_ca_file(second_id)


def test_endpoint_migration_retries_after_secret_copy_failure(tmp_path):
    mod = _load()
    endpoint_id = "7" * 32
    destination_key = f"{mod.ENDPOINT_SECRET_KEY_PREFIX}{endpoint_id}"
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {
                "server_url": "https://pve.example.test:8006",
                "token_user": "automation@pve",
                "token_id": "sshpilot",
            },
            mod.CUSTOM_CA_ENABLED_KEY: False,
        }
    )
    secrets = _KeyedSecrets(
        {mod.SECRET_KEY: "legacy-secret"},
        fail_set_once={destination_key},
    )
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: endpoint_id,
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert mod.ENDPOINTS_KEY not in settings.values
    assert settings.values[mod.ENDPOINT_MIGRATION_ID_KEY] == endpoint_id
    assert secrets.values[mod.SECRET_KEY] == "legacy-secret"

    collection = store.materialize_legacy()

    assert collection.active_endpoint_id == endpoint_id
    assert secrets.values[destination_key] == "legacy-secret"


def test_endpoint_migration_retries_after_collection_commit_failure(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    endpoint_id = "8" * 32
    secret = "legacy-secret"
    ca = b"public-ca"
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {
                "server_url": "https://pve.example.test:8006",
                "token_user": "automation@pve",
                "token_id": "sshpilot",
            },
            mod.CUSTOM_CA_ENABLED_KEY: True,
        },
        fail_set_once={mod.ENDPOINTS_KEY},
    )
    secrets = _KeyedSecrets({mod.SECRET_KEY: secret})
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(ca)
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii") if isinstance(value, bytes) else value,
    )
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: endpoint_id,
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert mod.ENDPOINTS_KEY not in settings.values
    assert secrets.values[store.secret_key(endpoint_id)] == secret
    assert (
        tmp_path / store.custom_ca_file(endpoint_id)
    ).read_bytes() == ca

    collection = store.materialize_legacy()

    assert collection.active_endpoint_id == endpoint_id
    assert settings.values[mod.CONFIGURATION_KEY]["server_url"] == (
        "https://pve.example.test:8006"
    )
    assert settings.values[mod.CUSTOM_CA_ENABLED_KEY] is True
    assert secrets.values[mod.SECRET_KEY] == secret


def test_endpoint_migration_fails_closed_when_enabled_legacy_ca_is_missing(
    tmp_path,
):
    mod = _load()
    endpoint_id = "a" * 32
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {
                "server_url": "https://pve.example.test:8006",
                "token_user": "automation@pve",
                "token_id": "sshpilot",
            },
            mod.CUSTOM_CA_ENABLED_KEY: True,
        }
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=lambda: endpoint_id,
    )

    with pytest.raises(mod.EndpointStorageError) as raised:
        store.materialize_legacy()

    assert str(raised.value) == "Endpoint storage is unavailable."
    assert mod.ENDPOINTS_KEY not in settings.values
    assert settings.values[mod.CUSTOM_CA_ENABLED_KEY] is True


def test_endpoint_store_rejects_a_malformed_existing_model_without_migrating(
    tmp_path,
):
    mod = _load()
    settings = _KeyedSettings(
        {
            mod.ENDPOINTS_KEY: {
                "schema_version": 1,
                "active_endpoint_id": "not-an-endpoint-id",
                "endpoints": [],
            },
            mod.CONFIGURATION_KEY: {
                "server_url": "https://legacy.example.test:8006",
            },
        }
    )
    secrets = _KeyedSecrets({mod.SECRET_KEY: "legacy-secret"})
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: pytest.fail("corrupt storage must not be replaced"),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert settings.set_calls == []
    assert secrets.calls == []


def test_endpoint_model_settings_never_contain_per_endpoint_secrets(tmp_path):
    mod = _load()
    endpoint_id = "9" * 32
    secret = "token-value-that-must-remain-private"
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {
                "server_url": "https://pve.example.test:8006",
                "token_user": "automation@pve",
                "token_id": "sshpilot",
            },
            mod.CUSTOM_CA_ENABLED_KEY: False,
        }
    )
    secrets = _KeyedSecrets({mod.SECRET_KEY: secret})
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: endpoint_id,
    )

    store.materialize_legacy()

    assert secret not in repr(settings.values)
    assert mod.SECRET_KEY not in repr(settings.values[mod.ENDPOINTS_KEY])


def test_endpoint_store_does_not_materialize_absent_legacy_configuration(tmp_path):
    mod = _load()
    settings = _KeyedSettings()
    secrets = _KeyedSecrets()
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: pytest.fail("absent configuration must not allocate an id"),
    )

    assert store.materialize_legacy() is None
    assert settings.set_calls == []
    assert secrets.calls == []
    assert mod.ENDPOINT_MIGRATION_ID_KEY not in settings.values
    assert mod.ENDPOINTS_KEY not in settings.values


@pytest.mark.parametrize(
    "case",
    [
        "root_non_dict",
        "root_extra",
        "schema_bool",
        "schema_unknown",
        "endpoints_non_list",
        "endpoints_empty",
        "endpoint_non_dict",
        "endpoint_extra",
        "endpoint_id_invalid",
        "endpoint_id_duplicate",
        "active_missing",
        "active_unknown",
        "configuration_missing",
        "configuration_non_dict",
        "server_url_missing",
        "token_user_missing",
        "token_id_missing",
        "server_url_non_string",
        "token_user_non_string",
        "token_id_non_string",
        "configuration_extra",
        "custom_ca_missing",
        "custom_ca_non_bool",
        "secret_source_missing",
        "secret_source_unknown",
    ],
)
def test_endpoint_store_rejects_invalid_schema_v1_payloads(tmp_path, case):
    mod = _load()
    endpoint_id = "b" * 32
    payload = _endpoint_model(mod, endpoint_id)

    if case == "root_non_dict":
        payload = []
    elif case == "root_extra":
        payload["unexpected"] = True
    elif case == "schema_bool":
        payload["schema_version"] = True
    elif case == "schema_unknown":
        payload["schema_version"] = 2
    elif case == "endpoints_non_list":
        payload["endpoints"] = {}
    elif case == "endpoints_empty":
        payload["endpoints"] = []
    elif case == "endpoint_non_dict":
        payload["endpoints"] = [None]
    elif case == "endpoint_extra":
        payload["endpoints"][0]["unexpected"] = True
    elif case == "endpoint_id_invalid":
        payload["endpoints"][0]["endpoint_id"] = "invalid"
    elif case == "endpoint_id_duplicate":
        payload["endpoints"].append(dict(payload["endpoints"][0]))
    elif case == "active_missing":
        payload.pop("active_endpoint_id")
    elif case == "active_unknown":
        payload["active_endpoint_id"] = "c" * 32
    elif case == "configuration_missing":
        payload["endpoints"][0].pop("configuration")
    elif case == "configuration_non_dict":
        payload["endpoints"][0]["configuration"] = []
    elif case.endswith("_missing") and case.split("_missing")[0] in {
        "server_url",
        "token_user",
        "token_id",
    }:
        payload["endpoints"][0]["configuration"].pop(
            case.removesuffix("_missing")
        )
    elif case.endswith("_non_string"):
        payload["endpoints"][0]["configuration"][
            case.removesuffix("_non_string")
        ] = 1
    elif case == "configuration_extra":
        payload["endpoints"][0]["configuration"]["unexpected"] = "value"
    elif case == "custom_ca_missing":
        payload["endpoints"][0].pop("custom_ca_enabled")
    elif case == "custom_ca_non_bool":
        payload["endpoints"][0]["custom_ca_enabled"] = 1
    elif case == "secret_source_missing":
        payload["endpoints"][0].pop("secret_source")
    elif case == "secret_source_unknown":
        payload["endpoints"][0]["secret_source"] = "unknown"

    store = mod.EndpointStore(
        _KeyedSettings({mod.ENDPOINTS_KEY: payload}),
        _KeyedSecrets(),
        _Files(str(tmp_path)),
    )

    with pytest.raises(mod.EndpointStorageError) as raised:
        store.load()

    assert str(raised.value) == "Endpoint storage is unavailable."


@pytest.mark.parametrize("case", ["schema_bool", "custom_ca_integer"])
def test_endpoint_store_save_rejects_type_coercing_readback(tmp_path, case):
    mod = _load()
    expected = _endpoint_model(mod)
    confirmed = _endpoint_model(mod)
    if case == "schema_bool":
        confirmed["schema_version"] = True
    else:
        confirmed["endpoints"][0]["custom_ca_enabled"] = 0
    assert confirmed == expected
    with pytest.raises(mod.EndpointStorageError):
        mod.EndpointCollection.from_settings(confirmed)
    settings = _KeyedSettings(
        get_sequences={mod.ENDPOINTS_KEY: [confirmed]},
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
    )

    with pytest.raises(mod.EndpointStorageError) as raised:
        store.save(mod.EndpointCollection.from_settings(expected))

    assert str(raised.value) == "Endpoint storage is unavailable."


def test_endpoint_store_save_rejects_valid_but_different_readback(tmp_path):
    mod = _load()
    expected = _endpoint_model(mod)
    confirmed = _endpoint_model(
        mod,
        configuration={
            "server_url": "https://different.example.test:8006",
            "token_user": "automation@pve",
            "token_id": "sshpilot",
        },
    )
    settings = _KeyedSettings(
        get_sequences={mod.ENDPOINTS_KEY: [confirmed]},
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.save(mod.EndpointCollection.from_settings(expected))


def test_endpoint_store_save_accepts_strictly_identical_readback(tmp_path):
    mod = _load()
    expected = _endpoint_model(mod)
    settings = _KeyedSettings()
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
    )

    store.save(mod.EndpointCollection.from_settings(expected))

    assert settings.values[mod.ENDPOINTS_KEY] == expected
    assert store.load().to_settings() == expected


def test_endpoint_migration_keeps_legacy_secret_fallback_when_lookup_is_none(
    tmp_path,
):
    mod = _load()
    endpoint_id = "c" * 32
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
        }
    )
    secrets = _KeyedSecrets(
        get_sequences={mod.SECRET_KEY: [None, None, "available-later"]}
    )
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: endpoint_id,
    )

    collection = store.materialize_legacy()

    assert collection.active_endpoint.secret_source == (
        mod.ENDPOINT_SECRET_SOURCE_LEGACY
    )
    assert store.resolve_secret(collection.active_endpoint) == "available-later"
    assert store.secret_key(endpoint_id) not in secrets.values
    assert "available-later" not in repr(settings.values)


def test_endpoint_migration_reuses_an_identical_namespaced_secret(tmp_path):
    mod = _load()
    endpoint_id = "d" * 32
    secret = "legacy-secret"
    destination = mod.EndpointStore.secret_key(endpoint_id)
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
        }
    )
    secrets = _KeyedSecrets({mod.SECRET_KEY: secret, destination: secret})
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: endpoint_id,
    )

    collection = store.materialize_legacy()

    assert collection.active_endpoint.secret_source == (
        mod.ENDPOINT_SECRET_SOURCE_ENDPOINT
    )
    assert store.resolve_secret(collection.active_endpoint) == secret
    assert not any(call[0] == "set" for call in secrets.calls)


def test_endpoint_migration_preserves_a_conflicting_namespaced_secret(tmp_path):
    mod = _load()
    first_id = "d" * 32
    replacement_id = "e" * 32
    generated_ids = iter((first_id, replacement_id))
    destination = mod.EndpointStore.secret_key(first_id)
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
        }
    )
    secrets = _KeyedSecrets(
        {mod.SECRET_KEY: "current-legacy", destination: "different-secret"}
    )
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: next(generated_ids),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert secrets.values[destination] == "different-secret"
    assert mod.ENDPOINTS_KEY not in settings.values
    assert settings.values[mod.ENDPOINT_MIGRATION_ID_KEY] == replacement_id

    collection = store.materialize_legacy()

    assert collection.active_endpoint_id == replacement_id
    assert secrets.values[store.secret_key(replacement_id)] == "current-legacy"
    assert secrets.values[destination] == "different-secret"


def test_endpoint_explicit_secret_save_establishes_namespaced_authority(tmp_path):
    mod = _load()
    endpoint_id = "f" * 32
    settings = _KeyedSettings(
        {
            mod.ENDPOINTS_KEY: _endpoint_model(mod, endpoint_id),
        }
    )
    secrets = _KeyedSecrets({mod.SECRET_KEY: "legacy-secret"})
    store = mod.EndpointStore(settings, secrets, _Files(str(tmp_path)))

    updated = store.promote_secret(endpoint_id, "new-secret")

    assert updated.active_endpoint.secret_source == (
        mod.ENDPOINT_SECRET_SOURCE_ENDPOINT
    )
    assert store.resolve_secret(updated.active_endpoint) == "new-secret"
    assert secrets.values[mod.SECRET_KEY] == "legacy-secret"
    assert "new-secret" not in repr(settings.values)


def test_endpoint_migration_rechecks_legacy_configuration_before_publication(
    tmp_path,
):
    mod = _load()
    first_id = "1" * 32
    replacement_id = "2" * 32
    first_configuration = {
        "server_url": "https://first.example.test:8006",
        "token_user": "automation@pve",
        "token_id": "sshpilot",
    }
    second_configuration = {
        **first_configuration,
        "server_url": "https://second.example.test:8006",
    }
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: second_configuration,
            mod.CUSTOM_CA_ENABLED_KEY: False,
        },
        get_sequences={
            mod.CONFIGURATION_KEY: [first_configuration, second_configuration]
        },
    )
    generated_ids = iter((first_id, replacement_id))
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=lambda: next(generated_ids),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert mod.ENDPOINTS_KEY not in settings.values
    assert settings.values[mod.ENDPOINT_MIGRATION_ID_KEY] == replacement_id

    collection = store.materialize_legacy()

    assert collection.active_endpoint_id == replacement_id
    assert collection.active_endpoint.configuration == second_configuration


def test_endpoint_migration_rechecks_legacy_secret_before_publication(tmp_path):
    mod = _load()
    first_id = "3" * 32
    replacement_id = "4" * 32
    generated_ids = iter((first_id, replacement_id))
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
        }
    )
    secrets = _KeyedSecrets(
        {mod.SECRET_KEY: "second-secret"},
        get_sequences={mod.SECRET_KEY: ["first-secret", "second-secret"]},
    )
    store = mod.EndpointStore(
        settings,
        secrets,
        _Files(str(tmp_path)),
        id_factory=lambda: next(generated_ids),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert mod.ENDPOINTS_KEY not in settings.values
    assert secrets.values[store.secret_key(first_id)] == "first-secret"
    assert settings.values[mod.ENDPOINT_MIGRATION_ID_KEY] == replacement_id

    collection = store.materialize_legacy()

    assert collection.active_endpoint_id == replacement_id
    assert secrets.values[store.secret_key(replacement_id)] == "second-secret"


def test_endpoint_migration_rechecks_legacy_ca_before_publication(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    first_id = "5" * 32
    replacement_id = "6" * 32
    first_ca = b"first-public-ca"
    second_ca = b"second-public-ca"
    source = tmp_path / mod.CUSTOM_CA_FILE
    source.write_bytes(first_ca)
    generated_ids = iter((first_id, replacement_id))
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: True,
        }
    )
    files = _Files(str(tmp_path))
    original_path = files.path
    source_reads = 0

    def changing_path(relative):
        nonlocal source_reads
        if relative == mod.CUSTOM_CA_FILE:
            source_reads += 1
            if source_reads == 2:
                source.write_bytes(second_ca)
        return original_path(relative)

    files.path = changing_path
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii") if isinstance(value, bytes) else value,
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        files,
        id_factory=lambda: next(generated_ids),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert mod.ENDPOINTS_KEY not in settings.values
    assert settings.values[mod.ENDPOINT_MIGRATION_ID_KEY] == replacement_id
    assert (tmp_path / store.custom_ca_file(first_id)).read_bytes() == first_ca

    collection = store.materialize_legacy()

    assert collection.active_endpoint_id == replacement_id
    assert (tmp_path / store.custom_ca_file(replacement_id)).read_bytes() == second_ca


def test_endpoint_migration_retries_when_migration_id_write_fails(tmp_path):
    mod = _load()
    first_id = "7" * 32
    second_id = "8" * 32
    generated_ids = iter((first_id, second_id))
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
        },
        fail_set_once={mod.ENDPOINT_MIGRATION_ID_KEY},
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=lambda: next(generated_ids),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert mod.ENDPOINT_MIGRATION_ID_KEY not in settings.values
    assert store.materialize_legacy().active_endpoint_id == second_id


def test_endpoint_migration_reuses_id_written_before_readback_failure(tmp_path):
    mod = _load()
    endpoint_id = "9" * 32
    allocations = []
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
        },
        set_then_fail_once={mod.ENDPOINT_MIGRATION_ID_KEY},
    )

    def allocate():
        allocations.append(endpoint_id)
        return endpoint_id

    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=allocate,
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert settings.values[mod.ENDPOINT_MIGRATION_ID_KEY] == endpoint_id
    assert store.materialize_legacy().active_endpoint_id == endpoint_id
    assert allocations == [endpoint_id]


def test_endpoint_migration_recovers_when_model_write_precedes_readback_failure(
    tmp_path,
):
    mod = _load()
    endpoint_id = "a" * 32
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
        },
        set_then_fail_once={mod.ENDPOINTS_KEY},
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=lambda: endpoint_id,
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert settings.values[mod.ENDPOINTS_KEY]["active_endpoint_id"] == endpoint_id
    set_calls = list(settings.set_calls)

    collection = store.materialize_legacy()

    assert collection.active_endpoint_id == endpoint_id
    assert settings.set_calls == set_calls


def test_endpoint_migration_rechecks_journal_id_before_publication(tmp_path):
    mod = _load()
    first_id = "d" * 32
    external_id = "e" * 32
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
            mod.ENDPOINT_MIGRATION_ID_KEY: external_id,
        },
        get_sequences={mod.ENDPOINT_MIGRATION_ID_KEY: [first_id, external_id]},
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=lambda: pytest.fail("an existing journal id must be reused"),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert mod.ENDPOINTS_KEY not in settings.values
    assert settings.values[mod.ENDPOINT_MIGRATION_ID_KEY] == external_id


def test_endpoint_migration_does_not_overwrite_a_concurrently_published_model(
    tmp_path,
):
    mod = _load()
    migration_id = "d" * 32
    published_id = "e" * 32
    published = _endpoint_model(mod, published_id)
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
        },
        get_sequences={mod.ENDPOINTS_KEY: [MISSING, published]},
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=lambda: migration_id,
    )

    collection = store.materialize_legacy()

    assert collection.active_endpoint_id == published_id
    assert not any(key == mod.ENDPOINTS_KEY for key, _value in settings.set_calls)


def test_endpoint_migration_serializes_process_local_materialization(tmp_path):
    mod = _load()
    endpoint_id = "f" * 32
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: False,
        }
    )
    secrets = _KeyedSecrets()
    files = _Files(str(tmp_path))
    first_allocation_started = mod.threading.Event()
    second_allocation_started = mod.threading.Event()
    release_first = mod.threading.Event()
    second_call_started = mod.threading.Event()
    allocation_count = 0
    results = []
    errors = []

    def allocate():
        nonlocal allocation_count
        allocation_count += 1
        if allocation_count == 1:
            first_allocation_started.set()
            if not release_first.wait(2):
                raise RuntimeError("test synchronization failed")
        else:
            second_allocation_started.set()
        return endpoint_id

    stores = [
        mod.EndpointStore(settings, secrets, files, id_factory=allocate),
        mod.EndpointStore(settings, secrets, files, id_factory=allocate),
    ]

    def materialize(store, started=None):
        if started is not None:
            started.set()
        try:
            results.append(store.materialize_legacy())
        except Exception as exc:
            errors.append(exc)

    first = mod.threading.Thread(target=materialize, args=(stores[0],))
    second = mod.threading.Thread(
        target=materialize,
        args=(stores[1], second_call_started),
    )
    first.start()
    assert first_allocation_started.wait(2)
    second.start()
    assert second_call_started.wait(2)
    assert not second_allocation_started.wait(0.1)
    release_first.set()
    first.join(2)
    second.join(2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert allocation_count == 1
    assert len(results) == 2
    assert results[0] == results[1]
    assert results[0].active_endpoint_id == endpoint_id


def test_endpoint_migration_rejects_invalid_legacy_ca_with_real_validator(tmp_path):
    mod = _load()
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: True,
        }
    )
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(
        b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
    )

    with pytest.raises(mod.EndpointStorageError) as raised:
        store.materialize_legacy()

    assert str(raised.value) == "Endpoint storage is unavailable."
    assert mod.ENDPOINTS_KEY not in settings.values


def test_endpoint_migration_rejects_oversized_legacy_ca_before_publication(
    tmp_path,
):
    mod = _load()
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: True,
        }
    )
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(
        b"x" * (mod.MAX_CUSTOM_CA_BYTES + 1)
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert mod.ENDPOINT_MIGRATION_ID_KEY not in settings.values
    assert mod.ENDPOINTS_KEY not in settings.values


def test_endpoint_migration_rejects_oversized_namespaced_ca(tmp_path, monkeypatch):
    mod = _load()
    first_id = "b" * 32
    replacement_id = "c" * 32
    generated_ids = iter((first_id, replacement_id))
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: True,
        }
    )
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(b"public-ca")
    destination = tmp_path / mod.EndpointStore.custom_ca_file(first_id)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"x" * (mod.MAX_CUSTOM_CA_BYTES + 1))
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii") if isinstance(value, bytes) else value,
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=lambda: next(generated_ids),
    )

    with pytest.raises(mod.EndpointStorageError):
        store.materialize_legacy()

    assert destination.stat().st_size == mod.MAX_CUSTOM_CA_BYTES + 1
    assert mod.ENDPOINTS_KEY not in settings.values
    assert settings.values[mod.ENDPOINT_MIGRATION_ID_KEY] == replacement_id

    collection = store.materialize_legacy()

    assert collection.active_endpoint_id == replacement_id
    assert (
        tmp_path / store.custom_ca_file(replacement_id)
    ).read_bytes() == b"public-ca"


@pytest.mark.parametrize(
    ("same", "mode", "succeeds"),
    [(True, 0o600, True), (False, 0o600, False), (True, 0o644, False)],
)
def test_endpoint_migration_handles_an_existing_namespaced_ca(
    tmp_path,
    monkeypatch,
    same,
    mode,
    succeeds,
):
    mod = _load()
    first_id = "d" * 32
    replacement_id = "e" * 32
    generated_ids = iter((first_id, replacement_id))
    source_ca = b"public-ca"
    target_ca = source_ca if same else b"different-ca"
    settings = _KeyedSettings(
        {
            mod.CONFIGURATION_KEY: {},
            mod.CUSTOM_CA_ENABLED_KEY: True,
        }
    )
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(source_ca)
    destination = tmp_path / mod.EndpointStore.custom_ca_file(first_id)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(target_ca)
    destination.chmod(mode)
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii") if isinstance(value, bytes) else value,
    )
    store = mod.EndpointStore(
        settings,
        _KeyedSecrets(),
        _Files(str(tmp_path)),
        id_factory=lambda: next(generated_ids),
    )

    if succeeds:
        collection = store.materialize_legacy()
        assert collection.active_endpoint_id == first_id
    else:
        with pytest.raises(mod.EndpointStorageError):
            store.materialize_legacy()
        assert mod.ENDPOINTS_KEY not in settings.values
        assert settings.values[mod.ENDPOINT_MIGRATION_ID_KEY] == replacement_id

        collection = store.materialize_legacy()
        assert collection.active_endpoint_id == replacement_id
        assert (
            tmp_path / store.custom_ca_file(replacement_id)
        ).read_bytes() == source_ca

    assert destination.read_bytes() == target_ca


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


def test_save_endpoint_configuration_preserves_custom_ca_state():
    mod = _load()
    settings = _Settings(custom_ca_enabled=True)
    configuration = mod.build_configuration(
        "https://pve.example.test:8006",
        "automation@pve",
        "sshpilot",
    )

    result = mod.save_configuration(settings, _Secrets(), configuration, "")

    assert result.success is True
    assert settings.custom_ca_enabled is True
    assert settings.set_calls == [("configuration", configuration)]


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


class _FakeInventoryClient:
    def __init__(self, result, operation_log=None):
        self.result = result
        self.operation_log = operation_log
        self.calls = []

    def get_inventory(self, configuration, secret):
        self.calls.append((configuration, secret))
        if self.operation_log is not None:
            self.operation_log.append(
                ("client.get_inventory", configuration.server_url)
            )
        return self.result


class _FakeGuestAddressClient:
    def __init__(self, result, operation_log=None):
        self.result = result
        self.operation_log = operation_log
        self.calls = []

    def get_guest_addresses(self, configuration, secret, guest):
        self.calls.append((configuration, secret, guest))
        if self.operation_log is not None:
            self.operation_log.append(
                ("client.get_guest_addresses", guest.guest_type, guest.vmid)
            )
        return self.result


def test_guest_address_discovery_uses_saved_configuration_ca_and_secret(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    operation_log = []
    settings = _Settings(
        {
            "server_url": "https://pve.example.test:8006/",
            "token_user": "automation@pve",
            "token_id": "sshpilot",
        },
        custom_ca_enabled=True,
        operation_log=operation_log,
    )
    secrets = _Secrets(readback="stored-secret", operation_log=operation_log)
    files = _Files(str(tmp_path))
    (tmp_path / "custom-ca.pem").write_text("public CA", encoding="ascii")
    guest = _api(mod).ProxmoxGuest(
        "qemu", 101, "guest", "node-a", "running", False
    )
    expected = _api(mod).GuestAddressResult("success", ("192.0.2.10",))
    client = _FakeGuestAddressClient(expected, operation_log)
    factory_calls = []

    def factory(**kwargs):
        factory_calls.append(kwargs)
        return client

    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii"),
    )
    result = mod.run_guest_address_discovery(
        settings,
        secrets,
        guest,
        factory,
        files,
    )

    assert result is expected
    assert factory_calls == [{"custom_ca_pem": "public CA"}]
    assert len(client.calls) == 1
    configuration, secret, supplied_guest = client.calls[0]
    assert configuration.server_url == "https://pve.example.test:8006"
    assert secret == "stored-secret"
    assert supplied_guest is guest
    assert operation_log == [
        ("settings.get", "configuration"),
        ("settings.get", "custom_ca_enabled"),
        ("secrets.get", "api_token_secret"),
        ("client.get_guest_addresses", "qemu", 101),
    ]


@pytest.mark.parametrize(
    "stored",
    [
        {},
        {"server_url": "http://pve.test", "token_user": "user", "token_id": "id"},
    ],
)
def test_guest_address_discovery_invalid_configuration_uses_manual_fallback(
    stored,
):
    mod = _load()
    settings = _Settings(stored)
    secrets = _Secrets(readback="stored-secret")
    guest = _api(mod).ProxmoxGuest(
        "qemu", 101, "guest", "node-a", "running", False
    )

    def forbidden_factory(**_kwargs):
        raise AssertionError("client created for invalid configuration")

    result = mod.run_guest_address_discovery(
        settings,
        secrets,
        guest,
        forbidden_factory,
        _Files(),
    )

    assert result.category in {"invalid_configuration", "invalid_url"}
    assert result.suggested_host is None
    assert secrets.calls == []


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
    assert settings.get_calls == [
        ("configuration", {}),
        ("custom_ca_enabled", False),
    ]
    assert secrets.calls == [("get", "api_token_secret")]
    assert len(client.calls) == 1
    configuration, secret = client.calls[0]
    assert configuration.server_url == "https://pve.example.test:8006"
    assert configuration.token_user == "automation@pve"
    assert configuration.token_id == "sshpilot"
    assert secret == "stored-secret"
    assert operation_log == [
        ("settings.get", "configuration"),
        ("settings.get", "custom_ca_enabled"),
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


def test_inventory_refresh_uses_saved_settings_then_secret():
    mod = _load()
    operation_log = []
    settings = _Settings(
        {
            "server_url": "https://pve.example.test:8006/",
            "token_user": "automation@pve",
            "token_id": "sshpilot",
        },
        operation_log=operation_log,
    )
    secrets = _Secrets(readback="stored-secret", operation_log=operation_log)
    inventory = mod.ProxmoxInventory(nodes=(), guests=())
    expected = mod.InventoryResult("success", "Inventory loaded.", inventory)
    client = _FakeInventoryClient(expected, operation_log)

    result = mod.run_inventory_refresh(settings, secrets, lambda: client)

    assert result is expected
    assert settings.get_calls == [
        ("configuration", {}),
        ("custom_ca_enabled", False),
    ]
    assert secrets.calls == [("get", "api_token_secret")]
    assert len(client.calls) == 1
    configuration, secret = client.calls[0]
    assert configuration.server_url == "https://pve.example.test:8006"
    assert configuration.token_user == "automation@pve"
    assert configuration.token_id == "sshpilot"
    assert secret == "stored-secret"
    assert operation_log == [
        ("settings.get", "configuration"),
        ("settings.get", "custom_ca_enabled"),
        ("secrets.get", "api_token_secret"),
        ("client.get_inventory", "https://pve.example.test:8006"),
    ]


@pytest.mark.parametrize(
    "stored, expected_category",
    [
        ({}, "invalid_configuration"),
        (None, "invalid_configuration"),
        (
            {
                "server_url": "https://pve.test",
                "token_user": "",
                "token_id": "id",
            },
            "invalid_configuration",
        ),
        (
            {
                "server_url": "http://pve.test",
                "token_user": "user@pve",
                "token_id": "id",
            },
            "invalid_url",
        ),
    ],
)
def test_inventory_refresh_rejects_invalid_saved_configuration(
    stored,
    expected_category,
):
    mod = _load()
    settings = _Settings(stored)
    secrets = _Secrets(readback="stored-secret")

    def forbidden_factory():
        raise AssertionError("client created for invalid configuration")

    result = mod.run_inventory_refresh(settings, secrets, forbidden_factory)

    assert result.category == expected_category
    assert secrets.calls == []
    assert result.inventory is None


def test_inventory_refresh_reports_settings_failure_safely():
    mod = _load()

    def forbidden_factory():
        raise AssertionError("client created after settings failure")

    result = mod.run_inventory_refresh(
        _Settings(fail_get=True),
        _Secrets(readback="stored-secret"),
        forbidden_factory,
    )

    assert result.category == "unexpected_error"
    assert result.message == "The inventory could not be loaded."


def test_inventory_refresh_does_not_create_client_without_secret():
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

    result = mod.run_inventory_refresh(settings, secrets, forbidden_factory)

    assert result.category == "missing_secret"
    assert result.message == "No API token secret is stored."
    assert secrets.calls == [("get", "api_token_secret")]


def test_inventory_refresh_reports_keyring_failure_safely():
    mod = _load()
    settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        }
    )
    def forbidden_factory():
        raise AssertionError("client created after keyring failure")

    result = mod.run_inventory_refresh(
        settings,
        _Secrets(fail_get=True),
        forbidden_factory,
    )

    assert result.category == "secret_unavailable"
    assert result.message == (
        "The API token secret could not be read from secure storage."
    )


def test_inventory_refresh_hides_secret_from_unexpected_client_failure():
    mod = _load()
    secret = "inventory-worker-secret-sentinel"
    settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        }
    )

    class _FailingClient:
        def get_inventory(self, _configuration, supplied_secret):
            raise RuntimeError(f"client exposed {supplied_secret}")

    result = mod.run_inventory_refresh(
        settings,
        _Secrets(readback=secret),
        _FailingClient,
    )

    assert result.category == "unexpected_error"
    assert result.message == "The inventory could not be loaded."
    assert secret not in result.message
    assert secret not in repr(result)


def test_connection_passes_the_configured_private_ca_to_the_client(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    stored = tmp_path / mod.CUSTOM_CA_FILE
    stored.write_bytes(b"stored-ca")
    settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        },
        custom_ca_enabled=True,
    )
    expected = mod.connection_test_result("success")
    client = _FakeClient(expected)
    factory_calls = []
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii"),
    )

    def factory(**kwargs):
        factory_calls.append(kwargs)
        return client

    result = mod.run_connection_test(
        settings,
        _Secrets(readback="stored-secret"),
        factory,
        _Files(str(tmp_path)),
    )

    assert result is expected
    assert factory_calls == [{"custom_ca_pem": "stored-ca"}]
    assert len(client.calls) == 1


def test_inventory_passes_the_same_configured_private_ca_to_the_client(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(b"stored-ca")
    settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        },
        custom_ca_enabled=True,
    )
    inventory = mod.ProxmoxInventory(nodes=(), guests=())
    expected = mod.InventoryResult("success", "Inventory loaded.", inventory)
    client = _FakeInventoryClient(expected)
    factory_calls = []
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii"),
    )

    def factory(**kwargs):
        factory_calls.append(kwargs)
        return client

    result = mod.run_inventory_refresh(
        settings,
        _Secrets(readback="stored-secret"),
        factory,
        _Files(str(tmp_path)),
    )

    assert result is expected
    assert factory_calls == [{"custom_ca_pem": "stored-ca"}]
    assert len(client.calls) == 1


@pytest.mark.parametrize("operation", ["connection", "inventory"])
@pytest.mark.parametrize("stored_data", [None, b"not a certificate"])
def test_unusable_configured_ca_stops_before_secret_or_client(
    tmp_path,
    operation,
    stored_data,
):
    mod = _load()
    if stored_data is not None:
        (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(stored_data)
    settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        },
        custom_ca_enabled=True,
    )
    secrets = _Secrets(readback="stored-secret")

    def forbidden_factory(**_kwargs):
        raise AssertionError("client created with an unusable configured CA")

    if operation == "connection":
        result = mod.run_connection_test(
            settings,
            secrets,
            forbidden_factory,
            _Files(str(tmp_path)),
        )
    else:
        result = mod.run_inventory_refresh(
            settings,
            secrets,
            forbidden_factory,
            _Files(str(tmp_path)),
        )

    assert result.category == "custom_ca_error"
    assert result.message == (
        "The configured custom CA certificate is unavailable or invalid."
    )
    assert secrets.calls == []


@pytest.mark.parametrize("operation", ["connection", "inventory"])
def test_unconfigured_ca_keeps_the_existing_no_argument_client_factory(operation):
    mod = _load()
    settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        },
        custom_ca_enabled=False,
    )
    factory_calls = []

    if operation == "connection":
        expected = mod.connection_test_result("success")
        client = _FakeClient(expected)
    else:
        inventory = mod.ProxmoxInventory(nodes=(), guests=())
        expected = mod.InventoryResult("success", "Inventory loaded.", inventory)
        client = _FakeInventoryClient(expected)

    def factory():
        factory_calls.append(())
        return client

    if operation == "connection":
        result = mod.run_connection_test(
            settings,
            _Secrets(readback="stored-secret"),
            factory,
            _Files(),
        )
    else:
        result = mod.run_inventory_refresh(
            settings,
            _Secrets(readback="stored-secret"),
            factory,
            _Files(),
        )

    assert result is expected
    assert factory_calls == [()]


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


def _thread_type_failing_at(failure_point):
    if failure_point == "constructor":

        def fail_constructor(**_kwargs):
            raise RuntimeError("unexpected thread constructor detail")

        return fail_constructor

    class _StartFailingThread(_DeferredThread):
        def start(self):
            raise RuntimeError("unexpected thread start detail")

    return _StartFailingThread


def _build_headless_page(mod, ctx, monkeypatch):
    _install_fake_gi(monkeypatch)
    plugin = mod.Plugin()
    plugin.activate(ctx)
    page = plugin._build_page()
    return plugin, page


def _headless_plugin(mod, ctx):
    plugin = mod.Plugin()
    plugin.activate(ctx)
    plugin._page_token = object()
    plugin._save_button = _Button()
    plugin._test_button = _Button()
    plugin._refresh_button = _Button()
    plugin._import_custom_ca_button = _Button()
    plugin._remove_custom_ca_button = _Button()
    plugin._custom_ca_row = _AdwActionRow(
        title="Custom CA certificate",
        subtitle="System trust store",
    )
    plugin._custom_ca_enabled = False
    plugin._status_label = _StatusLabel()
    return plugin


@pytest.mark.parametrize("failure_point", ("constructor", "start"))
def test_save_thread_startup_failure_restores_ui_without_running_worker(
    failure_point,
    monkeypatch,
):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(
        mod.threading,
        "Thread",
        _thread_type_failing_at(failure_point),
    )
    ctx = _Ctx()
    plugin = _headless_plugin(mod, ctx)
    plugin._server_url_row = _TextRow("https://pve.test")
    plugin._token_user_row = _TextRow("user@pve")
    plugin._token_id_row = _TextRow("id")
    plugin._secret_row = _TextRow("new-secret")

    plugin._on_save_clicked(None)

    assert plugin._operation_in_progress is False
    assert plugin._save_button.sensitive_calls == [False, True]
    assert plugin._test_button.sensitive_calls == [False, True]
    assert plugin._refresh_button.sensitive_calls == [False, True]
    assert plugin._import_custom_ca_button.sensitive_calls == [False, True]
    assert plugin._remove_custom_ca_button.sensitive_calls == [False, False]
    assert plugin._status_label.label == "The save operation could not be started."
    assert plugin._status_label.css_classes == {"error"}
    assert "unexpected thread" not in plugin._status_label.label
    assert ctx.settings.set_calls == []
    assert ctx.secrets.calls == []
    assert ctx.ui_thread_calls == []


@pytest.mark.parametrize("failure_point", ("constructor", "start"))
def test_connection_thread_startup_failure_restores_ui_without_running_worker(
    failure_point,
    monkeypatch,
):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(
        mod.threading,
        "Thread",
        _thread_type_failing_at(failure_point),
    )
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
    factory_calls = []

    def forbidden_factory(**kwargs):
        factory_calls.append(kwargs)
        raise AssertionError("client created after thread startup failure")

    plugin._client_factory = forbidden_factory

    plugin._on_test_clicked(None)

    assert plugin._operation_in_progress is False
    assert plugin._save_button.sensitive_calls == [False, True]
    assert plugin._test_button.sensitive_calls == [False, True]
    assert plugin._refresh_button.sensitive_calls == [False, True]
    assert plugin._import_custom_ca_button.sensitive_calls == [False, True]
    assert plugin._remove_custom_ca_button.sensitive_calls == [False, False]
    assert plugin._status_label.label == (
        "The connection test could not be started."
    )
    assert plugin._status_label.css_classes == {"error"}
    assert "unexpected thread" not in plugin._status_label.label
    assert ctx.settings.get_calls == []
    assert ctx.secrets.calls == []
    assert factory_calls == []
    assert ctx.ui_thread_calls == []


@pytest.mark.parametrize("failure_point", ("constructor", "start"))
def test_refresh_thread_startup_failure_restores_ui_without_running_worker(
    failure_point,
    monkeypatch,
):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(
        mod.threading,
        "Thread",
        _thread_type_failing_at(failure_point),
    )
    ctx = _Ctx()
    ctx.settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        }
    )
    ctx.secrets = _Secrets(readback="stored-secret")
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)
    ctx.settings.get_calls.clear()
    factory_calls = []

    def forbidden_factory(**kwargs):
        factory_calls.append(kwargs)
        raise AssertionError("client created after thread startup failure")

    plugin._client_factory = forbidden_factory

    plugin._on_refresh_clicked(None)

    assert plugin._operation_in_progress is False
    assert plugin._save_button.sensitive_calls == [False, True]
    assert plugin._test_button.sensitive_calls == [False, True]
    assert plugin._refresh_button.sensitive_calls == [False, True]
    assert plugin._import_custom_ca_button.sensitive_calls == [False, True]
    assert plugin._remove_custom_ca_button.sensitive_calls[-2:] == [False, False]
    assert plugin._inventory_spinner.active is False
    assert plugin._inventory_spinner.visible is False
    assert plugin._inventory_status_row.title == (
        "The inventory refresh could not be started."
    )
    assert ctx.settings.get_calls == []
    assert ctx.secrets.calls == []
    assert factory_calls == []
    assert ctx.ui_thread_calls == []


def test_stale_thread_startup_failure_does_not_finish_rebuilt_page_operation(
    monkeypatch,
):
    mod = _load()
    plugin = _headless_plugin(mod, _Ctx())

    class _StaleStartFailingThread(_DeferredThread):
        def start(self):
            plugin._page_token = object()
            plugin._operation_in_progress = True
            plugin._save_button = _ForbiddenWidget()
            plugin._test_button = _ForbiddenWidget()
            plugin._refresh_button = _ForbiddenWidget()
            plugin._import_custom_ca_button = _ForbiddenWidget()
            plugin._remove_custom_ca_button = _ForbiddenWidget()
            plugin._status_label = _ForbiddenWidget()
            raise RuntimeError("unexpected stale thread start detail")

    monkeypatch.setattr(mod.threading, "Thread", _StaleStartFailingThread)

    plugin._on_test_clicked(None)

    assert plugin._operation_in_progress is True


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
    assert plugin._refresh_button.sensitive_calls == [False]
    assert plugin._status_label.label == "Testing connection…"
    assert ctx.settings.get_calls == []

    worker.target(*worker.args)

    assert len(ctx.ui_thread_calls) == 1
    callback, args = ctx.ui_thread_calls[0]
    assert callback == plugin._finish_test
    assert args == (expected, page_token)
    assert ctx.settings.get_calls == [
        ("configuration", {}),
        ("custom_ca_enabled", False),
    ]
    assert ctx.secrets.calls == [("get", "api_token_secret")]

    callback(*args)

    assert plugin._operation_in_progress is False
    assert plugin._save_button.sensitive_calls == [False, True]
    assert plugin._test_button.sensitive_calls == [False, True]
    assert plugin._refresh_button.sensitive_calls == [False, True]
    assert plugin._status_label.label == expected.message
    assert plugin._status_label.css_classes == {"success"}


def test_test_connection_invalid_custom_ca_flag_fails_closed_and_restores_busy(
    monkeypatch,
):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    ctx = _Ctx()
    ctx.settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        },
        custom_ca_enabled="true",
    )
    ctx.secrets = _Secrets(readback="stored-secret")
    plugin = _headless_plugin(mod, ctx)
    factory_calls = []

    def forbidden_factory(**kwargs):
        factory_calls.append(kwargs)
        raise AssertionError("client created with an invalid custom CA flag")

    plugin._client_factory = forbidden_factory

    plugin._on_test_clicked(None)
    worker = _DeferredThread.created[0]
    worker.target(*worker.args)

    callback, args = ctx.ui_thread_calls[0]
    result, _page_token = args
    assert result.category == "custom_ca_error"
    assert result.message == (
        "The configured custom CA certificate is unavailable or invalid."
    )
    assert ctx.secrets.calls == []
    assert factory_calls == []

    callback(*args)

    assert plugin._operation_in_progress is False
    assert plugin._save_button.sensitive_calls == [False, True]
    assert plugin._test_button.sensitive_calls == [False, True]
    assert plugin._refresh_button.sensitive_calls == [False, True]
    assert plugin._status_label.label == result.message
    assert plugin._status_label.css_classes == {"error"}


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
    plugin._on_refresh_clicked(None)

    assert len(_DeferredThread.created) == 1
    assert _DeferredThread.created[0].target == plugin._save_worker
    assert plugin._operation_in_progress is True
    assert plugin._save_button.sensitive_calls == [False]
    assert plugin._test_button.sensitive_calls == [False]
    assert plugin._refresh_button.sensitive_calls == [False]


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


def _inventory_result(mod, nodes=(), guests=()):
    inventory = mod.ProxmoxInventory(nodes=tuple(nodes), guests=tuple(guests))
    return mod.InventoryResult("success", "Inventory loaded.", inventory)


def _api(mod):
    return sys.modules[f"{mod.__name__}.proxmox_api"]


def test_page_builds_inventory_controls_with_lazy_fake_gtk(monkeypatch):
    mod = _load()
    plugin, page = _build_headless_page(mod, _Ctx(), monkeypatch)
    content = page.child.child
    inventory_group = next(
        child
        for child in content.children
        if isinstance(child, _AdwPreferencesGroup) and child.title == "Inventory"
    )

    assert inventory_group.description == "Uses the saved endpoint and API token."
    assert inventory_group.header_suffix is plugin._refresh_button
    assert plugin._refresh_button.label == "Refresh"
    assert plugin._refresh_button.connections == [
        ("clicked", plugin._on_refresh_clicked)
    ]
    assert inventory_group.rows == [plugin._inventory_status_row]
    assert plugin._inventory_status_row.title == "Inventory has not been loaded."
    assert plugin._inventory_status_row.prefixes == [plugin._inventory_spinner]
    assert plugin._inventory_spinner.active is False
    assert plugin._inventory_spinner.visible is False
    assert plugin._secret_row.text == ""
    assert "gi" not in mod.__dict__


def test_page_builds_minimal_tls_custom_ca_controls(monkeypatch):
    mod = _load()
    plugin, page = _build_headless_page(mod, _Ctx(), monkeypatch)
    content = page.child.child
    tls_group = next(
        child
        for child in content.children
        if isinstance(child, _AdwPreferencesGroup) and child.title == "TLS"
    )

    assert tls_group.rows == [plugin._custom_ca_row]
    assert plugin._custom_ca_row.title == "Custom CA certificate"
    assert plugin._custom_ca_row.subtitle == "System trust store"
    assert plugin._custom_ca_row.suffixes == [
        plugin._import_custom_ca_button,
        plugin._remove_custom_ca_button,
    ]
    assert plugin._import_custom_ca_button.label == "Import…"
    assert plugin._remove_custom_ca_button.label == "Remove"
    assert plugin._remove_custom_ca_button.sensitive_calls == [False]
    assert plugin._import_custom_ca_button.connections == [
        ("clicked", plugin._on_import_custom_ca_clicked)
    ]
    assert plugin._remove_custom_ca_button.connections == [
        ("clicked", plugin._on_remove_custom_ca_clicked)
    ]


def test_page_shows_enabled_custom_ca_without_exposing_source_details(monkeypatch):
    mod = _load()
    ctx = _Ctx()
    ctx.settings = _Settings(custom_ca_enabled=True)

    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)

    assert plugin._custom_ca_row.subtitle == "Custom CA configured"
    assert plugin._remove_custom_ca_button.sensitive_calls == [True]
    assert "path" not in plugin._custom_ca_row.subtitle.lower()


def test_custom_ca_import_uses_chooser_callback_and_updates_ui(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    source = tmp_path / "selected.pem"
    source.write_bytes(b"selected-ca")
    private_root = tmp_path / "private"
    private_root.mkdir()
    ctx = _Ctx()
    ctx.settings = _Settings(custom_ca_enabled=False)
    ctx.files = _Files(str(private_root))
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_choose_custom_ca_file",
        lambda parent, selected, cancelled, error: callbacks.update(
            parent=parent,
            selected=selected,
            cancelled=cancelled,
            error=error,
        ),
    )
    monkeypatch.setattr(
        mod,
        "validate_custom_ca_pem",
        lambda value: value.decode("ascii"),
    )
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)

    plugin._on_import_custom_ca_clicked(plugin._import_custom_ca_button)

    assert plugin._operation_in_progress is True
    assert callbacks["parent"] is None
    assert plugin._save_button.sensitive_calls[-1] is False
    assert plugin._test_button.sensitive_calls[-1] is False
    assert plugin._refresh_button.sensitive_calls[-1] is False
    assert plugin._remove_custom_ca_button.sensitive_calls[-1] is False

    callbacks["selected"](str(source))

    assert plugin._operation_in_progress is False
    assert plugin._custom_ca_enabled is True
    assert plugin._custom_ca_row.subtitle == "Custom CA configured"
    assert plugin._status_label.label == "Custom CA certificate imported."
    assert plugin._status_label.css_classes == {"success"}
    assert (private_root / mod.CUSTOM_CA_FILE).read_bytes() == b"selected-ca"
    assert ctx.settings.set_calls == [(mod.CUSTOM_CA_ENABLED_KEY, True)]
    assert str(source) not in repr(ctx.settings.set_calls)


def test_custom_ca_import_busy_state_blocks_save_test_refresh_and_remove(
    monkeypatch,
):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_choose_custom_ca_file",
        lambda _parent, selected, cancelled, error: callbacks.update(
            selected=selected,
            cancelled=cancelled,
            error=error,
        ),
    )
    ctx = _Ctx()
    ctx.settings = _Settings(custom_ca_enabled=True)
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)
    plugin._server_url_row = _ForbiddenWidget()
    plugin._token_user_row = _ForbiddenWidget()
    plugin._token_id_row = _ForbiddenWidget()
    plugin._secret_row = _ForbiddenWidget()

    plugin._on_import_custom_ca_clicked(plugin._import_custom_ca_button)
    plugin._on_save_clicked(None)
    plugin._on_test_clicked(None)
    plugin._on_refresh_clicked(None)
    plugin._on_remove_custom_ca_clicked(None)

    assert plugin._operation_in_progress is True
    assert _DeferredThread.created == []
    assert ctx.settings.set_calls == []


def test_custom_ca_chooser_cancellation_restores_busy_state_without_mutation(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_choose_custom_ca_file",
        lambda _parent, selected, cancelled, error: callbacks.update(
            selected=selected,
            cancelled=cancelled,
            error=error,
        ),
    )
    ctx = _Ctx()
    ctx.settings = _Settings(custom_ca_enabled=False)
    ctx.files = _Files(str(tmp_path))
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)

    plugin._on_import_custom_ca_clicked(plugin._import_custom_ca_button)
    callbacks["cancelled"]()

    assert plugin._operation_in_progress is False
    assert plugin._status_label.label == ""
    assert ctx.settings.set_calls == []
    assert list(tmp_path.iterdir()) == []


def test_custom_ca_dialog_error_is_sanitized_and_restores_busy_state(
    monkeypatch,
):
    mod = _load()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_choose_custom_ca_file",
        lambda _parent, selected, cancelled, error: callbacks.update(
            selected=selected,
            cancelled=cancelled,
            error=error,
        ),
    )
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)

    plugin._on_import_custom_ca_clicked(plugin._import_custom_ca_button)
    callbacks["error"]()

    assert plugin._operation_in_progress is False
    assert plugin._custom_ca_enabled is False
    assert plugin._custom_ca_row.subtitle == "System trust store"
    assert plugin._status_label.label == (
        "The custom CA certificate file could not be opened."
    )
    assert plugin._status_label.css_classes == {"error"}


def test_stale_custom_ca_chooser_callback_does_not_store_or_touch_widgets(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    source = tmp_path / "selected.pem"
    source.write_bytes(b"selected-ca")
    private_root = tmp_path / "private"
    private_root.mkdir()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_choose_custom_ca_file",
        lambda _parent, selected, cancelled, error: callbacks.update(
            selected=selected,
            cancelled=cancelled,
            error=error,
        ),
    )
    ctx = _Ctx()
    ctx.settings = _Settings(custom_ca_enabled=False)
    ctx.files = _Files(str(private_root))
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)

    plugin._on_import_custom_ca_clicked(plugin._import_custom_ca_button)
    plugin._page_token = object()
    plugin._custom_ca_row = _ForbiddenWidget()
    plugin._status_label = _ForbiddenWidget()
    plugin._save_button = _ForbiddenWidget()
    plugin._test_button = _ForbiddenWidget()
    plugin._refresh_button = _ForbiddenWidget()
    plugin._import_custom_ca_button = _ForbiddenWidget()
    plugin._remove_custom_ca_button = _ForbiddenWidget()

    callbacks["selected"](str(source))

    assert ctx.settings.set_calls == []
    assert list(private_root.iterdir()) == []


def test_remove_custom_ca_updates_ui_and_restores_system_trust(
    tmp_path,
    monkeypatch,
):
    mod = _load()
    (tmp_path / mod.CUSTOM_CA_FILE).write_bytes(b"stored-ca")
    ctx = _Ctx()
    ctx.settings = _Settings(custom_ca_enabled=True)
    ctx.files = _Files(str(tmp_path))
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)

    plugin._on_remove_custom_ca_clicked(plugin._remove_custom_ca_button)

    assert plugin._operation_in_progress is False
    assert plugin._custom_ca_enabled is False
    assert plugin._custom_ca_row.subtitle == "System trust store"
    assert plugin._remove_custom_ca_button.sensitive_calls[-1] is False
    assert plugin._status_label.label == "System trust store restored."
    assert not (tmp_path / mod.CUSTOM_CA_FILE).exists()


def test_refresh_uses_worker_saved_values_and_ui_thread_callback(
    monkeypatch,
):
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
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)
    expected = _inventory_result(
        mod,
        nodes=[_api(mod).ProxmoxNode("node-a", "online")],
    )
    client = _FakeInventoryClient(expected)
    plugin._client_factory = lambda: client
    plugin._server_url_row = _ForbiddenWidget()
    plugin._token_user_row = _ForbiddenWidget()
    plugin._token_id_row = _ForbiddenWidget()
    plugin._secret_row = _ForbiddenWidget()
    page_token = plugin._page_token

    plugin._on_refresh_clicked(None)

    assert len(_DeferredThread.created) == 1
    worker = _DeferredThread.created[0]
    assert worker.started is True
    assert worker.target == plugin._refresh_worker
    assert worker.args == (page_token,)
    assert plugin._operation_in_progress is True
    assert plugin._save_button.sensitive_calls == [False]
    assert plugin._test_button.sensitive_calls == [False]
    assert plugin._refresh_button.sensitive_calls == [False]
    assert plugin._inventory_spinner.active is True
    assert plugin._inventory_spinner.visible is True
    assert plugin._inventory_status_row.title == "Loading inventory…"
    assert ctx.settings.get_calls == [
        ("configuration", {}),
        ("custom_ca_enabled", False),
    ]
    assert ctx.secrets.calls == []

    worker.target(*worker.args)

    assert len(ctx.ui_thread_calls) == 1
    callback, args = ctx.ui_thread_calls[0]
    assert callback == plugin._finish_refresh
    assert args == (expected, page_token)
    assert ctx.settings.get_calls == [
        ("configuration", {}),
        ("custom_ca_enabled", False),
        ("configuration", {}),
        ("custom_ca_enabled", False),
    ]
    assert ctx.secrets.calls == [("get", "api_token_secret")]
    assert len(client.calls) == 1

    callback(*args)

    assert plugin._operation_in_progress is False
    assert plugin._inventory_spinner.active is False
    assert plugin._inventory_spinner.visible is False
    assert plugin._inventory_status_row.title == (
        "No guests visible to this API token were returned."
    )
    assert plugin._save_button.sensitive_calls == [False, True]
    assert plugin._test_button.sensitive_calls == [False, True]
    assert plugin._refresh_button.sensitive_calls == [False, True]


def test_refresh_invalid_custom_ca_flag_fails_closed_and_restores_busy(
    monkeypatch,
):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    ctx = _Ctx()
    ctx.settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        },
        custom_ca_enabled=1,
    )
    ctx.secrets = _Secrets(readback="stored-secret")
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)
    factory_calls = []

    def forbidden_factory(**kwargs):
        factory_calls.append(kwargs)
        raise AssertionError("client created with an invalid custom CA flag")

    plugin._client_factory = forbidden_factory

    plugin._on_refresh_clicked(None)
    worker = _DeferredThread.created[0]
    worker.target(*worker.args)

    callback, args = ctx.ui_thread_calls[0]
    result, _page_token = args
    assert result.category == "custom_ca_error"
    assert result.message == (
        "The configured custom CA certificate is unavailable or invalid."
    )
    assert ctx.secrets.calls == []
    assert factory_calls == []

    callback(*args)

    assert plugin._operation_in_progress is False
    assert plugin._inventory_spinner.active is False
    assert plugin._inventory_spinner.visible is False
    assert plugin._inventory_status_row.title == result.message
    assert plugin._save_button.sensitive_calls[-1] is True
    assert plugin._test_button.sensitive_calls[-1] is True
    assert plugin._refresh_button.sensitive_calls[-1] is True


def test_second_refresh_is_blocked_while_first_is_running(monkeypatch):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)

    plugin._on_refresh_clicked(None)
    plugin._on_refresh_clicked(None)

    assert len(_DeferredThread.created) == 1
    assert _DeferredThread.created[0].target == plugin._refresh_worker


def test_refresh_blocks_save_and_test_on_same_page(monkeypatch):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)
    plugin._server_url_row = _ForbiddenWidget()
    plugin._token_user_row = _ForbiddenWidget()
    plugin._token_id_row = _ForbiddenWidget()
    plugin._secret_row = _ForbiddenWidget()

    plugin._on_refresh_clicked(None)
    plugin._on_save_clicked(None)
    plugin._on_test_clicked(None)

    assert len(_DeferredThread.created) == 1
    assert _DeferredThread.created[0].target == plugin._refresh_worker


def test_test_blocks_refresh_on_same_page(monkeypatch):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)

    plugin._on_test_clicked(None)
    plugin._on_refresh_clicked(None)

    assert len(_DeferredThread.created) == 1
    assert _DeferredThread.created[0].target == plugin._test_worker


def test_stale_refresh_callback_does_not_touch_rebuilt_page_widgets():
    mod = _load()
    plugin = mod.Plugin()
    page_a_token = object()
    plugin._page_token = object()
    plugin._inventory_spinner = _ForbiddenWidget()
    plugin._inventory_status_row = _ForbiddenWidget()
    plugin._inventory_groups_box = _ForbiddenWidget()
    plugin._inventory_groups = _ForbiddenWidget()
    plugin._save_button = _ForbiddenWidget()
    plugin._test_button = _ForbiddenWidget()
    plugin._refresh_button = _ForbiddenWidget()

    plugin._finish_refresh(_inventory_result(mod), page_a_token)


def test_inventory_renders_nodes_qemu_lxc_template_and_fallback(monkeypatch):
    mod = _load()
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)
    result = _inventory_result(
        mod,
        nodes=[
            _api(mod).ProxmoxNode("node-a", "online"),
            _api(mod).ProxmoxNode("node-b", "offline"),
        ],
        guests=[
            _api(mod).ProxmoxGuest(
                "qemu", 100, "database", "node-a", "running", True
            ),
            _api(mod).ProxmoxGuest(
                "lxc", 101, "", "node-a", "stopped", False
            ),
        ],
    )

    plugin._finish_refresh(result, plugin._page_token)

    assert plugin._inventory_status_row.title == (
        "Inventory loaded: 2 nodes and 2 guests visible to this API token."
    )
    assert [group.title for group in plugin._inventory_groups] == [
        "node-a",
        "node-b",
    ]
    node_a, node_b = plugin._inventory_groups
    assert node_a.description == "Status: online"
    assert [(row.title, row.subtitle) for row in node_a.rows] == [
        (
            "database",
            "QEMU · VMID 100 · Status: running · Node: node-a",
        ),
        (
            "LXC 101",
            "LXC · VMID 101 · Status: stopped · Node: node-a",
        ),
    ]
    assert [label.label for label in node_a.rows[0].suffixes] == ["Template"]
    assert node_a.rows[1].suffixes == []
    assert node_b.description == "Status: offline"
    assert [row.title for row in node_b.rows] == [
        "No guests visible to this API token were returned for this node."
    ]


@pytest.mark.parametrize(
    "value, expected",
    [
        ("guest.example.test", "guest.example.test"),
        ("  GUEST.EXAMPLE.TEST  ", "guest.example.test"),
        ("192.0.2.10", "192.0.2.10"),
        ("[2001:db8::10]", "2001:db8::10"),
    ],
)
def test_manual_ssh_host_validation_accepts_supported_hosts(value, expected):
    mod = _load()

    assert mod.normalize_ssh_host(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://guest.test",
        "user@guest.test",
        "guest.test:2222",
        "bad host",
        "999",
    ],
)
def test_manual_ssh_host_validation_rejects_non_host_input(value):
    mod = _load()

    with pytest.raises(ValueError):
        mod.normalize_ssh_host(value)


def test_guest_host_prompt_prefills_discovered_address(monkeypatch):
    mod = _load()
    adw, _gtk = _install_fake_gi(monkeypatch)
    captured = {}

    class _MessageDialog:
        def __init__(self, **kwargs):
            captured["dialog"] = self
            captured["kwargs"] = kwargs

        def set_extra_child(self, child):
            captured["host_row"] = child.children[0]

        def add_response(self, _response, _label):
            pass

        def set_default_response(self, _response):
            pass

        def set_close_response(self, _response):
            pass

        def connect(self, _signal, callback):
            captured["callback"] = callback

        def present(self):
            captured["presented"] = True

    adw.MessageDialog = _MessageDialog

    mod._prompt_ssh_host(
        None,
        lambda _host: None,
        lambda: None,
        lambda: None,
        "2001:db8::60",
    )

    assert captured["host_row"].text == "2001:db8::60"
    assert captured["presented"] is True


def test_guest_connection_identity_uses_endpoint_type_and_vmid_not_guest_name():
    mod = _load()

    qemu = mod.guest_connection_nickname("https://pve.test/", "qemu", 100)

    assert qemu == mod.guest_connection_nickname(
        "https://PVE.TEST",
        "qemu",
        100,
    )
    assert qemu != mod.guest_connection_nickname("https://other.test", "qemu", 100)
    assert qemu != mod.guest_connection_nickname("https://pve.test", "lxc", 100)
    assert qemu != mod.guest_connection_nickname("https://pve.test", "qemu", 101)
    assert "pve.test" not in qemu


def _render_importable_guest(mod, ctx, monkeypatch):
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    monkeypatch.setattr(
        mod,
        "run_guest_address_discovery",
        lambda *_args: _api(mod).GuestAddressResult("success"),
    )
    ctx.settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        }
    )
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)
    guest = _api(mod).ProxmoxGuest(
        "qemu",
        100,
        "database",
        "node-a",
        "running",
        False,
    )
    plugin._finish_refresh(
        _inventory_result(
            mod,
            nodes=[_api(mod).ProxmoxNode("node-a", "online")],
            guests=[guest],
        ),
        plugin._page_token,
    )
    row = plugin._inventory_groups[0].rows[0]
    return plugin, guest, row, row.suffixes[0]


def _complete_guest_address_discovery(ctx):
    assert len(_DeferredThread.created) == 1
    worker = _DeferredThread.created.pop()
    assert worker.started is True
    worker.target(*worker.args)
    assert len(ctx.ui_thread_calls) == 1
    callback, args = ctx.ui_thread_calls.pop()
    callback(*args)


def test_guest_import_requires_explicit_action_and_creates_normal_ssh_connection(
    monkeypatch,
):
    mod = _load()
    ctx = _Ctx()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_prompt_ssh_host",
        lambda parent, submitted, cancelled, error, suggested: callbacks.update(
            parent=parent,
            submitted=submitted,
            cancelled=cancelled,
            error=error,
            suggested=suggested,
        ),
    )
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)

    assert button.label == "Import…"
    assert [call for call in ctx.connection_calls if call[0] == "add"] == []

    plugin._on_guest_connection_clicked(button, guest, nickname)

    assert plugin._operation_in_progress is True
    assert [call for call in ctx.connection_calls if call[0] == "add"] == []
    assert ctx.secrets.calls == []
    _complete_guest_address_discovery(ctx)
    assert callbacks["suggested"] == ""

    callbacks["submitted"]("  GUEST.EXAMPLE.TEST  ")

    add_calls = [call for call in ctx.connection_calls if call[0] == "add"]
    assert add_calls == [
        (
            "add",
            {
                "nickname": nickname,
                "display_name": "Proxmox: database",
                "hostname": "guest.example.test",
                "port": 22,
                "protocol": "ssh",
            },
        )
    ]
    assert ctx.secrets.calls == []
    assert button.label == "Open"
    assert plugin._operation_in_progress is False
    assert plugin._status_label.label == "SSH connection imported."
    assert plugin._status_label.css_classes == {"success"}

    plugin._on_guest_connection_clicked(button, guest, nickname)

    assert ("open", nickname) in ctx.connection_calls
    assert len([call for call in ctx.connection_calls if call[0] == "add"]) == 1


def test_guest_import_prefills_one_discovered_address_but_allows_replacement(
    monkeypatch,
):
    mod = _load()
    ctx = _Ctx()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_prompt_ssh_host",
        lambda _parent, submitted, _cancelled, _error, suggested: callbacks.update(
            submitted=submitted,
            suggested=suggested,
        ),
    )
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    monkeypatch.setattr(
        mod,
        "run_guest_address_discovery",
        lambda *_args: _api(mod).GuestAddressResult(
            "success",
            ("192.0.2.40",),
        ),
    )

    plugin._on_guest_connection_clicked(
        button,
        guest,
        mod.guest_connection_nickname("https://pve.test", "qemu", 100),
    )

    assert [call for call in ctx.connection_calls if call[0] == "add"] == []
    _complete_guest_address_discovery(ctx)
    assert callbacks["suggested"] == "192.0.2.40"

    callbacks["submitted"]("replacement.example.test")

    add_call = next(call for call in ctx.connection_calls if call[0] == "add")
    assert add_call[1]["hostname"] == "replacement.example.test"
    assert add_call[1]["port"] == 22
    assert ctx.secrets.calls == []


@pytest.mark.parametrize(
    ("category", "addresses"),
    [
        ("success", ()),
        ("success", ("192.0.2.50", "2001:db8::50")),
        ("forbidden", ()),
        ("invalid_response", ()),
    ],
)
def test_guest_import_uses_empty_manual_fallback_without_one_reliable_address(
    category,
    addresses,
    monkeypatch,
):
    mod = _load()
    ctx = _Ctx()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_prompt_ssh_host",
        lambda _parent, _submitted, cancelled, _error, suggested: callbacks.update(
            cancelled=cancelled,
            suggested=suggested,
        ),
    )
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    monkeypatch.setattr(
        mod,
        "run_guest_address_discovery",
        lambda *_args: _api(mod).GuestAddressResult(category, addresses),
    )

    plugin._on_guest_connection_clicked(
        button,
        guest,
        mod.guest_connection_nickname("https://pve.test", "qemu", 100),
    )
    _complete_guest_address_discovery(ctx)

    assert callbacks["suggested"] == ""
    assert plugin._operation_in_progress is True
    assert [call for call in ctx.connection_calls if call[0] == "add"] == []
    callbacks["cancelled"]()
    assert plugin._operation_in_progress is False


@pytest.mark.parametrize("failure_point", ("constructor", "start"))
def test_guest_address_thread_startup_failure_keeps_manual_import_available(
    failure_point,
    monkeypatch,
):
    mod = _load()
    ctx = _Ctx()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_prompt_ssh_host",
        lambda _parent, _submitted, cancelled, _error, suggested: callbacks.update(
            cancelled=cancelled,
            suggested=suggested,
        ),
    )
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    monkeypatch.setattr(
        mod.threading,
        "Thread",
        _thread_type_failing_at(failure_point),
    )
    ctx.settings.get_calls.clear()

    plugin._on_guest_connection_clicked(
        button,
        guest,
        mod.guest_connection_nickname("https://pve.test", "qemu", 100),
    )

    assert callbacks["suggested"] == ""
    assert plugin._operation_in_progress is True
    assert ctx.settings.get_calls == []
    assert ctx.secrets.calls == []
    callbacks["cancelled"]()
    assert plugin._operation_in_progress is False


def test_stale_guest_address_callback_does_not_open_prompt_or_touch_new_page(
    monkeypatch,
):
    mod = _load()
    ctx = _Ctx()

    def forbidden_prompt(*_args):
        raise AssertionError("stale discovery opened host prompt")

    monkeypatch.setattr(mod, "_prompt_ssh_host", forbidden_prompt)
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)

    plugin._on_guest_connection_clicked(button, guest, nickname)
    worker = _DeferredThread.created.pop()
    worker.target(*worker.args)
    callback, args = ctx.ui_thread_calls.pop()
    calls_before_callback = list(ctx.connection_calls)
    plugin._page_token = object()
    plugin._operation_in_progress = True
    plugin._save_button = _ForbiddenWidget()
    plugin._test_button = _ForbiddenWidget()
    plugin._refresh_button = _ForbiddenWidget()
    plugin._status_label = _ForbiddenWidget()

    callback(*args)

    assert plugin._operation_in_progress is True
    assert ctx.connection_calls == calls_before_callback
    assert ctx.connections == []


def test_guest_import_cancellation_restores_shared_busy_state(monkeypatch):
    mod = _load()
    ctx = _Ctx()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_prompt_ssh_host",
        lambda _parent, _submitted, cancelled, _error, suggested: callbacks.update(
            cancelled=cancelled,
            suggested=suggested,
        ),
    )
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)

    plugin._on_guest_connection_clicked(button, guest, nickname)

    assert plugin._operation_in_progress is True
    assert button.sensitive_calls[-1] is False
    assert plugin._save_button.sensitive_calls[-1] is False
    assert plugin._test_button.sensitive_calls[-1] is False
    assert plugin._refresh_button.sensitive_calls[-1] is False
    assert plugin._import_custom_ca_button.sensitive_calls[-1] is False

    _complete_guest_address_discovery(ctx)
    assert callbacks["suggested"] == ""
    callbacks["cancelled"]()

    assert plugin._operation_in_progress is False
    assert button.sensitive_calls[-1] is True
    assert plugin._save_button.sensitive_calls[-1] is True
    assert plugin._test_button.sensitive_calls[-1] is True
    assert plugin._refresh_button.sensitive_calls[-1] is True
    assert plugin._import_custom_ca_button.sensitive_calls[-1] is True


def test_template_guest_has_no_ssh_import_action(monkeypatch):
    mod = _load()
    ctx = _Ctx()
    ctx.settings = _Settings(
        {
            "server_url": "https://pve.test",
            "token_user": "user@pve",
            "token_id": "id",
        }
    )
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)
    plugin._finish_refresh(
        _inventory_result(
            mod,
            nodes=[_api(mod).ProxmoxNode("node-a", "online")],
            guests=[
                _api(mod).ProxmoxGuest(
                    "qemu",
                    100,
                    "template",
                    "node-a",
                    "stopped",
                    True,
                )
            ],
        ),
        plugin._page_token,
    )

    assert [
        suffix.label for suffix in plugin._inventory_groups[0].rows[0].suffixes
    ] == ["Template"]
    assert plugin._guest_connection_buttons == []


def test_guest_import_rejects_invalid_manual_host_without_creating_connection(
    monkeypatch,
):
    mod = _load()
    ctx = _Ctx()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_prompt_ssh_host",
        lambda _parent, submitted, _cancelled, _error, suggested: callbacks.update(
            submitted=submitted,
            suggested=suggested,
        ),
    )
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)

    plugin._on_guest_connection_clicked(button, guest, nickname)
    _complete_guest_address_discovery(ctx)
    callbacks["submitted"]("https://guest.test/path")

    assert [call for call in ctx.connection_calls if call[0] == "add"] == []
    assert ctx.secrets.calls == []
    assert button.label == "Import…"
    assert plugin._operation_in_progress is False
    assert plugin._status_label.label == "Enter a valid SSH host or IP address."
    assert "https://guest.test/path" not in plugin._status_label.label


def test_existing_guest_connection_is_opened_without_duplicate(monkeypatch):
    mod = _load()
    ctx = _Ctx()
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)
    ctx.connections = [
        types.SimpleNamespace(
            nickname=nickname,
            host="guest.example.test",
            username="",
            port=22,
            protocol="ssh",
        )
    ]
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )

    assert button.label == "Open"

    plugin._on_guest_connection_clicked(button, guest, nickname)

    assert ("open", nickname) in ctx.connection_calls
    assert [call for call in ctx.connection_calls if call[0] == "add"] == []
    assert plugin._operation_in_progress is False
    assert plugin._status_label.label == "SSH connection opened."


def test_guest_open_error_is_sanitized_and_restores_busy(monkeypatch):
    mod = _load()
    ctx = _Ctx()
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)
    ctx.connections = [
        types.SimpleNamespace(
            nickname=nickname,
            host="guest.example.test",
            username="",
            port=22,
            protocol="ssh",
        )
    ]
    ctx.fail_open_connection = True
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )

    plugin._on_guest_connection_clicked(button, guest, nickname)

    assert [call for call in ctx.connection_calls if call[0] == "add"] == []
    assert plugin._operation_in_progress is False
    assert plugin._status_label.label == "The SSH connection could not be opened."
    assert "open detail" not in plugin._status_label.label


def test_unavailable_connection_list_blocks_guest_import_fail_closed(monkeypatch):
    mod = _load()
    ctx = _Ctx()
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    ctx.fail_list_connections = True
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)

    plugin._on_guest_connection_clicked(button, guest, nickname)

    assert [call for call in ctx.connection_calls if call[0] == "add"] == []
    assert [call for call in ctx.connection_calls if call[0] == "open"] == []
    assert plugin._operation_in_progress is False
    assert plugin._status_label.label == "SSH Pilot connections are unavailable."


def test_guest_import_rechecks_identity_before_creation_to_avoid_race_duplicate(
    monkeypatch,
):
    mod = _load()
    ctx = _Ctx()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_prompt_ssh_host",
        lambda _parent, submitted, _cancelled, _error, suggested: callbacks.update(
            submitted=submitted,
            suggested=suggested,
        ),
    )
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)
    plugin._on_guest_connection_clicked(button, guest, nickname)
    _complete_guest_address_discovery(ctx)
    ctx.connections.append(
        types.SimpleNamespace(
            nickname=nickname,
            host="guest.example.test",
            username="",
            port=22,
            protocol="ssh",
        )
    )

    callbacks["submitted"]("guest.example.test")

    assert [call for call in ctx.connection_calls if call[0] == "add"] == []
    assert ("open", nickname) in ctx.connection_calls
    assert button.label == "Open"


def test_guest_connection_creation_error_is_sanitized_and_restores_busy(
    monkeypatch,
):
    mod = _load()
    ctx = _Ctx()
    ctx.fail_add_connection = True
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_prompt_ssh_host",
        lambda _parent, submitted, _cancelled, _error, suggested: callbacks.update(
            submitted=submitted,
            suggested=suggested,
        ),
    )
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)

    plugin._on_guest_connection_clicked(button, guest, nickname)
    _complete_guest_address_discovery(ctx)
    callbacks["submitted"]("guest.example.test")

    assert plugin._operation_in_progress is False
    assert button.label == "Import…"
    assert plugin._status_label.label == (
        "The SSH connection could not be imported."
    )
    assert "creation detail" not in plugin._status_label.label
    assert ctx.secrets.calls == []


def test_stale_guest_host_callback_does_not_create_or_open_connection(monkeypatch):
    mod = _load()
    ctx = _Ctx()
    callbacks = {}
    monkeypatch.setattr(
        mod,
        "_prompt_ssh_host",
        lambda _parent, submitted, _cancelled, _error, suggested: callbacks.update(
            submitted=submitted,
            suggested=suggested,
        ),
    )
    plugin, guest, _row, button = _render_importable_guest(
        mod,
        ctx,
        monkeypatch,
    )
    nickname = mod.guest_connection_nickname("https://pve.test", "qemu", 100)
    plugin._on_guest_connection_clicked(button, guest, nickname)
    _complete_guest_address_discovery(ctx)
    calls_before_callback = list(ctx.connection_calls)
    plugin._page_token = object()
    plugin._save_button = _ForbiddenWidget()
    plugin._test_button = _ForbiddenWidget()
    plugin._refresh_button = _ForbiddenWidget()
    plugin._status_label = _ForbiddenWidget()

    callbacks["submitted"]("guest.example.test")

    assert ctx.connection_calls == calls_before_callback
    assert ctx.connections == []


@pytest.mark.parametrize(
    "node_count, guest_count, expected",
    [
        (
            1,
            1,
            "Inventory loaded: 1 node and 1 guest visible to this API token.",
        ),
        (
            2,
            1,
            "Inventory loaded: 2 nodes and 1 guest visible to this API token.",
        ),
        (
            1,
            2,
            "Inventory loaded: 1 node and 2 guests visible to this API token.",
        ),
    ],
)
def test_inventory_success_message_uses_natural_pluralization(
    node_count,
    guest_count,
    expected,
):
    mod = _load()
    nodes = tuple(
        _api(mod).ProxmoxNode(f"node-{index}", "online")
        for index in range(node_count)
    )
    guests = tuple(
        _api(mod).ProxmoxGuest(
            "qemu", 100 + index, "", "node-0", "running", False
        )
        for index in range(guest_count)
    )

    assert mod.inventory_success_message(
        mod.ProxmoxInventory(nodes=nodes, guests=guests)
    ) == expected


def test_inventory_with_nodes_and_no_guests_is_a_visible_success(monkeypatch):
    mod = _load()
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)

    plugin._finish_refresh(
        _inventory_result(
            mod,
            nodes=[_api(mod).ProxmoxNode("node-a", "online")],
        ),
        plugin._page_token,
    )

    assert plugin._inventory_status_row.title == (
        "No guests visible to this API token were returned."
    )
    assert [group.title for group in plugin._inventory_groups] == ["node-a"]


def test_fully_empty_inventory_is_a_visible_success(monkeypatch):
    mod = _load()
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)

    plugin._finish_refresh(_inventory_result(mod), plugin._page_token)

    assert plugin._inventory_status_row.title == (
        "No nodes or guests visible to this API token were returned."
    )
    assert plugin._inventory_groups == []
    assert plugin._inventory_groups_box.children == []


def test_inventory_error_clears_previous_groups_and_uses_backend_message(monkeypatch):
    mod = _load()
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)
    plugin._render_inventory(
        mod.ProxmoxInventory(
            nodes=(_api(mod).ProxmoxNode("old-node", "online"),),
            guests=(),
        )
    )
    result = mod.InventoryResult(
        "forbidden",
        "The API token is not authorized for this operation.",
    )

    plugin._finish_refresh(result, plugin._page_token)

    assert plugin._inventory_groups == []
    assert plugin._inventory_groups_box.children == []
    assert plugin._inventory_status_row.title == result.message


def test_inventory_success_without_payload_is_handled_defensively(monkeypatch):
    mod = _load()
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)

    plugin._finish_refresh(
        mod.InventoryResult("success", "Inventory loaded."),
        plugin._page_token,
    )

    assert plugin._inventory_status_row.title == "The inventory could not be loaded."
    assert plugin._operation_in_progress is False


def test_refresh_start_removes_previous_inventory_before_worker(monkeypatch):
    mod = _load()
    _DeferredThread.created = []
    monkeypatch.setattr(mod.threading, "Thread", _DeferredThread)
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)
    plugin._render_inventory(
        mod.ProxmoxInventory(
            nodes=(_api(mod).ProxmoxNode("old-node", "online"),),
            guests=(),
        )
    )

    plugin._on_refresh_clicked(None)

    assert plugin._inventory_groups == []
    assert plugin._inventory_groups_box.children == []
    assert plugin._inventory_status_row.title == "Loading inventory…"


def test_successful_empty_refresh_replaces_non_empty_inventory(monkeypatch):
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
    plugin, _page = _build_headless_page(mod, ctx, monkeypatch)
    plugin._finish_refresh(
        _inventory_result(
            mod,
            nodes=[_api(mod).ProxmoxNode("old-node", "online")],
            guests=[
                _api(mod).ProxmoxGuest(
                    "qemu", 100, "old-guest", "old-node", "running", False
                )
            ],
        ),
        plugin._page_token,
    )
    old_group = plugin._inventory_groups[0]
    old_guest_row = old_group.rows[0]
    assert old_group.title == "old-node"
    assert old_guest_row.title == "old-guest"

    expected = _inventory_result(mod)
    client = _FakeInventoryClient(expected)
    plugin._client_factory = lambda: client
    page_token = plugin._page_token

    plugin._on_refresh_clicked(None)

    assert plugin._operation_in_progress is True
    assert plugin._inventory_groups == []
    assert plugin._inventory_groups_box.children == []
    assert old_group not in plugin._inventory_groups_box.children
    assert plugin._inventory_status_row.title == "Loading inventory…"
    assert plugin._inventory_spinner.active is True
    assert plugin._inventory_spinner.visible is True
    assert plugin._save_button.sensitive_calls[-1] is False
    assert plugin._test_button.sensitive_calls[-1] is False
    assert plugin._refresh_button.sensitive_calls[-1] is False

    worker = _DeferredThread.created[0]
    worker.target(*worker.args)
    callback, args = ctx.ui_thread_calls[0]
    assert callback == plugin._finish_refresh
    assert args == (expected, page_token)

    callback(*args)

    assert plugin._inventory_groups == []
    assert plugin._inventory_groups_box.children == []
    assert old_group not in plugin._inventory_groups_box.children
    assert old_guest_row not in [
        row
        for group in plugin._inventory_groups_box.children
        for row in group.rows
    ]
    assert plugin._inventory_status_row.title == (
        "No nodes or guests visible to this API token were returned."
    )
    assert plugin._inventory_spinner.active is False
    assert plugin._inventory_spinner.visible is False
    assert plugin._operation_in_progress is False
    assert plugin._save_button.sensitive_calls[-1] is True
    assert plugin._test_button.sensitive_calls[-1] is True
    assert plugin._refresh_button.sensitive_calls[-1] is True
    assert plugin._import_custom_ca_button.sensitive_calls[-1] is True
    assert plugin._remove_custom_ca_button.sensitive_calls[-1] is False


def test_successive_inventory_results_replace_groups_without_accumulation(monkeypatch):
    mod = _load()
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)
    first = _inventory_result(
        mod,
        nodes=[_api(mod).ProxmoxNode("node-a", "online")],
        guests=[
            _api(mod).ProxmoxGuest(
                "qemu", 100, "old", "node-a", "running", False
            )
        ],
    )
    second = _inventory_result(
        mod,
        nodes=[_api(mod).ProxmoxNode("node-b", "online")],
        guests=[
            _api(mod).ProxmoxGuest(
                "lxc", 101, "new", "node-b", "stopped", False
            )
        ],
    )

    plugin._finish_refresh(first, plugin._page_token)
    plugin._finish_refresh(second, plugin._page_token)

    assert [group.title for group in plugin._inventory_groups] == ["node-b"]
    assert [group.title for group in plugin._inventory_groups_box.children] == [
        "node-b"
    ]
    assert [row.title for row in plugin._inventory_groups[0].rows] == ["new"]


def test_inventory_rendering_preserves_backend_node_and_guest_order(monkeypatch):
    mod = _load()
    plugin, _page = _build_headless_page(mod, _Ctx(), monkeypatch)
    result = _inventory_result(
        mod,
        nodes=[
            _api(mod).ProxmoxNode("node-b", "online"),
            _api(mod).ProxmoxNode("node-a", "online"),
        ],
        guests=[
            _api(mod).ProxmoxGuest(
                "lxc", 202, "second", "node-b", "running", False
            ),
            _api(mod).ProxmoxGuest(
                "qemu", 201, "first", "node-b", "running", False
            ),
        ],
    )

    plugin._finish_refresh(result, plugin._page_token)

    assert [group.title for group in plugin._inventory_groups] == [
        "node-b",
        "node-a",
    ]
    assert [row.title for row in plugin._inventory_groups[0].rows] == [
        "second",
        "first",
    ]
