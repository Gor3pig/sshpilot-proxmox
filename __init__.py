"""Proxmox VE integration plugin for SSH Pilot."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from typing import Any

from sshpilot.plugins.api import PluginContext, SshPilotPlugin

if __package__:
    from .proxmox_api import (
        ConnectionTestResult,
        GuestAddressResult,
        InventoryResult,
        ProxmoxClient,
        ProxmoxInventory,
        ProxmoxValidationError,
        connection_test_result,
        guest_address_result,
        normalize_server_url,
        prepare_configuration,
        validate_custom_ca_pem,
    )
else:
    from proxmox_api import (
        ConnectionTestResult,
        GuestAddressResult,
        InventoryResult,
        ProxmoxClient,
        ProxmoxInventory,
        ProxmoxValidationError,
        connection_test_result,
        guest_address_result,
        normalize_server_url,
        prepare_configuration,
        validate_custom_ca_pem,
    )

CONFIGURATION_KEY = "configuration"
SECRET_KEY = "api_token_secret"
CUSTOM_CA_ENABLED_KEY = "custom_ca_enabled"
CUSTOM_CA_FILE = "custom-ca.pem"
MAX_CUSTOM_CA_BYTES = 1_048_576
CONFIGURATION_FIELDS = ("server_url", "token_user", "token_id")
SSH_PORT = 22

_SSH_HOST_LABEL = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)

_INVENTORY_REFRESH_MESSAGES = {
    "invalid_configuration": (
        "Save a complete Proxmox VE configuration before refreshing."
    ),
    "invalid_url": "Enter a valid HTTPS Proxmox VE server URL.",
    "missing_secret": "No API token secret is stored.",
    "secret_unavailable": (
        "The API token secret could not be read from secure storage."
    ),
    "custom_ca_error": (
        "The configured custom CA certificate is unavailable or invalid."
    ),
    "unexpected_error": "The inventory could not be loaded.",
}


@dataclass(frozen=True)
class SaveResult:
    success: bool
    partial: bool
    clear_secret: bool
    message: str


@dataclass(frozen=True)
class CustomCAResult:
    success: bool
    enabled: bool | None
    message: str


def normalize_configuration(value: Any) -> dict[str, str]:
    """Return the supported text fields from persisted configuration."""
    if not isinstance(value, dict):
        value = {}
    return {
        key: field_value if isinstance(field_value := value.get(key), str) else ""
        for key in CONFIGURATION_FIELDS
    }


def load_configuration(settings: Any) -> dict[str, str]:
    """Load configuration defensively from the scoped settings facade."""
    try:
        value = settings.get(CONFIGURATION_KEY, {})
    except Exception:
        value = {}
    return normalize_configuration(value)


def build_configuration(
    server_url: str,
    token_user: str,
    token_id: str,
) -> dict[str, str]:
    """Build the non-sensitive settings payload from UI text."""
    return {
        "server_url": server_url.strip(),
        "token_user": token_user.strip(),
        "token_id": token_id.strip(),
    }


def save_configuration(
    settings: Any,
    secrets: Any,
    configuration: dict[str, str],
    new_secret: str,
) -> SaveResult:
    """Persist settings first, then optionally store and verify a new secret."""
    try:
        settings.set(CONFIGURATION_KEY, configuration)
    except Exception:
        return SaveResult(
            success=False,
            partial=False,
            clear_secret=False,
            message="Could not save the configuration.",
        )

    if not new_secret:
        return SaveResult(
            success=True,
            partial=False,
            clear_secret=False,
            message="Configuration saved. Token secret unchanged.",
        )

    stored_secret = None
    try:
        secrets.set(SECRET_KEY, new_secret)
        stored_secret = secrets.get(SECRET_KEY)
        confirmed = stored_secret == new_secret
    except Exception:
        confirmed = False
    finally:
        stored_secret = None

    if confirmed:
        return SaveResult(
            success=True,
            partial=False,
            clear_secret=True,
            message="Configuration and token secret saved.",
        )
    return SaveResult(
        success=False,
        partial=True,
        clear_secret=False,
        message=(
            "Configuration saved, but the token secret could not be saved "
            "or verified."
        ),
    )


def _custom_ca_enabled(settings: Any) -> bool:
    try:
        value = settings.get(CUSTOM_CA_ENABLED_KEY, False)
    except Exception as exc:
        raise ProxmoxValidationError("custom_ca_error") from exc
    if type(value) is not bool:
        raise ProxmoxValidationError("custom_ca_error")
    return value


def load_custom_ca_pem(settings: Any, files: Any) -> str | None:
    """Load the configured private copy, failing closed when it is unusable."""
    if not _custom_ca_enabled(settings):
        return None
    try:
        raw = files.read_bytes(CUSTOM_CA_FILE)
        if len(raw) > MAX_CUSTOM_CA_BYTES:
            raise ProxmoxValidationError("custom_ca_error")
        return validate_custom_ca_pem(raw)
    except ProxmoxValidationError as exc:
        raise ProxmoxValidationError("custom_ca_error") from exc
    except Exception as exc:
        raise ProxmoxValidationError("custom_ca_error") from exc


def _read_custom_ca_source(source_path: str) -> bytes:
    try:
        with open(source_path, "rb") as source:
            data = source.read(MAX_CUSTOM_CA_BYTES + 1)
    except Exception as exc:
        raise ProxmoxValidationError("custom_ca_read_error") from exc
    if len(data) > MAX_CUSTOM_CA_BYTES:
        raise ProxmoxValidationError("custom_ca_too_large")
    return data


def _write_custom_ca(files: Any, pem: str) -> None:
    final_path = files.path(CUSTOM_CA_FILE)
    directory = os.path.dirname(final_path)
    descriptor = None
    temporary_path = None
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            dir=directory,
            prefix=".custom-ca-",
            suffix=".tmp",
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as temporary:
            descriptor = None
            temporary.write(pem.encode("ascii"))
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, final_path)
        temporary_path = None
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
        raise


def import_custom_ca(settings: Any, files: Any, source_path: str) -> CustomCAResult:
    """Validate and persist one selected CA bundle without retaining its path."""
    try:
        was_enabled = _custom_ca_enabled(settings)
    except ProxmoxValidationError:
        return CustomCAResult(
            False,
            None,
            "The custom CA configuration is unavailable.",
        )

    try:
        raw = _read_custom_ca_source(source_path)
        pem = validate_custom_ca_pem(raw)
    except ProxmoxValidationError as exc:
        messages = {
            "custom_ca_too_large": (
                "The selected CA certificate file is too large."
            ),
            "custom_ca_private_key": (
                "The selected file contains private key material and was not "
                "imported."
            ),
            "custom_ca_read_error": (
                "The selected CA certificate file could not be read."
            ),
        }
        return CustomCAResult(
            False,
            was_enabled,
            messages.get(
                exc.category,
                "The selected file is not a valid CA certificate bundle.",
            ),
        )
    except Exception:
        return CustomCAResult(
            False,
            was_enabled,
            "The selected file is not a valid CA certificate bundle.",
        )

    try:
        _write_custom_ca(files, pem)
    except Exception:
        return CustomCAResult(
            False,
            was_enabled,
            "The custom CA certificate could not be saved.",
        )

    if not was_enabled:
        try:
            settings.set(CUSTOM_CA_ENABLED_KEY, True)
        except Exception:
            try:
                os.unlink(files.path(CUSTOM_CA_FILE))
            except Exception:
                pass
            return CustomCAResult(
                False,
                False,
                "The custom CA certificate could not be enabled.",
            )

    return CustomCAResult(True, True, "Custom CA certificate imported.")


def remove_custom_ca(settings: Any, files: Any) -> CustomCAResult:
    """Disable the custom CA before removing only its private stored copy."""
    try:
        settings.set(CUSTOM_CA_ENABLED_KEY, False)
    except Exception:
        return CustomCAResult(
            False,
            None,
            "The custom CA certificate could not be disabled.",
        )

    try:
        os.unlink(files.path(CUSTOM_CA_FILE))
    except FileNotFoundError:
        pass
    except Exception:
        return CustomCAResult(
            False,
            False,
            "System trust was restored, but the stored custom CA could not be "
            "removed.",
        )
    return CustomCAResult(True, False, "System trust store restored.")


def run_connection_test(
    settings: Any,
    secrets: Any,
    client_factory=None,
    files=None,
) -> ConnectionTestResult:
    """Test the saved configuration without retaining or exposing its secret."""
    try:
        stored_configuration = settings.get(CONFIGURATION_KEY, {})
    except Exception:
        return connection_test_result("unexpected_error")

    configuration = normalize_configuration(stored_configuration)
    try:
        prepared = prepare_configuration(
            configuration["server_url"],
            configuration["token_user"],
            configuration["token_id"],
        )
    except ProxmoxValidationError as exc:
        return connection_test_result(exc.category)

    try:
        custom_ca_pem = load_custom_ca_pem(settings, files)
    except ProxmoxValidationError as exc:
        return connection_test_result(exc.category)

    try:
        secret = secrets.get(SECRET_KEY)
    except Exception:
        return connection_test_result("secret_unavailable")
    if not secret:
        return connection_test_result("missing_secret")

    try:
        factory = client_factory if client_factory is not None else ProxmoxClient
        client = (
            factory(custom_ca_pem=custom_ca_pem)
            if custom_ca_pem is not None
            else factory()
        )
        return client.test_connection(prepared, secret)
    except Exception:
        return connection_test_result("unexpected_error")
    finally:
        secret = ""


def _inventory_refresh_result(category: str) -> InventoryResult:
    message = _INVENTORY_REFRESH_MESSAGES.get(
        category,
        _INVENTORY_REFRESH_MESSAGES["unexpected_error"],
    )
    return InventoryResult(category=category, message=message)


def run_inventory_refresh(
    settings: Any,
    secrets: Any,
    client_factory=None,
    files=None,
) -> InventoryResult:
    """Load inventory from saved configuration without retaining its secret."""
    try:
        stored_configuration = settings.get(CONFIGURATION_KEY, {})
    except Exception:
        return _inventory_refresh_result("unexpected_error")

    configuration = normalize_configuration(stored_configuration)
    try:
        prepared = prepare_configuration(
            configuration["server_url"],
            configuration["token_user"],
            configuration["token_id"],
        )
    except ProxmoxValidationError as exc:
        return _inventory_refresh_result(exc.category)

    try:
        custom_ca_pem = load_custom_ca_pem(settings, files)
    except ProxmoxValidationError as exc:
        return _inventory_refresh_result(exc.category)

    try:
        secret = secrets.get(SECRET_KEY)
    except Exception:
        return _inventory_refresh_result("secret_unavailable")
    if not secret:
        return _inventory_refresh_result("missing_secret")

    try:
        factory = client_factory if client_factory is not None else ProxmoxClient
        client = (
            factory(custom_ca_pem=custom_ca_pem)
            if custom_ca_pem is not None
            else factory()
        )
        return client.get_inventory(prepared, secret)
    except Exception:
        return _inventory_refresh_result("unexpected_error")
    finally:
        secret = ""


def run_guest_address_discovery(
    settings: Any,
    secrets: Any,
    guest: Any,
    client_factory=None,
    files=None,
) -> GuestAddressResult:
    """Discover addresses for one guest without retaining its API secret."""
    try:
        stored_configuration = settings.get(CONFIGURATION_KEY, {})
    except Exception:
        return guest_address_result("unexpected_error")

    configuration = normalize_configuration(stored_configuration)
    try:
        prepared = prepare_configuration(
            configuration["server_url"],
            configuration["token_user"],
            configuration["token_id"],
        )
    except ProxmoxValidationError as exc:
        return guest_address_result(exc.category)

    try:
        custom_ca_pem = load_custom_ca_pem(settings, files)
    except ProxmoxValidationError as exc:
        return guest_address_result(exc.category)

    try:
        secret = secrets.get(SECRET_KEY)
    except Exception:
        return guest_address_result("secret_unavailable")
    if not secret:
        return guest_address_result("missing_secret")

    try:
        factory = client_factory if client_factory is not None else ProxmoxClient
        client = (
            factory(custom_ca_pem=custom_ca_pem)
            if custom_ca_pem is not None
            else factory()
        )
        return client.get_guest_addresses(prepared, secret, guest)
    except Exception:
        return guest_address_result("unexpected_error")
    finally:
        secret = ""


def _pluralized_count(count: int, singular: str) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {singular}{suffix}"


def inventory_success_message(inventory: ProxmoxInventory) -> str:
    """Describe only resources visible to the configured API token."""
    node_count = len(inventory.nodes)
    guest_count = len(inventory.guests)
    if node_count == 0 and guest_count == 0:
        return "No nodes or guests visible to this API token were returned."
    if guest_count == 0:
        return "No guests visible to this API token were returned."
    return (
        f"Inventory loaded: {_pluralized_count(node_count, 'node')} and "
        f"{_pluralized_count(guest_count, 'guest')} visible to this API token."
    )


def normalize_ssh_host(value: Any) -> str:
    """Validate a manually entered SSH hostname or IP address."""
    if type(value) is not str:
        raise ValueError("invalid SSH host")
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > 253
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in candidate
        )
    ):
        raise ValueError("invalid SSH host")

    address_candidate = candidate
    if candidate.startswith("[") or candidate.endswith("]"):
        if not (candidate.startswith("[") and candidate.endswith("]")):
            raise ValueError("invalid SSH host")
        address_candidate = candidate[1:-1]
    try:
        return str(ipaddress.ip_address(address_candidate))
    except ValueError:
        pass

    if re.fullmatch(r"[0-9.]+", candidate):
        raise ValueError("invalid SSH host")
    labels = candidate.split(".")
    if not labels or any(
        not _SSH_HOST_LABEL.fullmatch(label) for label in labels
    ):
        raise ValueError("invalid SSH host")
    return candidate.lower()


def guest_connection_nickname(
    server_url: str,
    guest_type: str,
    vmid: int,
) -> str:
    """Build a stable SSH Pilot nickname for one guest on one endpoint."""
    normalized_url = normalize_server_url(server_url)
    normalized_type = str(guest_type).lower()
    if (
        normalized_type not in ("qemu", "lxc")
        or type(vmid) is not int
        or vmid < 0
    ):
        raise ValueError("invalid guest identity")
    endpoint_id = (
        hashlib.sha256(normalized_url.encode("utf-8")).digest()[:16].hex()
    )
    return f"proxmox-{endpoint_id}-{normalized_type}-{vmid}"


def _connection_named(connections: Any, nickname: str) -> Any:
    expected = nickname.casefold()
    return next(
        (
            connection
            for connection in connections
            if str(getattr(connection, "nickname", "")).casefold() == expected
        ),
        None,
    )


def _prompt_ssh_host(
    parent: Any,
    on_submitted: Any,
    on_cancelled: Any,
    on_error: Any,
    suggested_host: str = "",
) -> None:
    """Prompt for a guest SSH host without retaining it outside the connection."""
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw, Gtk

        dialog = Adw.MessageDialog(
            transient_for=parent,
            modal=True,
            heading="Import SSH connection",
            body="Enter the guest's SSH hostname or IP address.",
        )
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        host_row = Adw.EntryRow(title="SSH host or IP address")
        host_row.set_text(suggested_host)
        content.append(host_row)
        dialog.set_extra_child(content)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("import", "Import")
        dialog.set_default_response("import")
        dialog.set_close_response("cancel")

        def _on_response(response_dialog, response):
            response_dialog.close()
            if response == "import":
                on_submitted(host_row.get_text())
            else:
                on_cancelled()

        dialog.connect("response", _on_response)
        dialog.present()
    except Exception:
        on_error()


def _choose_custom_ca_file(
    parent: Any,
    on_selected: Any,
    on_cancelled: Any,
    on_error: Any,
) -> None:
    """Open the platform file chooser without retaining the selected path."""
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        from gi.repository import Gio, GLib, Gtk

        dialog = Gtk.FileDialog(title="Import custom CA certificate")
        ca_filter = Gtk.FileFilter()
        ca_filter.set_name("Certificate files")
        for pattern in ("*.pem", "*.crt", "*.cer"):
            ca_filter.add_pattern(pattern)
        all_filter = Gtk.FileFilter()
        all_filter.set_name("All files")
        all_filter.add_pattern("*")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(ca_filter)
        filters.append(all_filter)
        dialog.set_filters(filters)

        def _done(file_dialog, result):
            try:
                selected = file_dialog.open_finish(result)
                source_path = selected.get_path() if selected is not None else None
                if not source_path:
                    on_error()
                    return
                on_selected(source_path)
            except GLib.Error as exc:
                try:
                    cancelled = exc.matches(
                        Gio.io_error_quark(),
                        Gio.IOErrorEnum.CANCELLED,
                    )
                except Exception:
                    cancelled = False
                if cancelled:
                    on_cancelled()
                else:
                    on_error()
            except Exception:
                on_error()

        dialog.open(parent, None, _done)
    except Exception:
        on_error()


class Plugin(SshPilotPlugin):
    def activate(self, ctx: PluginContext) -> None:
        self.ctx = ctx
        self._server_url_row = None
        self._token_user_row = None
        self._token_id_row = None
        self._secret_row = None
        self._save_button = None
        self._test_button = None
        self._refresh_button = None
        self._custom_ca_row = None
        self._import_custom_ca_button = None
        self._remove_custom_ca_button = None
        self._custom_ca_enabled = False
        self._status_label = None
        self._inventory_status_row = None
        self._inventory_spinner = None
        self._inventory_groups_box = None
        self._inventory_groups = []
        self._guest_connection_buttons = []
        self._adw = None
        self._gtk = None
        self._page_token = None
        self._operation_in_progress = False
        self._client_factory = ProxmoxClient
        ctx.ui.register_page(
            "proxmox",
            "Proxmox VE",
            "network-server-symbolic",
            self._build_page,
        )

    def _build_page(self):
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw, Gtk

        self._adw = Adw
        self._gtk = Gtk
        self._page_token = object()
        self._operation_in_progress = False
        self._inventory_groups = []
        self._guest_connection_buttons = []
        configuration = load_configuration(self.ctx.settings)
        try:
            self._custom_ca_enabled = _custom_ca_enabled(self.ctx.settings)
        except ProxmoxValidationError:
            self._custom_ca_enabled = False

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        for set_margin in (
            content.set_margin_top,
            content.set_margin_bottom,
            content.set_margin_start,
            content.set_margin_end,
        ):
            set_margin(18)

        title = Gtk.Label(label="Proxmox VE", xalign=0)
        title.add_css_class("title-2")
        content.append(title)

        form = Adw.PreferencesGroup(title="Endpoint configuration")
        self._server_url_row = Adw.EntryRow(title="Server URL")
        self._server_url_row.set_text(configuration["server_url"])
        form.add(self._server_url_row)

        self._token_user_row = Adw.EntryRow(title="API token user")
        self._token_user_row.set_text(configuration["token_user"])
        form.add(self._token_user_row)

        self._token_id_row = Adw.EntryRow(title="API token ID")
        self._token_id_row.set_text(configuration["token_id"])
        form.add(self._token_id_row)

        self._secret_row = Adw.PasswordEntryRow(title="API token secret")
        self._secret_row.set_show_apply_button(False)
        try:
            self._secret_row.set_show_peek_icon(True)
        except Exception:
            pass
        form.add(self._secret_row)
        content.append(form)

        secret_help = Gtk.Label(
            label="Leave blank to keep the current token secret.",
            xalign=0,
        )
        secret_help.add_css_class("dim-label")
        secret_help.add_css_class("caption")
        secret_help.set_wrap(True)
        content.append(secret_help)

        tls_group = Adw.PreferencesGroup(title="TLS")
        self._custom_ca_row = Adw.ActionRow(
            title="Custom CA certificate",
            subtitle=(
                "Custom CA configured"
                if self._custom_ca_enabled
                else "System trust store"
            ),
        )
        self._import_custom_ca_button = Gtk.Button(label="Import…")
        self._import_custom_ca_button.connect(
            "clicked",
            self._on_import_custom_ca_clicked,
        )
        self._custom_ca_row.add_suffix(self._import_custom_ca_button)
        self._remove_custom_ca_button = Gtk.Button(label="Remove")
        self._remove_custom_ca_button.connect(
            "clicked",
            self._on_remove_custom_ca_clicked,
        )
        self._remove_custom_ca_button.set_sensitive(self._custom_ca_enabled)
        self._custom_ca_row.add_suffix(self._remove_custom_ca_button)
        tls_group.add(self._custom_ca_row)
        content.append(tls_group)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_halign(Gtk.Align.END)

        self._test_button = Gtk.Button(label="Test connection")
        self._test_button.connect("clicked", self._on_test_clicked)
        actions.append(self._test_button)

        self._save_button = Gtk.Button(label="Save")
        self._save_button.add_css_class("suggested-action")
        self._save_button.connect("clicked", self._on_save_clicked)
        actions.append(self._save_button)
        content.append(actions)

        self._status_label = Gtk.Label(xalign=0)
        self._status_label.set_wrap(True)
        content.append(self._status_label)

        inventory_group = Adw.PreferencesGroup(
            title="Inventory",
            description="Uses the saved endpoint and API token.",
        )
        self._refresh_button = Gtk.Button(label="Refresh")
        self._refresh_button.connect("clicked", self._on_refresh_clicked)
        inventory_group.set_header_suffix(self._refresh_button)

        self._inventory_status_row = Adw.ActionRow(
            title="Inventory has not been loaded."
        )
        self._inventory_spinner = Gtk.Spinner()
        self._inventory_spinner.set_visible(False)
        self._inventory_status_row.add_prefix(self._inventory_spinner)
        inventory_group.add(self._inventory_status_row)
        content.append(inventory_group)

        self._inventory_groups_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=18,
        )
        content.append(self._inventory_groups_box)

        clamp = Adw.Clamp(maximum_size=640)
        clamp.set_child(content)
        scroller = Gtk.ScrolledWindow()
        scroller.set_child(clamp)
        return scroller

    def _on_save_clicked(self, _button) -> None:
        if self._operation_in_progress:
            return
        configuration = build_configuration(
            self._server_url_row.get_text(),
            self._token_user_row.get_text(),
            self._token_id_row.get_text(),
        )
        new_secret = self._secret_row.get_text()
        page_token = self._page_token
        self._set_busy(True)
        self._set_status("Saving…", "dim-label")
        try:
            threading.Thread(
                target=self._save_worker,
                args=(configuration, new_secret, page_token),
                daemon=True,
            ).start()
        except Exception:
            if page_token is not self._page_token:
                return
            self._set_status("The save operation could not be started.", "error")
            self._set_busy(False)

    def _save_worker(
        self,
        configuration: dict[str, str],
        new_secret: str,
        page_token: object,
    ) -> None:
        result = save_configuration(
            self.ctx.settings,
            self.ctx.secrets,
            configuration,
            new_secret,
        )
        new_secret = ""
        self.ctx.run_on_ui_thread(self._finish_save, result, page_token)

    def _on_test_clicked(self, _button) -> None:
        if self._operation_in_progress:
            return
        page_token = self._page_token
        self._set_busy(True)
        self._set_status("Testing connection…", "dim-label")
        try:
            threading.Thread(
                target=self._test_worker,
                args=(page_token,),
                daemon=True,
            ).start()
        except Exception:
            if page_token is not self._page_token:
                return
            self._set_status(
                "The connection test could not be started.",
                "error",
            )
            self._set_busy(False)

    def _test_worker(self, page_token: object) -> None:
        result = run_connection_test(
            self.ctx.settings,
            self.ctx.secrets,
            self._client_factory,
            self.ctx.files,
        )
        self.ctx.run_on_ui_thread(self._finish_test, result, page_token)

    def _on_refresh_clicked(self, _button) -> None:
        if self._operation_in_progress:
            return
        page_token = self._page_token
        self._set_busy(True)
        self._clear_inventory_groups()
        self._inventory_spinner.set_visible(True)
        self._inventory_spinner.start()
        self._inventory_status_row.set_title("Loading inventory…")
        try:
            threading.Thread(
                target=self._refresh_worker,
                args=(page_token,),
                daemon=True,
            ).start()
        except Exception:
            if page_token is not self._page_token:
                return
            self._inventory_spinner.stop()
            self._inventory_spinner.set_visible(False)
            self._inventory_status_row.set_title(
                "The inventory refresh could not be started."
            )
            self._set_busy(False)

    def _refresh_worker(self, page_token: object) -> None:
        result = run_inventory_refresh(
            self.ctx.settings,
            self.ctx.secrets,
            self._client_factory,
            self.ctx.files,
        )
        self.ctx.run_on_ui_thread(self._finish_refresh, result, page_token)

    def _on_import_custom_ca_clicked(self, button) -> None:
        if self._operation_in_progress:
            return
        page_token = self._page_token
        self._set_busy(True)
        parent = None
        get_root = getattr(button, "get_root", None)
        if callable(get_root):
            try:
                parent = get_root()
            except Exception:
                parent = None
        _choose_custom_ca_file(
            parent,
            lambda source_path: self._on_custom_ca_selected(
                source_path,
                page_token,
            ),
            lambda: self._on_custom_ca_cancelled(page_token),
            lambda: self._on_custom_ca_dialog_error(page_token),
        )

    def _on_custom_ca_selected(
        self,
        source_path: str,
        page_token: object,
    ) -> None:
        if page_token is not self._page_token:
            return
        result = import_custom_ca(self.ctx.settings, self.ctx.files, source_path)
        self._finish_custom_ca_operation(result, page_token)

    def _on_custom_ca_cancelled(self, page_token: object) -> None:
        if page_token is not self._page_token:
            return
        self._set_busy(False)

    def _on_custom_ca_dialog_error(self, page_token: object) -> None:
        self._finish_custom_ca_operation(
            CustomCAResult(
                False,
                None,
                "The custom CA certificate file could not be opened.",
            ),
            page_token,
        )

    def _on_remove_custom_ca_clicked(self, _button) -> None:
        if self._operation_in_progress or not self._custom_ca_enabled:
            return
        page_token = self._page_token
        self._set_busy(True)
        result = remove_custom_ca(self.ctx.settings, self.ctx.files)
        self._finish_custom_ca_operation(result, page_token)

    def _finish_custom_ca_operation(
        self,
        result: CustomCAResult,
        page_token: object,
    ) -> None:
        if page_token is not self._page_token:
            return
        if result.enabled is not None:
            self._custom_ca_enabled = result.enabled
            self._custom_ca_row.set_subtitle(
                "Custom CA configured" if result.enabled else "System trust store"
            )
        self._set_status(result.message, "success" if result.success else "error")
        self._set_busy(False)

    def _finish_save(self, result: SaveResult, page_token: object) -> None:
        if page_token is not self._page_token:
            return
        if result.clear_secret:
            self._secret_row.set_text("")
        self._set_status(result.message, "success" if result.success else "error")
        self._set_busy(False)

    def _finish_test(
        self,
        result: ConnectionTestResult,
        page_token: object,
    ) -> None:
        if page_token is not self._page_token:
            return
        self._set_status(result.message, "success" if result.success else "error")
        self._set_busy(False)

    def _finish_refresh(self, result: InventoryResult, page_token: object) -> None:
        if page_token is not self._page_token:
            return
        self._inventory_spinner.stop()
        self._inventory_spinner.set_visible(False)
        try:
            if result.success and result.inventory is not None:
                self._render_inventory(result.inventory)
                self._inventory_status_row.set_title(
                    inventory_success_message(result.inventory)
                )
            else:
                self._clear_inventory_groups()
                message = (
                    result.message
                    if not result.success
                    else _INVENTORY_REFRESH_MESSAGES["unexpected_error"]
                )
                self._inventory_status_row.set_title(message)
        except Exception:
            self._clear_inventory_groups()
            self._inventory_status_row.set_title(
                _INVENTORY_REFRESH_MESSAGES["unexpected_error"]
            )
        finally:
            self._set_busy(False)

    def _guest_connection_error(self, message: str, page_token: object) -> None:
        if page_token is not self._page_token:
            return
        self._set_status(message, "error")
        self._set_busy(False)

    def _open_guest_connection(self, nickname: str, page_token: object) -> None:
        try:
            opened = self.ctx.open_connection(nickname)
        except Exception:
            opened = False
        if page_token is not self._page_token:
            return
        if opened:
            self._set_status("SSH connection opened.", "success")
            self._set_busy(False)
        else:
            self._guest_connection_error(
                "The SSH connection could not be opened.",
                page_token,
            )

    def _list_connections_for_guest_action(self, page_token: object) -> Any:
        try:
            return self.ctx.list_connections()
        except Exception:
            self._guest_connection_error(
                "SSH Pilot connections are unavailable.",
                page_token,
            )
            return None

    def _on_guest_connection_clicked(
        self,
        button: Any,
        guest: Any,
        nickname: str,
    ) -> None:
        if self._operation_in_progress:
            return
        page_token = self._page_token
        self._set_busy(True)
        get_label = getattr(button, "get_label", None)
        if callable(get_label) and get_label() == "Open":
            self._open_guest_connection(nickname, page_token)
            return
        connections = self._list_connections_for_guest_action(page_token)
        if connections is None:
            return
        existing = _connection_named(connections, nickname)
        if existing is not None:
            if getattr(existing, "protocol", "ssh") != "ssh":
                self._guest_connection_error(
                    "The SSH connection could not be imported.",
                    page_token,
                )
                return
            self._open_guest_connection(existing.nickname, page_token)
            return

        parent = None
        get_root = getattr(button, "get_root", None)
        if callable(get_root):
            try:
                parent = get_root()
            except Exception:
                parent = None
        try:
            threading.Thread(
                target=self._guest_address_worker,
                args=(button, guest, nickname, parent, page_token),
                daemon=True,
            ).start()
        except Exception:
            if page_token is not self._page_token:
                return
            self._show_guest_ssh_host_prompt(
                button,
                guest,
                nickname,
                parent,
                page_token,
                "",
            )

    def _guest_address_worker(
        self,
        button: Any,
        guest: Any,
        nickname: str,
        parent: Any,
        page_token: object,
    ) -> None:
        result = run_guest_address_discovery(
            self.ctx.settings,
            self.ctx.secrets,
            guest,
            self._client_factory,
            self.ctx.files,
        )
        self.ctx.run_on_ui_thread(
            self._finish_guest_address_discovery,
            result,
            button,
            guest,
            nickname,
            parent,
            page_token,
        )

    def _finish_guest_address_discovery(
        self,
        result: GuestAddressResult,
        button: Any,
        guest: Any,
        nickname: str,
        parent: Any,
        page_token: object,
    ) -> None:
        if page_token is not self._page_token:
            return
        self._show_guest_ssh_host_prompt(
            button,
            guest,
            nickname,
            parent,
            page_token,
            result.suggested_host if result.success else "",
        )

    def _show_guest_ssh_host_prompt(
        self,
        button: Any,
        guest: Any,
        nickname: str,
        parent: Any,
        page_token: object,
        suggested_host: str | None,
    ) -> None:
        _prompt_ssh_host(
            parent,
            lambda host: self._on_guest_ssh_host_submitted(
                host,
                button,
                guest,
                nickname,
                page_token,
            ),
            lambda: self._on_guest_ssh_host_cancelled(page_token),
            lambda: self._guest_connection_error(
                "The SSH host prompt could not be opened.",
                page_token,
            ),
            suggested_host or "",
        )

    def _on_guest_ssh_host_cancelled(self, page_token: object) -> None:
        if page_token is not self._page_token:
            return
        self._set_busy(False)

    def _on_guest_ssh_host_submitted(
        self,
        host: str,
        button: Any,
        guest: Any,
        nickname: str,
        page_token: object,
    ) -> None:
        if page_token is not self._page_token:
            return
        try:
            normalized_host = normalize_ssh_host(host)
        except ValueError:
            self._guest_connection_error(
                "Enter a valid SSH host or IP address.",
                page_token,
            )
            return

        connections = self._list_connections_for_guest_action(page_token)
        if connections is None:
            return
        existing = _connection_named(connections, nickname)
        if existing is not None:
            if getattr(existing, "protocol", "ssh") != "ssh":
                self._guest_connection_error(
                    "The SSH connection could not be imported.",
                    page_token,
                )
                return
            button.set_label("Open")
            self._open_guest_connection(existing.nickname, page_token)
            return

        guest_type = guest.guest_type.upper()
        guest_title = guest.name or f"{guest_type} {guest.vmid}"
        try:
            self.ctx.add_connection(
                {
                    "nickname": nickname,
                    "display_name": f"Proxmox: {guest_title}",
                    "hostname": normalized_host,
                    "port": SSH_PORT,
                    "protocol": "ssh",
                }
            )
        except Exception:
            self._guest_connection_error(
                "The SSH connection could not be imported.",
                page_token,
            )
            return
        if page_token is not self._page_token:
            return
        button.set_label("Open")
        self._set_status("SSH connection imported.", "success")
        self._set_busy(False)

    def _render_inventory(self, inventory: ProxmoxInventory) -> None:
        self._clear_inventory_groups()
        configuration = load_configuration(self.ctx.settings)
        try:
            server_url = normalize_server_url(configuration["server_url"])
        except ProxmoxValidationError:
            server_url = None
        try:
            connections = self.ctx.list_connections()
        except Exception:
            connections = ()
        guests_by_node = {node.name: [] for node in inventory.nodes}
        for guest in inventory.guests:
            guests_by_node.setdefault(guest.node, []).append(guest)

        for node in inventory.nodes:
            group = self._adw.PreferencesGroup(
                title=node.name,
                description=f"Status: {node.status}",
            )
            guests = guests_by_node.get(node.name, ())
            if not guests:
                group.add(
                    self._adw.ActionRow(
                        title=(
                            "No guests visible to this API token were returned "
                            "for this node."
                        )
                    )
                )
            for guest in guests:
                guest_type = guest.guest_type.upper()
                title = guest.name or f"{guest_type} {guest.vmid}"
                row = self._adw.ActionRow(
                    title=title,
                    subtitle=(
                        f"{guest_type} · VMID {guest.vmid} · "
                        f"Status: {guest.status} · Node: {guest.node}"
                    ),
                )
                if guest.template:
                    template_label = self._gtk.Label(label="Template")
                    template_label.add_css_class("caption")
                    template_label.add_css_class("dim-label")
                    template_label.set_valign(self._gtk.Align.CENTER)
                    row.add_suffix(template_label)
                elif server_url is not None:
                    nickname = guest_connection_nickname(
                        server_url,
                        guest.guest_type,
                        guest.vmid,
                    )
                    existing = _connection_named(connections, nickname)
                    is_ssh = (
                        existing is not None
                        and getattr(existing, "protocol", "ssh") == "ssh"
                    )
                    connection_button = self._gtk.Button(
                        label="Open" if is_ssh else "Import…"
                    )

                    def _on_connection_clicked(
                        clicked_button,
                        selected_guest=guest,
                        connection_nickname=nickname,
                    ):
                        self._on_guest_connection_clicked(
                            clicked_button,
                            selected_guest,
                            connection_nickname,
                        )

                    connection_button.connect(
                        "clicked",
                        _on_connection_clicked,
                    )
                    connection_button.set_sensitive(
                        not self._operation_in_progress
                    )
                    row.add_suffix(connection_button)
                    self._guest_connection_buttons.append(connection_button)
                group.add(row)
            self._inventory_groups_box.append(group)
            self._inventory_groups.append(group)

    def _clear_inventory_groups(self) -> None:
        for group in self._inventory_groups:
            self._inventory_groups_box.remove(group)
        self._inventory_groups.clear()
        self._guest_connection_buttons.clear()

    def _set_busy(self, busy: bool) -> None:
        self._operation_in_progress = busy
        self._save_button.set_sensitive(not busy)
        self._test_button.set_sensitive(not busy)
        self._refresh_button.set_sensitive(not busy)
        self._import_custom_ca_button.set_sensitive(not busy)
        self._remove_custom_ca_button.set_sensitive(
            not busy and self._custom_ca_enabled
        )
        for button in self._guest_connection_buttons:
            button.set_sensitive(not busy)

    def _set_status(self, message: str, css_class: str) -> None:
        for current_class in ("dim-label", "success", "error"):
            self._status_label.remove_css_class(current_class)
        self._status_label.set_label(message)
        self._status_label.add_css_class(css_class)
