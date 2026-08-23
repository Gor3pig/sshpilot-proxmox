"""Proxmox VE integration plugin for SSH Pilot."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from sshpilot.plugins.api import PluginContext, SshPilotPlugin

if __package__:
    from .proxmox_api import (
        ConnectionTestResult,
        InventoryResult,
        ProxmoxClient,
        ProxmoxInventory,
        ProxmoxValidationError,
        connection_test_result,
        prepare_configuration,
    )
else:
    from proxmox_api import (
        ConnectionTestResult,
        InventoryResult,
        ProxmoxClient,
        ProxmoxInventory,
        ProxmoxValidationError,
        connection_test_result,
        prepare_configuration,
    )

CONFIGURATION_KEY = "configuration"
SECRET_KEY = "api_token_secret"
CONFIGURATION_FIELDS = ("server_url", "token_user", "token_id")

_INVENTORY_REFRESH_MESSAGES = {
    "invalid_configuration": (
        "Save a complete Proxmox VE configuration before refreshing."
    ),
    "invalid_url": "Enter a valid HTTPS Proxmox VE server URL.",
    "missing_secret": "No API token secret is stored.",
    "secret_unavailable": (
        "The API token secret could not be read from secure storage."
    ),
    "unexpected_error": "The inventory could not be loaded.",
}


@dataclass(frozen=True)
class SaveResult:
    success: bool
    partial: bool
    clear_secret: bool
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


def run_connection_test(
    settings: Any,
    secrets: Any,
    client_factory=None,
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
        secret = secrets.get(SECRET_KEY)
    except Exception:
        return connection_test_result("secret_unavailable")
    if not secret:
        return connection_test_result("missing_secret")

    try:
        factory = client_factory if client_factory is not None else ProxmoxClient
        return factory().test_connection(prepared, secret)
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
        secret = secrets.get(SECRET_KEY)
    except Exception:
        return _inventory_refresh_result("secret_unavailable")
    if not secret:
        return _inventory_refresh_result("missing_secret")

    try:
        factory = client_factory if client_factory is not None else ProxmoxClient
        return factory().get_inventory(prepared, secret)
    except Exception:
        return _inventory_refresh_result("unexpected_error")
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
        self._status_label = None
        self._inventory_status_row = None
        self._inventory_spinner = None
        self._inventory_groups_box = None
        self._inventory_groups = []
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
        configuration = load_configuration(self.ctx.settings)

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
        threading.Thread(
            target=self._save_worker,
            args=(configuration, new_secret, page_token),
            daemon=True,
        ).start()

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
        threading.Thread(
            target=self._test_worker,
            args=(page_token,),
            daemon=True,
        ).start()

    def _test_worker(self, page_token: object) -> None:
        result = run_connection_test(
            self.ctx.settings,
            self.ctx.secrets,
            self._client_factory,
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
        threading.Thread(
            target=self._refresh_worker,
            args=(page_token,),
            daemon=True,
        ).start()

    def _refresh_worker(self, page_token: object) -> None:
        result = run_inventory_refresh(
            self.ctx.settings,
            self.ctx.secrets,
            self._client_factory,
        )
        self.ctx.run_on_ui_thread(self._finish_refresh, result, page_token)

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

    def _render_inventory(self, inventory: ProxmoxInventory) -> None:
        self._clear_inventory_groups()
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
                group.add(row)
            self._inventory_groups_box.append(group)
            self._inventory_groups.append(group)

    def _clear_inventory_groups(self) -> None:
        for group in self._inventory_groups:
            self._inventory_groups_box.remove(group)
        self._inventory_groups.clear()

    def _set_busy(self, busy: bool) -> None:
        self._operation_in_progress = busy
        self._save_button.set_sensitive(not busy)
        self._test_button.set_sensitive(not busy)
        self._refresh_button.set_sensitive(not busy)

    def _set_status(self, message: str, css_class: str) -> None:
        for current_class in ("dim-label", "success", "error"):
            self._status_label.remove_css_class(current_class)
        self._status_label.set_label(message)
        self._status_label.add_css_class(css_class)
