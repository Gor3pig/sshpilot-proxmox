"""Proxmox VE integration plugin for SSH Pilot."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from sshpilot.plugins.api import PluginContext, SshPilotPlugin

CONFIGURATION_KEY = "configuration"
SECRET_KEY = "api_token_secret"
CONFIGURATION_FIELDS = ("server_url", "token_user", "token_id")


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


class Plugin(SshPilotPlugin):
    def activate(self, ctx: PluginContext) -> None:
        self.ctx = ctx
        self._server_url_row = None
        self._token_user_row = None
        self._token_id_row = None
        self._secret_row = None
        self._save_button = None
        self._status_label = None
        self._page_token = None
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

        self._page_token = object()
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

        self._save_button = Gtk.Button(label="Save")
        self._save_button.add_css_class("suggested-action")
        self._save_button.set_halign(Gtk.Align.END)
        self._save_button.connect("clicked", self._on_save_clicked)
        content.append(self._save_button)

        self._status_label = Gtk.Label(xalign=0)
        self._status_label.set_wrap(True)
        content.append(self._status_label)

        clamp = Adw.Clamp(maximum_size=640)
        clamp.set_child(content)
        scroller = Gtk.ScrolledWindow()
        scroller.set_child(clamp)
        return scroller

    def _on_save_clicked(self, _button) -> None:
        configuration = build_configuration(
            self._server_url_row.get_text(),
            self._token_user_row.get_text(),
            self._token_id_row.get_text(),
        )
        new_secret = self._secret_row.get_text()
        page_token = self._page_token
        self._save_button.set_sensitive(False)
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

    def _finish_save(self, result: SaveResult, page_token: object) -> None:
        if page_token is not self._page_token:
            return
        if result.clear_secret:
            self._secret_row.set_text("")
        self._set_status(result.message, "success" if result.success else "error")
        self._save_button.set_sensitive(True)

    def _set_status(self, message: str, css_class: str) -> None:
        for current_class in ("dim-label", "success", "error"):
            self._status_label.remove_css_class(current_class)
        self._status_label.set_label(message)
        self._status_label.add_css_class(css_class)
