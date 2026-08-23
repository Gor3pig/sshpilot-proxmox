"""Proxmox VE integration plugin for SSH Pilot."""

from __future__ import annotations

from sshpilot.plugins.api import PluginContext, SshPilotPlugin


class Plugin(SshPilotPlugin):
    def activate(self, ctx: PluginContext) -> None:
        ctx.ui.register_page(
            "proxmox",
            "Proxmox VE",
            "network-server-symbolic",
            self._build_page,
        )

    def _build_page(self):
        import gi

        gi.require_version("Gtk", "4.0")
        from gi.repository import Gtk

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        for set_margin in (
            box.set_margin_top,
            box.set_margin_bottom,
            box.set_margin_start,
            box.set_margin_end,
        ):
            set_margin(18)

        title = Gtk.Label(label="Proxmox VE", xalign=0)
        title.add_css_class("title-2")
        box.append(title)

        message = Gtk.Label(
            label="The Proxmox VE integration is currently under development.",
            xalign=0,
        )
        box.append(message)
        return box
