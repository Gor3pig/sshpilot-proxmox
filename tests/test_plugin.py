"""Tests for the minimal Proxmox VE plugin without instantiating GTK."""

import importlib.util
import os

HERE = os.path.dirname(__file__)


def _load():
    spec = importlib.util.spec_from_file_location(
        "proxmox_plugin", os.path.join(HERE, "..", "__init__.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Ctx:
    def __init__(self):
        self.pages = []
        self.ui = self

    def register_page(self, page_id, title, icon, factory):
        self.pages.append((page_id, title, icon, factory))


def test_activate_registers_proxmox_page():
    mod = _load()
    ctx = _Ctx()

    mod.Plugin().activate(ctx)

    assert len(ctx.pages) == 1
    page_id, title, _icon, factory = ctx.pages[0]
    assert page_id == "proxmox"
    assert title == "Proxmox VE"
    assert callable(factory)
