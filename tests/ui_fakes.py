"""Headless GTK and Adwaita fakes for plugin tests."""

import sys
import types


class _Button:
    def __init__(self):
        self.sensitive_calls = []

    def set_sensitive(self, sensitive):
        self.sensitive_calls.append(sensitive)


class _GtkBox:
    def __init__(self, *, orientation, spacing):
        self.orientation = orientation
        self.spacing = spacing
        self.children = []
        self.halign = None
        self.margins = {}

    def append(self, child):
        self.children.append(child)

    def remove(self, child):
        self.children.remove(child)

    def set_halign(self, align):
        self.halign = align

    def set_margin_top(self, value):
        self.margins["top"] = value

    def set_margin_bottom(self, value):
        self.margins["bottom"] = value

    def set_margin_start(self, value):
        self.margins["start"] = value

    def set_margin_end(self, value):
        self.margins["end"] = value


class _GtkLabel:
    def __init__(self, *, label="", xalign=None):
        self.label = label
        self.xalign = xalign
        self.css_classes = set()
        self.wrap = False
        self.valign = None

    def add_css_class(self, css_class):
        self.css_classes.add(css_class)

    def remove_css_class(self, css_class):
        self.css_classes.discard(css_class)

    def set_label(self, label):
        self.label = label

    def set_wrap(self, wrap):
        self.wrap = wrap

    def set_valign(self, align):
        self.valign = align


class _GtkButton(_Button):
    def __init__(self, *, label):
        super().__init__()
        self.label = label
        self.css_classes = set()
        self.connections = []

    def add_css_class(self, css_class):
        self.css_classes.add(css_class)

    def connect(self, signal, callback):
        self.connections.append((signal, callback))

    def set_label(self, label):
        self.label = label

    def get_label(self):
        return self.label


class _GtkSpinner:
    def __init__(self):
        self.active = False
        self.visible = True
        self.start_calls = 0
        self.stop_calls = 0

    def set_visible(self, visible):
        self.visible = visible

    def start(self):
        self.active = True
        self.start_calls += 1

    def stop(self):
        self.active = False
        self.stop_calls += 1


class _GtkScrolledWindow:
    def __init__(self):
        self.child = None

    def set_child(self, child):
        self.child = child


class _AdwClamp:
    def __init__(self, *, maximum_size):
        self.maximum_size = maximum_size
        self.child = None

    def set_child(self, child):
        self.child = child


class _AdwPreferencesGroup:
    def __init__(self, *, title, description=None):
        self.title = title
        self.description = description
        self.rows = []
        self.header_suffix = None

    def add(self, row):
        self.rows.append(row)

    def set_header_suffix(self, widget):
        self.header_suffix = widget


class _AdwEntryRow:
    def __init__(self, *, title):
        self.title = title
        self.text = ""

    def set_text(self, text):
        self.text = text

    def get_text(self):
        return self.text


class _AdwPasswordEntryRow(_AdwEntryRow):
    def __init__(self, *, title):
        super().__init__(title=title)
        self.show_apply_button = None
        self.show_peek_icon = None

    def set_show_apply_button(self, visible):
        self.show_apply_button = visible

    def set_show_peek_icon(self, visible):
        self.show_peek_icon = visible


class _AdwActionRow:
    def __init__(self, *, title, subtitle=None):
        self.title = title
        self.subtitle = subtitle
        self.prefixes = []
        self.suffixes = []

    def add_prefix(self, widget):
        self.prefixes.append(widget)

    def add_suffix(self, widget):
        self.suffixes.append(widget)

    def set_title(self, title):
        self.title = title

    def set_subtitle(self, subtitle):
        self.subtitle = subtitle


def _install_fake_gi(monkeypatch):
    gtk = types.SimpleNamespace(
        Align=types.SimpleNamespace(END="end", CENTER="center"),
        Orientation=types.SimpleNamespace(
            VERTICAL="vertical",
            HORIZONTAL="horizontal",
        ),
        Box=_GtkBox,
        Button=_GtkButton,
        Label=_GtkLabel,
        ScrolledWindow=_GtkScrolledWindow,
        Spinner=_GtkSpinner,
    )
    adw = types.SimpleNamespace(
        ActionRow=_AdwActionRow,
        Clamp=_AdwClamp,
        EntryRow=_AdwEntryRow,
        PasswordEntryRow=_AdwPasswordEntryRow,
        PreferencesGroup=_AdwPreferencesGroup,
    )
    gi = types.ModuleType("gi")
    repository = types.ModuleType("gi.repository")
    gi.require_version = lambda _namespace, _version: None
    gi.repository = repository
    repository.Adw = adw
    repository.Gtk = gtk
    monkeypatch.setitem(sys.modules, "gi", gi)
    monkeypatch.setitem(sys.modules, "gi.repository", repository)
    return adw, gtk
