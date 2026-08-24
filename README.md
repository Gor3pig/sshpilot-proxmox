# Proxmox VE integration for SSH Pilot

This project is a Proxmox VE integration plugin for SSH Pilot. It is currently
under development and provides local endpoint configuration and an authenticated
HTTPS connection test, plus manual read-only inventory loading.

## Current status

The plugin stores the server URL, API token user, and token ID in SSH Pilot's
per-plugin settings. The API token secret is stored separately through SSH
Pilot's secure secrets backend. Saving this configuration does not connect to or
validate the Proxmox VE server. The separate connection test verifies HTTPS and
API token authentication using the saved configuration. TLS certificate
verification is required.

An optional custom CA certificate bundle can be imported for private Proxmox
deployments. The selected bundle is copied into the plugin's private storage and
added to a TLS context initialized from Python's default trust store; the source
file does not need to remain accessible after import. Without a custom CA, the
normal default trust store is used. Certificate and hostname verification always
remain enabled, and the plugin provides no insecure TLS mode. Under Flatpak, the
one-time source selection uses the platform file chooser and document portal
rather than broad host filesystem access. This behavior still requires runtime
validation on each supported packaging environment, including macOS.

The **Refresh** action loads the Proxmox VE nodes, QEMU virtual machines, and LXC
containers visible to the configured API token and displays their current
status. Non-template guests can be imported as normal SSH Pilot connections by
entering an SSH hostname or IP address; imported connections can then be opened
directly from Inventory. Guest visibility depends on the permissions assigned
to the token in Proxmox VE.

## Planned direction

Guest IP discovery, multiple Proxmox VE endpoints, power actions, and automatic
refresh are not implemented.

## Development and testing

Create and activate a Python virtual environment, then install the test runner
and the SSH Pilot plugin API used by the upstream UI template:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install pytest
pip install "sshpilot @ git+https://github.com/mfat/sshpilot" --no-deps
pytest -ra
```

GTK is imported only when the page factory is called, so the unit tests do not
require a graphical environment or instantiate GTK widgets.

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).
