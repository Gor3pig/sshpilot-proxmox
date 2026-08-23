# Proxmox VE integration for SSH Pilot

This project is a Proxmox VE integration plugin for SSH Pilot. It is currently
under development; the initial version only registers a minimal plugin page and
does not communicate with the Proxmox VE API yet.

## Planned direction

The integration is intended to:

- browse Proxmox VE nodes;
- browse QEMU virtual machines and LXC containers;
- display guest status;
- add guests as SSH Pilot connections;
- open existing SSH Pilot connections.

These Proxmox VE features are planned and are not implemented yet.

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
