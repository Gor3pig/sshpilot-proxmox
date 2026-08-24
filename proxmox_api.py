"""Minimal authenticated Proxmox VE API client."""

from __future__ import annotations

import json
import re
import socket
import ssl
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

API_PATH = "/api2/json/access/permissions"
CLUSTER_RESOURCES_PATH = "/api2/json/cluster/resources"
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

_CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----"
_CERTIFICATE_END = "-----END CERTIFICATE-----"
_PRIVATE_KEY_MARKER = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
)

_NODE_QUERY = (("type", "node"),)
_GUEST_QUERY = (("type", "vm"),)

_MESSAGES = {
    "success": "Connection and API token authentication succeeded.",
    "invalid_configuration": (
        "Save a complete Proxmox VE configuration before testing."
    ),
    "missing_secret": "No API token secret is stored.",
    "secret_unavailable": (
        "The API token secret could not be read from secure storage."
    ),
    "invalid_url": "Enter a valid HTTPS Proxmox VE server URL.",
    "custom_ca_error": (
        "The configured custom CA certificate is unavailable or invalid."
    ),
    "timeout": "The connection attempt timed out.",
    "certificate_error": "The server certificate could not be verified.",
    "tls_error": "A secure TLS connection could not be established.",
    "connection_error": "Could not connect to the Proxmox VE server.",
    "redirected": (
        "The server redirected the API request. Check the Proxmox VE server URL."
    ),
    "unauthorized": "Authentication was rejected by the server.",
    "forbidden": "The API token is not authorized for this operation.",
    "invalid_response": "The server returned an invalid Proxmox VE response.",
    "unexpected_error": "The connection test failed.",
}

_INVENTORY_MESSAGES = {
    **_MESSAGES,
    "success": "Inventory loaded.",
    "invalid_configuration": "The Proxmox VE configuration is invalid.",
    "missing_secret": "No API token secret is available.",
    "unexpected_error": "The inventory could not be loaded.",
}


@dataclass(frozen=True)
class ConnectionTestResult:
    """Secret-free outcome returned to the UI layer."""

    category: str
    message: str
    http_status: int | None = None

    @property
    def success(self) -> bool:
        return self.category == "success"


@dataclass(frozen=True)
class ProxmoxNode:
    """Minimal normalized Proxmox VE node."""

    name: str
    status: str


@dataclass(frozen=True)
class ProxmoxGuest:
    """Minimal normalized QEMU or LXC guest."""

    guest_type: str
    vmid: int
    name: str
    node: str
    status: str
    template: bool


@dataclass(frozen=True)
class ProxmoxInventory:
    """Immutable node and guest inventory."""

    nodes: tuple[ProxmoxNode, ...]
    guests: tuple[ProxmoxGuest, ...]


@dataclass(frozen=True)
class InventoryResult:
    """Secret-free inventory outcome returned to a caller."""

    category: str
    message: str
    inventory: ProxmoxInventory | None = None
    http_status: int | None = None

    @property
    def success(self) -> bool:
        return self.category == "success"


@dataclass(frozen=True)
class ProxmoxConfiguration:
    """Validated non-sensitive values used for one API request."""

    server_url: str
    token_user: str
    token_id: str

    @property
    def endpoint_url(self) -> str:
        return self.server_url + API_PATH


class ProxmoxValidationError(ValueError):
    """Internal validation failure classified without retaining input values."""

    def __init__(self, category: str):
        self.category = category
        super().__init__(category)


def connection_test_result(
    category: str,
    *,
    http_status: int | None = None,
) -> ConnectionTestResult:
    """Build a fixed, secret-free result for a known outcome category."""
    if category == "http_error":
        message = f"The server returned HTTP {int(http_status or 0)}."
    else:
        message = _MESSAGES.get(category, _MESSAGES["unexpected_error"])
    return ConnectionTestResult(category, message, http_status)


def _inventory_result(
    category: str,
    *,
    inventory: ProxmoxInventory | None = None,
    http_status: int | None = None,
) -> InventoryResult:
    if category == "http_error":
        message = f"The server returned HTTP {int(http_status or 0)}."
    else:
        message = _INVENTORY_MESSAGES.get(
            category,
            _INVENTORY_MESSAGES["unexpected_error"],
        )
    return InventoryResult(category, message, inventory, http_status)


def _contains_control_characters(value: str) -> bool:
    return any(unicodedata.category(character) == "Cc" for character in value)


def normalize_server_url(value: str) -> str:
    """Validate and normalize a Proxmox VE HTTPS server root URL."""
    if not isinstance(value, str) or not value or _contains_control_characters(value):
        raise ProxmoxValidationError("invalid_url")

    candidate = value.strip()
    if not candidate:
        raise ProxmoxValidationError("invalid_url")

    try:
        parsed = urllib.parse.urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ProxmoxValidationError("invalid_url") from exc

    hostname = parsed.hostname
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or any(character.isspace() for character in hostname)
        or _contains_control_characters(hostname)
        or (port is not None and not 1 <= port <= 65535)
        or (port is None and parsed.netloc.endswith(":"))
    ):
        raise ProxmoxValidationError("invalid_url")

    normalized_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        normalized_host = f"{normalized_host}:{port}"
    return f"https://{normalized_host}"


def prepare_configuration(
    server_url: Any,
    token_user: Any,
    token_id: Any,
) -> ProxmoxConfiguration:
    """Validate the saved, non-sensitive configuration before secret access."""
    if not all(isinstance(value, str) for value in (server_url, token_user, token_id)):
        raise ProxmoxValidationError("invalid_configuration")

    normalized_user = token_user.strip()
    normalized_id = token_id.strip()
    if (
        not server_url.strip()
        or not normalized_user
        or not normalized_id
        or _contains_control_characters(token_user)
        or _contains_control_characters(token_id)
    ):
        raise ProxmoxValidationError("invalid_configuration")

    return ProxmoxConfiguration(
        server_url=normalize_server_url(server_url),
        token_user=normalized_user,
        token_id=normalized_id,
    )


def build_authorization_header(
    configuration: ProxmoxConfiguration,
    secret: str,
) -> str:
    """Build the Proxmox token header value for immediate request use."""
    if not isinstance(secret, str) or not secret:
        raise ProxmoxValidationError("missing_secret")
    if _contains_control_characters(secret):
        raise ProxmoxValidationError("invalid_configuration")
    return (
        f"PVEAPIToken={configuration.token_user}!{configuration.token_id}={secret}"
    )


def _normalize_custom_ca_pem(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            pem = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProxmoxValidationError("invalid_custom_ca") from exc
    elif isinstance(value, str):
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ProxmoxValidationError("invalid_custom_ca") from exc
        pem = value
    else:
        raise ProxmoxValidationError("invalid_custom_ca")

    if not pem.strip():
        raise ProxmoxValidationError("invalid_custom_ca")
    if _PRIVATE_KEY_MARKER.search(pem):
        raise ProxmoxValidationError("custom_ca_private_key")
    if (
        _CERTIFICATE_BEGIN not in pem
        or _CERTIFICATE_END not in pem
        or pem.count(_CERTIFICATE_BEGIN) != pem.count(_CERTIFICATE_END)
    ):
        raise ProxmoxValidationError("invalid_custom_ca")
    return pem


def _load_custom_ca(context: ssl.SSLContext, value: Any) -> str:
    pem = _normalize_custom_ca_pem(value)
    try:
        context.load_verify_locations(cadata=pem)
    except (OSError, ValueError, ssl.SSLError) as exc:
        raise ProxmoxValidationError("invalid_custom_ca") from exc
    return pem


def validate_custom_ca_pem(value: Any) -> str:
    """Return an ASCII CA bundle after structural and OpenSSL validation."""
    try:
        context = ssl.create_default_context()
    except Exception as exc:
        raise ProxmoxValidationError("invalid_custom_ca") from exc
    return _load_custom_ca(context, value)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every redirect before urllib can construct a second request."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def _build_opener(custom_ca_pem: str | None = None):
    context = ssl.create_default_context()
    if custom_ca_pem is not None:
        _load_custom_ca(context, custom_ca_pem)
    return urllib.request.build_opener(
        _NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )


def _http_result(status: int) -> ConnectionTestResult:
    if status in REDIRECT_STATUSES:
        return connection_test_result("redirected", http_status=status)
    if status == 401:
        return connection_test_result("unauthorized", http_status=status)
    if status == 403:
        return connection_test_result("forbidden", http_status=status)
    return connection_test_result("http_error", http_status=status)


def _transport_result(error: BaseException) -> ConnectionTestResult:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return connection_test_result("timeout")
    if isinstance(reason, ssl.SSLCertVerificationError):
        return connection_test_result("certificate_error")
    if isinstance(reason, ssl.SSLError):
        return connection_test_result("tls_error")
    return connection_test_result("connection_error")


def _build_api_url(
    configuration: ProxmoxConfiguration,
    path: str,
    query: tuple[tuple[str, str], ...],
) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/api2/json/")
        or _contains_control_characters(path)
    ):
        raise ProxmoxValidationError("unexpected_error")

    parsed_path = urllib.parse.urlsplit(path)
    if (
        parsed_path.scheme
        or parsed_path.netloc
        or parsed_path.query
        or parsed_path.fragment
        or parsed_path.path != path
    ):
        raise ProxmoxValidationError("unexpected_error")

    url = configuration.server_url + path
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"

    server = urllib.parse.urlsplit(configuration.server_url)
    target = urllib.parse.urlsplit(url)
    server_origin = (server.scheme.lower(), server.hostname, server.port or 443)
    target_origin = (target.scheme.lower(), target.hostname, target.port or 443)
    if target_origin != server_origin:
        raise ProxmoxValidationError("unexpected_error")
    return url


def _normalize_optional_text(value: Any, default: str) -> str:
    return (
        value
        if (
            isinstance(value, str)
            and value.strip()
            and not _contains_control_characters(value)
        )
        else default
    )


def _is_valid_node_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not _contains_control_characters(value)
    )


def _parse_nodes(data: Any) -> tuple[ProxmoxNode, ...]:
    if not isinstance(data, list):
        raise ProxmoxValidationError("invalid_response")

    nodes: dict[str, ProxmoxNode] = {}
    for entry in data:
        if not isinstance(entry, dict) or entry.get("type") != "node":
            raise ProxmoxValidationError("invalid_response")
        name = entry.get("node")
        if not _is_valid_node_name(name):
            raise ProxmoxValidationError("invalid_response")
        node = ProxmoxNode(
            name=name,
            status=_normalize_optional_text(entry.get("status"), "unknown"),
        )
        previous = nodes.get(name)
        if previous is not None and previous != node:
            raise ProxmoxValidationError("invalid_response")
        nodes[name] = node

    return tuple(sorted(nodes.values(), key=lambda node: node.name))


def _normalize_template(entry: dict[str, Any]) -> bool:
    if "template" not in entry:
        return False
    value = entry["template"]
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise ProxmoxValidationError("invalid_response")


def _parse_guests(data: Any) -> tuple[ProxmoxGuest, ...]:
    if not isinstance(data, list):
        raise ProxmoxValidationError("invalid_response")

    guests: dict[int, ProxmoxGuest] = {}
    for entry in data:
        if not isinstance(entry, dict):
            raise ProxmoxValidationError("invalid_response")
        guest_type = entry.get("type")
        if guest_type not in ("qemu", "lxc"):
            raise ProxmoxValidationError("invalid_response")
        vmid = entry.get("vmid")
        if (
            not isinstance(vmid, int)
            or isinstance(vmid, bool)
            or not 100 <= vmid <= 999_999_999
        ):
            raise ProxmoxValidationError("invalid_response")
        node = entry.get("node")
        if not _is_valid_node_name(node):
            raise ProxmoxValidationError("invalid_response")

        guest = ProxmoxGuest(
            guest_type=guest_type,
            vmid=vmid,
            name=_normalize_optional_text(entry.get("name"), ""),
            node=node,
            status=_normalize_optional_text(entry.get("status"), "unknown"),
            template=_normalize_template(entry),
        )
        previous = guests.get(vmid)
        if previous is not None and previous != guest:
            raise ProxmoxValidationError("invalid_response")
        guests[vmid] = guest

    return tuple(
        sorted(
            guests.values(),
            key=lambda guest: (guest.node, guest.vmid, guest.guest_type),
        )
    )


class ProxmoxClient:
    """Minimal Proxmox client with strict TLS and no redirects."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        opener=None,
        custom_ca_pem: str | None = None,
    ):
        if opener is not None and custom_ca_pem is not None:
            raise ValueError("opener and custom_ca_pem are mutually exclusive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._timeout = timeout
        self._opener = (
            opener
            if opener is not None
            else _build_opener(custom_ca_pem=custom_ca_pem)
        )

    def _get_json(
        self,
        configuration: ProxmoxConfiguration,
        secret: str,
        path: str,
        query: tuple[tuple[str, str], ...] = (),
    ) -> tuple[ConnectionTestResult, Any]:
        authorization = None
        headers = None
        request = None
        raw = None
        try:
            url = _build_api_url(configuration, path, query)
            authorization = build_authorization_header(configuration, secret)
            headers = {
                "Authorization": authorization,
                "Accept": "application/json",
            }
            request = urllib.request.Request(url, method="GET", headers=headers)
            with self._opener.open(request, timeout=self._timeout) as response:
                status = int(
                    getattr(response, "status", None)
                    or response.getcode()
                    or 0
                )
                if not 200 <= status < 300:
                    return _http_result(status), None
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    return connection_test_result("invalid_response"), None
        except ProxmoxValidationError as exc:
            return connection_test_result(exc.category), None
        except urllib.error.HTTPError as exc:
            try:
                return _http_result(int(exc.code or 0)), None
            finally:
                exc.close()
        except urllib.error.URLError as exc:
            return _transport_result(exc), None
        except (TimeoutError, socket.timeout) as exc:
            return _transport_result(exc), None
        except (ssl.SSLCertVerificationError, ssl.SSLError) as exc:
            return _transport_result(exc), None
        except OSError as exc:
            return _transport_result(exc), None
        except ValueError:
            return connection_test_result("invalid_url"), None
        except Exception:
            return connection_test_result("unexpected_error"), None
        finally:
            authorization = None
            headers = None
            request = None
            secret = ""

        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return connection_test_result("invalid_response"), None
        finally:
            raw = None
        if not isinstance(payload, dict) or "data" not in payload:
            return connection_test_result("invalid_response"), None
        return connection_test_result("success"), payload["data"]

    def test_connection(
        self,
        configuration: ProxmoxConfiguration,
        secret: str,
    ) -> ConnectionTestResult:
        """Authenticate with one read-only request and validate its JSON shape."""
        result, _data = self._get_json(configuration, secret, API_PATH)
        return result

    def get_inventory(
        self,
        configuration: ProxmoxConfiguration,
        secret: str,
    ) -> InventoryResult:
        """Load a normalized cluster inventory with two read-only requests."""
        try:
            result, node_data = self._get_json(
                configuration,
                secret,
                CLUSTER_RESOURCES_PATH,
                _NODE_QUERY,
            )
            if not result.success:
                return _inventory_result(
                    result.category,
                    http_status=result.http_status,
                )
            nodes = _parse_nodes(node_data)

            result, guest_data = self._get_json(
                configuration,
                secret,
                CLUSTER_RESOURCES_PATH,
                _GUEST_QUERY,
            )
            if not result.success:
                return _inventory_result(
                    result.category,
                    http_status=result.http_status,
                )
            guests = _parse_guests(guest_data)

            nodes_by_name = {node.name: node for node in nodes}
            for guest in guests:
                nodes_by_name.setdefault(
                    guest.node,
                    ProxmoxNode(name=guest.node, status="unknown"),
                )
            inventory = ProxmoxInventory(
                nodes=tuple(
                    sorted(nodes_by_name.values(), key=lambda node: node.name)
                ),
                guests=guests,
            )
            return _inventory_result("success", inventory=inventory)
        except ProxmoxValidationError as exc:
            return _inventory_result(exc.category)
        except Exception:
            return _inventory_result("unexpected_error")
        finally:
            secret = ""
