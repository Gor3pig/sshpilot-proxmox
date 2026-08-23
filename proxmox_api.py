"""Minimal authenticated Proxmox VE API client."""

from __future__ import annotations

import json
import socket
import ssl
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

API_PATH = "/api2/json/access/permissions"
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

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


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every redirect before urllib can construct a second request."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def _build_opener():
    return urllib.request.build_opener(_NoRedirectHandler())


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


class ProxmoxClient:
    """One-request Proxmox client with strict TLS and no redirects."""

    def __init__(self, *, timeout: float = DEFAULT_TIMEOUT_SECONDS, opener=None):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._timeout = timeout
        self._opener = opener if opener is not None else _build_opener()

    def test_connection(
        self,
        configuration: ProxmoxConfiguration,
        secret: str,
    ) -> ConnectionTestResult:
        """Authenticate with one read-only request and validate its JSON shape."""
        authorization = None
        headers = None
        request = None
        try:
            authorization = build_authorization_header(configuration, secret)
            headers = {
                "Authorization": authorization,
                "Accept": "application/json",
            }
            request = urllib.request.Request(
                configuration.endpoint_url,
                method="GET",
                headers=headers,
            )
            with self._opener.open(request, timeout=self._timeout) as response:
                status = int(
                    getattr(response, "status", None)
                    or response.getcode()
                    or 0
                )
                if not 200 <= status < 300:
                    return _http_result(status)
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    return connection_test_result("invalid_response")
        except ProxmoxValidationError as exc:
            return connection_test_result(exc.category)
        except urllib.error.HTTPError as exc:
            try:
                return _http_result(int(exc.code or 0))
            finally:
                exc.close()
        except urllib.error.URLError as exc:
            return _transport_result(exc)
        except (TimeoutError, socket.timeout) as exc:
            return _transport_result(exc)
        except (ssl.SSLCertVerificationError, ssl.SSLError) as exc:
            return _transport_result(exc)
        except OSError as exc:
            return _transport_result(exc)
        except ValueError:
            return connection_test_result("invalid_url")
        except Exception:
            return connection_test_result("unexpected_error")
        finally:
            authorization = None
            headers = None
            request = None
            secret = ""

        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return connection_test_result("invalid_response")
        if not isinstance(payload, dict) or "data" not in payload:
            return connection_test_result("invalid_response")
        return connection_test_result("success")
