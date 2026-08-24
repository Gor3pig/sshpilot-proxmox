"""Headless tests for the minimal authenticated Proxmox VE client."""

import email.message
import importlib.util
import io
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest


def _load_api_module():
    module_name = "sshpilot_proxmox_api_under_test"
    module_path = Path(__file__).resolve().parents[1] / "proxmox_api.py"
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError("Could not load proxmox_api.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


api = _load_api_module()


class _Response:
    def __init__(self, status=200, body=b'{"data": {}}', headers=None, url=None):
        self.status = status
        self.code = status
        self.msg = "response"
        self._body = body
        self._url = url or "https://pve.example.test/api"
        self.headers = email.message.Message()
        for name, value in (headers or {}).items():
            self.headers[name] = value
        self.closed = False
        self.read_calls = []

    def read(self, size=-1):
        self.read_calls.append(size)
        if size < 0 or len(self._body) <= size:
            return self._body
        return self._body[:size]

    def getcode(self):
        return self.status

    def geturl(self):
        return self._url

    def info(self):
        return self.headers

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
        return False


class _Opener:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class _SequenceOpener:
    def __init__(self, *outcomes):
        self.outcomes = outcomes
        self.calls = []

    def open(self, request, timeout):
        index = len(self.calls)
        self.calls.append((request, timeout))
        if index >= len(self.outcomes):
            raise AssertionError("unexpected HTTP request")
        outcome = self.outcomes[index]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _configuration(server_url="https://pve.example.test:8006/"):
    return api.prepare_configuration(server_url, "automation@pve", "sshpilot")


def _http_error(status, *, location=None, body=b""):
    headers = email.message.Message()
    if location is not None:
        headers["Location"] = location
    return urllib.error.HTTPError(
        "https://pve.example.test:8006" + api.API_PATH,
        status,
        "response",
        headers,
        io.BytesIO(body),
    )


def _json_response(data):
    return _Response(body=json.dumps({"data": data}).encode())


@pytest.mark.parametrize(
    ("value", "normalized"),
    [
        ("https://pve.example.test", "https://pve.example.test"),
        ("https://PVE.EXAMPLE.TEST/", "https://pve.example.test"),
        ("https://pve.example.test:8006/", "https://pve.example.test:8006"),
        ("https://[2001:db8::1]:8006", "https://[2001:db8::1]:8006"),
    ],
)
def test_normalize_server_url_accepts_https_roots(value, normalized):
    assert api.normalize_server_url(value) == normalized


@pytest.mark.parametrize(
    "value",
    [
        "http://pve.example.test:8006",
        "ftp://pve.example.test",
        "https://user@pve.example.test",
        "https://pve.example.test?view=full",
        "https://pve.example.test#fragment",
        "https://pve.example.test/custom/path",
        "https://pve.example.test:\n8006",
        "https://pve.example.test:0",
        "https://pve.example.test:65536",
        "https://pve.example.test:not-a-port",
        "https://pve.example.test:",
        "https://bad host.example.test",
        "",
    ],
)
def test_normalize_server_url_rejects_invalid_roots(value):
    with pytest.raises(api.ProxmoxValidationError) as raised:
        api.normalize_server_url(value)
    assert raised.value.category == "invalid_url"


@pytest.mark.parametrize(
    ("token_user", "token_id"),
    [
        ("user@pve\rInjected", "sshpilot"),
        ("user@pve\n", "sshpilot"),
        ("user@pve", "sshpilot\nInjected"),
        ("user@pve", "sshpilot\x00Injected"),
        ("user@pve", "sshpilot\x00"),
    ],
)
def test_prepare_configuration_rejects_header_control_characters(
    token_user,
    token_id,
):
    with pytest.raises(api.ProxmoxValidationError) as raised:
        api.prepare_configuration(
            "https://pve.example.test:8006",
            token_user,
            token_id,
        )
    assert raised.value.category == "invalid_configuration"


def test_request_uses_exact_endpoint_authorization_accept_and_timeout():
    secret = "token-secret-sentinel"
    opener = _Opener(_Response())
    client = api.ProxmoxClient(timeout=7.5, opener=opener)

    result = client.test_connection(_configuration(), secret)

    assert result.category == "success"
    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.full_url == (
        "https://pve.example.test:8006/api2/json/access/permissions"
    )
    assert request.get_method() == "GET"
    assert request.get_header("Authorization") == (
        "PVEAPIToken=automation@pve!sshpilot=token-secret-sentinel"
    )
    assert request.get_header("Accept") == "application/json"
    assert timeout == 7.5
    assert secret not in repr(result)
    assert secret not in result.message


def test_secret_control_character_prevents_request():
    opener = _Opener(_Response())
    result = api.ProxmoxClient(opener=opener).test_connection(
        _configuration(),
        "secret\nInjected",
    )

    assert result.category == "invalid_configuration"
    assert opener.calls == []


def test_missing_secret_prevents_request():
    opener = _Opener(_Response())
    result = api.ProxmoxClient(opener=opener).test_connection(_configuration(), "")

    assert result.category == "missing_secret"
    assert opener.calls == []


class _FakeSSLContext:
    def __init__(self, load_error=None):
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED
        self.load_error = load_error
        self.loaded_cadata = []

    def load_verify_locations(self, *, cadata):
        self.loaded_cadata.append(cadata)
        if self.load_error is not None:
            raise self.load_error


def test_default_opener_uses_verifying_context_and_refuses_redirects(monkeypatch):
    context = _FakeSSLContext()
    captured = {}

    monkeypatch.setattr(api.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(
        api.urllib.request,
        "HTTPSHandler",
        lambda *, context: ("https", context),
    )

    def capture_opener(*handlers):
        captured["handlers"] = handlers
        return object()

    monkeypatch.setattr(api.urllib.request, "build_opener", capture_opener)

    api._build_opener()

    redirect_handler, https_handler = captured["handlers"]
    assert isinstance(redirect_handler, api._NoRedirectHandler)
    assert https_handler == ("https", context)
    assert context.loaded_cadata == []
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_custom_ca_is_loaded_into_the_same_verifying_context(monkeypatch):
    context = _FakeSSLContext()
    captured = {}
    pem = "-----BEGIN CERTIFICATE-----\npublic-ca\n-----END CERTIFICATE-----\n"

    monkeypatch.setattr(api.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(
        api.urllib.request,
        "HTTPSHandler",
        lambda *, context: ("https", context),
    )
    monkeypatch.setattr(
        api.urllib.request,
        "build_opener",
        lambda *handlers: captured.setdefault("handlers", handlers),
    )

    api.ProxmoxClient(custom_ca_pem=pem)

    assert context.loaded_cadata == [pem]
    assert captured["handlers"][1] == ("https", context)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_injected_opener_is_preserved_without_custom_ca():
    opener = object()

    client = api.ProxmoxClient(opener=opener)

    assert client._opener is opener


def test_injected_opener_and_custom_ca_are_rejected_before_pem_validation():
    with pytest.raises(ValueError) as raised:
        api.ProxmoxClient(
            opener=object(),
            custom_ca_pem="not a certificate",
        )

    assert str(raised.value) == (
        "opener and custom_ca_pem are mutually exclusive"
    )


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b" \n\t",
        "non-ascii-\N{SNOWMAN}",
        "not a certificate",
        "-----BEGIN CERTIFICATE-----\nmissing end",
    ],
)
def test_custom_ca_validation_rejects_empty_non_ascii_or_malformed_input(value):
    with pytest.raises(api.ProxmoxValidationError) as raised:
        api.validate_custom_ca_pem(value)

    assert raised.value.category == "invalid_custom_ca"


@pytest.mark.parametrize(
    "marker",
    [
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ],
)
def test_custom_ca_validation_rejects_private_key_markers_before_openssl(
    marker,
    monkeypatch,
):
    context = _FakeSSLContext()
    monkeypatch.setattr(api.ssl, "create_default_context", lambda: context)
    value = (
        "-----BEGIN CERTIFICATE-----\npublic-ca\n-----END CERTIFICATE-----\n"
        f"-----BEGIN {marker}-----\nprivate-material\n-----END {marker}-----\n"
    )

    with pytest.raises(api.ProxmoxValidationError) as raised:
        api.validate_custom_ca_pem(value)

    assert raised.value.category == "custom_ca_private_key"
    assert context.loaded_cadata == []


def test_custom_ca_openssl_error_is_classified_without_exposing_details(monkeypatch):
    context = _FakeSSLContext(ssl.SSLError("OpenSSL detail sentinel"))
    monkeypatch.setattr(api.ssl, "create_default_context", lambda: context)
    value = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"

    with pytest.raises(api.ProxmoxValidationError) as raised:
        api.validate_custom_ca_pem(value)

    assert raised.value.category == "invalid_custom_ca"
    assert "OpenSSL detail sentinel" not in str(raised.value)


def test_invalid_custom_ca_prevents_opener_construction(monkeypatch):
    context = _FakeSSLContext(ssl.SSLError("invalid CA sentinel"))
    monkeypatch.setattr(api.ssl, "create_default_context", lambda: context)

    def forbidden_build_opener(*_handlers):
        raise AssertionError("opener built after invalid custom CA")

    monkeypatch.setattr(api.urllib.request, "build_opener", forbidden_build_opener)

    with pytest.raises(api.ProxmoxValidationError) as raised:
        api.ProxmoxClient(
            custom_ca_pem=(
                "-----BEGIN CERTIFICATE-----\ninvalid\n"
                "-----END CERTIFICATE-----\n"
            )
        )

    assert raised.value.category == "invalid_custom_ca"


@pytest.mark.parametrize(
    "path",
    [
        "@attacker.example.test/collect",
        "//attacker.example.test/collect",
        "https://attacker.example.test/collect",
        "/api2/json/access/permissions?scope=all",
        "/api2/json/access/permissions#fragment",
        "/api2/json/access/\rpermissions",
        "/api2/json/access/\npermissions",
        "/api2/json/access/\x00permissions",
    ],
)
def test_get_json_rejects_unsafe_internal_paths_before_authorization(
    path,
    monkeypatch,
):
    opener = _SequenceOpener()
    authorization_calls = []
    original_builder = api.build_authorization_header

    def track_authorization(configuration, secret):
        authorization_calls.append((configuration, secret))
        return original_builder(configuration, secret)

    monkeypatch.setattr(api, "build_authorization_header", track_authorization)

    result, data = api.ProxmoxClient(opener=opener)._get_json(
        _configuration(),
        "path-secret-sentinel",
        path,
    )

    assert result.category == "unexpected_error"
    assert result.message == "The connection test failed."
    assert data is None
    assert opener.calls == []
    assert authorization_calls == []
    assert "attacker" not in result.message
    assert path not in result.message


def test_inventory_internal_path_error_is_generic_and_sends_no_request(monkeypatch):
    opener = _SequenceOpener()
    monkeypatch.setattr(
        api,
        "CLUSTER_RESOURCES_PATH",
        "@attacker.example.test/collect",
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.category == "unexpected_error"
    assert result.message == "The inventory could not be loaded."
    assert result.inventory is None
    assert opener.calls == []
    assert "attacker" not in result.message


@pytest.mark.parametrize(
    ("body", "category"),
    [
        (b"not-json", "invalid_response"),
        (b"{}", "invalid_response"),
        (b"[]", "invalid_response"),
        (b'{"data": {}}', "success"),
    ],
)
def test_response_requires_proxmox_json_data(body, category):
    response = _Response(body=body)
    result = api.ProxmoxClient(opener=_Opener(response)).test_connection(
        _configuration(),
        "secret",
    )

    assert result.category == category
    assert response.read_calls == [api.MAX_RESPONSE_BYTES + 1]


class _SizedPayload:
    def __init__(self, size, marker):
        self.size = size
        self.marker = marker

    def __len__(self):
        return self.size

    def __repr__(self):
        return self.marker


def test_response_at_size_limit_is_parsed(monkeypatch):
    payload = _SizedPayload(api.MAX_RESPONSE_BYTES, "limit-payload-sentinel")
    response = _Response(body=payload)
    parsed = []

    def parse_json(raw):
        parsed.append(raw)
        return {"data": {}}

    monkeypatch.setattr(api.json, "loads", parse_json)

    result = api.ProxmoxClient(opener=_Opener(response)).test_connection(
        _configuration(),
        "secret",
    )

    assert result.category == "success"
    assert response.read_calls == [api.MAX_RESPONSE_BYTES + 1]
    assert parsed == [payload]


def test_oversized_response_is_rejected_without_json_parsing(monkeypatch):
    marker = "oversized-response-body-sentinel"
    payload = _SizedPayload(api.MAX_RESPONSE_BYTES + 1, marker)
    response = _Response(body=payload)

    def forbidden_json_parse(_raw):
        raise AssertionError("oversized response was parsed")

    monkeypatch.setattr(api.json, "loads", forbidden_json_parse)

    result = api.ProxmoxClient(opener=_Opener(response)).test_connection(
        _configuration(),
        "secret",
    )

    assert result.category == "invalid_response"
    assert response.read_calls == [api.MAX_RESPONSE_BYTES + 1]
    assert marker not in result.message
    assert marker not in repr(result)


@pytest.mark.parametrize(
    ("status", "category", "message"),
    [
        (401, "unauthorized", "Authentication was rejected by the server."),
        (403, "forbidden", "The API token is not authorized for this operation."),
        (418, "http_error", "The server returned HTTP 418."),
        (500, "http_error", "The server returned HTTP 500."),
    ],
)
def test_http_errors_are_classified_without_response_body(status, category, message):
    secret = "secret-response-sentinel"
    opener = _Opener(_http_error(status, body=secret.encode()))

    result = api.ProxmoxClient(opener=opener).test_connection(
        _configuration(),
        secret,
    )

    assert result.category == category
    assert result.http_status == status
    assert result.message == message
    assert secret not in repr(result)


@pytest.mark.parametrize("status", sorted(api.REDIRECT_STATUSES))
def test_redirect_statuses_are_rejected(status):
    destination = "https://redirected.example.test/collect"
    opener = _Opener(_http_error(status, location=destination))

    result = api.ProxmoxClient(opener=opener).test_connection(
        _configuration(),
        "secret",
    )

    assert result.category == "redirected"
    assert result.http_status == status
    assert destination not in result.message
    assert len(opener.calls) == 1


class _CrossOriginRedirectTransport(urllib.request.BaseHandler):
    handler_order = 100

    def __init__(self, status):
        self.status = status
        self.calls = []

    def https_open(self, request):
        self.calls.append(
            (request.full_url, request.get_header("Authorization"))
        )
        if len(self.calls) == 1:
            return _Response(
                status=self.status,
                body=b"",
                headers={"Location": "https://attacker.example.test/collect"},
                url=request.full_url,
            )
        return _Response(url=request.full_url)


class _SecondInventoryRequestRedirectTransport(urllib.request.BaseHandler):
    handler_order = 100

    def __init__(self, status):
        self.status = status
        self.calls = []

    def https_open(self, request):
        self.calls.append(
            (request.full_url, request.get_header("Authorization"))
        )
        if len(self.calls) == 1:
            return _Response(
                body=b'{"data": [{"type": "node", "node": "node-a"}]}',
                url=request.full_url,
            )
        if len(self.calls) == 2:
            return _Response(
                status=self.status,
                body=b"",
                headers={"Location": "https://attacker.example.test/collect"},
                url=request.full_url,
            )
        return _Response(url=request.full_url)


@pytest.mark.parametrize("status", sorted(api.REDIRECT_STATUSES))
def test_cross_origin_redirect_never_creates_second_authenticated_request(status):
    transport = _CrossOriginRedirectTransport(status)
    opener = urllib.request.build_opener(api._NoRedirectHandler(), transport)
    secret = "redirect-secret-sentinel"

    result = api.ProxmoxClient(opener=opener).test_connection(
        _configuration(),
        secret,
    )

    assert result.category == "redirected"
    assert transport.calls == [
        (
            "https://pve.example.test:8006/api2/json/access/permissions",
            "PVEAPIToken=automation@pve!sshpilot=redirect-secret-sentinel",
        )
    ]
    assert all("attacker.example.test" not in url for url, _header in transport.calls)
    assert secret not in repr(result)


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("timed out"),
        urllib.error.URLError(TimeoutError("timed out")),
    ],
)
def test_timeout_is_classified_for_direct_and_wrapped_errors(error):
    result = api.ProxmoxClient(opener=_Opener(error)).test_connection(
        _configuration(),
        "secret",
    )

    assert result.category == "timeout"
    assert result.message == "The connection attempt timed out."


def test_dns_or_connection_error_is_generic():
    error = urllib.error.URLError(socket.gaierror(-2, "name lookup failed"))

    result = api.ProxmoxClient(opener=_Opener(error)).test_connection(
        _configuration(),
        "secret",
    )

    assert result.category == "connection_error"
    assert "name lookup failed" not in result.message


@pytest.mark.parametrize(
    "error",
    [
        ssl.SSLCertVerificationError(1, "certificate detail sentinel"),
        urllib.error.URLError(
            ssl.SSLCertVerificationError(1, "certificate detail sentinel")
        ),
    ],
)
def test_certificate_verification_errors_are_specific_and_sanitized(error):
    secret = "certificate-secret-sentinel"

    result = api.ProxmoxClient(opener=_Opener(error)).test_connection(
        _configuration(),
        secret,
    )

    assert result.category == "certificate_error"
    assert result.message == "The server certificate could not be verified."
    assert "certificate detail sentinel" not in repr(result)
    assert "pve.example.test" not in repr(result)
    assert "Authorization" not in repr(result)
    assert secret not in repr(result)


@pytest.mark.parametrize(
    "error",
    [
        ssl.SSLError(1, "TLS protocol detail sentinel"),
        urllib.error.URLError(ssl.SSLError(1, "TLS protocol detail sentinel")),
    ],
)
def test_other_tls_errors_are_generic_and_sanitized(error):
    secret = "tls-secret-sentinel"

    result = api.ProxmoxClient(opener=_Opener(error)).test_connection(
        _configuration(),
        secret,
    )

    assert result.category == "tls_error"
    assert result.message == "A secure TLS connection could not be established."
    assert "TLS protocol detail sentinel" not in repr(result)
    assert "pve.example.test" not in repr(result)
    assert "Authorization" not in repr(result)
    assert secret not in repr(result)


def test_unexpected_exception_is_generic_and_secret_free():
    secret = "unexpected-secret-sentinel"
    result = api.ProxmoxClient(
        opener=_Opener(RuntimeError(f"backend exposed {secret}"))
    ).test_connection(_configuration(), secret)

    assert result.category == "unexpected_error"
    assert result.message == "The connection test failed."
    assert secret not in repr(result)


def test_client_module_has_no_graphical_imports():
    assert "gi" not in api.__dict__
    assert "Gtk" not in api.__dict__
    assert "Adw" not in api.__dict__


def test_inventory_models_are_frozen_dataclasses():
    for model in (
        api.ProxmoxNode,
        api.ProxmoxGuest,
        api.ProxmoxInventory,
        api.InventoryResult,
    ):
        assert model.__dataclass_params__.frozen is True


def test_inventory_uses_exact_requests_headers_timeout_and_order():
    secret = "inventory-secret-sentinel"
    node_response = _json_response(
        [
            {"type": "node", "node": "node-b", "status": "offline"},
            {"type": "node", "node": "node-a", "status": "online"},
        ]
    )
    guest_response = _json_response(
        [
            {
                "type": "qemu",
                "vmid": 100,
                "name": "example-vm",
                "node": "node-a",
                "status": "running",
                "template": False,
            }
        ]
    )
    opener = _SequenceOpener(node_response, guest_response)

    result = api.ProxmoxClient(timeout=7.5, opener=opener).get_inventory(
        _configuration(),
        secret,
    )

    assert result.success
    assert result.message == "Inventory loaded."
    assert len(opener.calls) == 2
    assert [request.full_url for request, _timeout in opener.calls] == [
        "https://pve.example.test:8006/api2/json/cluster/resources?type=node",
        "https://pve.example.test:8006/api2/json/cluster/resources?type=vm",
    ]
    for request, timeout in opener.calls:
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") == (
            "PVEAPIToken=automation@pve!sshpilot=inventory-secret-sentinel"
        )
        assert request.get_header("Accept") == "application/json"
        assert timeout == 7.5
    assert node_response.read_calls == [api.MAX_RESPONSE_BYTES + 1]
    assert guest_response.read_calls == [api.MAX_RESPONSE_BYTES + 1]
    assert secret not in repr(result)


@pytest.mark.parametrize(
    ("secret", "category"),
    [("", "missing_secret"), ("secret\nInjected", "invalid_configuration")],
)
def test_inventory_rejects_missing_or_invalid_secret_without_request(
    secret,
    category,
):
    opener = _SequenceOpener()

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        secret,
    )

    assert result.category == category
    assert result.inventory is None
    assert opener.calls == []


def test_inventory_normalizes_and_sorts_nodes():
    opener = _SequenceOpener(
        _json_response(
            [
                {"type": "node", "node": "node-c"},
                {"type": "node", "node": "node-a", "status": "online"},
                {"type": "node", "node": "node-b", "status": "offline"},
                {"type": "node", "node": "node-a", "status": "online"},
            ]
        ),
        _json_response([]),
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.inventory == api.ProxmoxInventory(
        nodes=(
            api.ProxmoxNode("node-a", "online"),
            api.ProxmoxNode("node-b", "offline"),
            api.ProxmoxNode("node-c", "unknown"),
        ),
        guests=(),
    )


@pytest.mark.parametrize(
    "node_data",
    [
        {},
        [{}],
        [{"type": "qemu", "node": "node-a"}],
        [{"type": "node"}],
        [{"type": "node", "node": ""}],
        [{"type": "node", "node": "   "}],
        [{"type": "node", "node": " node-a"}],
        [{"type": "node", "node": "node-a "}],
        [{"type": "node", "node": " node-a "}],
        [{"type": "node", "node": "node-a\nspoofed"}],
        [{"type": "node", "node": "node-a\rspoofed"}],
        [{"type": "node", "node": "node-a\x00spoofed"}],
        [{"type": "node", "node": 42}],
        [
            {"type": "node", "node": "node-a", "status": "online"},
            {"type": "node", "node": "node-a", "status": "offline"},
        ],
    ],
)
def test_inventory_rejects_malformed_or_conflicting_nodes_before_guest_request(
    node_data,
):
    opener = _SequenceOpener(_json_response(node_data))

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.category == "invalid_response"
    assert result.inventory is None
    assert len(opener.calls) == 1


@pytest.mark.parametrize(
    "name",
    ["guest\rspoofed", "guest\nspoofed", "guest\x00spoofed"],
)
def test_inventory_replaces_guest_names_with_control_characters(name):
    opener = _SequenceOpener(
        _json_response([]),
        _json_response(
            [{"type": "qemu", "vmid": 100, "node": "node-a", "name": name}]
        ),
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.inventory.guests[0].name == ""


@pytest.mark.parametrize(
    "status",
    ["online\rspoofed", "online\nspoofed", "online\x00spoofed"],
)
def test_inventory_replaces_statuses_with_control_characters(status):
    node_result = api.ProxmoxClient(
        opener=_SequenceOpener(
            _json_response(
                [{"type": "node", "node": "node-a", "status": status}]
            ),
            _json_response([]),
        )
    ).get_inventory(_configuration(), "secret")
    guest_result = api.ProxmoxClient(
        opener=_SequenceOpener(
            _json_response([]),
            _json_response(
                [
                    {
                        "type": "lxc",
                        "vmid": 100,
                        "node": "node-a",
                        "status": status,
                    }
                ]
            ),
        )
    ).get_inventory(_configuration(), "secret")

    assert node_result.inventory.nodes[0].status == "unknown"
    assert guest_result.inventory.guests[0].status == "unknown"


def test_inventory_normalizes_and_sorts_qemu_and_lxc_guests():
    opener = _SequenceOpener(
        _json_response(
            [
                {"type": "node", "node": "node-b", "status": "online"},
                {"type": "node", "node": "node-a", "status": "online"},
            ]
        ),
        _json_response(
            [
                {
                    "type": "lxc",
                    "vmid": 201,
                    "node": "node-b",
                    "status": "stopped",
                },
                {
                    "type": "qemu",
                    "vmid": 102,
                    "name": "example-qemu",
                    "node": "node-a",
                    "status": "running",
                    "template": True,
                },
                {
                    "type": "qemu",
                    "vmid": 101,
                    "name": 42,
                    "node": "node-a",
                    "status": None,
                    "template": 0,
                },
            ]
        ),
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.inventory.guests == (
        api.ProxmoxGuest("qemu", 101, "", "node-a", "unknown", False),
        api.ProxmoxGuest("qemu", 102, "example-qemu", "node-a", "running", True),
        api.ProxmoxGuest("lxc", 201, "", "node-b", "stopped", False),
    )


@pytest.mark.parametrize(
    ("template_value", "expected"),
    [(True, True), (False, False), (1, True), (0, False)],
)
def test_inventory_accepts_proxmox_template_representations(
    template_value,
    expected,
):
    guest = {
        "type": "qemu",
        "vmid": 100,
        "node": "node-a",
        "template": template_value,
    }
    opener = _SequenceOpener(
        _json_response([]),
        _json_response([guest]),
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.inventory.guests[0].template is expected


@pytest.mark.parametrize("template_value", [None, "1", 2, [], {}])
def test_inventory_rejects_invalid_template_representations(template_value):
    guest = {
        "type": "qemu",
        "vmid": 100,
        "node": "node-a",
        "template": template_value,
    }
    opener = _SequenceOpener(
        _json_response([]),
        _json_response([guest]),
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.category == "invalid_response"
    assert result.inventory is None


@pytest.mark.parametrize("vmid", [True, 99, 1_000_000_000, "100"])
def test_inventory_rejects_invalid_vmids(vmid):
    opener = _SequenceOpener(
        _json_response([]),
        _json_response([{"type": "qemu", "vmid": vmid, "node": "node-a"}]),
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.category == "invalid_response"
    assert result.inventory is None


@pytest.mark.parametrize(
    "guest",
    [
        {},
        {"type": "openvz", "vmid": 100, "node": "node-a"},
        {"type": "qemu", "vmid": 100},
        {"type": "qemu", "vmid": 100, "node": ""},
        {"type": "qemu", "vmid": 100, "node": "   "},
        {"type": "qemu", "vmid": 100, "node": " node-a"},
        {"type": "qemu", "vmid": 100, "node": "node-a "},
        {"type": "qemu", "vmid": 100, "node": " node-a "},
        {"type": "qemu", "vmid": 100, "node": "node-a\nspoofed"},
        {"type": "qemu", "vmid": 100, "node": "node-a\rspoofed"},
        {"type": "qemu", "vmid": 100, "node": "node-a\x00spoofed"},
        {"type": "lxc", "vmid": 100, "node": 42},
    ],
)
def test_inventory_rejects_invalid_guest_type_or_node(guest):
    opener = _SequenceOpener(
        _json_response([]),
        _json_response([guest]),
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.category == "invalid_response"
    assert result.inventory is None


def test_inventory_deduplicates_identical_guests_and_rejects_conflicts():
    guest = {
        "type": "qemu",
        "vmid": 100,
        "name": "example-vm",
        "node": "node-a",
        "status": "running",
    }
    identical_result = api.ProxmoxClient(
        opener=_SequenceOpener(
            _json_response([]),
            _json_response([guest, dict(guest)]),
        )
    ).get_inventory(_configuration(), "secret")

    conflicting_result = api.ProxmoxClient(
        opener=_SequenceOpener(
            _json_response([]),
            _json_response([guest, {**guest, "node": "node-b"}]),
        )
    ).get_inventory(_configuration(), "secret")

    assert len(identical_result.inventory.guests) == 1
    assert conflicting_result.category == "invalid_response"
    assert conflicting_result.inventory is None


def test_inventory_adds_one_unknown_node_for_visible_guests_on_missing_node():
    opener = _SequenceOpener(
        _json_response(
            [{"type": "node", "node": "node-a", "status": "online"}]
        ),
        _json_response(
            [
                {"type": "qemu", "vmid": 100, "node": "node-z"},
                {"type": "lxc", "vmid": 101, "node": "node-z"},
            ]
        ),
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.inventory.nodes == (
        api.ProxmoxNode("node-a", "online"),
        api.ProxmoxNode("node-z", "unknown"),
    )


def test_empty_and_acl_filtered_inventory_responses_are_successful():
    empty_result = api.ProxmoxClient(
        opener=_SequenceOpener(_json_response([]), _json_response([]))
    ).get_inventory(_configuration(), "secret")
    filtered_result = api.ProxmoxClient(
        opener=_SequenceOpener(
            _json_response([{"type": "node", "node": "node-a"}]),
            _json_response(
                [{"type": "lxc", "vmid": 101, "node": "node-a"}]
            ),
        )
    ).get_inventory(_configuration(), "secret")

    assert empty_result.success
    assert empty_result.inventory == api.ProxmoxInventory((), ())
    assert filtered_result.success
    assert [guest.vmid for guest in filtered_result.inventory.guests] == [101]


@pytest.mark.parametrize(
    ("outcome", "category"),
    [
        (_http_error(401), "unauthorized"),
        (_http_error(403), "forbidden"),
        (_http_error(500), "http_error"),
        (
            _http_error(302, location="https://redirected.example.test/collect"),
            "redirected",
        ),
        (ssl.SSLCertVerificationError(1, "certificate detail"), "certificate_error"),
        (ssl.SSLError(1, "TLS detail"), "tls_error"),
        (TimeoutError("timeout detail"), "timeout"),
        (urllib.error.URLError(socket.gaierror(-2, "DNS detail")), "connection_error"),
        (_Response(body=b"not-json"), "invalid_response"),
        (_Response(body=b'{"data": {}}'), "invalid_response"),
        (
            _Response(
                body=_SizedPayload(
                    api.MAX_RESPONSE_BYTES + 1,
                    "oversized-node-response",
                )
            ),
            "invalid_response",
        ),
    ],
)
def test_first_inventory_request_errors_stop_before_guest_request(outcome, category):
    opener = _SequenceOpener(outcome)

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.category == category
    assert result.inventory is None
    assert len(opener.calls) == 1


@pytest.mark.parametrize(
    ("outcome", "category"),
    [
        (_http_error(401), "unauthorized"),
        (_http_error(403), "forbidden"),
        (_http_error(500), "http_error"),
        (
            _http_error(307, location="https://redirected.example.test/collect"),
            "redirected",
        ),
        (ssl.SSLCertVerificationError(1, "certificate detail"), "certificate_error"),
        (ssl.SSLError(1, "TLS detail"), "tls_error"),
        (urllib.error.URLError(TimeoutError("timeout detail")), "timeout"),
        (urllib.error.URLError(OSError("connection detail")), "connection_error"),
        (_Response(body=b"not-json"), "invalid_response"),
        (_Response(body=b'{"data": {}}'), "invalid_response"),
        (
            _Response(
                body=_SizedPayload(
                    api.MAX_RESPONSE_BYTES + 1,
                    "oversized-guest-response",
                )
            ),
            "invalid_response",
        ),
    ],
)
def test_second_inventory_request_errors_publish_no_partial_inventory(
    outcome,
    category,
):
    opener = _SequenceOpener(
        _json_response([{"type": "node", "node": "node-a"}]),
        outcome,
    )

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        "secret",
    )

    assert result.category == category
    assert result.inventory is None
    assert len(opener.calls) == 2


@pytest.mark.parametrize(
    ("status", "category", "message"),
    [
        (401, "unauthorized", "Authentication was rejected by the server."),
        (403, "forbidden", "The API token is not authorized for this operation."),
        (418, "http_error", "The server returned HTTP 418."),
    ],
)
def test_inventory_http_results_preserve_safe_status_and_message(
    status,
    category,
    message,
):
    result = api.ProxmoxClient(
        opener=_SequenceOpener(_http_error(status, body=b"raw body"))
    ).get_inventory(_configuration(), "secret")

    assert result.category == category
    assert result.http_status == status
    assert result.message == message
    assert result.inventory is None
    assert "raw body" not in repr(result)


@pytest.mark.parametrize("status", sorted(api.REDIRECT_STATUSES))
def test_inventory_cross_origin_redirect_never_creates_second_request(status):
    transport = _CrossOriginRedirectTransport(status)
    opener = urllib.request.build_opener(api._NoRedirectHandler(), transport)
    secret = "inventory-redirect-secret-sentinel"

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        secret,
    )

    assert result.category == "redirected"
    assert transport.calls == [
        (
            "https://pve.example.test:8006/api2/json/cluster/resources?type=node",
            "PVEAPIToken=automation@pve!sshpilot=inventory-redirect-secret-sentinel",
        )
    ]
    assert "attacker.example.test" not in repr(transport.calls)
    assert secret not in repr(result)


@pytest.mark.parametrize("status", sorted(api.REDIRECT_STATUSES))
def test_second_inventory_redirect_never_creates_third_request(status):
    transport = _SecondInventoryRequestRedirectTransport(status)
    opener = urllib.request.build_opener(api._NoRedirectHandler(), transport)
    secret = "second-redirect-secret-sentinel"

    result = api.ProxmoxClient(opener=opener).get_inventory(
        _configuration(),
        secret,
    )

    assert result.category == "redirected"
    assert [url for url, _authorization in transport.calls] == [
        "https://pve.example.test:8006/api2/json/cluster/resources?type=node",
        "https://pve.example.test:8006/api2/json/cluster/resources?type=vm",
    ]
    assert all(
        authorization == (
            "PVEAPIToken=automation@pve!sshpilot=second-redirect-secret-sentinel"
        )
        for _url, authorization in transport.calls
    )
    assert "attacker.example.test" not in repr(transport.calls)
    assert secret not in repr(result)


def test_inventory_errors_do_not_expose_secret_body_location_or_exception():
    secret = "inventory-secret-sentinel"
    body_marker = "raw-response-body-sentinel"
    location = "https://redirected.example.test/private-location"
    raw_result = api.ProxmoxClient(
        opener=_SequenceOpener(_Response(body=body_marker.encode()))
    ).get_inventory(_configuration(), secret)
    redirect_result = api.ProxmoxClient(
        opener=_SequenceOpener(_http_error(302, location=location))
    ).get_inventory(_configuration(), secret)
    exception_result = api.ProxmoxClient(
        opener=_SequenceOpener(RuntimeError(f"backend exposed {secret}"))
    ).get_inventory(_configuration(), secret)

    for result in (raw_result, redirect_result, exception_result):
        rendered = repr(result)
        assert result.inventory is None
        assert secret not in rendered
        assert "Authorization" not in rendered
        assert body_marker not in rendered
        assert location not in rendered
