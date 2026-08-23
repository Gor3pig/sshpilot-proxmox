"""Headless tests for the minimal authenticated Proxmox VE client."""

import email.message
import io
import socket
import ssl
import urllib.error
import urllib.request

import pytest

import proxmox_api as api


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
