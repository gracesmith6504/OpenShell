# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""E2E tests for supervisor-managed provider placeholders in sandboxes.

Provider credentials are fetched at runtime by the sandbox supervisor via the
GetSandboxProviderEnvironment gRPC call. Sandboxed child processes should see
placeholder values (not raw secrets). Credentials must never be present in the
persisted sandbox spec environment map.

Tests in the "Providers v2 static injection" section verify that static
provider credentials are injected into outbound HTTP requests by the proxy
when ``providers_v2_enabled`` is active. They exercise the full server →
sandbox → proxy injection path with a local echo server and check that the
upstream receives the real header value while the sandbox process sees only
the existing credential placeholder, never the raw secret.
"""

from __future__ import annotations

import fcntl
import json
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TYPE_CHECKING

import grpc
import pytest

from openshell._proto import datamodel_pb2, openshell_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from openshell import Sandbox, SandboxClient


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------


def _is_placeholder_for_env_key(value: str, key: str) -> bool:
    """Return true when value is an OpenShell credential placeholder for key."""
    prefix = "openshell:resolve:env:"
    if value == f"{prefix}{key}":
        return True
    token = value.removeprefix(prefix)
    if token == value:
        return False
    return token.startswith("v") and token.endswith(f"_{key}")


def _default_policy() -> sandbox_pb2.SandboxPolicy:
    """Build a sandbox policy with standard filesystem/process/landlock settings."""
    return sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=sandbox_pb2.FilesystemPolicy(
            include_workdir=True,
            read_only=["/usr", "/lib", "/etc", "/app", "/dev/urandom"],
            read_write=["/sandbox", "/tmp"],
        ),
        landlock=sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
        process=sandbox_pb2.ProcessPolicy(
            run_as_user="sandbox", run_as_group="sandbox"
        ),
    )


# ---------------------------------------------------------------------------
# Provider lifecycle helper
# ---------------------------------------------------------------------------


@contextmanager
def provider(
    stub: object,
    *,
    name: str,
    provider_type: str,
    credentials: dict[str, str],
) -> Iterator[str]:
    """Create a provider for the duration of the block, then delete it."""
    _delete_provider(stub, name)
    stub.CreateProvider(
        openshell_pb2.CreateProviderRequest(
            provider=datamodel_pb2.Provider(
                metadata=datamodel_pb2.ObjectMeta(name=name),
                type=provider_type,
                credentials=credentials,
            )
        )
    )
    try:
        yield name
    finally:
        _delete_provider(stub, name)


def _delete_provider(stub: object, name: str) -> None:
    """Delete a provider, ignoring not-found errors."""
    try:
        stub.DeleteProvider(openshell_pb2.DeleteProviderRequest(name=name))
    except grpc.RpcError as exc:
        if hasattr(exc, "code") and exc.code() == grpc.StatusCode.NOT_FOUND:
            pass
        else:
            raise


# ===========================================================================
# Tests: placeholder visibility
# ===========================================================================


def test_provider_credentials_available_as_env_vars(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Sandbox child processes see provider env vars as placeholders."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-provider-env",
        provider_type="claude",
        credentials={"ANTHROPIC_API_KEY": "sk-e2e-test-key-12345"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_env_var() -> str:
            import os

            return os.environ.get("ANTHROPIC_API_KEY", "NOT_SET")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_env_var)
            assert result.exit_code == 0, result.stderr
            value = result.stdout.strip()
            assert _is_placeholder_for_env_key(value, "ANTHROPIC_API_KEY")
            assert value != "sk-e2e-test-key-12345"


def test_generic_provider_credentials_available_as_env_vars(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Generic provider env vars are placeholders, not raw secrets."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-generic-provider-env",
        provider_type="generic",
        credentials={
            "CUSTOM_SERVICE_TOKEN": "token-generic-123",
            "CUSTOM_SERVICE_URL": "https://internal.example.test/api",
        },
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_generic_env_vars() -> str:
            import os

            token = os.environ.get("CUSTOM_SERVICE_TOKEN", "NOT_SET")
            url = os.environ.get("CUSTOM_SERVICE_URL", "NOT_SET")
            return f"{token}|{url}"

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_generic_env_vars)
            assert result.exit_code == 0, result.stderr
            token, url = result.stdout.strip().split("|")
            assert _is_placeholder_for_env_key(token, "CUSTOM_SERVICE_TOKEN")
            assert _is_placeholder_for_env_key(url, "CUSTOM_SERVICE_URL")


def test_nvidia_provider_injects_nvidia_api_key_env_var(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """NVIDIA provider projects a placeholder env value into child processes."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-nvidia-provider-env",
        provider_type="nvidia",
        credentials={"NVIDIA_API_KEY": "nvapi-e2e-test-key"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_nvidia_key() -> str:
            import os

            return os.environ.get("NVIDIA_API_KEY", "NOT_SET")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_nvidia_key)
            assert result.exit_code == 0, result.stderr
            assert _is_placeholder_for_env_key(result.stdout.strip(), "NVIDIA_API_KEY")


def test_attach_detach_updates_credentials_for_later_exec_launches(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Later exec launches see provider attach/detach credential changes."""
    stub = sandbox_client._stub
    provider_name = "e2e-test-attach-detach-env"

    with provider(
        stub,
        name=provider_name,
        provider_type="generic",
        credentials={"CUSTOM_ATTACH_TOKEN": "token-attach-detach"},
    ):
        spec = datamodel_pb2.SandboxSpec(policy=_default_policy(), providers=[])

        def read_attach_token() -> str:
            import os

            return os.environ.get("CUSTOM_ATTACH_TOKEN", "NOT_SET")

        def exec_token(sb: Sandbox) -> str:
            result = sb.exec_python(read_attach_token)
            assert result.exit_code == 0, result.stderr
            return result.stdout.strip()

        def wait_for_token(sb: Sandbox, expected: str) -> None:
            deadline = time.monotonic() + 35
            last = None
            while time.monotonic() < deadline:
                last = exec_token(sb)
                if expected == "NOT_SET":
                    matched = last == expected
                else:
                    matched = _is_placeholder_for_env_key(last, "CUSTOM_ATTACH_TOKEN")
                if matched:
                    return
                time.sleep(2)
            pytest.fail(f"expected {expected!r}, last exec saw {last!r}")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            assert exec_token(sb) == "NOT_SET"

            try:
                stub.AttachSandboxProvider(
                    openshell_pb2.AttachSandboxProviderRequest(
                        sandbox_name=sb.sandbox.name,
                        provider_name=provider_name,
                    )
                )
                wait_for_token(
                    sb,
                    "openshell:resolve:env:CUSTOM_ATTACH_TOKEN",
                )

                stub.DetachSandboxProvider(
                    openshell_pb2.DetachSandboxProviderRequest(
                        sandbox_name=sb.sandbox.name,
                        provider_name=provider_name,
                    )
                )
                wait_for_token(sb, "NOT_SET")
            finally:
                try:
                    stub.DetachSandboxProvider(
                        openshell_pb2.DetachSandboxProviderRequest(
                            sandbox_name=sb.sandbox.name,
                            provider_name=provider_name,
                        )
                    )
                except grpc.RpcError as exc:
                    if exc.code() != grpc.StatusCode.NOT_FOUND:
                        raise


# ===========================================================================
# Tests: security & edge cases
# ===========================================================================


def test_create_sandbox_rejects_unknown_provider(
    sandbox_client: SandboxClient,
) -> None:
    """CreateSandbox fails fast when a provider name does not exist."""
    spec = datamodel_pb2.SandboxSpec(
        policy=_default_policy(),
        providers=["nonexistent-provider-xyz"],
    )
    with pytest.raises(grpc.RpcError) as exc_info:
        sandbox_client.create(spec=spec)

    assert exc_info.value.code() == grpc.StatusCode.FAILED_PRECONDITION
    assert "nonexistent-provider-xyz" in (exc_info.value.details() or "")


def test_credentials_not_in_persisted_spec_environment(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Provider credentials should NOT appear in the sandbox spec's environment map."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-no-persist",
        provider_type="claude",
        credentials={"ANTHROPIC_API_KEY": "sk-should-not-persist"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            fetched = sandbox_client._stub.GetSandbox(
                openshell_pb2.GetSandboxRequest(name=sb.sandbox.name)
            )
            persisted_env = dict(fetched.sandbox.spec.environment)
            assert "ANTHROPIC_API_KEY" not in persisted_env, (
                "credentials should not be persisted in sandbox spec environment"
            )


# ===========================================================================
# Tests: provider update merge semantics
# ===========================================================================


def test_update_provider_preserves_unset_credentials_and_config(
    sandbox_client: SandboxClient,
) -> None:
    """Updating one credential must not clobber other credentials or config."""
    stub = sandbox_client._stub
    name = "merge-test-preserve"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            openshell_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="generic",
                    credentials={"KEY_A": "val-a", "KEY_B": "val-b"},
                    config={"BASE_URL": "https://example.com"},
                )
            )
        )

        stub.UpdateProvider(
            openshell_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="",
                    credentials={"KEY_A": "rotated-a"},
                )
            )
        )

        got = stub.GetProvider(openshell_pb2.GetProviderRequest(name=name))
        p = got.provider
        # Credential keys are preserved but values are redacted.
        assert len(p.credentials) > 0, "credential keys should be preserved"
        for key, val in p.credentials.items():
            assert val == "REDACTED", (
                f"credential '{key}' should be REDACTED, got '{val}'"
            )
        assert p.config["BASE_URL"] == "https://example.com", (
            "config should be preserved"
        )
    finally:
        _delete_provider(stub, name)


def test_update_provider_empty_maps_preserves_all(
    sandbox_client: SandboxClient,
) -> None:
    """Sending empty credential and config maps should be a no-op."""
    stub = sandbox_client._stub
    name = "merge-test-noop"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            openshell_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="generic",
                    credentials={"TOKEN": "secret"},
                    config={"URL": "https://api.example.com"},
                )
            )
        )

        stub.UpdateProvider(
            openshell_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="",
                )
            )
        )

        got = stub.GetProvider(openshell_pb2.GetProviderRequest(name=name))
        p = got.provider
        # Credential keys are preserved but values are redacted.
        assert len(p.credentials) > 0, "credential keys should be preserved"
        for key, val in p.credentials.items():
            assert val == "REDACTED", (
                f"credential '{key}' should be REDACTED, got '{val}'"
            )
        assert p.config["URL"] == "https://api.example.com"
    finally:
        _delete_provider(stub, name)


def test_update_provider_merges_config_preserves_credentials(
    sandbox_client: SandboxClient,
) -> None:
    """Updating only config should not touch credentials."""
    stub = sandbox_client._stub
    name = "merge-test-config-only"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            openshell_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="generic",
                    credentials={"API_KEY": "original-key"},
                    config={"ENDPOINT": "https://old.example.com"},
                )
            )
        )

        stub.UpdateProvider(
            openshell_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="",
                    config={"ENDPOINT": "https://new.example.com"},
                )
            )
        )

        got = stub.GetProvider(openshell_pb2.GetProviderRequest(name=name))
        p = got.provider
        # Credential keys are preserved but values are redacted.
        assert len(p.credentials) > 0, "credential keys should be preserved"
        for key, val in p.credentials.items():
            assert val == "REDACTED", (
                f"credential '{key}' should be REDACTED, got '{val}'"
            )
        assert p.config["ENDPOINT"] == "https://new.example.com"
    finally:
        _delete_provider(stub, name)


def test_update_provider_rejects_type_change(
    sandbox_client: SandboxClient,
) -> None:
    """Attempting to change a provider's type must be rejected."""
    stub = sandbox_client._stub
    name = "merge-test-type-reject"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            openshell_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="generic",
                    credentials={"KEY": "val"},
                )
            )
        )

        with pytest.raises(grpc.RpcError) as exc_info:
            stub.UpdateProvider(
                openshell_pb2.UpdateProviderRequest(
                    provider=datamodel_pb2.Provider(
                        metadata=datamodel_pb2.ObjectMeta(name=name),
                        type="nvidia",
                    )
                )
            )
        assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
        assert "type cannot be changed" in exc_info.value.details()
    finally:
        _delete_provider(stub, name)


# ===========================================================================
# Providers v2 static injection — helpers
# ===========================================================================

# Standard sandbox network namespace addresses
_PROXY_HOST = "10.200.0.1"
_PROXY_PORT = 3128
_SANDBOX_IP = "10.200.0.2"
_ECHO_SERVER_PORT = 19876
_PROVIDERS_V2_CONFIG_LOCK = Path("/tmp/openshell-e2e-providers-v2-config.lock")


def _set_providers_v2_enabled(stub: object, enabled: bool) -> None:
    """Toggle the providers_v2_enabled gateway-global setting."""
    stub.UpdateConfig(
        openshell_pb2.UpdateConfigRequest(
            setting_key="providers_v2_enabled",
            setting_value=sandbox_pb2.SettingValue(bool_value=enabled),
            **{"global": True},
        )
    )


def _delete_providers_v2_setting(stub: object) -> None:
    """Remove the providers_v2_enabled setting so it returns to the default."""
    with suppress(grpc.RpcError):
        stub.UpdateConfig(
            openshell_pb2.UpdateConfigRequest(
                setting_key="providers_v2_enabled",
                delete_setting=True,
                **{"global": True},
            )
        )


@contextmanager
def _providers_v2_enabled(stub: object) -> Iterator[None]:
    """Context manager that enables providers_v2 for the block, then resets."""
    with _PROVIDERS_V2_CONFIG_LOCK.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        _set_providers_v2_enabled(stub, True)
        try:
            yield
        finally:
            _delete_providers_v2_setting(stub)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _import_custom_profile(
    stub: object,
    *,
    profile_id: str,
    credential_name: str,
    auth_style: str,
    header_name: str,
    env_vars: list[str],
    endpoint_host: str,
    endpoint_port: int,
) -> None:
    """Import a custom provider type profile for E2E injection testing."""
    profile = openshell_pb2.ProviderProfile(
        id=profile_id,
        display_name=f"E2E {profile_id}",
        description="Temporary E2E test profile for static credential injection",
        credentials=[
            openshell_pb2.ProviderProfileCredential(
                name=credential_name,
                description="E2E test credential",
                env_vars=env_vars,
                required=True,
                auth_style=auth_style,
                header_name=header_name,
            ),
        ],
        endpoints=[
            sandbox_pb2.NetworkEndpoint(
                host=endpoint_host,
                port=endpoint_port,
                protocol="rest",
                enforcement="enforce",
                access="full",
            ),
        ],
        binaries=[sandbox_pb2.NetworkBinary(path="/**")],
    )
    resp = stub.ImportProviderProfiles(
        openshell_pb2.ImportProviderProfilesRequest(
            profiles=[
                openshell_pb2.ProviderProfileImportItem(
                    profile=profile,
                    source="e2e-test",
                ),
            ],
        )
    )
    for diag in resp.diagnostics:
        if diag.severity == "error":
            raise RuntimeError(f"Profile import error: {diag.field}: {diag.message}")


def _delete_custom_profile(stub: object, profile_id: str) -> None:
    """Delete a custom provider profile, ignoring not-found errors."""
    try:
        stub.DeleteProviderProfile(
            openshell_pb2.DeleteProviderProfileRequest(id=profile_id)
        )
    except grpc.RpcError as exc:
        if hasattr(exc, "code") and exc.code() == grpc.StatusCode.NOT_FOUND:
            pass
        else:
            raise


def _injection_policy() -> sandbox_pb2.SandboxPolicy:
    """Build a sandbox policy allowing L7-inspected traffic to the echo server."""
    return sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=sandbox_pb2.FilesystemPolicy(
            include_workdir=True,
            read_only=["/usr", "/lib", "/etc", "/app", "/dev/urandom"],
            read_write=["/sandbox", "/tmp"],
        ),
        landlock=sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
        process=sandbox_pb2.ProcessPolicy(
            run_as_user="sandbox", run_as_group="sandbox"
        ),
        network_policies={
            "echo": sandbox_pb2.NetworkPolicyRule(
                name="echo",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host=_SANDBOX_IP,
                        port=_ECHO_SERVER_PORT,
                        protocol="rest",
                        enforcement="enforce",
                        access="full",
                        allowed_ips=["10.200.0.0/24"],
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )


def _header_echo_server_and_request():
    """Return a closure that starts an echo server and sends a proxied request.

    The echo server returns all received HTTP request headers as a JSON object
    in the response body. The closure CONNECTs through the sandbox proxy, sends
    a plain HTTP request to the local server, and returns the JSON-decoded
    response.
    """

    def fn(
        proxy_host,
        proxy_port,
        target_host,
        target_port,
        extra_headers="",
    ):
        import json as _json
        import socket
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class EchoHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                headers_dict = dict(self.headers.items())
                body = _json.dumps(headers_dict).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        srv = HTTPServer(("0.0.0.0", int(target_port)), EchoHandler)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        time.sleep(0.5)

        conn = socket.create_connection((proxy_host, int(proxy_port)), timeout=30)
        try:
            conn.sendall(
                f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_host}\r\n\r\n".encode()
            )
            connect_resp = conn.recv(256).decode("latin1")
            if "200" not in connect_resp:
                return _json.dumps(
                    {
                        "connect_status": connect_resp.strip(),
                        "http_status": 0,
                        "headers": {},
                    }
                )

            request = (
                f"GET /echo HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                f"Connection: close\r\n"
                f"{extra_headers}"
                f"\r\n"
            )
            conn.sendall(request.encode())

            data = b""
            conn.settimeout(10)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except TimeoutError:
                pass

            response = data.decode("latin1", errors="replace")
            status_line = response.split("\r\n")[0] if response else ""
            status_code = (
                int(status_line.split()[1]) if len(status_line.split()) >= 2 else 0
            )

            header_end = response.find("\r\n\r\n")
            body = response[header_end + 4 :] if header_end > 0 else ""

            # Parse JSON body if present
            try:
                headers = _json.loads(body)
            except Exception:
                headers = {}

            return _json.dumps(
                {
                    "connect_status": connect_resp.strip(),
                    "http_status": status_code,
                    "headers": headers,
                    "raw_body": body,
                }
            )
        finally:
            conn.close()
            srv.server_close()

    return fn


# ===========================================================================
# Tests: providers v2 static credential injection
# ===========================================================================


def test_providers_v2_static_bearer_injection_through_proxy(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Static bearer credential is injected into outbound requests by the proxy.

    Verifies the full server → sandbox → proxy injection path:
    1. The sandbox process sees only the credential placeholder, not the raw
       secret.
    2. The proxy injects ``Authorization: Bearer <secret>`` into the request
       before forwarding to the upstream echo server.
    """
    stub = sandbox_client._stub
    profile_id = "e2e-static-bearer-inject"
    provider_name = "e2e-provider-bearer-inject"
    secret = "sk-e2e-bearer-secret-12345"
    env_key = "E2E_BEARER_TOKEN"

    _delete_provider(stub, provider_name)
    _delete_custom_profile(stub, profile_id)

    with _providers_v2_enabled(stub):
        try:
            _import_custom_profile(
                stub,
                profile_id=profile_id,
                credential_name="api_key",
                auth_style="bearer",
                header_name="authorization",
                env_vars=[env_key],
                endpoint_host=_SANDBOX_IP,
                endpoint_port=_ECHO_SERVER_PORT,
            )

            with provider(
                stub,
                name=provider_name,
                provider_type=profile_id,
                credentials={env_key: secret},
            ):
                spec = datamodel_pb2.SandboxSpec(
                    policy=_injection_policy(),
                    providers=[provider_name],
                )

                def read_env_var() -> str:
                    import os

                    return os.environ.get("E2E_BEARER_TOKEN", "NOT_SET")

                with sandbox(spec=spec, delete_on_exit=True) as sb:
                    # 1. The sandbox process receives only the placeholder.
                    env_result = sb.exec_python(read_env_var)
                    assert env_result.exit_code == 0, env_result.stderr
                    env_value = env_result.stdout.strip()
                    assert _is_placeholder_for_env_key(env_value, env_key), (
                        f"expected placeholder for {env_key}, got {env_value!r}"
                    )
                    assert env_value != secret

                    # 2. Proxy injects real credential into upstream request
                    echo_result = sb.exec_python(
                        _header_echo_server_and_request(),
                        args=(
                            _PROXY_HOST,
                            _PROXY_PORT,
                            _SANDBOX_IP,
                            _ECHO_SERVER_PORT,
                        ),
                    )
                    assert echo_result.exit_code == 0, echo_result.stderr
                    resp = json.loads(echo_result.stdout)
                    assert resp["http_status"] == 200, (
                        "expected 200 from echo server, got "
                        f"{resp['http_status']} after {resp['connect_status']!r}"
                    )
                    echoed_headers = resp["headers"]
                    # The proxy should have injected the Authorization header
                    auth_header = echoed_headers.get(
                        "Authorization", echoed_headers.get("authorization", "")
                    )
                    assert auth_header == f"Bearer {secret}", (
                        "proxy did not inject the expected bearer credential"
                    )
        finally:
            _delete_custom_profile(stub, profile_id)


def test_providers_v2_static_header_injection_through_proxy(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Static header credential is injected with a custom header name.

    Uses ``auth_style: header`` with ``header_name: X-Custom-Api-Key`` to
    verify that the proxy injects the credential as a raw header value (no
    ``Bearer`` prefix).
    """
    stub = sandbox_client._stub
    profile_id = "e2e-static-header-inject"
    provider_name = "e2e-provider-header-inject"
    secret = "custom-header-secret-67890"
    env_key = "E2E_CUSTOM_HEADER_TOKEN"

    _delete_provider(stub, provider_name)
    _delete_custom_profile(stub, profile_id)

    with _providers_v2_enabled(stub):
        try:
            _import_custom_profile(
                stub,
                profile_id=profile_id,
                credential_name="api_key",
                auth_style="header",
                header_name="X-Custom-Api-Key",
                env_vars=[env_key],
                endpoint_host=_SANDBOX_IP,
                endpoint_port=_ECHO_SERVER_PORT,
            )

            with provider(
                stub,
                name=provider_name,
                provider_type=profile_id,
                credentials={env_key: secret},
            ):
                spec = datamodel_pb2.SandboxSpec(
                    policy=_injection_policy(),
                    providers=[provider_name],
                )

                def read_env_var() -> str:
                    import os

                    return os.environ.get("E2E_CUSTOM_HEADER_TOKEN", "NOT_SET")

                with sandbox(spec=spec, delete_on_exit=True) as sb:
                    env_result = sb.exec_python(read_env_var)
                    assert env_result.exit_code == 0, env_result.stderr
                    env_value = env_result.stdout.strip()
                    assert _is_placeholder_for_env_key(env_value, env_key), (
                        f"expected placeholder for {env_key}, got {env_value!r}"
                    )
                    assert env_value != secret

                    echo_result = sb.exec_python(
                        _header_echo_server_and_request(),
                        args=(
                            _PROXY_HOST,
                            _PROXY_PORT,
                            _SANDBOX_IP,
                            _ECHO_SERVER_PORT,
                        ),
                    )
                    assert echo_result.exit_code == 0, echo_result.stderr
                    resp = json.loads(echo_result.stdout)
                    assert resp["http_status"] == 200, (
                        "expected 200 from echo server, got "
                        f"{resp['http_status']} after {resp['connect_status']!r}"
                    )
                    echoed_headers = resp["headers"]
                    custom_header = echoed_headers.get(
                        "X-Custom-Api-Key",
                        echoed_headers.get("x-custom-api-key", ""),
                    )
                    assert custom_header == secret, (
                        "proxy did not inject the expected custom-header credential"
                    )
        finally:
            _delete_custom_profile(stub, profile_id)


def test_providers_v2_placeholder_profile_collision_fails_closed(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Proxy rejects requests with placeholder-based values in the target header.

    Defense-in-depth: even though v2 credentials are suppressed from the
    sandbox environment, an application could construct a header containing
    a placeholder string directly. The proxy must detect the collision and
    fail closed (502 Bad Gateway) instead of double-injecting or leaking
    credentials.
    """
    stub = sandbox_client._stub
    profile_id = "e2e-collision-bearer"
    provider_name = "e2e-provider-collision"
    secret = "sk-collision-secret-99999"
    env_key = "E2E_COLLISION_TOKEN"

    _delete_provider(stub, provider_name)
    _delete_custom_profile(stub, profile_id)

    with _providers_v2_enabled(stub):
        try:
            _import_custom_profile(
                stub,
                profile_id=profile_id,
                credential_name="api_key",
                auth_style="bearer",
                header_name="authorization",
                env_vars=[env_key],
                endpoint_host=_SANDBOX_IP,
                endpoint_port=_ECHO_SERVER_PORT,
            )

            with provider(
                stub,
                name=provider_name,
                provider_type=profile_id,
                credentials={env_key: secret},
            ):
                spec = datamodel_pb2.SandboxSpec(
                    policy=_injection_policy(),
                    providers=[provider_name],
                )

                with sandbox(spec=spec, delete_on_exit=True) as sb:
                    # Send a request that already has a placeholder-based
                    # Authorization header — the proxy must reject it.
                    placeholder_value = f"openshell:resolve:env:{env_key}"
                    collision_header = f"Authorization: Bearer {placeholder_value}\r\n"
                    echo_result = sb.exec_python(
                        _header_echo_server_and_request(),
                        args=(
                            _PROXY_HOST,
                            _PROXY_PORT,
                            _SANDBOX_IP,
                            _ECHO_SERVER_PORT,
                            collision_header,
                        ),
                    )
                    assert echo_result.exit_code == 0, echo_result.stderr
                    resp = json.loads(echo_result.stdout)
                    # Injection collision → 502 Bad Gateway (fail closed)
                    assert resp["http_status"] == 502, (
                        "expected 502 for placeholder collision, got "
                        f"{resp['http_status']} after {resp['connect_status']!r}"
                    )
        finally:
            _delete_custom_profile(stub, profile_id)
