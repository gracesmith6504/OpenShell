# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import io
import json
import tarfile
from typing import TYPE_CHECKING, Any, cast

import pytest

from openshell._proto import datamodel_pb2, openshell_pb2, sandbox_pb2
from openshell.sandbox import (
    _PYTHON_CLOUDPICKLE_BOOTSTRAP,
    _SANDBOX_PYTHON_BIN,
    InferenceRouteClient,
    ProviderClient,
    SandboxClient,
    SandboxError,
    policy_from_yaml,
)

if TYPE_CHECKING:
    from pathlib import Path


class _FakeStub:
    def __init__(self) -> None:
        self.request: openshell_pb2.ExecSandboxRequest | None = None
        self.create_sandbox_request: openshell_pb2.CreateSandboxRequest | None = None
        self.exec_exit_code: int = 0
        self.exec_stdout: bytes = b""
        self.exec_stderr: bytes = b""

    def ExecSandbox(
        self,
        request: openshell_pb2.ExecSandboxRequest,
        timeout: float | None = None,
    ):
        self.request = request
        _ = timeout
        if self.exec_stdout:
            yield openshell_pb2.ExecSandboxEvent(
                stdout=openshell_pb2.ExecSandboxStdout(data=self.exec_stdout)
            )
        if self.exec_stderr:
            yield openshell_pb2.ExecSandboxEvent(
                stderr=openshell_pb2.ExecSandboxStderr(data=self.exec_stderr)
            )
        yield openshell_pb2.ExecSandboxEvent(
            exit=openshell_pb2.ExecSandboxExit(exit_code=self.exec_exit_code)
        )

    def CreateSandbox(
        self,
        request: openshell_pb2.CreateSandboxRequest,
        timeout: float | None = None,
    ):
        self.create_sandbox_request = request
        _ = timeout
        sandbox = openshell_pb2.Sandbox(
            metadata=datamodel_pb2.ObjectMeta(
                id="sandbox-id-1",
                name=request.name or "generated-name",
            ),
            phase=openshell_pb2.SANDBOX_PHASE_PROVISIONING,
        )
        return openshell_pb2.SandboxResponse(sandbox=sandbox)


class _FakeProviderStub:
    def __init__(self) -> None:
        self.create_request: openshell_pb2.CreateProviderRequest | None = None
        self.get_request: openshell_pb2.GetProviderRequest | None = None
        self.list_request: openshell_pb2.ListProvidersRequest | None = None
        self.delete_request: openshell_pb2.DeleteProviderRequest | None = None
        self.delete_response_flag: bool = True
        self.providers_to_return: list[datamodel_pb2.Provider] = []

    def CreateProvider(
        self,
        request: openshell_pb2.CreateProviderRequest,
        timeout: float | None = None,
    ):
        self.create_request = request
        _ = timeout
        echo = datamodel_pb2.Provider()
        echo.CopyFrom(request.provider)
        echo.metadata.id = "provider-id-1"
        return openshell_pb2.ProviderResponse(provider=echo)

    def GetProvider(
        self,
        request: openshell_pb2.GetProviderRequest,
        timeout: float | None = None,
    ):
        self.get_request = request
        _ = timeout
        provider = datamodel_pb2.Provider(
            metadata=datamodel_pb2.ObjectMeta(id="get-id", name=request.name),
            type="generic",
        )
        return openshell_pb2.ProviderResponse(provider=provider)

    def ListProviders(
        self,
        request: openshell_pb2.ListProvidersRequest,
        timeout: float | None = None,
    ):
        self.list_request = request
        _ = timeout
        return openshell_pb2.ListProvidersResponse(
            providers=self.providers_to_return,
        )

    def DeleteProvider(
        self,
        request: openshell_pb2.DeleteProviderRequest,
        timeout: float | None = None,
    ):
        self.delete_request = request
        _ = timeout
        return openshell_pb2.DeleteProviderResponse(deleted=self.delete_response_flag)


class _FakeInferenceStub:
    def __init__(self) -> None:
        self.request = None

    def SetClusterInference(self, request: Any, timeout: float | None = None) -> Any:
        self.request = request
        _ = timeout

        class _Response:
            provider_name = request.provider_name
            model_id = request.model_id
            version = 1

        return _Response()


def _client_with_fake_stub(stub: _FakeStub) -> SandboxClient:
    client = cast("SandboxClient", object.__new__(SandboxClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)
    client._providers = None
    return client


def _provider_client_with_fake_stub(stub: _FakeProviderStub) -> ProviderClient:
    client = cast("ProviderClient", object.__new__(ProviderClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)
    return client


def test_exec_sends_stdin_payload() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    result = client.exec("sandbox-1", ["python", "-c", "print('ok')"], stdin=b"payload")

    assert result.exit_code == 0
    assert stub.request is not None
    assert stub.request.stdin == b"payload"


def test_exec_python_serializes_callable_payload() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    def add(a: int, b: int) -> int:
        return a + b

    result = client.exec_python("sandbox-1", add, args=(2, 3))

    assert result.exit_code == 0
    assert stub.request is not None
    assert stub.request.command == [
        _SANDBOX_PYTHON_BIN,
        "-c",
        _PYTHON_CLOUDPICKLE_BOOTSTRAP,
    ]
    assert stub.request.environment["OPENSHELL_PYFUNC_B64"]
    assert stub.request.stdin == b""


def test_from_active_cluster_reads_gateway_metadata_layout(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    gateway_name = "test-gateway"
    gateway_dir = tmp_path / "openshell" / "gateways" / gateway_name
    mtls_dir = gateway_dir / "mtls"
    mtls_dir.mkdir(parents=True)
    (tmp_path / "openshell" / "active_gateway").write_text(gateway_name)
    (gateway_dir / "metadata.json").write_text(
        json.dumps({"gateway_endpoint": "https://127.0.0.1:8443"})
    )
    (mtls_dir / "ca.crt").write_text("ca")
    (mtls_dir / "tls.crt").write_text("cert")
    (mtls_dir / "tls.key").write_text("key")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("OPENSHELL_GATEWAY", raising=False)

    client = SandboxClient.from_active_cluster()
    try:
        assert client._cluster_name == gateway_name
    finally:
        client.close()


def test_from_active_cluster_prefers_openshell_gateway_env(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    gateway_name = "env-gateway"
    gateway_dir = tmp_path / "openshell" / "gateways" / gateway_name
    mtls_dir = gateway_dir / "mtls"
    mtls_dir.mkdir(parents=True)
    (gateway_dir / "metadata.json").write_text(
        json.dumps({"gateway_endpoint": "https://127.0.0.1:8443"})
    )
    (mtls_dir / "ca.crt").write_text("ca")
    (mtls_dir / "tls.crt").write_text("cert")
    (mtls_dir / "tls.key").write_text("key")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("OPENSHELL_GATEWAY", gateway_name)

    client = SandboxClient.from_active_cluster()
    try:
        assert client._cluster_name == gateway_name
    finally:
        client.close()


def test_inference_set_cluster_forwards_no_verify_flag() -> None:
    stub = _FakeInferenceStub()
    client = cast("InferenceRouteClient", object.__new__(InferenceRouteClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)

    client.set_cluster(
        provider_name="openai-dev",
        model_id="gpt-4.1",
        no_verify=True,
    )

    assert stub.request is not None
    assert stub.request.no_verify is True


def test_provider_create_resolves_credentials_from_env(monkeypatch: Any) -> None:
    monkeypatch.setenv("CODEX_AUTH_ACCESS_TOKEN", "access-secret")
    monkeypatch.setenv("CODEX_AUTH_REFRESH_TOKEN", "refresh-secret")

    stub = _FakeProviderStub()
    client = _provider_client_with_fake_stub(stub)

    ref = client.create(
        name="codex-oauth",
        provider_type="generic",
        credentials_from_env=[
            "CODEX_AUTH_ACCESS_TOKEN",
            "CODEX_AUTH_REFRESH_TOKEN",
        ],
    )

    assert stub.create_request is not None
    provider = stub.create_request.provider
    assert provider.metadata.name == "codex-oauth"
    assert provider.type == "generic"
    assert dict(provider.credentials) == {
        "CODEX_AUTH_ACCESS_TOKEN": "access-secret",
        "CODEX_AUTH_REFRESH_TOKEN": "refresh-secret",
    }
    assert ref.id == "provider-id-1"
    assert ref.name == "codex-oauth"
    assert ref.type == "generic"


def test_provider_create_passes_explicit_credentials(monkeypatch: Any) -> None:
    monkeypatch.setenv("DEMO_GITHUB_TOKEN", "from-env")

    stub = _FakeProviderStub()
    client = _provider_client_with_fake_stub(stub)

    client.create(
        name="github-memory",
        provider_type="generic",
        credentials={"DEMO_GITHUB_TOKEN": "explicit-override"},
        config={"endpoint": "api.github.com"},
    )

    assert stub.create_request is not None
    provider = stub.create_request.provider
    assert dict(provider.credentials) == {"DEMO_GITHUB_TOKEN": "explicit-override"}
    assert dict(provider.config) == {"endpoint": "api.github.com"}


def test_provider_create_missing_env_raises(monkeypatch: Any) -> None:
    monkeypatch.delenv("MISSING_TOKEN", raising=False)

    stub = _FakeProviderStub()
    client = _provider_client_with_fake_stub(stub)

    with pytest.raises(SandboxError, match="MISSING_TOKEN"):
        client.create(
            name="x",
            provider_type="generic",
            credentials_from_env=["MISSING_TOKEN"],
        )

    assert stub.create_request is None


def test_provider_delete_returns_response_flag() -> None:
    stub = _FakeProviderStub()
    stub.delete_response_flag = False
    client = _provider_client_with_fake_stub(stub)

    deleted = client.delete("github-memory")

    assert deleted is False
    assert stub.delete_request is not None
    assert stub.delete_request.name == "github-memory"


def test_provider_list_returns_refs() -> None:
    stub = _FakeProviderStub()
    stub.providers_to_return = [
        datamodel_pb2.Provider(
            metadata=datamodel_pb2.ObjectMeta(id="p1", name="alpha"),
            type="generic",
        ),
        datamodel_pb2.Provider(
            metadata=datamodel_pb2.ObjectMeta(id="p2", name="beta"),
            type="claude",
        ),
    ]
    client = _provider_client_with_fake_stub(stub)

    refs = client.list(limit=50)

    assert stub.list_request is not None
    assert stub.list_request.limit == 50
    assert [(r.id, r.name, r.type) for r in refs] == [
        ("p1", "alpha", "generic"),
        ("p2", "beta", "claude"),
    ]


def test_policy_from_yaml_loads_demo_template() -> None:
    yaml_text = """
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib]
  read_write: [/sandbox, /tmp]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  github_memory:
    name: github-memory
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/repos/owner/repo/contents/runs/run-id"
"""

    policy = policy_from_yaml(yaml_text)

    assert policy.version == 1
    assert policy.filesystem.include_workdir is True
    assert list(policy.filesystem.read_only) == ["/usr", "/lib"]
    assert list(policy.filesystem.read_write) == ["/sandbox", "/tmp"]
    assert policy.landlock.compatibility == "best_effort"
    assert policy.process.run_as_user == "sandbox"

    rule = policy.network_policies["github_memory"]
    assert rule.name == "github-memory"
    assert len(rule.endpoints) == 1
    endpoint = rule.endpoints[0]
    assert endpoint.host == "api.github.com"
    assert endpoint.port == 443
    assert endpoint.protocol == "rest"
    assert len(endpoint.rules) == 1
    assert endpoint.rules[0].allow.method == "GET"
    assert endpoint.rules[0].allow.path == "/repos/owner/repo/contents/runs/run-id"


def test_policy_from_yaml_reads_path(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("version: 2\nfilesystem_policy:\n  include_workdir: false\n")

    policy = policy_from_yaml(policy_file)

    assert policy.version == 2
    assert policy.filesystem.include_workdir is False


def test_policy_from_yaml_rejects_non_mapping() -> None:
    with pytest.raises(SandboxError, match="mapping"):
        policy_from_yaml("- just-a-list\n- item-2\n")


def test_upload_packages_tarball_and_pipes_to_exec(tmp_path: Path) -> None:
    src = tmp_path / "payload"
    src.mkdir()
    (src / "runner.sh").write_text("#!/bin/sh\necho hello\n")
    (src / "prompts").mkdir()
    (src / "prompts" / "worker.md").write_text("# worker\n")

    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    client.upload("sandbox-1", src, "/sandbox")

    assert stub.request is not None
    assert stub.request.sandbox_id == "sandbox-1"
    assert stub.request.command == [
        "sh",
        "-c",
        "mkdir -p '/sandbox' && tar xzf - -C '/sandbox'",
    ]
    assert stub.request.stdin
    with tarfile.open(fileobj=io.BytesIO(stub.request.stdin), mode="r:gz") as tar:
        names = sorted(tar.getnames())
    assert "payload" in names
    assert "payload/runner.sh" in names
    assert "payload/prompts/worker.md" in names


def test_upload_missing_source_raises(tmp_path: Path) -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    with pytest.raises(SandboxError, match="upload source does not exist"):
        client.upload("sandbox-1", tmp_path / "nope", "/sandbox")

    assert stub.request is None


def test_upload_failure_surfaces_stderr(tmp_path: Path) -> None:
    src = tmp_path / "payload"
    src.mkdir()
    (src / "f.txt").write_text("ok")

    stub = _FakeStub()
    stub.exec_exit_code = 2
    stub.exec_stderr = b"tar: cannot write: read-only filesystem"
    client = _client_with_fake_stub(stub)

    with pytest.raises(SandboxError, match="read-only filesystem"):
        client.upload("sandbox-1", src, "/sandbox")


def test_upload_quotes_destination_with_single_quote(tmp_path: Path) -> None:
    src = tmp_path / "f.txt"
    src.write_text("ok")

    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    client.upload("sandbox-1", src, "/sand'box")

    assert stub.request is not None
    assert stub.request.command[2] == (
        "mkdir -p '/sand'\\''box' && tar xzf - -C '/sand'\\''box'"
    )


def test_create_with_kwargs_constructs_spec() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    policy = sandbox_pb2.SandboxPolicy(version=3)
    policy.filesystem.include_workdir = True

    ref = client.create(
        name="agent-1",
        image="base",
        providers=["codex-oauth", "github-memory"],
        policy=policy,
        environment={"AGENT_INDEX": "1"},
        labels={"run-id": "20260506-001"},
    )

    assert stub.create_sandbox_request is not None
    request = stub.create_sandbox_request
    assert request.name == "agent-1"
    assert dict(request.labels) == {"run-id": "20260506-001"}
    assert request.spec.template.image == "base"
    assert list(request.spec.providers) == ["codex-oauth", "github-memory"]
    assert dict(request.spec.environment) == {"AGENT_INDEX": "1"}
    assert request.spec.policy.version == 3
    assert request.spec.policy.filesystem.include_workdir is True
    assert ref.id == "sandbox-id-1"
    assert ref.name == "agent-1"


def test_create_default_uses_empty_spec_with_name() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    client.create(name="just-a-name")

    assert stub.create_sandbox_request is not None
    request = stub.create_sandbox_request
    assert request.name == "just-a-name"
    assert request.spec.template.image == ""
    assert list(request.spec.providers) == []


def test_create_rejects_spec_and_kwargs_together() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    spec = openshell_pb2.SandboxSpec(
        template=openshell_pb2.SandboxTemplate(image="explicit"),
    )

    with pytest.raises(SandboxError, match="spec="):
        client.create(spec=spec, image="conflicting")

    assert stub.create_sandbox_request is None


def test_sandbox_client_providers_property_caches() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    first = client.providers
    second = client.providers

    assert first is second
    assert isinstance(first, ProviderClient)
