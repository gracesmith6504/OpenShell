# Python SDK

## Overview

The Python SDK at `python/openshell/` provides programmatic access to an OpenShell
gateway from notebooks, scripts, and tests. It is a peer to the `openshell` CLI:
both speak the same gRPC service, share the same mTLS bootstrap layout under
`~/.config/openshell/gateways/<cluster>/`, and target the same set of user-facing
RPCs from `proto/openshell.proto`. The CLI is the right tool for one-off
interactive work; the SDK is the right tool when the work is parallel,
data-driven, or needs to live in code that future readers can step through.

## When to reach for the SDK

- Driving multiple sandboxes in parallel from a single Python process — for
  example, the multi-agent flow in `examples/multi-agent-notepad/demo.sh`.
- Embedding sandbox lifecycle into evaluation harnesses, integration tests, or
  notebook-based investigations.
- Stitching sandbox results into other Python code (data frames, plotting,
  report generation) without shelling out to `openshell` and parsing text.

The CLI remains the right tool for ad-hoc operator work, image build / push,
gateway bootstrap, draft-policy review, and anything that benefits from a TTY.

## Design principle: mirror the CLI, not the raw protos

`crates/openshell-cli/src/run.rs` (`sandbox create`) is roughly 500 lines of
orchestration on top of a handful of RPCs. The work it does — gateway endpoint
resolution, mTLS cert loading, polling for `Provisioning -> Ready`, file
upload, friendly error mapping, multi-step sequencing — is exactly what every
SDK consumer would otherwise rewrite by hand. A proto-only SDK pushes that
500 lines into every notebook that wants to do anything more interesting than
`Health()`.

The SDK therefore mirrors CLI verbs (`sandbox create`, `provider create`,
`policy ...`, file upload, exec) at its public surface, and uses the protos as
its wire format. The public methods are designed so that a reader who knows
`openshell sandbox create --from base --provider X --policy y.yaml --upload
src:dst` can predict the SDK call.

## Public surface

The package exposes a small set of types that wrap the generated proto stubs.

| Type | Purpose |
|---|---|
| `SandboxClient` | Top-level gRPC client. Created from an explicit endpoint or via `from_active_cluster()` for mTLS auto-discovery. |
| `Sandbox` | Context-managed sandbox lifecycle: create, wait for ready, exec, delete on exit. |
| `SandboxSession` | Bound pair of `(client, sandbox)` for repeated exec calls without re-resolving names. |
| `ProviderClient` | Provider CRUD wrappers (`create`, `get`, `list`, `delete`). |
| `InferenceRouteClient` | Cluster-level inference config (`Set/GetClusterInference`). |
| `policy_from_yaml(path)` | YAML loader that returns a `SandboxPolicy` proto. |
| `ExecResult`, `ExecChunk`, `SandboxRef`, `ProviderRef`, `TlsConfig` | Plain dataclasses for return values and configuration. |
| `SandboxError` | Domain-specific runtime error surfaced from gRPC `Status` codes the SDK can interpret. |

Generated stubs live under `python/openshell/_proto/` and are an implementation
detail. Power users who need a field the SDK does not yet expose can still
construct `openshell_pb2.SandboxSpec` directly and pass it via
`SandboxClient.create(spec=...)`.

### Sketch — reproducing the demo flow

```python
from openshell import SandboxClient, policy_from_yaml

client = SandboxClient.from_active_cluster()

# Provider records that hold credentials by env-var name.
client.providers.create(
    name="codex-oauth",
    provider_type="generic",
    credentials_from_env=["CODEX_AUTH_ACCESS_TOKEN", "CODEX_AUTH_REFRESH_TOKEN"],
)

# Load and bind the same YAML the CLI accepts.
policy = policy_from_yaml(Path("policy.yaml"))

# Friendlier sandbox creation; raw spec= still supported for advanced cases.
sandbox = client.create(
    name="agent-1",
    image="base",
    providers=["codex-oauth"],
    policy=policy,
)
client.wait_ready(sandbox.name)

# Upload payloads and run an entrypoint command, mirroring CLI's --upload + -- bash ...
client.upload(sandbox.id, src="./payload", dst="/sandbox")
result = client.exec(sandbox.id, ["bash", "/sandbox/payload/run.sh", "worker", "1"])

client.delete(sandbox.name)
client.providers.delete("codex-oauth")
```

## Authentication

`SandboxClient.from_active_cluster()` reads
`~/.config/openshell/gateways/<cluster>/metadata.json` for the gateway endpoint
and `mtls/{ca.crt,tls.crt,tls.key}` for client certificates. Cluster name comes
from `OPENSHELL_GATEWAY` if set, otherwise from
`~/.config/openshell/active_gateway`. This matches the CLI exactly.

`XDG_CONFIG_HOME` is honored when set. Plain `SandboxClient(endpoint, tls=...)`
works for explicit setups (CI, multiple gateways in one process).

OIDC / Edge bearer-token auth (the CLI's interceptor path in
`crates/openshell-cli/src/tls.rs`) is **not** in the SDK today. mTLS only.
Adding bearer auth is straightforward when needed: a gRPC interceptor that
injects an `authorization: Bearer <token>` header, mirroring the Rust
`EdgeAuthInterceptor`.

## File upload

`SandboxClient.upload(sandbox_id, src, dst)` packages the source path as a
gzipped tar archive, then runs `mkdir -p <dst> && tar xzf -` inside the
sandbox via `ExecSandbox` with the tarball streamed as stdin. This matches the
behavior of the CLI's `--upload` flag for the demo's payload sizes without
introducing an SSH client dependency. The CLI uses the gateway's HTTP-CONNECT
SSH tunnel from `CreateSshSession`; we deliberately do **not** port that — the
tar-pipe is simpler, has no extra dependencies, and is sufficient for files up
to a few megabytes (the typical notebook scenario).

If a future use case requires preserving permissions or pushing larger payloads
efficiently, switch the implementation behind `upload()` to a streaming SSH
session over the gateway tunnel without changing the public signature.

## Codegen pipeline

Stubs are generated by the `python:proto` task in `tasks/python.toml`:

```sh
mise run python:proto
```

Which runs `grpc_tools.protoc` against `proto/*.proto`, writes outputs to
`python/openshell/_proto/`, and post-processes the generated files to use
package-relative imports (the regex rewrite in `tasks/python.toml`). The stubs
are checked in so end users do not need `protoc` installed to import the
package.

There is no `buf` today. The current setup works; if the SDK gains additional
target languages (Node/TS) the recommendation is to adopt `buf` at that point —
it cleanly replaces the regex import rewrite with proper plugin config and adds
`buf lint` / `buf breaking` for free.

## Out of scope

These are deliberate omissions. They are CLI-thick concerns that don't fit a
client library:

- **Image build and push.** `openshell sandbox create --from Dockerfile` builds
  locally and pushes into the gateway's registry. Not an RPC; not in the SDK.
  Build images via `mise run docker:build` or `docker build` ahead of time and
  pass an image reference.
- **Gateway bootstrap.** `openshell gateway start` provisions a local gateway
  along with mTLS material. Out of scope; the SDK assumes a running gateway.
- **Draft-policy review.** The interactive `policy advisor` flow lives in the
  CLI and TUI.
- **Port-forward helpers.** The CLI's `forward` subcommand binds local ports to
  sandbox services through SSH tunnels. The SDK could expose this later if
  notebooks need it.
- **`RelayStream` / `ConnectSupervisor`.** Internal gateway↔supervisor
  contracts. They are not part of the client surface and never should be.

## Testing

`python/openshell/sandbox_test.py` shows the test pattern: instantiate a
client with `object.__new__(SandboxClient)` to bypass the gRPC channel, then
inject a fake stub object that records the request. New SDK surface should
follow the same pattern — a `_FakeStub` per test, assertions on the request
shape.

Tests run via `pytest python/openshell/`. Lint and typecheck:

```sh
mise run python:lint
mise run python:typecheck
```

## Future work

- **Switch readiness polling to `WatchSandbox` server-streaming.** Today
  `SandboxClient.wait_ready` polls `GetSandbox` once a second. The proto
  already supports streaming snapshots; same blocking signature, fewer RPCs,
  richer events available for verbose modes.
- **Node / TypeScript SDK.** If a Node consumer surfaces, design the Node API
  to mirror the same CLI verbs the Python SDK does. At that point adopt `buf`
  for the codegen pipeline.
- **OIDC bearer auth interceptor.** Mirror the Rust `EdgeAuthInterceptor` for
  gateways behind Cloudflare Access or similar SSO.
