# Policy Governance Interceptor

This example implements a gateway interceptor that vends and enforces one source-control governance baseline:

- every sandbox receives the interceptor-vended [`policy.yaml`](policy.yaml)
- every sandbox attaches exactly two provider records: `github` and `gitlab`
- every sandbox gets a policy signature label
- users cannot attach or detach other providers after sandbox creation
- users cannot replace or merge sandbox policy after sandbox creation
- users cannot create provider records other than `github` and `gitlab`
- users cannot update or delete governed provider records after creation

The interceptor is intentionally hardcoded so the policy decision is easy to inspect. The gateway does not preload this policy from config or setup commands; it only calls the interceptor.

## Start the Interceptor

```shell
cargo run -p policy-governance-interceptor -- 127.0.0.1:18098
```

Configure the gateway to call it:

```toml
[[openshell.gateway.interceptors]]
name = "policy-governance"
endpoint = "grpc://127.0.0.1:18098"
order = 100
timeout = "750ms"
failure_policy = "fail_closed"
```

Restart the gateway after editing `gateway.toml`. Gateway startup fails if the interceptor is not reachable.

The TOML does not include a sandbox policy. During sandbox creation, the interceptor patches the sandbox object with its embedded policy and then validates that the final object still matches that policy.

## Create Governed Providers

The interceptor can require provider records, but it cannot create or mint credentials. Create the governed provider records before creating sandboxes:

```shell
openshell provider create \
  --name github \
  --type github \
  --credential GITHUB_TOKEN

openshell provider create \
  --name gitlab \
  --type gitlab \
  --credential GITLAB_TOKEN
```

Then create a sandbox normally, without passing `--policy`:

```shell
openshell sandbox create --name governed -- claude
```

The interceptor patches the create request so the sandbox uses the interceptor-vended policy and the `github` and `gitlab` providers. Requests that include any other provider or a different policy are denied.

The interceptor signs the SHA-256 digest of its embedded `policy.yaml` into an HS256 JWT at
startup. Before it vends or validates the policy, it verifies that JWT against the embedded
policy bytes, checks the local revocation list, and confirms the cached working copy is still
inside its declared freshness window. The sandbox stores the signed JWT in one metadata label:

```text
governance.nvidia.com/signature=<jwt>
```

Sandbox creation is denied if the caller tries to set that reserved label to a different value.
Mutation-capable reviews fail closed when the cached artifact is stale, revoked, or no longer
verifies against the embedded policy payload.
The signing key in this example is static and only demonstrates the workflow. A production
interceptor should use managed key material and asymmetric verification.

## Expected Denials

These operations fail while the interceptor is enabled:

```shell
openshell sandbox provider attach governed other-provider
openshell sandbox provider detach governed github
openshell policy set governed --policy custom-policy.yaml
openshell policy update governed --add-endpoint api.example.com:443:read-only:rest:enforce
openshell provider create --name slack --type generic --credential SLACK_TOKEN
openshell provider update github --credential GITHUB_TOKEN=new-token
openshell provider delete github
```

Non-policy settings updates are allowed.

## Smoke Test

Run the end-to-end smoke test from the repository root:

```shell
bash examples/policy-governance-interceptor/smoke.sh
```

The script builds the gateway, CLI, and interceptor; starts a temporary Docker-backed gateway configured only with the interceptor; and prints one `PASS` or `FAIL` line for each governance case.

The smoke build defaults to `CC=clang`, `CXX=clang++`, and an empty `RUSTC_WRAPPER` so local `sccache` or Homebrew GCC settings do not break native dependency builds. Override those defaults with `SMOKE_CC`, `SMOKE_CXX`, or `SMOKE_RUSTC_WRAPPER` when needed.
