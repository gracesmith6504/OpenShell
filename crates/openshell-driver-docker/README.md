# openshell-driver-docker

Docker-backed compute driver for local OpenShell gateways.

The driver manages sandbox containers through the local Docker daemon with the
`bollard` client. It is intended for developer environments where Docker is
already available and running Kubernetes would be unnecessary.

## Runtime Model

The gateway runs as a host process. The Docker driver creates one container per
sandbox and starts the `openshell-sandbox` supervisor inside that container. The
supervisor then creates the nested sandbox namespace for the agent process.

Docker containers join an OpenShell-managed bridge network. The driver injects
`host.openshell.internal` and `host.docker.internal` so supervisors have stable
names for reaching the gateway host. On Docker Desktop, Colima, Rancher
Desktop, OrbStack, and macOS-hosted gateways, those names use Docker's
`host-gateway` alias. On native Linux Docker, the gateway also binds the bridge
gateway IP so containers can call back to the host process.

## Container Instance Ownership

Docker labels identify containers for discovery and cleanup. They do not grant
authority to represent a persisted sandbox because another Docker client can
copy them. The driver records the authoritative container ID from the Docker
create response and restores it from `Sandbox.status.agent_pod` at gateway
startup. New containers also receive a driver-issued instance-generation label.
That label is not a secret; it is checked against an owner-only journal under
`$XDG_STATE_HOME/openshell/docker-sandbox-instances/<sha256(namespace)>/`, so
generic copied identity labels are insufficient to authorize a replacement.
The local Docker driver assumes that Docker-daemon access remains trusted host
authority.

The journal is written after Docker returns the created container ID and before
the driver publishes it as managed. It durably records the current ID, earlier
IDs, generation, and any exact replacement intent. A crash before the first
journal write fails closed as unresolved ownership. A crash after a replacement
journal commit can recover even if the public sandbox status still contains the
previous ID.

The driver permits one compatibility handoff used by NemoClaw's Docker GPU
patch. The current authoritative container must remain present in the `exited`
state under the exact `<canonical-name>-nemoclaw-gpu-backup-<digits>` name while
exactly one active replacement uses the canonical name and carries the recorded
generation. The first consistent observation journals an intent for those exact
container IDs; a subsequent consistent observation adopts the replacement. If
polling observes the gap or misses the overlap, the durable sandbox is retained.
One canonical, generation-matching replacement can then be authorized and
adopted through the same two-observation intent without resurrecting a skeletal
sandbox record.

Ambiguous candidates, terminal replacements, interrupted intents, and missing
or incorrect generations fail closed as ownership conflicts. Containers created
by an older driver without a journaled generation cannot use the external
handoff; recreate them through OpenShell first so the driver can establish the
generation. Explicit sandbox deletion removes every exact identity match, then
clears the driver's in-memory and journaled ownership.

Missing instances, ignored unowned containers, duplicate candidates, rejected
replacements, and accepted handoff or rollback transitions produce deduplicated
warnings and warning-level driver platform events. Notices generated before a
watcher subscribes remain eligible for delivery on the first watched snapshot.

## Container Contract

The driver-controlled container settings are part of the sandbox security
contract:

| Setting | Purpose |
|---|---|
| `user = "0"` | The supervisor needs root inside the container to prepare namespaces, mounts, Landlock, and seccomp. |
| `network_mode = openshell` | Places the supervisor on the managed Docker bridge network. |
| `cap_add` | Grants supervisor-only capabilities required for namespace setup and process inspection. |
| `apparmor=unconfined` | Avoids Docker's default profile blocking required mount operations. |
| `restart_policy = unless-stopped` | Keeps managed sandboxes resumable across daemon or gateway restarts. |
| `PidsLimit` | Enforces the sandbox PID budget at the Docker cgroup layer. Set `[openshell.drivers.docker].sandbox_pids_limit = 0` to inherit the Docker/runtime default. |
| CDI GPU request | Uses opaque `driver_config.cdi_devices` values when set; otherwise selects the requested count of NVIDIA CDI GPUs in round-robin order when daemon CDI support is detected. Docker daemon `/info` can permit `nvidia.com/gpu=all` as a WSL2 all-only compatibility fallback, where it counts as one selectable device. Exact CDI device lists must not contain duplicates and must match the effective GPU count. |

The agent child process does not retain these supervisor privileges.

## Driver Config Mounts

The gateway forwards the `docker` block from `--driver-config-json` to this
driver. The driver accepts user-supplied `mounts` entries with these Docker
mount types:

- `bind`: mounts an absolute host path when `[openshell.drivers.docker]`
  has `enable_bind_mounts = true`.
- `volume`: mounts an existing Docker named volume. The driver validates that
  the volume exists before provisioning and never creates or removes it.
  Docker local-driver volumes created with bind options are treated as host
  bind mounts and require `enable_bind_mounts = true`.
- `tmpfs`: mounts an in-memory filesystem with optional `options`,
  `size_bytes`, and `mode`.

Host bind mounts are disabled by default because they expose gateway host
paths to sandbox requests. Image mounts are not part of the Docker
driver-config schema. The driver still uses internal bind mounts for
OpenShell-owned supervisor, token, and TLS material.

Docker `bind` mounts accept `source`, `target`, and optional `read_only`.
Docker `volume` mounts may include `subpath`. User-supplied bind and volume
mounts are read-only by default; set `read_only: false` to make them writable.
Mount targets must be absolute container paths and must not replace the
workspace root (`/sandbox`) or overlap OpenShell supervisor files,
`/etc/openshell`, `/etc/openshell-tls`, or `/run/netns`.

Example named-volume usage:

```shell
docker volume create openshell-work

openshell sandbox create \
  --driver-config-json '{"docker":{"mounts":[{"type":"volume","source":"openshell-work","target":"/sandbox/work"}]}}' \
  -- claude
```

## Supervisor Binary Resolution

The Docker driver bind-mounts a host-side Linux `openshell-sandbox` binary into
each sandbox container. Resolution order is:

1. `supervisor_bin` in `[openshell.drivers.docker]`.
2. `supervisor_image` in `[openshell.drivers.docker]`, extracting
   `/openshell-sandbox` from that image.
3. A sibling `openshell-sandbox` next to the running `openshell-gateway` binary.
4. A local Linux cargo target build for the Docker daemon architecture.
5. The release-matched default supervisor image, extracting `/openshell-sandbox`.

Release and Docker-image gateway builds bake the matching supervisor image tag
into the binary at compile time. The default Docker supervisor image is not
`:latest` unless a custom build explicitly sets that tag.

## Callback and TLS

`OPENSHELL_ENDPOINT` is injected from the gateway's configured gRPC endpoint.
When no endpoint is configured, the driver uses
`host.openshell.internal:<gateway-port>` with the appropriate HTTP or HTTPS
scheme. Set `host_gateway_ip` only when the host has an explicit, locally
assigned address that containers should use for callbacks; package-managed
macOS gateways should leave it unset.

For HTTPS endpoints, the server certificate must include the endpoint host as a
subject alternative name. Docker sandboxes also need the client TLS bundle
mounted into the container and exposed with:

- `OPENSHELL_TLS_CA`
- `OPENSHELL_TLS_CERT`
- `OPENSHELL_TLS_KEY`

HTTP endpoints reject TLS material because the supervisor would not use it.

## Environment Ownership

The driver merges template environment and sandbox spec environment first, then
overwrites security-critical keys:

- `OPENSHELL_ENDPOINT`
- `OPENSHELL_SANDBOX_ID`
- `OPENSHELL_SANDBOX`
- `OPENSHELL_SSH_SOCKET_PATH`
- `OPENSHELL_SANDBOX_COMMAND`
- TLS path variables when HTTPS is enabled

Do not allow sandbox images or templates to override these values.
