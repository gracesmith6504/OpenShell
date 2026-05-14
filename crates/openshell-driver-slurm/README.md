# Slurm Compute Driver

The Slurm driver runs OpenShell sandboxes as Slurm batch jobs. It is intended
for clusters where the gateway process runs on a login node and compute nodes
launch sandbox workloads through the site scheduler.

The MVP uses Apptainer. The gateway writes a per-sandbox batch script and
environment file into a shared work directory, submits the script with
`sbatch`, and the script runs one `srun apptainer exec` task. The supervisor
binary is bind-mounted into the Apptainer container and connects back to the
gateway endpoint from the compute node.

## Requirements

- `sbatch`, `srun`, `squeue`, and `scancel` available to the gateway user.
- Apptainer available on login and compute nodes.
- A shared work directory visible to login and compute nodes.
- A Linux `openshell-sandbox` binary on the shared filesystem.
- `OPENSHELL_GRPC_ENDPOINT` set to a URL reachable from compute nodes.
- `OPENSHELL_SSH_HANDSHAKE_SECRET` set unless the deployment uses Docker or VM.

## Gateway Example

```shell
openshell-gateway \
  --drivers slurm \
  --db-url sqlite:/shared/openshell/gateway.db?mode=rwc \
  --grpc-endpoint http://login.example.com:8080 \
  --slurm-work-dir /shared/openshell/slurm \
  --slurm-supervisor-bin /shared/openshell/bin/openshell-sandbox \
  --sandbox-image ghcr.io/nvidia/openshell-community/sandboxes/base:latest
```

## Local Validation

Run the local Docker Compose Slurm fixture:

```shell
mise run e2e:slurm
```

The fixture starts login, controller, and compute containers, starts the
gateway on the login node, and runs the smoke e2e against a Slurm job.

To run the same pattern manually from the repository root and observe the
Slurm job while the sandbox is being created:

```shell
COMPOSE_PROJECT=openshell-slurm-demo
HOST_PORT=18080
WORKDIR="$(mktemp -d)"
BIN_DIR="${WORKDIR}/bin"
SANDBOX_CREATE_PID=""

compose() {
  OPENSHELL_SLURM_BIN_DIR="${BIN_DIR}" \
    OPENSHELL_SLURM_GATEWAY_PORT="${HOST_PORT}" \
    docker compose -p "${COMPOSE_PROJECT}" -f e2e/slurm/docker-compose.yml "$@"
}

cleanup() {
  if [ -n "${SANDBOX_CREATE_PID}" ]; then
    kill "${SANDBOX_CREATE_PID}" >/dev/null 2>&1 || true
  fi
  target/debug/openshell sandbox delete slurm-demo >/dev/null 2>&1 || true
  compose exec -T login sh -lc 'kill "$(cat /work/gateway.pid)"' >/dev/null 2>&1 || true
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

cargo build -p openshell-cli --bin openshell --features openshell-core/dev-settings
DAEMON_ARCH="$(docker info --format '{{.Architecture}}')"
case "${DAEMON_ARCH}" in
  amd64|x86_64) PREBUILT_ARCH=amd64 ;;
  arm64|aarch64) PREBUILT_ARCH=arm64 ;;
  *) echo "unsupported Docker architecture: ${DAEMON_ARCH}" >&2; exit 1 ;;
esac

PREBUILT_ARCH="${PREBUILT_ARCH}" tasks/scripts/stage-prebuilt-binaries.sh all
mkdir -p "${BIN_DIR}"
cp "deploy/docker/.build/prebuilt-binaries/${PREBUILT_ARCH}/openshell-gateway" "${BIN_DIR}/"
cp "deploy/docker/.build/prebuilt-binaries/${PREBUILT_ARCH}/openshell-sandbox" "${BIN_DIR}/"
chmod 0755 "${BIN_DIR}/openshell-gateway" "${BIN_DIR}/openshell-sandbox"

export XDG_CONFIG_HOME="${WORKDIR}/config"
export XDG_DATA_HOME="${WORKDIR}/data"

compose up -d --build
until compose exec -T login sinfo -h >/dev/null 2>&1; do sleep 2; done

HANDSHAKE_SECRET="slurm-demo-$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
compose exec -T login sh -lc "
  OPENSHELL_SSH_HANDSHAKE_SECRET='${HANDSHAKE_SECRET}' \
    /opt/openshell/bin/openshell-gateway \
      --bind-address 0.0.0.0 \
      --port 8080 \
      --drivers slurm \
      --disable-tls \
      --db-url 'sqlite:/work/gateway.db?mode=rwc' \
      --grpc-endpoint 'http://login:8080' \
      --sandbox-image 'ghcr.io/nvidia/openshell-community/sandboxes/base:latest' \
      --sandbox-image-pull-policy missing \
      --slurm-work-dir /work/openshell \
      --slurm-apptainer-bin singularity \
      --slurm-extra-apptainer-arg=--writable-tmpfs \
      --slurm-extra-apptainer-arg=--bind \
      --slurm-extra-apptainer-arg=/run/netns:/run/netns \
      --slurm-supervisor-bin /opt/openshell/bin/openshell-sandbox \
      --log-level info \
      >/work/gateway.log 2>&1 &
  echo \$! >/work/gateway.pid
"

until curl -fsS "http://127.0.0.1:${HOST_PORT}/healthz" >/dev/null; do sleep 2; done
target/debug/openshell gateway add "http://127.0.0.1:${HOST_PORT}" --local --name slurm-demo

target/debug/openshell sandbox create --name slurm-demo --no-tty -- /bin/sh -lc 'sleep 120' &
SANDBOX_CREATE_PID="$!"

for _ in $(seq 1 90); do
  compose exec -T login squeue -h -o '%i|%j|%T|%R' | grep openshell && break
  sleep 2
done

compose exec -T login squeue -o '%i|%j|%T|%R'
compose exec -T login sh -lc 'find /work/openshell -maxdepth 2 -type f -name "slurm-*" -print'
```
