# Walkthrough: run the opencode privacy-redaction demo

A guided, step-by-step run of this example. By the end you will have opencode running in an OpenShell sandbox, checking the weather and answering questions about an image - with image data kept away from the public model and recovered through a private local model on demand.

For architecture and file reference, see [README.md](README.md). This page is the runbook.

> If an AI assistant is helping you through this: when it reaches the API-key step it will ask you to paste your key into `proxy/.env` yourself and wait for you to confirm. It will not ask you to type your key into the chat.

---

## Prerequisites

- macOS or Linux, with [`uv`](https://docs.astral.sh/uv/) installed.
- A private OpenAI-compatible model for the MCP to call. This example defaults to [LM Studio](https://lmstudio.ai) serving a multimodal model at `http://localhost:1234` (the demo uses `nvidia/nemotron-3-nano-omni`). Load a model and start its local server.
- An `NVIDIA_API_KEY` for the public upstream (`https://inference-api.nvidia.com`).

---

## Step 1 - Install OpenShell

Follow the official docs: <https://docs.nvidia.com/openshell/> (Installation page). The one-liner:

```shell
curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
```

This installs the `openshell` CLI and a local gateway. Confirm a gateway is active:

```shell
openshell gateway list
```

You should see one row marked active (`*`). The local gateway is reachable from sandboxes as `host.openshell.internal` - that is how the sandbox talks back to the proxy and MCP on your host.

---

## Step 2 - Start the host services (proxy + MCP)

```shell
cd examples/opencode-privacy-redaction/proxy
cp .env.example .env
uv sync
```

Now add your API key:

1. Open `proxy/.env` in your editor.
2. Set `NVIDIA_API_KEY=` to your key.
3. Save the file.

When that is done, start both services:

```shell
make start          # starts the MCP (:8001) and the proxy (:8000)
```

Check they are up:

```shell
curl -s http://127.0.0.1:8000/v1/models      # should list openai/openai/gpt-5.5
make tail-proxy-log                            # leave this open to watch decisions
```

Both bind to `0.0.0.0` so the sandbox can reach them via `host.openshell.internal`.

---

## Step 3 - Wire `inference.local` to the proxy (one-time)

```shell
openshell provider create --name local-proxy --type openai \
  --credential OPENAI_API_KEY=dummy \
  --config OPENAI_BASE_URL=http://host.openshell.internal:8000/v1

openshell inference set --provider local-proxy --model openai/openai/gpt-5.5 --no-verify
```

`--no-verify` is expected: host-side validation cannot resolve `host.openshell.internal`, but runtime egress from inside the sandbox works.

---

## Step 4 - Create the opencode sandbox

```shell
cd ../sandbox
./setup-sandbox.sh
```

This creates the `opencode` sandbox, writes its config, starts `opencode web` inside it, exposes the service through the gateway, and **opens the web UI in your browser automatically**.

If the browser does not open, use the URL printed at the end (e.g. `http://opencode--web.openshell.localhost:18080/`).

---

## Step 5 - Run the demo

In the web UI, start a chat (the default model is `gpt-5.5 (inference.local)`).

**Check the weather** - just ask, e.g. "What's the weather in Victoria, BC tomorrow?" The sandbox policy already allows the weather data sources.

**The privacy magic - before vs after.** The proxy reads `policies/content-policy.yaml` on every request, so you flip behavior live (no restart). From `examples/opencode-privacy-redaction/proxy`:

```shell
make demo-status     # show the current rule
make demo-allow      # images pass through to the public model
make demo-redact     # images are stripped; recovered via the local_model MCP
```

1. With `make demo-allow`, attach an image and ask about it. In the proxy log you'll see `image_redaction_skipped reason=allowed_by_policy` - the image went to the public model.
2. Run `make demo-redact`, then send another image. The log shows `image_redaction_applied`, the image is replaced with a note, and opencode calls the `local_model` MCP tool to read it from the private model. The image never reaches the public model.

Request/response captures land in `proxy/request-logs/` if you want to inspect exactly what was sent.

---

## Troubleshooting

- **Web UI shows 403 / `policy_denied`**: the sandbox policy is missing a host. `app.opencode.ai` (the web SPA) and the weather hosts are already included; if you add a tool that needs another host, approve it and add it to `policies/opencode-policy.yaml`.
- **`opencode mcp list` shows the server disconnected**: make sure `make start` is running and `:8001` is reachable; the MCP must bind `0.0.0.0`.
- **MCP image extraction returns nothing useful**: your private model at `:1234` must be multimodal and loaded. Check `curl http://localhost:1234/v1/models`.
- **Inference errors**: confirm `NVIDIA_API_KEY` in `proxy/.env` and that Step 3 ran (`openshell inference get`).

---

## Tear down

```shell
cd examples/opencode-privacy-redaction/proxy && make stop
openshell service delete opencode web
openshell sandbox delete opencode
```

---

Questions or something not behaving? Check the proxy log (`make tail-proxy-log`) and the sandbox OCSF log (`openshell logs opencode --source sandbox --since 10m`), or just ask - happy to help debug.
