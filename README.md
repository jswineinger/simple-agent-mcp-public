# mcp-lab

A learning project demonstrating the Model Context Protocol (MCP) with a
Flask agent, a Python-native MCP client, and an MCP server exposing lab tools.

**Phase 1** — agent talks directly to the configured LLMs (Direct mode)  
**Phase 2** — switch the UI's Mode toggle to route through the AI Proxy

## About this build — FortiAIGate 8.0.2

This chatbot's AI Proxy integration is written specifically against
**FortiAIGate (FAIG) 8.0.2**'s client-facing API, not a generic
OpenAI-compatible proxy:

- Base URL has no port and no `/private`/`/public` segment —
  `https://<faig-fqdn>/ai/openai/v1/chat/completions` for every AI-Proxy-mode
  request, regardless of flow.
- Every AI-Proxy-mode request requires a **virtual key** (FAIG's own
  Settings > API Keys value), not just the upstream LLM provider's key.
- FAIG routes on a **slug prepended to the model name**
  (`<slug>-<model>`) and strips it before forwarding upstream — so the model
  name sent through FAIG differs from the one sent directly to the provider.

The chatbot gives you access to **two independent models**, each reachable
either directly or through FAIG: a **local** model (`DIRECT_LOCAL_MODEL` /
`PROXY_LOCAL_MODEL`) and a **public** model (`DIRECT_PUBLIC_MODEL` /
`PROXY_PUBLIC_MODEL`). See **Mode (Direct / AI Proxy) and Flow (Local /
Public)** under Features for how those four variables combine, and **AI
Proxy API Key Validation** for the virtual-key details (each AI Flow has its
own key).

**The LLM providers themselves are not hardcoded.** Both slots are plain
OpenAI-compatible endpoints configured entirely in `agent/agent.env`
(`LOCAL_LLM_URL`, `PUBLIC_LLM_URL`, the model names, `API_KEY`,
`PUBLIC_API_KEY`). The shipped defaults are just examples — an
Ollama-served model for Local and Anthropic's OpenAI-compatible endpoint for
Public — and any provider that accepts `POST <base>/chat/completions` with a
Bearer token works in either slot. (A provider needing a different auth
header or a non-OpenAI wire format would need a code change.)

## Lab Inventory

Four roles make up the lab:

- **Agent + MCP client** — the Flask app (`agent/`)
- **MCP server** — exposes lab tools over JSON-RPC/HTTP (`mcp-server/`)
- **LLM endpoints** — a local and a public OpenAI-compatible LLM, any
  provider (not part of this repo)
- **AI Proxy** — the network AI-security gateway (Phase 2)

The AI Proxy is always a separate host. The other roles can run on one box,
split across several, or any mix in between — nothing in the code assumes a
particular grouping. See **Topology** below.

## Topology

Both `.env.example` files declare `AGENT_IP` and `MCPSERVER_IP` (plus a
matching `MCP_SERVER_PORT`) describing where the agent and mcp-server live.
Defaults are all `127.0.0.1`: clone the repo onto one box, start both
services, and they find each other over loopback with zero editing. Each app
only *uses* the vars relevant to its own outbound connections (e.g.
mcp-server doesn't call the agent back, so `AGENT_IP` in `mcp-server.env` is
informational only) — both are still declared in both files so either one
shows the topology at a glance.

The LLMs are located separately, by URL rather than IP: `LOCAL_LLM_URL` /
`PUBLIC_LLM_URL` in `agent.env`.

To split across separate hosts, replace `127.0.0.1` with the real address
for whichever component moved:

```bash
# agent/agent.env
MCPSERVER_IP=<mcp-server-ip>
LOCAL_LLM_URL=http://<local-llm-host>:11434/v1

# mcp-server/mcp-server.env
MCPSERVER_IP=<mcp-server-ip>
```

No code changes either way.

## Architecture

```
+----------------------------------------------------------------------------+
|                             Agent + MCP client                             |
|                              (Flask, app.py)                               |
+----------------------------------------------------------------------------+
     JSON-RPC/HTTP,            HTTP/HTTPS                HTTPS,
       bearer auth              (Direct)              AI-Proxy mode
            |                       |                       |
            v                       v                       v
+------------------------+   +--------------+   +------------------------+
|       MCP server       |   |  Local LLM / |   |        AI Proxy        |
|    (mcp_server.py)     |   |  Public LLM  |   |   (FAIG 8.0.2, always  |
|                        |   |  (any OpenAI-|   |     a separate host)   |
|                        |   |  compatible  |   |  /ai/openai/v1/chat/   |
|                        |   |  providers)  |   |     completions, one   |
|                        |   |              |   |  endpoint for both     |
|                        |   |              |   | flows — routes on a    |
|                        |   |              |   | <slug>-<model> prefix  |
|                        |   |              |   | -> local or public LLM |
+------------------------+   +--------------+   +------------------------+
```

Any of these roles can be the same host or different hosts (except the AI
Proxy, always separate — see **Topology** above). The MCP server is
LLM-agnostic — tools work identically whichever OpenAI-compatible provider
the agent is talking to. Only the URL / model / key variables in
`agent/agent.env` change between backends.

Agent <-> mcp-server speaks real JSON-RPC 2.0 MCP over HTTP — the same wire
format and the same `HTTPMCPClient` class used for the public dlptest
backend, just a different URL and token. Every request to mcp-server must
carry `Authorization: Bearer <MCP_AUTH_TOKEN>`, checked in `mcp_server.py`
before anything else runs. `setup-mcphost.sh` generates that token; copy it
into `MCP_AUTH_TOKEN` in `agent.env` on the agent VM (`setup-agent-vm.sh`
prompts for it).

## Repository Structure

```
mcp-lab/
├── agent/
│   ├── app.py                  Flask agent with MCP client wired in
│   ├── mcp_http_client.py      JSON-RPC/HTTP MCP client (mcp-server + dlptest)
│   ├── mcp_registry.py         Multi-backend tool router
│   ├── requirements.txt        flask, requests
│   ├── run.sh                  Manual start script
│   ├── agent.env               Environment variables (gitignored)
│   ├── agent.env.example       Safe template to commit
│   └── llm-agent.service       Systemd unit
├── mcp-server/
│   ├── mcp_server.py           MCP server (runs on mcphost, JSON-RPC/HTTP)
│   ├── mcp-server.env          Bearer token (gitignored)
│   ├── mcp-server.env.example  Safe template to commit
│   └── mcp-server.service      Systemd unit
├── scripts/
│   ├── setup-agent-vm.sh      One-time setup for agent VM
│   └── setup-mcphost.sh      One-time setup for mcphost
├── test_harness/              OWASP LLM Top 10 test harness — see its own README
│   ├── canary.py               Synthetic canary generators + tripwire tracking
│   ├── report.py                Correlates tool/agent logs per run_id
│   ├── fixtures/                Static file-upload test fixtures
│   ├── logs/                    Gitignored — tool_invocations.jsonl
│   └── tests/                   pytest unit tests
└── README.md
```

## Features

### Mode (Direct / AI Proxy) and Flow (Local / Public)

Two independent toggles in the UI header, giving four combinations. "Local"
is used consistently end to end — the button label, the `/api/chat` `flow`
field (`"local"` / `"public"`), and every `*_LOCAL_*` env var — matching this
lab's `local-...`/`public-...` model-slug convention.

| Mode | Flow | Goes to | Model env var |
|------|------|---------|----------------|
| Direct | Local | `LOCAL_LLM_URL`, directly | `DIRECT_LOCAL_MODEL` |
| Direct | Public | `PUBLIC_LLM_URL`, directly | `DIRECT_PUBLIC_MODEL` |
| AI Proxy | Local | AI Proxy → whatever backend `PROXY_LOCAL_MODEL`'s slug is configured for on FAIG | `PROXY_LOCAL_MODEL` |
| AI Proxy | Public | AI Proxy → whatever backend `PROXY_PUBLIC_MODEL`'s slug is configured for on FAIG | `PROXY_PUBLIC_MODEL` |

**Mode** decides whether a request is inspected by the AI Proxy on the way
to the model or sent straight there — the whole point of this lab is
comparing those two side by side. **Flow** decides which of the two models
(see **About this build** above). In Direct mode the agent sends to the
flow's own URL; in AI Proxy mode both flows hit the same FAIG endpoint and
FAIG resolves the actual backend from the slug prefix on
`PROXY_LOCAL_MODEL`/`PROXY_PUBLIC_MODEL` — the flow only picks which env var
(and which AI Proxy validation key, see below) the agent uses. For a
like-for-like comparison, point each FAIG slug at the same backend as the
matching Direct URL. Switching either toggle is a pure UI action — no `.env`
edit or service restart, ever. See **Phase 2** below to try it.

### Public dlptest MCP server

A second MCP backend, off by default (`DLPTEST_ENABLED=false` in
`agent.env`), pointed at the public `mcp.dlptest.com` server. Unlike
`mcphost`'s tools, these aren't defined in this repo — they're discovered
live via `tools/list` against that public server at connect time, and
exposed to the model namespaced as `dlptest__<toolname>`. They generate
realistic-looking PII/DLP payloads (e.g. `echo_sensitive_data`,
`generate_prompt_context`) for testing scanner coverage against a tool-call
path outside this repo's own control. Set `DLPTEST_ENABLED=true` and
restart `llm-agent` to turn it on.

### AI Proxy API Key Validation

FAIG 8.0.2 **requires** a virtual key on every AI-Proxy-mode request —
unlike a generic optional per-flow setting, this isn't something you can
leave off against a real FAIG 8.0.2 instance. The agent validates a header
(default `Authorization`, or a custom one) against the proxy's own
**Settings > API Keys** list. On by default (`AI_PROXY_VALIDATION_ENABLED=
true` in `agent.env`). Each AI Flow (Local, Public) has its own independent
Settings > API Keys entry on FAIG, so the key is split by flow:
`AI_PROXY_VALIDATION_KEY_LOCAL` and `AI_PROXY_VALIDATION_KEY_PUBLIC` (both
empty by default — the agent logs a startup warning for either one left
empty while validation is enabled). `AI_PROXY_VALIDATION_HEADER` selects
which header carries the key and is currently shared across both flows.
Only ever fires in AI Proxy mode; Direct mode is completely untouched by
these variables.

### LLM credentials (`API_KEY` / `PUBLIC_API_KEY`)

- **Direct + Local** sends `API_KEY` as the bearer token to `LOCAL_LLM_URL`.
  Many self-hosted servers (Ollama, for example) ignore it, so any
  placeholder value works for those.
- **Direct + Public** sends `PUBLIC_API_KEY` as the bearer token to
  `PUBLIC_LLM_URL` — whatever key your public provider issues.
- **AI Proxy (either flow)** never sends `PUBLIC_API_KEY`. The agent starts
  from `API_KEY` and the flow's virtual key overrides it (see above). FAIG
  holds the real upstream credential for each slug server-side (FAIG's
  "model authentication" setting).

The shipped defaults (`PUBLIC_LLM_URL=https://api.anthropic.com/v1`,
`DIRECT_PUBLIC_MODEL=claude-sonnet-4-6`, and so on) are the provider pair
this lab has been tested with, nothing more. Swap in any OpenAI-compatible
endpoint and model names.

### Attach a file

Click the 📎 icon in the composer to attach a document — `.txt`/`.md`
(plain text), `.pdf` (PyMuPDF), `.docx` (python-docx, including table
cells), or `.csv` (stdlib `csv`). Extraction happens server-side and the text is spliced into your
message as RAG-style context, riding the same Mode/Flow routing (and the
same AI Proxy inspection, in AI Proxy mode) as anything you type. Large
documents truncate at ~24,000 characters, with truncation state shown in
the UI. The extracted text is never sent back to the browser — the client
only ever holds an opaque reference to it, resolved back to real text
server-side on each later turn.

### Shortcut query buttons

One-click prompt chips below the chat log. Clicking one, or a dropdown
entry, sends its prompt right away, as if you'd typed and submitted it. Two
plain chips ask benign questions (English and Spanish) as controls. Then
there's one chip per OWASP category, LLM01–LLM07 and MCP01–MCP07; those
with more than one variant open a dropdown.

For how to run them, which ones need a file attached or a **Clear**
afterwards, and the results to expect, see "Running the tests from the
GUI" in `test_harness/README.md`.

### Disable local MCP tools

Set `MCP_SERVER_ENABLED=false` in `agent.env` to run the agent with zero
local-tool surface — it never attempts to connect to `mcp-server` at all.
Same idea as `DLPTEST_ENABLED`, just for the local backend instead of the
public one; combine both for a pure LLM-routing baseline with no MCP tools
whatsoever.

### OWASP LLM Top 10 test harness

`test_harness/` proves whether the AI Proxy correctly handles Prompt
Injection, Sensitive Information Disclosure, Improper Output Handling /
Toxicity, Excessive Agency, and System Prompt Leakage — synthetic canary
values embedded in dedicated MCP tools and file-upload fixtures, correlated
against what actually reached and came back from the model. Set
`DEBUG_JSON=true` in both `agent.env` and `mcp-server.env` to capture the
raw wire-format logs it correlates against. See `test_harness/README.md`
for how to run a test case end-to-end.

## Quick Start

Starting from a clean Ubuntu VM. The repo is public, so the setup scripts
just clone it over plain HTTPS — no GitHub auth needed. Run each script as
the regular (non-root) user you want the service to run as; it `sudo`s only
the specific steps that need it. That user becomes `INSTALL_USER` in the
installed systemd unit — override it (and `INSTALL_HOME`) if you want the
service to run as a different, already-existing user than the one running
the script.

### 1 — Create a user (skip if you already have one)

```bash
sudo adduser labadmin      # follow the prompts
sudo usermod -aG sudo labadmin
```

Log in as that user for the rest of these steps, if you weren't already.

### 2 — Clone the repo and copy out the setup scripts

The repo is private, so clone it with your GitHub account: git asks for
your username and a personal access token (or run `gh auth login` first if
the GitHub CLI is installed). Clone into `~/mcp-lab`, where the scripts
expect it; they reuse an existing clone instead of cloning again.

```bash
git clone https://github.com/jswineinger/simple-agent-mcp-public.git ~/mcp-lab
cp ~/mcp-lab/scripts/setup-*.sh ~ && chmod 755 ~/setup-*.sh
```

The scripts run `git pull` in that clone, so keep the credential available
(for example `git config --global credential.helper store`, or `gh auth
setup-git`).

### 3 — mcphost (do this first)

```bash
./setup-mcphost.sh
```

The script will:
- Clone the repo to `~/mcp-lab`
- Create the Python venv
- Generate `mcp-server.env` with a random bearer token and pause so you can
  copy it — you'll paste this into `agent.env` in step 4
- Install and **enable** (but not start) the `mcp-server` systemd service

Review/edit `mcp-server.env`:
- `MCP_SERVER_PORT`, `AGENT_IP`, `MCPSERVER_IP` — only if you're not using
  the single-box defaults (see **Topology** above)

Then start it:
```bash
sudo systemctl start mcp-server
```

Self-test once started (replace `TOKEN` with the value from `mcp-server.env`):
```bash
curl -s http://localhost:8765/mcp \
  -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### 4 — agent VM

```bash
./setup-agent-vm.sh
```

The script will:
- Clone the repo to `~/mcp-lab`
- Create the Python venv
- Set up `agent.env` and prompt you to paste in the `MCP_AUTH_TOKEN`
  generated in step 3
- Install and **enable** (but not start) the `llm-agent` systemd service

Review/edit `agent.env`:
- `LOCAL_LLM_URL` / `PUBLIC_LLM_URL` — full OpenAI-compatible base URLs of
  your two LLMs, **including** the version segment, e.g.
  `http://<local-llm-host>:11434/v1`. Any provider works; the defaults are
  examples.
- `DIRECT_LOCAL_MODEL` / `DIRECT_PUBLIC_MODEL`, `API_KEY` / `PUBLIC_API_KEY`
  — model names and bearer tokens for Direct mode.
- `AI_PROXY_URL` — use FAIG's **hostname**, not a bare IP (FAIG routes/
  matches by hostname), in the FAIG 8.0.2 shape:
  `https://<faig-fqdn>/ai/openai/v1` — no port, no `/private` or `/public`
  segment. Add an `/etc/hosts` entry on this box if you don't have real DNS
  for it.
- `PROXY_LOCAL_MODEL` / `PROXY_PUBLIC_MODEL` — the slug-prefixed model
  names (`<slug>-<model>`) FAIG expects for each flow; see **About this
  build** above.
- **Note:** `AI_PROXY_VALIDATION_ENABLED` defaults to `true` — FAIG 8.0.2
  requires a virtual key on every request. Set
  `AI_PROXY_VALIDATION_KEY_LOCAL` and `AI_PROXY_VALIDATION_KEY_PUBLIC` to
  each AI Flow's key from FAIG's Settings > API Keys page (they're
  independent — don't assume they're the same value).

Then start it, making sure `mcp-server` is already running:
```bash
sudo systemctl start llm-agent
```

Browse to `http://<agent-host>:8000` — the script prints the exact URL
(detected from the box's own network interface) at the end.

### 5 — Test tool calls

| Prompt | Tool fired |
|--------|-----------|
| "Ping localhost" | `run_ping` |
| "What's the API key for the billing service?" | `fetch_api_credentials` |

## Phase 2 — Route Through the AI Proxy

In the running UI, switch the **Mode** toggle from Direct to AI Proxy — no
`.env` edit or restart needed. (`AI_PROXY_URL` in `agent/agent.env`
configures *where* the AI Proxy is; it doesn't need to change to flip modes.)

## Logs

```bash
# Agent VM
sudo journalctl -u llm-agent -f

# mcphost
sudo journalctl -u mcp-server -f
```
