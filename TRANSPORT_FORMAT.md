# Memory Transport HTTP API: v1.6 wire format

**Purpose:** This is the HTTP compatibility contract for a memory engine or adapter used by Sona. An independent engine (including EngramDB) may implement it without using ToastRAM, ToastLink, PostgreSQL, Python, or any particular storage design.

**Implementation reference:** [ToastRAM's frozen transport guide](https://github.com/razor5070/ToastRAM/blob/main/docs/TRANSPORT_V16.md), `toastram_transport.py`, and `toastram_v1_handler.py`. This file documents the current v1.6 wire behavior, not the draft `.toastlink` pairing/SDK protocol.

## Connection

- HTTP/1.1; JSON request and response bodies, UTF-8.
- Use verified HTTPS when connecting over a network. Localhost/SSH forwarding is also supported by the reference adapter. Never disable certificate validation to connect.
- Set `Authorization: Bearer <token>` for protected routes.
- Set `Content-Type: application/json` on JSON POST requests.
- Four memory POST endpoints require an `X-Memory-Request-Id` header containing a **canonical lowercase UUIDv4**. Each distinct HTTP attempt gets a new request ID. The server echoes a valid request ID in the response header, including errors. This is **not** the idempotent save operation ID.
- Authenticate **before** validating the request ID. Invalid credentials and insufficient permissions return `401` on the frozen v1.6 memory routes.
- Maximum request body: 1,048,576 bytes. The save endpoint has its own smaller limit (below).
- The exact `/health` capability flag is `"memory":"memory/v1"`, even though this specification is called transport v1.6.

## Required endpoints

| Method | Route | Scope | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | Public | Readiness and supported memory capability |
| `POST` | `/api/chat` | `chat` | Ollama-compatible chat, optionally with memory retrieval |
| `POST` | `/api/memory/access-check` | `write` | Non-mutating check that durable writes are ready |
| `POST` | `/api/memory/save` | `write` | Durable, idempotent explicit memory save |
| `POST` | `/api/memory/acknowledgements` | `chat` | Non-mutating presentation acknowledgement |
| `GET` | `/api/tags` | `chat` | Ollama-compatible model-list pass-through |
| `POST` | `/api/show` | `chat` | Ollama-compatible model-metadata pass-through |

The four memory POST endpoints are `/api/chat`, `/api/memory/access-check`, `/api/memory/save`, and `/api/memory/acknowledgements`. All four require `X-Memory-Request-Id`.

### 1. Health

`GET /health`

A v1.6-ready service accepting durable writes responds `200`:

```json
{
  "status": "ok",
  "service": "toastram-adapter",
  "writes_enabled": true,
  "capabilities": { "memory": "memory/v1" }
}
```

An independent adapter can use its own `service` name. **Only advertise** `capabilities.memory = "memory/v1"` after the required durable-save functionality is available. The existing ToastRAM adapter omits `capabilities` in legacy mode or when durable writes are not ready.

### 2. Chat with optional memory retrieval

`POST /api/chat`

Example headers (the token is a placeholder):

```http
Authorization: Bearer <token>
Content-Type: application/json
X-Memory-Request-Id: 44bb07c1-5960-4235-a51d-2abe8d87adce
```

Example non-streaming request:

```json
{
  "model": "your-local-model",
  "stream": false,
  "memory_limit": 5,
  "messages": [
    { "role": "user", "content": "What do you remember about the blue cabinet?" }
  ]
}
```

- `messages`, `model`, `tools`, and ordinary Ollama chat parameters retain their Ollama meaning. The adapter preserves tool definitions and model-generated tool-call data; it does **not** execute the tools.
- `memory_limit` is **optional** and must be a JSON integer from **0 through 30**, not a boolean, string, or float.
- **Omitted `memory_limit`:** pure Ollama-compatible chat pass-through, with **no memory lookup** and **no `memory_retrieval` metadata**.
- **`memory_limit: 0`:** no memory lookup, but **do return** empty `memory_retrieval` metadata.
- **`memory_limit: 1..30`:** retrieve up to that many memories, add them to the model's context as reference-only data, and return the retrieval metadata below.
- Optional `retrieval_mode` is an adapter-level selection hint. The reference implementation recognizes `recent` (default), `associative`, and `associative_adaptive`. Internal ranking and search algorithms are **not** part of the HTTP wire contract.
- When `memory_limit` is supplied, strip adapter-only fields `memory_limit`, `retrieval_mode`, and `memory_capture` before forwarding to Ollama. When `memory_limit` is omitted, the reference adapter forwards the request unchanged.
- Model-generated save instructions are parsed by the **desktop/client**, not by this v1.6 chat transport. Do not automatically save a model's response on this route.

Example successful `200` **non-streaming** response (the model's actual content varies):

```json
{
  "model": "your-local-model",
  "message": { "role": "assistant", "content": "The keys were in the blue cabinet." },
  "done": true,
  "memory_retrieval": {
    "requested_limit": 5,
    "returned_count": 1,
    "block_tokens": 18,
    "memory_ids": ["0ebd1b21-ae65-4ef0-a4c8-0ecb1922dc8f"]
  }
}
```

- `memory_ids` contains the selected records' IDs **in the order injected**.
- `returned_count` equals the number of IDs; it cannot exceed `requested_limit`.
- `block_tokens` is a count of the injected memory block, **not** an inference-usage figure. ToastRAM currently uses a provisional whitespace-unit counter, not an exact model tokenizer. Benchmark comparisons must agree on a token counter separately.
- When `memory_limit` is present, the response includes `X-Memory-Retrieval-Us: <nonnegative integer>`, measured in **microseconds** for retrieval and context preparation **before model inference**. It is not total chat latency.

For `"stream": true` (or omitted `stream`), use HTTP/1.1 chunked transfer of Ollama-style **newline-delimited JSON** (NDJSON). Attach `memory_retrieval` **only to the final record with `"done":true`** when `memory_limit` was supplied. Preserve the intermediary model/tool-call records and a terminating `done:true`. If upstream inference disconnects early, the stream must remain visibly incomplete; do not forge a successful `done:true` or terminating chunk.

### 3. Durable-write access check

`POST /api/memory/access-check`

Exact request JSON (plus Bearer authorization and a new UUIDv4 request header):

```json
{ "output": "Memory service access check." }
```

If durable saves are ready, respond `200`:

```json
{ "saved": false }
```

This does **not** write a memory. If durable writes are not enabled, return `500` with `error.code = "save_failed"`.

### 4. Explicit durable save

`POST /api/memory/save`

Exact request keys:

```json
{
  "operation_id": "1237986c-61ca-4a19-a045-5c1cdcfde3ba",
  "content": "The blue cabinet contains the spare keys."
}
```

- `operation_id` is a canonical lowercase UUIDv4 and is **separate from** the `X-Memory-Request-Id` header.
- `content` is a **non-empty UTF-8 string of at most 16,384 bytes**, measured after UTF-8 encoding.
- **First successful commit:** HTTP `201`, `saved:true`, `duplicate:false`.
- **Retry with the same operation ID and identical content:** HTTP `200`, `saved:true`, `duplicate:true`, and the **same stable memory ID**. The retry uses a *new HTTP request ID*, but reuses the *original operation ID*.
- **Same operation ID, different content:** HTTP `409`, `error.code = "conflict"`. Do not overwrite either record.
- **Storage or commit uncertainty:** do not acknowledge a successful save. Return `500`/`save_failed`. The client can retry with the original operation ID.
- Never return `saved:true` before the write is durably committed. The storage mechanism is up to the provider.

First success:

```json
{
  "memory_confirmation": {
    "saved": true,
    "memory_id": "c6c1b25c-ae04-47cb-88f2-9e8617db2eef",
    "duplicate": false
  }
}
```

The duplicate response has the same `memory_id` and `"duplicate":true`.

### 5. UI presentation acknowledgement

`POST /api/memory/acknowledgements`

Exact request keys:

```json
{
  "request_id": "44bb07c1-5960-4235-a51d-2abe8d87adce",
  "time_to_first_byte_ms": 10,
  "time_to_first_visible_token_ms": 20,
  "time_to_last_byte_presented_ms": 40,
  "outcome": "presented"
}
```

- Body `request_id` is the **original chat request ID**, and must **differ** from the current acknowledgement's `X-Memory-Request-Id` header.
- Body `request_id` must be a canonical lowercase UUIDv4.
- All three timing fields are **nonnegative JSON integers or `null`**, in **milliseconds**; no strings, negatives, or booleans.
- `outcome` must be exactly one of `presented`, `suppressed`, `cancelled`, `failed`.
- For `presented`, `time_to_first_visible_token_ms` and `time_to_last_byte_presented_ms` must not be `null`.
- Successful acknowledgement: HTTP `204 No Content`, with an empty body.
- This endpoint is **telemetry, not a durable memory write**. The reference adapter accepts valid acknowledgements even if the original chat request is no longer in its in-memory cache.

### 6. Ollama metadata compatibility

- `GET /api/tags`: return the upstream Ollama model list response, preserving normal model metadata such as names, sizes, and quantization details.
- `POST /api/show`: forward a normal Ollama request such as `{"model":"your-local-model"}` and return its metadata. This route does **not** require `X-Memory-Request-Id` in v1.6.
- Both routes require the `chat` scope. The caller's Bearer credential must **not** be forwarded to Ollama.
- These are explicit routes, not an unrestricted proxy to arbitrary upstream URLs.

## Errors and retries

Frozen v1.6 protocol errors have this JSON shape:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Invalid request ID."
  }
}
```

| Status | `error.code` | Meaning |
| --- | --- | --- |
| `400` | `invalid_request` | Invalid JSON, field, size, or request ID |
| `401` | `unauthorized` | Authentication/required scope failed |
| `409` | `conflict` | Save operation ID was already used with different content |
| `500` | `save_failed` | Durable write unavailable, failed, or unconfirmed |
| `502` | `upstream_unavailable` | Inference backend unavailable/incomplete or chat capacity reached |

Non-TLS loopback installations may also return `429` from rate limiting, using the adapter's general error shape. Upstream Ollama HTTP errors may be passed through with their original status and body. Clients must therefore handle HTTP transport failures without assuming every error response has the frozen nested JSON shape.

**Retry rule:** Preserve the `operation_id` for a save whose outcome is unknown, but issue a new `X-Memory-Request-Id` for every new HTTP attempt. Never interpret a timeout or dropped stream as a confirmed durable save.

## Optional legacy adapter routes (not part of frozen v1.6)

The existing ToastRAM server also supports these routes for older clients:

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/v1/context` | Direct JSON retrieval returning `query`, `memories`, `memory_block`, `count`, and `retrieval` |
| `POST` | `/v1/memories` | Legacy memory insert |
| `DELETE` | `/v1/memories/{id}` | Legacy delete |
| `POST` | `/v1/memory-decisions` | Optional legacy model-directive processing |

These routes have **different** request/response contracts, limits, error shape, and durability behavior. They are **not required** for Memory Transport v1.6 compatibility. In particular, do not treat a successful legacy save as proof of v1.6 durable-save compliance.

## Independent-provider conformance checklist

A memory provider can claim **Memory Transport v1.6 HTTP compatibility** if it:

1. Implements the routes, headers, validation, auth scopes, status codes, and JSON structures above.
2. Preserves ordinary Ollama chat/tool-call behavior in both streaming and non-streaming modes.
3. Observes omitted vs. zero vs. positive `memory_limit` semantics.
4. Provides ordered retrieval metadata and a genuine retrieval-only microsecond timing header.
5. Provides truly durable, replay-safe `operation_id` saves across process restarts.
6. Keeps the memory provider's storage/indexing strategy independent of the transport protocol.
7. Does not require the ToastLink SDK, `.toastlink` files, or ToastRAM branding for compliance.

**Scope:** This document defines *HTTP interoperability*, not the common benchmark corpus, scoring rules, memory-ranking algorithm, or the future secure `.toastlink` enrollment handshake.
