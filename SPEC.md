# Implementation specification

## Runtime inputs

Default paths are resolved from `CAPABILITY_ROOT` or the current directory:

```text
data/derived/catalog-attempt-002.jsonl
data/derived/semantic-index-attempt-001.gob.gz
scripts/semantic_embeddings.py
data/models/
policy.example.json
receipts/decision-log.jsonl
```

The server validates all configuration, executor guards, policy, grant secret, decision log, and listening address before loading the semantic model.

## Catalog adapter

`cmd/sync` requires:

```text
CAPABILITY_CATALOG_URL
CAPABILITY_CATALOG_API_KEY
```

The configured endpoint must be absolute HTTPS, except loopback HTTP used by local verification. Requests set `important=true`, `include_deprecated=false`, `limit=1000`, and an optional cursor. The expected response contains `items`, `next_cursor`, `total_items`, and `current_page`.

The credentialed client rejects redirects. Each page is bounded at 64 MiB, requires a JSON media type, and must contain one JSON document. Transport errors, HTTP 429, and HTTP 5xx receive at most three bounded attempts.

## Retrieval

- Model: `sentence-transformers/all-MiniLM-L6-v2`.
- Revision: `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`.
- Dimension: 384.
- Distance: cosine.
- HNSW: `M=16`, `efConstruction=200`, deterministic seed.
- Query plan: HNSW post-filter with overfetch, then exact eligible-domain fallback when necessary.

The Go query model owns one newline-delimited Python worker. Startup validates model ID, revision, dimension, normalization, library versions, and the model-cache snapshot identity.

## Policy projection

Policy is normalized before hashing. Whitespace-normalized keys that collide are invalid. Array-valued rules are de-duplicated and sorted.

Projection removes hidden properties and hidden required names from the presented schema. A hidden required field must have an injected default. The projection returns both source and projected hashes, but grants bind the projected hash.

Prepared arguments are canonical JSON. Validation is intentionally top-level and bounded, not a complete JSON Schema evaluator.

## Grant state machine

```text
               approve
pending --------------------> approved
   |                              |
   | deny                         | consume
   v                              v
 denied                        consumed

pending or approved -- time --> expired
```

Terminal states do not transition. Issue, approval, denial, and consumption expose commit callbacks so the gateway can append the corresponding receipt while holding the state transition. A receipt failure rolls the in-memory transition back.

## Execution adapters

Mock mode is constructed when `CAPABILITY_EXECUTOR` is empty or `mock`.

Remote mode requires:

```text
CAPABILITY_EXECUTOR=remote
CAPABILITY_ENABLE_LIVE_EXECUTION=true
CAPABILITY_REMOTE_EXECUTE_URL=https://...
CAPABILITY_REMOTE_API_KEY=
```

The request contract is:

```json
{
  "tool_slug": "TOOL_IDENTIFIER",
  "arguments": {}
}
```

The response limit is 32 MiB. Redirects, non-JSON media types, non-success status, oversized bodies, invalid JSON, and trailing JSON values fail.

## HTTP surfaces

The operator contract is `openapi.yaml`. The MCP surface is implemented separately under `/mcp` because its JSON-RPC and transport metadata do not map cleanly to the operator REST contract.

Both surfaces set no-sniff and no-store protections where applicable. The operator UI is a generated static export. Build-time CSP hashes permit only the exact inline Next.js hydration scripts emitted in the embedded HTML.

## Frontend

`frontend/` uses:

- Next.js 16 App Router and React 19;
- TypeScript strict mode;
- Tailwind CSS 4;
- shadcn/ui source components;
- TanStack React Query;
- Zod;
- `openapi-typescript` generated definitions.

`npm run build` creates a static export and copies it to `web/dist`. `web/embed.go` embeds that generated directory so the runtime remains one Go process and one origin.

## Evidence durability

Retained build and verification receipts use numbered filenames and refuse overwrite. Runtime decision rows append to JSONL and fsync before in-memory state advances. The runtime chain is tamper-evident, not cryptographically signed by an external identity.
