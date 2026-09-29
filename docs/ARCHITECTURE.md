# Architecture

## Runtime shape

```text
Browser
  |
  | same-origin HTML, assets, and JSON
  v
Go HTTP server
  |-- Next.js static export
  |-- /api/* operator contract
  |-- /mcp protocol contract
  |
  v
Capability gateway
  |-- semantic retrieval: pinned MiniLM + HNSW + exact fallback
  |-- policy: eligibility + schema projection + defaults
  |-- grants: HMAC binding + approval + expiry + single-use admission
  |-- evidence: append-only hash chain
  `-- executor adapter: mock by default, explicitly configured remote endpoint
```

This is a process-local system. There is no database, queue, tenant layer, or distributed grant coordinator. That is an intentional limit, not hidden infrastructure.

## Module boundaries

- `frontend/`: Next.js App Router source, generated OpenAPI types, React Query hooks, and shadcn/ui components.
- `web/dist/`: generated static export embedded by Go. It is build output, not an authored UI layer.
- `internal/control`: HTTP adapter for the operator OpenAPI contract and static files.
- `internal/mcphttp`: MCP Streamable HTTP adapter.
- `internal/gateway`: application orchestration between retrieval, policy, grants, receipts, and execution.
- `internal/policy`, `internal/grant`, `internal/receipt`: security boundary modules.
- `internal/search`, `internal/semantic`: retrieval over the independently preserved vector engine pieces.
- `internal/catalog`, `internal/remotehttp`, `internal/gateway/executor.go`: provider-neutral adapter seam.
- `internal/upstream`: version B. An MCP client (official Go SDK, stdio) for LatentGraph's server whose discovered tools satisfy `gateway.Catalog` through a BM25 index, and whose calls satisfy `gateway.Executor`. The gateway depends only on those two interfaces, so neither version knows about the other.

## API and type ownership

`openapi.yaml` is the operator API contract. The frontend generates TypeScript definitions from it and does not declare parallel response interfaces. Go remains the runtime implementation; the verifier exercises the same routes.

## Build and serving

`npm run build` inside `frontend/` performs a Next.js static export and synchronizes it to `web/dist/`. The Go `embed` package then includes that directory in the server binary. Client-side requests use relative `/api/*` URLs, preserving one origin and one launch command.

## Error handling

- The backend returns `{ "error": "..." }` for operator API failures.
- The client verifies JSON content type and valid JSON before accepting a response.
- React Query owns server state, retry policy, loading state, and refresh behavior.
- Execution success is committed to the interface before follow-up grant and receipt refreshes, so a refresh failure cannot rewrite the effect outcome.

## Security decisions

- Server binds to loopback only.
- Origin, body-size, method, and JSON-shape checks remain at the HTTP boundary.
- Remote adapters reject credential-bearing redirects, non-HTTPS remote endpoints, non-JSON responses, oversized bodies, and multiple JSON documents.
- The signed grant binds the projected schema identity and canonical prepared arguments.
- Remote execution remains disabled unless all explicit live settings are present.
