package mcphttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
	"vectorengine.local/poc/capabilityenvelope/internal/gateway"
)

const (
	ProtocolVersion = "2026-07-28"
	serverName      = "mcp-capability-envelope"
	serverVersion   = "1.0.0"
	maxRequestBytes = 2 * 1024 * 1024
)

type Handler struct {
	gateway        *gateway.Gateway
	allowedOrigins map[string]struct{}
}

type rpcRequest struct {
	JSONRPC string
	ID      json.RawMessage
	HasID   bool
	Method  string
	Params  map[string]json.RawMessage
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolDefinition struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func New(gateway *gateway.Gateway, allowedOrigins []string) (*Handler, error) {
	if gateway == nil {
		return nil, fmt.Errorf("MCP handler requires a gateway")
	}
	origins := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" {
			return nil, fmt.Errorf("invalid allowed origin %q", origin)
		}
		origins[origin] = struct{}{}
	}
	return &Handler{gateway: gateway, allowedOrigins: origins}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("Vary", "MCP-Protocol-Version, Mcp-Method, Mcp-Name, Origin")
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		handler.writeError(writer, http.StatusMethodNotAllowed, nil, -32600, "MCP endpoint accepts POST only", nil)
		return
	}
	if !handler.originAllowed(request.Header.Get("Origin")) {
		handler.writeError(writer, http.StatusForbidden, nil, -32600, "request Origin is not allowed", nil)
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		handler.writeError(writer, http.StatusBadRequest, nil, -32600, "Content-Type must be application/json", nil)
		return
	}
	if !accepts(request.Header.Get("Accept"), "application/json") || !accepts(request.Header.Get("Accept"), "text/event-stream") {
		handler.writeError(writer, http.StatusBadRequest, nil, -32600, "Accept must include application/json and text/event-stream", nil)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		handler.writeError(writer, http.StatusBadRequest, nil, -32700, "request body is unreadable or too large", nil)
		return
	}
	rpc, parseError := parseRequest(body)
	if parseError != nil {
		handler.writeError(writer, http.StatusBadRequest, nil, parseError.Code, parseError.Message, parseError.Data)
		return
	}
	if !rpc.HasID {
		writer.WriteHeader(http.StatusAccepted)
		return
	}
	if err := validateID(rpc.ID); err != nil {
		handler.writeError(writer, http.StatusBadRequest, nil, -32600, err.Error(), nil)
		return
	}
	if protocolError := handler.validateRequestMetadata(request, rpc); protocolError != nil {
		handler.writeError(writer, protocolError.status, rpc.ID, protocolError.code, protocolError.message, protocolError.data)
		return
	}

	switch rpc.Method {
	case "server/discover":
		writer.Header().Set("Cache-Control", "private, max-age=300")
		handler.writeResult(writer, rpc.ID, map[string]any{
			"resultType":        "complete",
			"supportedVersions": []string{ProtocolVersion},
			"capabilities":      map[string]any{"tools": map[string]any{"listChanged": false}},
			"instructions":      "Search the governed catalog, prepare exact arguments, obtain approval when required, then execute the single-use grant.",
			"ttlMs":             300000,
			"cacheScope":        "private",
			"_meta":             serverMeta(),
		})
	case "tools/list":
		writer.Header().Set("Cache-Control", "private, max-age=300")
		handler.writeResult(writer, rpc.ID, map[string]any{
			"resultType": "complete",
			"tools":      tools(),
			"ttlMs":      300000,
			"cacheScope": "private",
			"_meta":      serverMeta(),
		})
	case "tools/call":
		handler.handleToolCall(writer, request.Context(), rpc)
	default:
		handler.writeError(writer, http.StatusNotFound, rpc.ID, -32601, "method not found", nil)
	}
}

type protocolFailure struct {
	status  int
	code    int
	message string
	data    any
}

func (handler *Handler) validateRequestMetadata(request *http.Request, rpc rpcRequest) *protocolFailure {
	metaRaw, exists := rpc.Params["_meta"]
	if !exists {
		return invalidParams("params._meta is required")
	}
	var meta map[string]json.RawMessage
	if err := strictDecode(metaRaw, &meta); err != nil || meta == nil {
		return invalidParams("params._meta must be an object")
	}
	var bodyVersion string
	if raw, exists := meta["io.modelcontextprotocol/protocolVersion"]; !exists || json.Unmarshal(raw, &bodyVersion) != nil || bodyVersion == "" {
		return invalidParams("_meta protocolVersion is required")
	}
	var capabilities map[string]json.RawMessage
	if raw, exists := meta["io.modelcontextprotocol/clientCapabilities"]; !exists || strictDecode(raw, &capabilities) != nil || capabilities == nil {
		return invalidParams("_meta clientCapabilities object is required")
	}
	headerVersion := request.Header.Get("MCP-Protocol-Version")
	if headerVersion == "" || headerVersion != bodyVersion {
		return headerMismatch("MCP-Protocol-Version must match _meta protocolVersion")
	}
	if bodyVersion != ProtocolVersion {
		return &protocolFailure{
			status:  http.StatusBadRequest,
			code:    -32022,
			message: "unsupported protocol version",
			data:    map[string]any{"supportedVersions": []string{ProtocolVersion}},
		}
	}
	if request.Header.Get("Mcp-Method") != rpc.Method {
		return headerMismatch("Mcp-Method must match the JSON-RPC method")
	}
	if rpc.Method == "tools/call" {
		var name string
		if raw, exists := rpc.Params["name"]; !exists || json.Unmarshal(raw, &name) != nil || name == "" {
			return invalidParams("tools/call params.name is required")
		}
		headerName, err := decodeHeaderValue(request.Header.Get("Mcp-Name"))
		if err != nil || headerName != name {
			return headerMismatch("Mcp-Name must match tools/call params.name")
		}
	}
	return nil
}

func invalidParams(message string) *protocolFailure {
	return &protocolFailure{status: http.StatusBadRequest, code: -32602, message: message}
}

func headerMismatch(message string) *protocolFailure {
	return &protocolFailure{status: http.StatusBadRequest, code: -32020, message: message}
}

func (handler *Handler) handleToolCall(writer http.ResponseWriter, ctx context.Context, rpc rpcRequest) {
	var name string
	_ = json.Unmarshal(rpc.Params["name"], &name)
	arguments := rpc.Params["arguments"]
	if len(bytes.TrimSpace(arguments)) == 0 {
		arguments = json.RawMessage("{}")
	}
	var value any
	var err error
	switch name {
	case "capability.search":
		var input struct {
			Task string `json:"task"`
			K    int    `json:"k,omitempty"`
		}
		if err = strictDecode(arguments, &input); err == nil {
			if input.K == 0 {
				input.K = 5
			}
			value, err = handler.gateway.Search(ctx, input.Task, input.K)
		}
	case "capability.prepare":
		var input struct {
			Task       string          `json:"task"`
			ToolSlug   string          `json:"tool_slug"`
			Arguments  json.RawMessage `json:"arguments"`
			TTLSeconds int             `json:"ttl_seconds,omitempty"`
		}
		if err = strictDecode(arguments, &input); err == nil {
			if len(bytes.TrimSpace(input.Arguments)) == 0 {
				input.Arguments = json.RawMessage("{}")
			}
			value, err = handler.gateway.Prepare(ctx, input.Task, input.ToolSlug, input.Arguments, time.Duration(input.TTLSeconds)*time.Second)
		}
	case "capability.execute":
		var input struct {
			GrantToken string          `json:"grant_token"`
			ToolSlug   string          `json:"tool_slug"`
			Arguments  json.RawMessage `json:"arguments"`
		}
		if err = strictDecode(arguments, &input); err == nil {
			if len(bytes.TrimSpace(input.Arguments)) == 0 {
				input.Arguments = json.RawMessage("{}")
			}
			value, err = handler.gateway.Execute(ctx, input.GrantToken, input.ToolSlug, input.Arguments)
		}
	case "capability.inspect":
		var input struct {
			GrantID string `json:"grant_id"`
		}
		if err = strictDecode(arguments, &input); err == nil {
			value, err = handler.gateway.Inspect(input.GrantID)
		}
	default:
		handler.writeError(writer, http.StatusBadRequest, rpc.ID, -32602, "unknown tool name", map[string]any{"name": name})
		return
	}
	if err != nil {
		handler.writeToolResult(writer, rpc.ID, map[string]any{"error": err.Error()}, true)
		return
	}
	handler.writeToolResult(writer, rpc.ID, value, false)
}

func (handler *Handler) writeToolResult(writer http.ResponseWriter, id json.RawMessage, value any, isError bool) {
	encoded, err := canonical.Encode(value)
	if err != nil {
		handler.writeError(writer, http.StatusInternalServerError, id, -32603, "encode tool result", nil)
		return
	}
	handler.writeResult(writer, id, map[string]any{
		"resultType":        "complete",
		"content":           []any{map[string]any{"type": "text", "text": string(encoded)}},
		"structuredContent": value,
		"isError":           isError,
		"_meta":             serverMeta(),
	})
}

func (handler *Handler) writeResult(writer http.ResponseWriter, id json.RawMessage, result any) {
	handler.writeJSON(writer, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func (handler *Handler) writeError(writer http.ResponseWriter, status int, id json.RawMessage, code int, message string, data any) {
	handler.writeJSON(writer, status, rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message, Data: data},
	})
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func parseRequest(body []byte) (rpcRequest, *rpcError) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return rpcRequest{}, &rpcError{Code: -32700, Message: "parse error"}
	}
	if object == nil {
		return rpcRequest{}, &rpcError{Code: -32600, Message: "request must be a JSON object"}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return rpcRequest{}, &rpcError{Code: -32700, Message: "request must contain one JSON value"}
	}
	for key := range object {
		switch key {
		case "jsonrpc", "id", "method", "params":
		default:
			return rpcRequest{}, &rpcError{Code: -32600, Message: "unknown JSON-RPC field " + key}
		}
	}
	var request rpcRequest
	if raw, exists := object["jsonrpc"]; !exists || json.Unmarshal(raw, &request.JSONRPC) != nil || request.JSONRPC != "2.0" {
		return rpcRequest{}, &rpcError{Code: -32600, Message: "jsonrpc must equal 2.0"}
	}
	if raw, exists := object["method"]; !exists || json.Unmarshal(raw, &request.Method) != nil || strings.TrimSpace(request.Method) == "" {
		return rpcRequest{}, &rpcError{Code: -32600, Message: "method must be a non-empty string"}
	}
	request.ID, request.HasID = object["id"]
	paramsRaw, exists := object["params"]
	if !exists {
		paramsRaw = json.RawMessage("{}")
	}
	if err := strictDecode(paramsRaw, &request.Params); err != nil || request.Params == nil {
		return rpcRequest{}, &rpcError{Code: -32602, Message: "params must be an object"}
	}
	return request, nil
}

func validateID(raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("request id must be a string or integer and cannot be null")
	}
	var text string
	if json.Unmarshal(trimmed, &text) == nil {
		return nil
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil {
		return fmt.Errorf("request id must be a string or integer")
	}
	if _, err := strconv.ParseInt(number.String(), 10, 64); err != nil {
		return fmt.Errorf("numeric request id must be an integer")
	}
	return nil
}

func strictDecode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func decodeHeaderValue(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("header is missing")
	}
	if strings.HasPrefix(value, "=?base64?") && strings.HasSuffix(value, "?=") {
		encoded := strings.TrimSuffix(strings.TrimPrefix(value, "=?base64?"), "?=")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", err
		}
		return string(decoded), nil
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return "", fmt.Errorf("header contains unsafe characters")
		}
	}
	return value, nil
}

func accepts(header, mediaType string) bool {
	for _, part := range strings.Split(header, ",") {
		candidate := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if candidate == mediaType || candidate == "*/*" {
			return true
		}
	}
	return false
}

func (handler *Handler) originAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	if _, exists := handler.allowedOrigins[origin]; exists {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	hostname := parsed.Hostname()
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

func serverMeta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/serverInfo": map[string]any{
			"name":    serverName,
			"version": serverVersion,
		},
	}
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	value := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		value["required"] = required
	}
	return value
}

func tools() []toolDefinition {
	return []toolDefinition{
		{
			Name:        "capability.search",
			Title:       "Search governed tools",
			Description: "Retrieve up to eight policy-eligible tools from the pinned catalog snapshot.",
			InputSchema: objectSchema(map[string]any{
				"task": map[string]any{"type": "string", "minLength": 1, "description": "Concrete task to perform"},
				"k":    map[string]any{"type": "integer", "minimum": 1, "maximum": 8, "default": 5},
			}, "task"),
			Annotations: map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
		},
		{
			Name:        "capability.prepare",
			Title:       "Prepare a capability grant",
			Description: "Project policy-controlled schema, bind exact canonical arguments, and issue a short-lived grant or approval request.",
			InputSchema: objectSchema(map[string]any{
				"task":        map[string]any{"type": "string", "minLength": 1},
				"tool_slug":   map[string]any{"type": "string", "minLength": 1},
				"arguments":   map[string]any{"type": "object"},
				"ttl_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 600, "default": 120},
			}, "task", "tool_slug", "arguments"),
			Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false},
		},
		{
			Name:        "capability.execute",
			Title:       "Execute a single-use capability",
			Description: "Consume an argument-bound grant once and dispatch through the configured mock or guarded remote executor.",
			InputSchema: objectSchema(map[string]any{
				"grant_token": map[string]any{"type": "string", "minLength": 1},
				"tool_slug":   map[string]any{"type": "string", "minLength": 1},
				"arguments":   map[string]any{"type": "object"},
			}, "grant_token", "tool_slug", "arguments"),
			Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true},
		},
		{
			Name:        "capability.inspect",
			Title:       "Inspect a capability grant",
			Description: "Inspect explicit grant state and retrieve its token after local approval.",
			InputSchema: objectSchema(map[string]any{
				"grant_id": map[string]any{"type": "string", "minLength": 1},
			}, "grant_id"),
			Annotations: map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
		},
	}
}
