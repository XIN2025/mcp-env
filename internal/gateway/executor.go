package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
	"vectorengine.local/poc/capabilityenvelope/internal/remotehttp"
)

type Executor interface {
	Mode() string
	Execute(context.Context, catalog.Tool, json.RawMessage) (any, error)
}

type MockExecutor struct {
	mu    sync.Mutex
	calls []MockCall
}

type MockCall struct {
	DispatchID      int    `json:"dispatch_id"`
	ToolSlug        string `json:"tool_slug"`
	ToolVersion     string `json:"tool_version"`
	ArgumentsSHA256 string `json:"arguments_sha256"`
}

func (executor *MockExecutor) Mode() string {
	return "mock"
}

func (executor *MockExecutor) Execute(_ context.Context, tool catalog.Tool, arguments json.RawMessage) (any, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	call := MockCall{
		DispatchID:      len(executor.calls) + 1,
		ToolSlug:        tool.Slug,
		ToolVersion:     tool.Version,
		ArgumentsSHA256: canonical.BytesSHA256(arguments),
	}
	executor.calls = append(executor.calls, call)
	return map[string]any{
		"mode":             "mock",
		"dispatched":       true,
		"dispatch_id":      call.DispatchID,
		"tool_slug":        call.ToolSlug,
		"tool_version":     call.ToolVersion,
		"arguments_sha256": call.ArgumentsSHA256,
	}, nil
}

func (executor *MockExecutor) Calls() []MockCall {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	result := make([]MockCall, len(executor.calls))
	copy(result, executor.calls)
	return result
}

type RemoteExecutor struct {
	apiKey   string
	client   *http.Client
	endpoint string
}

func NewRemoteExecutor(endpoint, apiKey string, client *http.Client) (*RemoteExecutor, error) {
	validatedEndpoint, err := remotehttp.ValidateEndpoint(endpoint, "remote execution endpoint")
	if err != nil {
		return nil, err
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, fmt.Errorf("remote executor API key is required")
	}
	return &RemoteExecutor{
		apiKey:   apiKey,
		client:   remotehttp.CredentialedClient(client),
		endpoint: validatedEndpoint,
	}, nil
}

func (executor *RemoteExecutor) Mode() string {
	return "remote"
}

func (executor *RemoteExecutor) Execute(ctx context.Context, tool catalog.Tool, arguments json.RawMessage) (any, error) {
	body, err := canonical.Encode(map[string]any{
		"tool_slug": tool.Slug,
		"arguments": json.RawMessage(arguments),
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, executor.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("x-api-key", executor.apiKey)
	request.Header.Set("User-Agent", "mcp-capability-envelope/1.0")
	response, err := executor.client.Do(request)
	if err != nil {
		return nil, err
	}
	var decoded any
	if _, err := remotehttp.DecodeJSONResponse(response, 32*1024*1024, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}
