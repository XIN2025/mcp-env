package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
	"vectorengine.local/poc/capabilityenvelope/internal/gateway"
)

type Config struct {
	Name           string
	DisplayName    string
	Command        []string
	Dir            string
	Env            []string
	Project        string
	Classification Classification
}

type Server struct {
	config  Config
	session *mcp.ClientSession
	info    gateway.UpstreamInfo
	*lexicalCatalog
}

var (
	_ gateway.Catalog  = (*Server)(nil)
	_ gateway.Executor = (*Server)(nil)
)

func Connect(ctx context.Context, config Config) (*Server, error) {
	if len(config.Command) == 0 {
		return nil, fmt.Errorf("upstream command is required")
	}
	if err := os.MkdirAll(config.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create upstream working directory: %w", err)
	}
	command := exec.Command(config.Command[0], config.Command[1:]...)
	command.Dir = config.Dir
	command.Env = config.Env

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-capability-envelope", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to upstream %s: %w", config.Name, err)
	}
	server := &Server{config: config, session: session}
	if err := server.discover(ctx); err != nil {
		_ = session.Close()
		return nil, err
	}
	return server, nil
}

func (server *Server) discover(ctx context.Context) error {
	serverInfo := server.session.InitializeResult().ServerInfo
	server.info = gateway.UpstreamInfo{
		Server:  serverInfo.Name,
		Version: serverInfo.Version,
		Project: server.config.Project,
	}
	tools := make([]catalog.Tool, 0)
	for tool, err := range server.session.Tools(ctx, nil) {
		if err != nil {
			return fmt.Errorf("list upstream tools: %w", err)
		}
		converted, err := server.catalogTool(tool)
		if err != nil {
			return err
		}
		tools = append(tools, converted)
	}
	slices.SortFunc(tools, func(a, b catalog.Tool) int { return strings.Compare(a.Slug, b.Slug) })
	lexical, err := newLexicalCatalog(tools)
	if err != nil {
		return err
	}
	server.lexicalCatalog = lexical
	return nil
}

func (server *Server) catalogTool(tool *mcp.Tool) (catalog.Tool, error) {
	schema, err := json.Marshal(tool.InputSchema)
	if err != nil {
		return catalog.Tool{}, fmt.Errorf("encode schema for %s: %w", tool.Name, err)
	}
	return catalog.Normalize(catalog.Tool{
		Slug:             tool.Name,
		Name:             tool.Name,
		Description:      tool.Description,
		Version:          server.info.Version,
		Toolkit:          catalog.Toolkit{Slug: server.config.Name, Name: server.config.DisplayName},
		InputParameters:  schema,
		OutputParameters: json.RawMessage(`{}`),
		// Unlisted tools get no tag and are treated as unknown.
		Tags:   server.config.Classification.Tags(tool.Name),
		NoAuth: true,
	})
}

func (server *Server) Upstream() gateway.UpstreamInfo { return server.info }

func (server *Server) Mode() string { return "upstream:" + server.config.Name }

// A tool-level error is a result, not a failure: the call was dispatched.
func (server *Server) Execute(ctx context.Context, tool catalog.Tool, arguments json.RawMessage) (any, error) {
	var parsed map[string]any
	if err := json.Unmarshal(arguments, &parsed); err != nil {
		return nil, fmt.Errorf("decode arguments for %s: %w", tool.Slug, err)
	}
	result, err := server.session.CallTool(ctx, &mcp.CallToolParams{Name: tool.Slug, Arguments: parsed})
	if err != nil {
		return nil, fmt.Errorf("call upstream %s: %w", tool.Slug, err)
	}
	var text strings.Builder
	for _, content := range result.Content {
		if part, ok := content.(*mcp.TextContent); ok {
			text.WriteString(part.Text)
		}
	}
	return map[string]any{
		"is_error":      result.IsError,
		"text":          text.String(),
		"result_sha256": canonical.BytesSHA256([]byte(text.String())),
	}, nil
}

func (server *Server) Close() error { return server.session.Close() }
