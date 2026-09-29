package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/gateway"
	"vectorengine.local/poc/capabilityenvelope/internal/policy"
)

const maxBodyBytes = 2 * 1024 * 1024

type Handler struct {
	gateway               *gateway.Gateway
	policyPath            string
	allowedOrigins        map[string]struct{}
	assets                http.Handler
	contentSecurityPolicy string
}

func New(gateway *gateway.Gateway, policyPath string, assets fs.FS, allowedOrigins []string) (*Handler, error) {
	if gateway == nil {
		return nil, fmt.Errorf("control handler requires a gateway")
	}
	if strings.TrimSpace(policyPath) == "" {
		return nil, fmt.Errorf("control handler requires a policy path")
	}
	origins := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		if origin = strings.TrimSpace(origin); origin != "" {
			origins[origin] = struct{}{}
		}
	}
	var assetHandler http.Handler
	contentSecurityPolicy := "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
	if assets != nil {
		manifest, err := loadCSPManifest(assets)
		if err != nil {
			return nil, err
		}
		scriptSources := make([]string, len(manifest.ScriptHashes))
		for index, hash := range manifest.ScriptHashes {
			scriptSources[index] = "'" + hash + "'"
		}
		contentSecurityPolicy = "default-src 'self'; script-src 'self' " + strings.Join(scriptSources, " ") + "; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
		assetHandler = http.FileServer(http.FS(assets))
	}
	return &Handler{
		gateway:               gateway,
		policyPath:            policyPath,
		allowedOrigins:        origins,
		assets:                assetHandler,
		contentSecurityPolicy: contentSecurityPolicy,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("Content-Security-Policy", handler.contentSecurityPolicy)
	if strings.HasPrefix(request.URL.Path, "/api/") {
		writer.Header().Set("Cache-Control", "no-store")
		if !handler.originAllowed(request.Header.Get("Origin")) {
			handler.writeError(writer, http.StatusForbidden, "request Origin is not allowed")
			return
		}
		handler.serveAPI(writer, request)
		return
	}
	if handler.assets == nil {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	handler.assets.ServeHTTP(writer, request)
}

type cspManifest struct {
	ScriptHashes []string `json:"script_hashes"`
}

func loadCSPManifest(assets fs.FS) (cspManifest, error) {
	data, err := fs.ReadFile(assets, "csp.json")
	if err != nil {
		return cspManifest{}, fmt.Errorf("read generated CSP manifest: %w", err)
	}
	var manifest cspManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return cspManifest{}, fmt.Errorf("decode generated CSP manifest: %w", err)
	}
	if len(manifest.ScriptHashes) == 0 {
		return cspManifest{}, fmt.Errorf("generated CSP manifest contains no inline script hashes")
	}
	for _, hash := range manifest.ScriptHashes {
		if !strings.HasPrefix(hash, "sha256-") || strings.ContainsAny(hash, " \t\r\n;'") {
			return cspManifest{}, fmt.Errorf("generated CSP manifest contains an invalid script hash")
		}
	}
	return manifest, nil
}

func (handler *Handler) serveAPI(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/api/health":
		if !method(writer, request, http.MethodGet) {
			return
		}
		handler.writeJSON(writer, http.StatusOK, handler.gateway.Health())
	case "/api/search":
		if !method(writer, request, http.MethodPost) {
			return
		}
		var input struct {
			Task string `json:"task"`
			K    int    `json:"k"`
		}
		if err := handler.decode(writer, request, &input); err != nil {
			handler.writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		if input.K == 0 {
			input.K = 5
		}
		result, err := handler.gateway.Search(request.Context(), input.Task, input.K)
		handler.writeOutcome(writer, result, err)
	case "/api/prepare":
		if !method(writer, request, http.MethodPost) {
			return
		}
		var input struct {
			Task       string          `json:"task"`
			ToolSlug   string          `json:"tool_slug"`
			Arguments  json.RawMessage `json:"arguments"`
			TTLSeconds int             `json:"ttl_seconds"`
		}
		if err := handler.decode(writer, request, &input); err != nil {
			handler.writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		if len(bytes.TrimSpace(input.Arguments)) == 0 {
			input.Arguments = json.RawMessage("{}")
		}
		result, err := handler.gateway.Prepare(request.Context(), input.Task, input.ToolSlug, input.Arguments, time.Duration(input.TTLSeconds)*time.Second)
		handler.writeOutcome(writer, result, err)
	case "/api/execute":
		if !method(writer, request, http.MethodPost) {
			return
		}
		var input struct {
			GrantToken string          `json:"grant_token"`
			ToolSlug   string          `json:"tool_slug"`
			Arguments  json.RawMessage `json:"arguments"`
		}
		if err := handler.decode(writer, request, &input); err != nil {
			handler.writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		if len(bytes.TrimSpace(input.Arguments)) == 0 {
			input.Arguments = json.RawMessage("{}")
		}
		result, err := handler.gateway.Execute(request.Context(), input.GrantToken, input.ToolSlug, input.Arguments)
		handler.writeOutcome(writer, result, err)
	case "/api/grants":
		if !method(writer, request, http.MethodGet) {
			return
		}
		handler.writeJSON(writer, http.StatusOK, map[string]any{"grants": handler.gateway.Grants()})
	case "/api/receipts":
		if !method(writer, request, http.MethodGet) {
			return
		}
		health := handler.gateway.Health()
		handler.writeJSON(writer, http.StatusOK, map[string]any{
			"chain_valid": health.ChainValid,
			"rows":        handler.gateway.Receipts(),
		})
	case "/api/policy/reload":
		if !method(writer, request, http.MethodPost) {
			return
		}
		active, err := policy.Load(handler.policyPath)
		if err == nil {
			err = handler.gateway.Reload(active)
		}
		if err != nil {
			handler.writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		handler.writeJSON(writer, http.StatusOK, handler.gateway.Health())
	default:
		if strings.HasPrefix(request.URL.Path, "/api/grants/") {
			handler.serveGrant(writer, request)
			return
		}
		handler.writeError(writer, http.StatusNotFound, "API endpoint not found")
	}
}

func (handler *Handler) serveGrant(writer http.ResponseWriter, request *http.Request) {
	tail := strings.TrimPrefix(request.URL.Path, "/api/grants/")
	parts := strings.Split(tail, "/")
	if len(parts) == 0 || parts[0] == "" || len(parts) > 2 {
		handler.writeError(writer, http.StatusNotFound, "grant endpoint not found")
		return
	}
	grantID, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(grantID) == "" {
		handler.writeError(writer, http.StatusBadRequest, "grant ID is invalid")
		return
	}
	if len(parts) == 1 {
		if !method(writer, request, http.MethodGet) {
			return
		}
		result, inspectErr := handler.gateway.Inspect(grantID)
		handler.writeOutcome(writer, result, inspectErr)
		return
	}
	if !method(writer, request, http.MethodPost) {
		return
	}
	switch parts[1] {
	case "approve":
		var input struct {
			Principal string `json:"principal"`
		}
		if err := handler.decode(writer, request, &input); err != nil {
			handler.writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		result, approveErr := handler.gateway.Approve(grantID, input.Principal)
		handler.writeOutcome(writer, result, approveErr)
	case "deny":
		var input struct {
			Reason string `json:"reason"`
		}
		if err := handler.decode(writer, request, &input); err != nil {
			handler.writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		result, denyErr := handler.gateway.Deny(grantID, input.Reason)
		handler.writeOutcome(writer, result, denyErr)
	default:
		handler.writeError(writer, http.StatusNotFound, "grant endpoint not found")
	}
}

func (handler *Handler) decode(writer http.ResponseWriter, request *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("Content-Type must be application/json")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON body: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("body must contain one JSON value")
		}
		return err
	}
	return nil
}

func (handler *Handler) writeOutcome(writer http.ResponseWriter, value any, err error) {
	if err != nil {
		handler.writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	handler.writeJSON(writer, http.StatusOK, value)
}

func (handler *Handler) writeError(writer http.ResponseWriter, status int, message string) {
	handler.writeJSON(writer, status, map[string]any{"error": message})
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func method(writer http.ResponseWriter, request *http.Request, expected string) bool {
	if request.Method == expected {
		return true
	}
	writer.Header().Set("Allow", expected)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = writer.Write([]byte(`{"error":"method not allowed"}` + "\n"))
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
