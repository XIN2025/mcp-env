package remotehttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTimeout = 90 * time.Second

// Never follow a redirect with credentials attached.
func CredentialedClient(source *http.Client) *http.Client {
	client := &http.Client{Timeout: defaultTimeout}
	if source != nil {
		copy := *source
		client = &copy
		if client.Timeout == 0 {
			client.Timeout = defaultTimeout
		}
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("credentialed request redirects are disabled")
	}
	return client
}

func ValidateEndpoint(raw, label string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Opaque != "" {
		return "", fmt.Errorf("%s must be an absolute URL", label)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("%s cannot contain credentials or a fragment", label)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !isLoopback(parsed.Hostname()) {
			return "", fmt.Errorf("%s must use HTTPS outside loopback", label)
		}
	default:
		return "", fmt.Errorf("%s must use HTTP or HTTPS", label)
	}
	return parsed.String(), nil
}

func DecodeJSONResponse(response *http.Response, limit int64, target any) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("remote endpoint returned an empty response")
	}
	defer response.Body.Close()
	if limit < 1 {
		return nil, fmt.Errorf("response size limit must be positive")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return nil, fmt.Errorf("remote endpoint returned non-JSON content")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read remote response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("remote response exceeds %d bytes", limit)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("remote endpoint returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return nil, fmt.Errorf("remote endpoint returned invalid JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("remote endpoint returned multiple JSON values")
		}
		return nil, fmt.Errorf("decode remote response trailer: %w", err)
	}
	return body, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
