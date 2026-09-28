package catalog

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
	"vectorengine.local/poc/capabilityenvelope/internal/remotehttp"
)

type SyncOptions struct {
	Root       string
	Endpoint   string
	APIKey     string
	Attempt    int
	HTTPClient *http.Client
}

type PageIdentity struct {
	Page        int    `json:"page"`
	URL         string `json:"url"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	Items       int    `json:"items"`
	TotalItems  int    `json:"total_items"`
	CurrentPage int    `json:"current_page"`
}

type FileIdentity struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type SyncReceipt struct {
	SchemaVersion                int            `json:"schema_version"`
	Attempt                      int            `json:"attempt"`
	Verdict                      string         `json:"verdict"`
	FailureReason                string         `json:"failure_reason,omitempty"`
	StartedAt                    string         `json:"started_at"`
	CompletedAt                  string         `json:"completed_at"`
	Endpoint                     string         `json:"endpoint"`
	Profile                      map[string]any `json:"profile"`
	Pages                        []PageIdentity `json:"pages"`
	ReportedTotalFirst           int            `json:"reported_total_first"`
	ReportedTotalLast            int            `json:"reported_total_last"`
	ReportedTotalMin             int            `json:"reported_total_min"`
	ReportedTotalMax             int            `json:"reported_total_max"`
	CursorTraversalComplete      bool           `json:"cursor_traversal_complete"`
	RawItems                     int            `json:"raw_items"`
	UniqueTools                  int            `json:"unique_tools"`
	TaggedTools                  int            `json:"tagged_tools"`
	TaggedFraction               float64        `json:"tagged_fraction"`
	ReadOnlyTools                int            `json:"read_only_tools"`
	DestructiveTools             int            `json:"destructive_tools"`
	DuplicateOccurrences         int            `json:"duplicate_occurrences"`
	ConflictingDuplicateSlugs    int            `json:"conflicting_duplicate_slugs"`
	IncompleteRequiredRecords    int            `json:"incomplete_required_records"`
	DeprecatedRecords            int            `json:"deprecated_records"`
	SecretOccurrencesInArtifacts int            `json:"secret_occurrences_in_artifacts"`
	Derived                      FileIdentity   `json:"derived"`
}

type pageResponse struct {
	Items       []Tool `json:"items"`
	NextCursor  string `json:"next_cursor"`
	TotalItems  int    `json:"total_items"`
	CurrentPage int    `json:"current_page"`
}

func Sync(ctx context.Context, options SyncOptions) (SyncReceipt, error) {
	started := time.Now().UTC()
	receipt := SyncReceipt{
		SchemaVersion: 1,
		Attempt:       options.Attempt,
		Verdict:       "INVALID",
		StartedAt:     started.Format(time.RFC3339Nano),
		Profile: map[string]any{
			"important":          true,
			"include_deprecated": false,
			"limit":              1000,
			"version_behavior":   "v3.1 latest default",
		},
	}
	finish := func() {
		receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	endpoint, err := remotehttp.ValidateEndpoint(options.Endpoint, "catalog endpoint")
	if err != nil {
		finish()
		return receipt, err
	}
	receipt.Endpoint = endpoint
	if strings.TrimSpace(options.APIKey) == "" {
		finish()
		return receipt, fmt.Errorf("catalog API key is required")
	}
	if options.Attempt < 1 {
		finish()
		return receipt, fmt.Errorf("attempt must be at least one")
	}
	client := remotehttp.CredentialedClient(options.HTTPClient)
	rawDir := filepath.Join(options.Root, "data", "raw", fmt.Sprintf("catalog-attempt-%03d", options.Attempt))
	derivedPath := filepath.Join(options.Root, "data", "derived", fmt.Sprintf("catalog-attempt-%03d.jsonl", options.Attempt))
	if _, err := os.Stat(rawDir); err == nil {
		finish()
		return receipt, fmt.Errorf("refusing to overwrite retained raw directory %s", rawDir)
	} else if !os.IsNotExist(err) {
		finish()
		return receipt, err
	}
	if _, err := os.Stat(derivedPath); err == nil {
		finish()
		return receipt, fmt.Errorf("refusing to overwrite retained catalog %s", derivedPath)
	} else if !os.IsNotExist(err) {
		finish()
		return receipt, err
	}
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		finish()
		return receipt, fmt.Errorf("create raw catalog directory: %w", err)
	}

	bySlug := make(map[string]Tool)
	encodedBySlug := make(map[string]string)
	cursor := ""
	for page := 1; ; page++ {
		requestURL, err := catalogURL(endpoint, cursor)
		if err != nil {
			finish()
			return receipt, err
		}
		body, decoded, err := fetchCatalogPage(ctx, client, requestURL, options.APIKey, page)
		if err != nil {
			finish()
			return receipt, err
		}
		rawPath := filepath.Join(rawDir, fmt.Sprintf("page-%04d.json", page))
		if err := writeExclusive(rawPath, body); err != nil {
			finish()
			return receipt, err
		}
		if page == 1 {
			receipt.ReportedTotalFirst = decoded.TotalItems
			receipt.ReportedTotalMin = decoded.TotalItems
			receipt.ReportedTotalMax = decoded.TotalItems
		}
		receipt.ReportedTotalLast = decoded.TotalItems
		if decoded.TotalItems < receipt.ReportedTotalMin {
			receipt.ReportedTotalMin = decoded.TotalItems
		}
		if decoded.TotalItems > receipt.ReportedTotalMax {
			receipt.ReportedTotalMax = decoded.TotalItems
		}
		receipt.Pages = append(receipt.Pages, PageIdentity{
			Page:        page,
			URL:         requestURL,
			Bytes:       len(body),
			SHA256:      canonical.BytesSHA256(body),
			Items:       len(decoded.Items),
			TotalItems:  decoded.TotalItems,
			CurrentPage: decoded.CurrentPage,
		})
		for _, rawTool := range decoded.Items {
			receipt.RawItems++
			tool, normalizeErr := Normalize(rawTool)
			if normalizeErr != nil {
				finish()
				return receipt, normalizeErr
			}
			encoded, encodeErr := canonical.Encode(tool)
			if encodeErr != nil {
				finish()
				return receipt, encodeErr
			}
			if previous, exists := encodedBySlug[tool.Slug]; exists {
				receipt.DuplicateOccurrences++
				if previous != string(encoded) {
					receipt.ConflictingDuplicateSlugs++
				}
				continue
			}
			encodedBySlug[tool.Slug] = string(encoded)
			bySlug[tool.Slug] = tool
		}
		if decoded.NextCursor == "" {
			receipt.CursorTraversalComplete = true
			break
		}
		if decoded.NextCursor == cursor {
			finish()
			return receipt, fmt.Errorf("catalog cursor did not advance on page %d", page)
		}
		cursor = decoded.NextCursor
		if page >= 1000 {
			finish()
			return receipt, fmt.Errorf("catalog exceeded 1000 pages")
		}
	}

	tools := make([]Tool, 0, len(bySlug))
	for _, tool := range bySlug {
		tools = append(tools, tool)
	}
	sort.Slice(tools, func(left, right int) bool { return tools[left].Slug < tools[right].Slug })
	for _, tool := range tools {
		if tool.Slug == "" || tool.Name == "" || tool.Description == "" || tool.Version == "" ||
			tool.Toolkit.Slug == "" || tool.Toolkit.Name == "" {
			receipt.IncompleteRequiredRecords++
		}
		if tool.IsDeprecated {
			receipt.DeprecatedRecords++
		}
		if len(tool.Tags) > 0 {
			receipt.TaggedTools++
		}
		if contains(tool.Tags, "readOnlyHint") {
			receipt.ReadOnlyTools++
		}
		if contains(tool.Tags, "destructiveHint") {
			receipt.DestructiveTools++
		}
	}
	receipt.UniqueTools = len(tools)
	if len(tools) > 0 {
		receipt.TaggedFraction = float64(receipt.TaggedTools) / float64(len(tools))
	}
	if err := writeCatalog(derivedPath, tools); err != nil {
		finish()
		return receipt, err
	}
	identity, err := identifyFile(derivedPath, options.Root)
	if err != nil {
		finish()
		return receipt, err
	}
	receipt.Derived = identity
	receipt.SecretOccurrencesInArtifacts, err = countSecretOccurrences(options.APIKey, []string{rawDir, derivedPath})
	if err != nil {
		finish()
		return receipt, err
	}

	passed := receipt.UniqueTools >= 10_000 &&
		receipt.CursorTraversalComplete &&
		receipt.IncompleteRequiredRecords == 0 &&
		receipt.TaggedFraction >= 0.90 &&
		receipt.ConflictingDuplicateSlugs == 0 &&
		receipt.DeprecatedRecords == 0 &&
		receipt.SecretOccurrencesInArtifacts == 0
	if passed {
		receipt.Verdict = "PASS"
	} else {
		receipt.Verdict = "KILL"
		receipt.FailureReason = "one or more preregistered catalog integrity gates failed"
	}
	finish()
	return receipt, nil
}

func catalogURL(endpoint, cursor string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("important", "true")
	query.Set("include_deprecated", "false")
	query.Set("limit", "1000")
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func fetchCatalogPage(ctx context.Context, client *http.Client, endpoint, apiKey string, page int) ([]byte, pageResponse, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, pageResponse{}, fmt.Errorf("create catalog request: %w", err)
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("x-api-key", apiKey)
		request.Header.Set("User-Agent", "mcp-capability-envelope/1.0")
		response, err := client.Do(request)
		if err == nil && (response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError) {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4*1024))
			_ = response.Body.Close()
			lastErr = fmt.Errorf("catalog page %d returned retryable HTTP %d", page, response.StatusCode)
		} else if err == nil {
			var decoded pageResponse
			body, decodeErr := remotehttp.DecodeJSONResponse(response, 64*1024*1024, &decoded)
			if decodeErr != nil {
				return nil, pageResponse{}, fmt.Errorf("fetch catalog page %d: %w", page, decodeErr)
			}
			return body, decoded, nil
		} else {
			lastErr = fmt.Errorf("fetch catalog page %d: %w", page, err)
		}
		if attempt < 3 {
			timer := time.NewTimer(time.Duration(attempt) * 250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, pageResponse{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil, pageResponse{}, lastErr
}

func writeCatalog(path string, tools []Tool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeAtomicExclusive(path, "retained catalog", func(file *os.File) error {
		buffered := bufio.NewWriterSize(file, 1024*1024)
		for _, tool := range tools {
			encoded, err := canonical.Encode(tool)
			if err != nil {
				return err
			}
			if _, err := buffered.Write(encoded); err != nil {
				return err
			}
			if err := buffered.WriteByte('\n'); err != nil {
				return err
			}
		}
		return buffered.Flush()
	})
}

func writeExclusive(path string, data []byte) error {
	return writeAtomicExclusive(path, "retained source page", func(file *os.File) error {
		_, err := file.Write(data)
		return err
	})
}

func writeAtomicExclusive(path, label string, write func(*os.File) error) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite %s %s", label, path)
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary := path + ".partial"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", label, err)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(temporary)
		}
	}()
	if err := write(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	complete = true
	return nil
}

func identifyFile(path, root string) (FileIdentity, error) {
	file, err := os.Open(path)
	if err != nil {
		return FileIdentity{}, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return FileIdentity{}, err
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return FileIdentity{}, err
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return FileIdentity{}, err
	}
	return FileIdentity{
		Path:   filepath.ToSlash(relative),
		Bytes:  stat.Size(),
		SHA256: hex.EncodeToString(digest.Sum(nil)),
	}, nil
}

func countSecretOccurrences(secret string, targets []string) (int, error) {
	occurrences := 0
	needle := []byte(secret)
	for _, target := range targets {
		stat, err := os.Stat(target)
		if err != nil {
			return 0, err
		}
		paths := []string{target}
		if stat.IsDir() {
			paths = paths[:0]
			err := filepath.WalkDir(target, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if !entry.IsDir() {
					paths = append(paths, path)
				}
				return nil
			})
			if err != nil {
				return 0, err
			}
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				return 0, err
			}
			occurrences += strings.Count(string(data), string(needle))
		}
	}
	return occurrences, nil
}

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}
