package catalog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
)

type Toolkit struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	Logo string `json:"logo,omitempty"`
}

type Tool struct {
	Slug              string          `json:"slug"`
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	AvailableVersions []string        `json:"available_versions,omitempty"`
	Version           string          `json:"version"`
	Toolkit           Toolkit         `json:"toolkit"`
	InputParameters   json.RawMessage `json:"input_parameters"`
	OutputParameters  json.RawMessage `json:"output_parameters"`
	Scopes            []string        `json:"scopes,omitempty"`
	ScopeRequirements json.RawMessage `json:"scope_requirements,omitempty"`
	Tags              []string        `json:"tags,omitempty"`
	NoAuth            bool            `json:"no_auth"`
	IsDeprecated      bool            `json:"is_deprecated"`
}

func (tool Tool) Identity() string {
	return tool.Slug + "@" + tool.Version
}

func (tool Tool) SchemaSHA256() string {
	return canonical.BytesSHA256(tool.InputParameters)
}

func Normalize(tool Tool) (Tool, error) {
	tool.Slug = strings.TrimSpace(tool.Slug)
	tool.Name = strings.TrimSpace(tool.Name)
	tool.Description = strings.TrimSpace(tool.Description)
	tool.Version = strings.TrimSpace(tool.Version)
	tool.Toolkit.Slug = strings.TrimSpace(tool.Toolkit.Slug)
	tool.Toolkit.Name = strings.TrimSpace(tool.Toolkit.Name)
	tool.Toolkit.Logo = strings.TrimSpace(tool.Toolkit.Logo)
	tool.AvailableVersions = normalizedStrings(tool.AvailableVersions)
	tool.Scopes = normalizedStrings(tool.Scopes)
	tool.Tags = normalizedStrings(tool.Tags)
	var err error
	tool.InputParameters, err = canonical.NormalizeRaw(tool.InputParameters)
	if err != nil {
		return Tool{}, fmt.Errorf("normalize input schema for %q: %w", tool.Slug, err)
	}
	tool.OutputParameters, err = canonical.NormalizeRaw(tool.OutputParameters)
	if err != nil {
		return Tool{}, fmt.Errorf("normalize output schema for %q: %w", tool.Slug, err)
	}
	if len(tool.ScopeRequirements) > 0 {
		tool.ScopeRequirements, err = canonical.NormalizeRaw(tool.ScopeRequirements)
		if err != nil {
			return Tool{}, fmt.Errorf("normalize scope requirements for %q: %w", tool.Slug, err)
		}
	}
	return tool, nil
}

func Load(path string) ([]Tool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open catalog: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)
	tools := make([]Tool, 0)
	previousSlug := ""
	for line := 1; scanner.Scan(); line++ {
		var tool Tool
		if err := json.Unmarshal(scanner.Bytes(), &tool); err != nil {
			return nil, fmt.Errorf("decode catalog line %d: %w", line, err)
		}
		tool, err = Normalize(tool)
		if err != nil {
			return nil, fmt.Errorf("normalize catalog line %d: %w", line, err)
		}
		if tool.Slug == "" || tool.Name == "" || tool.Description == "" || tool.Version == "" || tool.Toolkit.Slug == "" || tool.Toolkit.Name == "" {
			return nil, fmt.Errorf("catalog line %d is missing required tool identity fields", line)
		}
		if previousSlug != "" && tool.Slug <= previousSlug {
			return nil, fmt.Errorf("catalog is not strictly sorted by slug at line %d", line)
		}
		previousSlug = tool.Slug
		tools = append(tools, tool)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan catalog: %w", err)
	}
	return tools, nil
}

func normalizedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}
