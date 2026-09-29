package upstream

import (
	"encoding/json"
	"fmt"
	"os"
)

// Risk tags for upstream tools that don't declare MCP annotations.
type Classification struct {
	Server string            `json:"server"`
	Tools  map[string]string `json:"tools"`
}

var knownHints = map[string]bool{
	"readOnlyHint": true, "updateHint": true, "createHint": true,
	"deleteHint": true, "destructiveHint": true,
}

func LoadClassification(path string) (Classification, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Classification{}, fmt.Errorf("read classification: %w", err)
	}
	var value Classification
	if err := json.Unmarshal(raw, &value); err != nil {
		return Classification{}, fmt.Errorf("decode classification: %w", err)
	}
	for tool, hint := range value.Tools {
		if !knownHints[hint] {
			return Classification{}, fmt.Errorf("classification for %s uses unknown hint %q", tool, hint)
		}
	}
	return value, nil
}

func (c Classification) Tags(tool string) []string {
	if hint, ok := c.Tools[tool]; ok {
		return []string{hint}
	}
	return nil
}
