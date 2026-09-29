package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
)

const (
	UnknownDenyPrepare     = "deny_prepare"
	UnknownRequireApproval = "require_approval"
	UnknownAllow           = "allow"
)

type Policy struct {
	Name                        string                                `json:"name"`
	AllowedToolkits             []string                              `json:"allowed_toolkits"`
	DeniedToolkits              []string                              `json:"denied_toolkits"`
	AllowedTools                []string                              `json:"allowed_tools"`
	DeniedTools                 []string                              `json:"denied_tools"`
	RequiredTags                []string                              `json:"required_tags"`
	DeniedTags                  []string                              `json:"denied_tags"`
	UnknownRisk                 string                                `json:"unknown_risk"`
	DestructiveRequiresApproval bool                                  `json:"destructive_requires_approval"`
	HiddenArguments             map[string][]string                   `json:"hidden_arguments"`
	InjectedDefaults            map[string]map[string]json.RawMessage `json:"injected_defaults"`
	hash                        string
}

type Decision struct {
	Allowed          bool     `json:"allowed"`
	Reason           string   `json:"reason"`
	Risk             string   `json:"risk"`
	ApprovalRequired bool     `json:"approval_required"`
	MatchedTags      []string `json:"matched_tags"`
}

type Projection struct {
	OriginalSchemaSHA256  string                     `json:"original_schema_sha256"`
	ProjectedSchemaSHA256 string                     `json:"projected_schema_sha256"`
	ProjectedSchema       json.RawMessage            `json:"projected_schema"`
	HiddenArguments       []string                   `json:"hidden_arguments"`
	InjectedDefaults      map[string]json.RawMessage `json:"injected_defaults"`
}

func Load(path string) (*Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open policy: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var value Policy
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	return Normalize(value)
}

func Normalize(value Policy) (*Policy, error) {
	value.Name = strings.TrimSpace(value.Name)
	if value.Name == "" {
		return nil, fmt.Errorf("policy name is required")
	}
	value.AllowedToolkits = normalizeStrings(value.AllowedToolkits)
	value.DeniedToolkits = normalizeStrings(value.DeniedToolkits)
	value.AllowedTools = normalizeStrings(value.AllowedTools)
	value.DeniedTools = normalizeStrings(value.DeniedTools)
	value.RequiredTags = normalizeStrings(value.RequiredTags)
	value.DeniedTags = normalizeStrings(value.DeniedTags)
	switch value.UnknownRisk {
	case UnknownDenyPrepare, UnknownRequireApproval, UnknownAllow:
	default:
		return nil, fmt.Errorf("unknown_risk must be %q, %q, or %q", UnknownDenyPrepare, UnknownRequireApproval, UnknownAllow)
	}
	if !value.DestructiveRequiresApproval {
		return nil, fmt.Errorf("destructive_requires_approval must be true for this boundary")
	}
	if value.HiddenArguments == nil {
		value.HiddenArguments = make(map[string][]string)
	}
	normalizedHidden := make(map[string][]string, len(value.HiddenArguments))
	for slug, arguments := range value.HiddenArguments {
		normalizedSlug := strings.TrimSpace(slug)
		if normalizedSlug == "" {
			return nil, fmt.Errorf("hidden_arguments contains an empty tool key")
		}
		if _, exists := normalizedHidden[normalizedSlug]; exists {
			return nil, fmt.Errorf("hidden_arguments contains colliding tool key %q", normalizedSlug)
		}
		normalizedHidden[normalizedSlug] = normalizeStrings(arguments)
	}
	value.HiddenArguments = normalizedHidden
	if value.InjectedDefaults == nil {
		value.InjectedDefaults = make(map[string]map[string]json.RawMessage)
	}
	normalizedInjected := make(map[string]map[string]json.RawMessage, len(value.InjectedDefaults))
	for slug, defaults := range value.InjectedDefaults {
		normalizedSlug := strings.TrimSpace(slug)
		if normalizedSlug == "" {
			return nil, fmt.Errorf("injected_defaults contains an empty tool key")
		}
		if _, exists := normalizedInjected[normalizedSlug]; exists {
			return nil, fmt.Errorf("injected_defaults contains colliding tool key %q", normalizedSlug)
		}
		normalizedDefaults := make(map[string]json.RawMessage, len(defaults))
		for rawName, raw := range defaults {
			name := strings.TrimSpace(rawName)
			if name == "" {
				return nil, fmt.Errorf("injected_defaults for %s contains an empty argument", normalizedSlug)
			}
			if _, exists := normalizedDefaults[name]; exists {
				return nil, fmt.Errorf("injected_defaults for %s contains colliding argument %q", normalizedSlug, name)
			}
			normalized, err := canonical.NormalizeRaw(raw)
			if err != nil {
				return nil, fmt.Errorf("normalize default %s.%s: %w", normalizedSlug, name, err)
			}
			normalizedDefaults[name] = normalized
		}
		normalizedInjected[normalizedSlug] = normalizedDefaults
	}
	value.InjectedDefaults = normalizedInjected
	hash, err := canonical.SHA256(publicPolicy(value))
	if err != nil {
		return nil, err
	}
	value.hash = hash
	return &value, nil
}

func (policy *Policy) SHA256() string {
	return policy.hash
}

func (policy *Policy) Evaluate(tool catalog.Tool) Decision {
	risk := riskOf(tool)
	decision := Decision{Risk: risk, MatchedTags: append([]string(nil), tool.Tags...)}
	if contains(policy.DeniedTools, tool.Slug) {
		decision.Reason = "tool_explicitly_denied"
		return decision
	}
	if contains(policy.DeniedToolkits, tool.Toolkit.Slug) {
		decision.Reason = "toolkit_explicitly_denied"
		return decision
	}
	if len(policy.AllowedTools) > 0 && !contains(policy.AllowedTools, tool.Slug) {
		decision.Reason = "tool_not_in_allowlist"
		return decision
	}
	if len(policy.AllowedToolkits) > 0 && !contains(policy.AllowedToolkits, tool.Toolkit.Slug) {
		decision.Reason = "toolkit_not_in_allowlist"
		return decision
	}
	for _, denied := range policy.DeniedTags {
		if contains(tool.Tags, denied) {
			decision.Reason = "denied_tag:" + denied
			return decision
		}
	}
	for _, required := range policy.RequiredTags {
		if !contains(tool.Tags, required) {
			decision.Reason = "missing_required_tag:" + required
			return decision
		}
	}
	if risk == "unknown" {
		switch policy.UnknownRisk {
		case UnknownDenyPrepare:
			decision.Reason = "unknown_risk_denied"
			return decision
		case UnknownRequireApproval:
			decision.Allowed = true
			decision.ApprovalRequired = true
			decision.Reason = "unknown_risk_requires_approval"
			return decision
		case UnknownAllow:
			decision.Allowed = true
			decision.Reason = "unknown_risk_allowed"
			return decision
		}
	}
	decision.Allowed = true
	if risk == "destructive" && policy.DestructiveRequiresApproval {
		decision.ApprovalRequired = true
		decision.Reason = "destructive_requires_approval"
		return decision
	}
	decision.Reason = "allowed"
	return decision
}

func (policy *Policy) Project(tool catalog.Tool) (Projection, error) {
	hidden := union(policy.HiddenArguments["*"], policy.HiddenArguments[tool.Slug])
	defaults := mergedDefaults(policy.InjectedDefaults["*"], policy.InjectedDefaults[tool.Slug])
	var schema map[string]any
	decoder := json.NewDecoder(bytes.NewReader(tool.InputParameters))
	decoder.UseNumber()
	if err := decoder.Decode(&schema); err != nil {
		return Projection{}, fmt.Errorf("decode input schema for %s: %w", tool.Slug, err)
	}
	if err := requireEOF(decoder); err != nil {
		return Projection{}, fmt.Errorf("decode input schema for %s: %w", tool.Slug, err)
	}
	properties, _ := schema["properties"].(map[string]any)
	required, err := schemaStrings(schema["required"], "required")
	if err != nil {
		return Projection{}, fmt.Errorf("input schema for %s: %w", tool.Slug, err)
	}
	for _, name := range hidden {
		if contains(required, name) {
			if _, exists := defaults[name]; !exists {
				return Projection{}, fmt.Errorf("hidden required argument %s.%s has no injected default", tool.Slug, name)
			}
		}
		delete(properties, name)
	}
	visibleRequired := make([]string, 0, len(required))
	for _, name := range required {
		if !contains(hidden, name) {
			visibleRequired = append(visibleRequired, name)
		}
	}
	if len(required) > 0 {
		schema["required"] = visibleRequired
	}
	projected, err := canonical.Encode(schema)
	if err != nil {
		return Projection{}, err
	}
	return Projection{
		OriginalSchemaSHA256:  tool.SchemaSHA256(),
		ProjectedSchemaSHA256: canonical.BytesSHA256(projected),
		ProjectedSchema:       json.RawMessage(projected),
		HiddenArguments:       hidden,
		InjectedDefaults:      defaults,
	}, nil
}

func (policy *Policy) PrepareArguments(tool catalog.Tool, supplied json.RawMessage) (json.RawMessage, Projection, error) {
	projection, err := policy.Project(tool)
	if err != nil {
		return nil, Projection{}, err
	}
	var arguments map[string]any
	decoder := json.NewDecoder(bytes.NewReader(supplied))
	decoder.UseNumber()
	if err := decoder.Decode(&arguments); err != nil {
		return nil, Projection{}, fmt.Errorf("arguments must be a JSON object: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, Projection{}, fmt.Errorf("arguments must contain one JSON object: %w", err)
	}
	if arguments == nil {
		return nil, Projection{}, fmt.Errorf("arguments must be a JSON object, not null")
	}
	for _, name := range projection.HiddenArguments {
		if _, exists := arguments[name]; exists {
			return nil, Projection{}, fmt.Errorf("argument %q is controlled by policy", name)
		}
	}
	for name, raw := range projection.InjectedDefaults {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, Projection{}, err
		}
		arguments[name] = value
	}
	if err := validateTopLevel(tool.InputParameters, arguments); err != nil {
		return nil, Projection{}, err
	}
	prepared, err := canonical.Encode(arguments)
	if err != nil {
		return nil, Projection{}, err
	}
	return json.RawMessage(prepared), projection, nil
}

func riskOf(tool catalog.Tool) string {
	for _, mutationHint := range []string{"createHint", "deleteHint", "destructiveHint", "updateHint"} {
		if contains(tool.Tags, mutationHint) {
			return "destructive"
		}
	}
	if contains(tool.Tags, "readOnlyHint") {
		return "read_only"
	}
	return "unknown"
}

func publicPolicy(value Policy) any {
	return struct {
		Name                        string                                `json:"name"`
		AllowedToolkits             []string                              `json:"allowed_toolkits"`
		DeniedToolkits              []string                              `json:"denied_toolkits"`
		AllowedTools                []string                              `json:"allowed_tools"`
		DeniedTools                 []string                              `json:"denied_tools"`
		RequiredTags                []string                              `json:"required_tags"`
		DeniedTags                  []string                              `json:"denied_tags"`
		UnknownRisk                 string                                `json:"unknown_risk"`
		DestructiveRequiresApproval bool                                  `json:"destructive_requires_approval"`
		HiddenArguments             map[string][]string                   `json:"hidden_arguments"`
		InjectedDefaults            map[string]map[string]json.RawMessage `json:"injected_defaults"`
	}{
		Name:                        value.Name,
		AllowedToolkits:             value.AllowedToolkits,
		DeniedToolkits:              value.DeniedToolkits,
		AllowedTools:                value.AllowedTools,
		DeniedTools:                 value.DeniedTools,
		RequiredTags:                value.RequiredTags,
		DeniedTags:                  value.DeniedTags,
		UnknownRisk:                 value.UnknownRisk,
		DestructiveRequiresApproval: value.DestructiveRequiresApproval,
		HiddenArguments:             value.HiddenArguments,
		InjectedDefaults:            value.InjectedDefaults,
	}
}

func mergedDefaults(first, second map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(first)+len(second))
	for name, raw := range first {
		result[name] = append(json.RawMessage(nil), raw...)
	}
	for name, raw := range second {
		result[name] = append(json.RawMessage(nil), raw...)
	}
	return result
}

func normalizeStrings(values []string) []string {
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
	sort.Strings(result)
	return result
}

func union(first, second []string) []string {
	return normalizeStrings(append(append([]string(nil), first...), second...))
}

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func schemaStrings(value any, name string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array of strings", name)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("%s must contain non-empty strings", name)
		}
		result = append(result, text)
	}
	sort.Strings(result)
	return result, nil
}

func validateTopLevel(rawSchema json.RawMessage, arguments map[string]any) error {
	var schema map[string]any
	decoder := json.NewDecoder(bytes.NewReader(rawSchema))
	decoder.UseNumber()
	if err := decoder.Decode(&schema); err != nil {
		return fmt.Errorf("decode input schema: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return fmt.Errorf("decode input schema: %w", err)
	}
	required, err := schemaStrings(schema["required"], "required")
	if err != nil {
		return err
	}
	missing := make([]string, 0)
	for _, name := range required {
		if _, exists := arguments[name]; !exists {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required top-level arguments: %s", strings.Join(missing, ", "))
	}
	properties, _ := schema["properties"].(map[string]any)
	if additional, ok := schema["additionalProperties"].(bool); ok && !additional {
		unknown := make([]string, 0)
		for name := range arguments {
			if _, exists := properties[name]; !exists {
				unknown = append(unknown, name)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return fmt.Errorf("unknown top-level arguments: %s", strings.Join(unknown, ", "))
		}
	}
	for name, value := range arguments {
		definition, exists := properties[name]
		if !exists {
			continue
		}
		if err := validateProperty(name, value, definition); err != nil {
			return err
		}
	}
	return nil
}

func validateProperty(name string, value, rawDefinition any) error {
	if allowed, ok := rawDefinition.(bool); ok {
		if !allowed {
			return fmt.Errorf("argument %q is forbidden by its schema", name)
		}
		return nil
	}
	definition, ok := rawDefinition.(map[string]any)
	if !ok {
		return nil
	}
	if declared, exists := definition["type"]; exists && !matchesType(value, declared) {
		return fmt.Errorf("argument %q does not match its declared top-level type", name)
	}
	if enum, ok := definition["enum"].([]any); ok && !containsJSON(enum, value) {
		return fmt.Errorf("argument %q is not one of its allowed values", name)
	}
	if constant, exists := definition["const"]; exists && !containsJSON([]any{constant}, value) {
		return fmt.Errorf("argument %q does not match its required value", name)
	}
	switch typed := value.(type) {
	case string:
		length := utf8.RuneCountInString(typed)
		if minimum, ok := schemaInt(definition["minLength"]); ok && length < minimum {
			return fmt.Errorf("argument %q is shorter than minLength", name)
		}
		if maximum, ok := schemaInt(definition["maxLength"]); ok && length > maximum {
			return fmt.Errorf("argument %q is longer than maxLength", name)
		}
	case []any:
		if minimum, ok := schemaInt(definition["minItems"]); ok && len(typed) < minimum {
			return fmt.Errorf("argument %q has fewer than minItems entries", name)
		}
		if maximum, ok := schemaInt(definition["maxItems"]); ok && len(typed) > maximum {
			return fmt.Errorf("argument %q has more than maxItems entries", name)
		}
	}
	return nil
}

func matchesType(value, declaration any) bool {
	types := make([]string, 0, 1)
	switch typed := declaration.(type) {
	case string:
		types = append(types, typed)
	case []any:
		for _, item := range typed {
			if name, ok := item.(string); ok {
				types = append(types, name)
			}
		}
	default:
		return true
	}
	for _, expected := range types {
		switch expected {
		case "null":
			if value == nil {
				return true
			}
		case "boolean":
			_, ok := value.(bool)
			if ok {
				return true
			}
		case "object":
			_, ok := value.(map[string]any)
			if ok {
				return true
			}
		case "array":
			_, ok := value.([]any)
			if ok {
				return true
			}
		case "string":
			_, ok := value.(string)
			if ok {
				return true
			}
		case "number":
			_, ok := value.(json.Number)
			if ok {
				return true
			}
		case "integer":
			if number, ok := value.(json.Number); ok {
				parsed, err := number.Float64()
				if err == nil && math.Trunc(parsed) == parsed {
					return true
				}
			}
		}
	}
	return false
}

func containsJSON(values []any, target any) bool {
	targetBytes, err := canonical.Encode(target)
	if err != nil {
		return false
	}
	for _, candidate := range values {
		candidateBytes, err := canonical.Encode(candidate)
		if err == nil && bytes.Equal(candidateBytes, targetBytes) {
			return true
		}
	}
	return false
}

func schemaInt(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	return int(parsed), err == nil && parsed >= 0
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	return err
}
