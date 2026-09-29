package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
	"vectorengine.local/poc/capabilityenvelope/internal/grant"
	"vectorengine.local/poc/capabilityenvelope/internal/policy"
	"vectorengine.local/poc/capabilityenvelope/internal/receipt"
	"vectorengine.local/poc/capabilityenvelope/internal/search"
)

type Candidate struct {
	Slug                  string          `json:"slug"`
	Name                  string          `json:"name"`
	Description           string          `json:"description"`
	ToolkitSlug           string          `json:"toolkit_slug"`
	ToolkitName           string          `json:"toolkit_name"`
	Version               string          `json:"version"`
	Tags                  []string        `json:"tags"`
	Risk                  string          `json:"risk"`
	ApprovalRequired      bool            `json:"approval_required"`
	Distance              float64         `json:"distance"`
	OriginalSchemaSHA256  string          `json:"original_schema_sha256"`
	ProjectedSchemaSHA256 string          `json:"projected_schema_sha256"`
	OriginalInputSchema   json.RawMessage `json:"original_input_schema"`
	InputSchema           json.RawMessage `json:"input_schema"`
}

type SearchResponse struct {
	TaskSHA256   string       `json:"task_sha256"`
	PolicySHA256 string       `json:"policy_sha256"`
	Candidates   []Candidate  `json:"candidates"`
	Trace        search.Trace `json:"trace"`
}

type PrepareResponse struct {
	TaskSHA256        string            `json:"task_sha256"`
	ArgumentsSHA256   string            `json:"arguments_sha256"`
	PreparedArguments json.RawMessage   `json:"prepared_arguments"`
	Decision          policy.Decision   `json:"decision"`
	Projection        policy.Projection `json:"projection"`
	Grant             grant.Status      `json:"grant"`
}

type ExecuteResponse struct {
	GrantID          string `json:"grant_id"`
	Mode             string `json:"mode"`
	Result           any    `json:"result"`
	EvidenceRecorded bool   `json:"evidence_recorded"`
	EvidenceWarning  string `json:"evidence_warning,omitempty"`
}

type Health struct {
	Status         string        `json:"status"`
	CatalogMode    string        `json:"catalog_mode"`
	Upstream       *UpstreamInfo `json:"upstream,omitempty"`
	ExecutorMode   string        `json:"executor_mode"`
	CatalogTools   int           `json:"catalog_tools"`
	CatalogSHA256  string        `json:"catalog_sha256"`
	ModelSHA256    string        `json:"model_sha256"`
	TopologySHA256 string        `json:"topology_sha256"`
	PolicyName     string        `json:"policy_name"`
	PolicySHA256   string        `json:"policy_sha256"`
	DecisionRows   int           `json:"decision_rows"`
	ChainValid     bool          `json:"chain_valid"`
}

type Catalog interface {
	SearchContext(ctx context.Context, query string, k int, predicate search.Predicate) ([]search.Result, search.Trace, error)
	Tool(slug string) (catalog.Tool, bool)
	Len() int
	CatalogSHA256() string
	ModelSHA256() string
	TopologySHA256() string
}

type UpstreamInfo struct {
	Server  string         `json:"server"`
	Version string         `json:"version"`
	Project string         `json:"project"`
	Tools   []UpstreamTool `json:"tools"`
}

type UpstreamTool struct {
	Slug             string `json:"slug"`
	Description      string `json:"description"`
	Risk             string `json:"risk"`
	ApprovalRequired bool   `json:"approval_required"`
}

type upstreamCatalog interface {
	Upstream() UpstreamInfo
	Tools() []catalog.Tool
}

type Gateway struct {
	index    Catalog
	grants   *grant.Manager
	executor Executor
	log      *receipt.Log
	policyMu sync.RWMutex
	policy   *policy.Policy
}

func New(index Catalog, activePolicy *policy.Policy, grants *grant.Manager, executor Executor, log *receipt.Log) (*Gateway, error) {
	if isNil(index) || activePolicy == nil || grants == nil || executor == nil || log == nil {
		return nil, fmt.Errorf("gateway dependencies cannot be nil")
	}
	ownedPolicy, err := policy.Normalize(*activePolicy)
	if err != nil {
		return nil, fmt.Errorf("normalize gateway policy: %w", err)
	}
	return &Gateway{index: index, policy: ownedPolicy, grants: grants, executor: executor, log: log}, nil
}

func (gateway *Gateway) Search(ctx context.Context, task string, k int) (SearchResponse, error) {
	task = strings.TrimSpace(task)
	if task == "" {
		return SearchResponse{}, fmt.Errorf("task is required")
	}
	active := gateway.activePolicy()
	results, trace, err := gateway.index.SearchContext(ctx, task, k, func(tool catalog.Tool) bool {
		return active.Evaluate(tool).Allowed
	})
	if err != nil {
		return SearchResponse{}, err
	}
	response := SearchResponse{
		TaskSHA256:   canonical.BytesSHA256([]byte(task)),
		PolicySHA256: active.SHA256(),
		Candidates:   make([]Candidate, 0, len(results)),
		Trace:        trace,
	}
	resultSlugs := make([]any, 0, len(results))
	for _, result := range results {
		decision := active.Evaluate(result.Tool)
		projection, projectErr := active.Project(result.Tool)
		if projectErr != nil {
			return SearchResponse{}, projectErr
		}
		response.Candidates = append(response.Candidates, Candidate{
			Slug:                  result.Tool.Slug,
			Name:                  result.Tool.Name,
			Description:           result.Tool.Description,
			ToolkitSlug:           result.Tool.Toolkit.Slug,
			ToolkitName:           result.Tool.Toolkit.Name,
			Version:               result.Tool.Version,
			Tags:                  append([]string(nil), result.Tool.Tags...),
			Risk:                  decision.Risk,
			ApprovalRequired:      decision.ApprovalRequired,
			Distance:              result.Distance,
			OriginalSchemaSHA256:  projection.OriginalSchemaSHA256,
			ProjectedSchemaSHA256: projection.ProjectedSchemaSHA256,
			OriginalInputSchema:   append(json.RawMessage(nil), result.Tool.InputParameters...),
			InputSchema:           projection.ProjectedSchema,
		})
		resultSlugs = append(resultSlugs, result.Tool.Slug)
	}
	_, err = gateway.log.Append("search", map[string]any{
		"task_sha256":          response.TaskSHA256,
		"policy_sha256":        response.PolicySHA256,
		"result_slugs":         resultSlugs,
		"plan":                 trace.Plan,
		"exact_fallback":       trace.ExactFallback,
		"distance_evaluations": trace.DistanceEvaluations,
	})
	if err != nil {
		return SearchResponse{}, err
	}
	return response, nil
}

func (gateway *Gateway) Prepare(_ context.Context, task, slug string, arguments json.RawMessage, ttl time.Duration) (PrepareResponse, error) {
	task = strings.TrimSpace(task)
	slug = strings.TrimSpace(slug)
	if task == "" || slug == "" {
		return PrepareResponse{}, fmt.Errorf("task and tool slug are required")
	}
	tool, exists := gateway.index.Tool(slug)
	if !exists {
		return PrepareResponse{}, fmt.Errorf("unknown catalog tool %s", slug)
	}
	active := gateway.activePolicy()
	decision := active.Evaluate(tool)
	if !decision.Allowed {
		_, _ = gateway.log.Append("prepare_denied", map[string]any{
			"tool_slug":     slug,
			"policy_sha256": active.SHA256(),
			"reason":        decision.Reason,
		})
		return PrepareResponse{}, fmt.Errorf("policy denied %s: %s", slug, decision.Reason)
	}
	prepared, projection, err := active.PrepareArguments(tool, arguments)
	if err != nil {
		_, _ = gateway.log.Append("prepare_invalid", map[string]any{
			"tool_slug":     slug,
			"policy_sha256": active.SHA256(),
			"reason":        err.Error(),
		})
		return PrepareResponse{}, err
	}
	taskHash := canonical.BytesSHA256([]byte(task))
	argumentsHash := canonical.BytesSHA256(prepared)
	status, err := gateway.grants.IssueAndCommit(grant.IssueSpec{
		ToolSlug:         tool.Slug,
		ToolVersion:      tool.Version,
		SchemaSHA256:     projection.ProjectedSchemaSHA256,
		PolicySHA256:     active.SHA256(),
		TaskSHA256:       taskHash,
		ArgumentsSHA256:  argumentsHash,
		ApprovalRequired: decision.ApprovalRequired,
		TTL:              ttl,
	}, func(status grant.Status) error {
		_, appendErr := gateway.log.Append("grant_prepared", map[string]any{
			"grant_id":          status.GrantID,
			"tool_slug":         tool.Slug,
			"tool_version":      tool.Version,
			"task_sha256":       taskHash,
			"arguments_sha256":  argumentsHash,
			"schema_sha256":     projection.ProjectedSchemaSHA256,
			"policy_sha256":     active.SHA256(),
			"approval_required": decision.ApprovalRequired,
			"state":             string(status.State),
		})
		return appendErr
	})
	if err != nil {
		return PrepareResponse{}, err
	}
	return PrepareResponse{
		TaskSHA256:        taskHash,
		ArgumentsSHA256:   argumentsHash,
		PreparedArguments: prepared,
		Decision:          decision,
		Projection:        projection,
		Grant:             status,
	}, nil
}

func (gateway *Gateway) Approve(grantID, principal string) (grant.Status, error) {
	return gateway.grants.ApproveAndCommit(grantID, principal, func(status grant.Status) error {
		_, err := gateway.log.Append("grant_approved", map[string]any{
			"grant_id":    grantID,
			"tool_slug":   status.ToolSlug,
			"approved_by": status.ApprovedBy,
		})
		return err
	})
}

func (gateway *Gateway) Deny(grantID, reason string) (grant.Status, error) {
	return gateway.grants.DenyAndCommit(grantID, reason, func(status grant.Status) error {
		_, err := gateway.log.Append("grant_denied", map[string]any{
			"grant_id":  grantID,
			"tool_slug": status.ToolSlug,
			"reason":    status.DenialReason,
		})
		return err
	})
}

func (gateway *Gateway) Inspect(grantID string) (grant.Status, error) {
	return gateway.grants.Inspect(grantID)
}

func (gateway *Gateway) Grants() []grant.Status {
	return gateway.grants.List()
}

func (gateway *Gateway) Execute(ctx context.Context, token, slug string, arguments json.RawMessage) (ExecuteResponse, error) {
	tool, exists := gateway.index.Tool(strings.TrimSpace(slug))
	if !exists {
		return ExecuteResponse{}, fmt.Errorf("unknown catalog tool %s", slug)
	}
	active := gateway.activePolicy()
	decision := active.Evaluate(tool)
	if !decision.Allowed {
		return ExecuteResponse{}, fmt.Errorf("current policy denies %s: %s", slug, decision.Reason)
	}
	prepared, projection, err := active.PrepareArguments(tool, arguments)
	if err != nil {
		return ExecuteResponse{}, err
	}
	payload, err := gateway.grants.ConsumeAndCommit(token, grant.Expected{
		ToolSlug:        tool.Slug,
		ToolVersion:     tool.Version,
		SchemaSHA256:    projection.ProjectedSchemaSHA256,
		PolicySHA256:    active.SHA256(),
		ArgumentsSHA256: canonical.BytesSHA256(prepared),
	}, func(payload grant.Payload) error {
		_, appendErr := gateway.log.Append("execution_admitted", map[string]any{
			"grant_id":         payload.GrantID,
			"tool_slug":        tool.Slug,
			"tool_version":     tool.Version,
			"arguments_sha256": canonical.BytesSHA256(prepared),
			"executor_mode":    gateway.executor.Mode(),
		})
		return appendErr
	})
	if err != nil {
		_, _ = gateway.log.Append("execution_denied", map[string]any{
			"tool_slug":     tool.Slug,
			"policy_sha256": active.SHA256(),
			"reason":        err.Error(),
		})
		return ExecuteResponse{}, err
	}
	result, executeErr := gateway.executor.Execute(ctx, tool, prepared)
	event := "execution_dispatched"
	if executeErr != nil {
		event = "execution_failed_after_admission"
	}
	_, logErr := gateway.log.Append(event, map[string]any{
		"grant_id":         payload.GrantID,
		"tool_slug":        tool.Slug,
		"tool_version":     tool.Version,
		"arguments_sha256": canonical.BytesSHA256(prepared),
		"executor_mode":    gateway.executor.Mode(),
	})
	if executeErr != nil {
		if logErr != nil {
			return ExecuteResponse{}, fmt.Errorf("%w; record failed outcome: %v", executeErr, logErr)
		}
		return ExecuteResponse{}, executeErr
	}
	response := ExecuteResponse{
		GrantID:          payload.GrantID,
		Mode:             gateway.executor.Mode(),
		Result:           result,
		EvidenceRecorded: logErr == nil,
	}
	if logErr != nil {
		response.EvidenceWarning = "dispatch succeeded, but its outcome receipt could not be appended: " + logErr.Error()
	}
	return response, nil
}

func (gateway *Gateway) Reload(activePolicy *policy.Policy) error {
	if activePolicy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	ownedPolicy, err := policy.Normalize(*activePolicy)
	if err != nil {
		return err
	}
	gateway.policyMu.Lock()
	defer gateway.policyMu.Unlock()
	previous := gateway.policy
	_, err = gateway.log.Append("policy_reloaded", map[string]any{
		"previous_policy_sha256": previous.SHA256(),
		"policy_sha256":          ownedPolicy.SHA256(),
		"policy_name":            ownedPolicy.Name,
	})
	if err != nil {
		return err
	}
	gateway.policy = ownedPolicy
	return nil
}

func (gateway *Gateway) Receipts() []receipt.Row {
	return gateway.log.Rows()
}

func (gateway *Gateway) Health() Health {
	active := gateway.activePolicy()
	chainValid := gateway.log.Verify() == nil
	health := Health{
		Status:         "ok",
		CatalogMode:    "catalog",
		ExecutorMode:   gateway.executor.Mode(),
		CatalogTools:   gateway.index.Len(),
		CatalogSHA256:  gateway.index.CatalogSHA256(),
		ModelSHA256:    gateway.index.ModelSHA256(),
		TopologySHA256: gateway.index.TopologySHA256(),
		PolicyName:     active.Name,
		PolicySHA256:   active.SHA256(),
		DecisionRows:   len(gateway.log.Rows()),
		ChainValid:     chainValid,
	}
	if upstream, ok := gateway.index.(upstreamCatalog); ok {
		info := upstream.Upstream()
		for _, tool := range upstream.Tools() {
			decision := active.Evaluate(tool)
			info.Tools = append(info.Tools, UpstreamTool{
				Slug:             tool.Slug,
				Description:      tool.Description,
				Risk:             decision.Risk,
				ApprovalRequired: decision.ApprovalRequired,
			})
		}
		health.CatalogMode = "upstream"
		health.Upstream = &info
	}
	return health
}

// Also catches a typed nil pointer stored in the interface.
func isNil(index Catalog) bool {
	if index == nil {
		return true
	}
	value := reflect.ValueOf(index)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func (gateway *Gateway) activePolicy() *policy.Policy {
	gateway.policyMu.RLock()
	defer gateway.policyMu.RUnlock()
	return gateway.policy
}
