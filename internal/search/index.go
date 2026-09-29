package search

import (
	"context"
	"fmt"
	"math"
	"sort"

	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
	"vectorengine.local/poc/internal/hnsw"
	"vectorengine.local/poc/internal/vector"
)

const (
	GraphSeed      = uint64(2026082311)
	HNSWM          = 16
	EFConstruction = 200
)

type Predicate func(catalog.Tool) bool

type QueryEmbedder interface {
	EmbedQuery(string) ([]float32, error)
	Space() vector.Space
	SHA256() string
}

type contextQueryEmbedder interface {
	EmbedQueryContext(context.Context, string) ([]float32, error)
}

type Result struct {
	Tool     catalog.Tool `json:"tool"`
	Distance float64      `json:"distance"`
}

type Trace struct {
	RequestedK           int    `json:"requested_k"`
	EligibleTools        int    `json:"eligible_tools"`
	Overfetch            int    `json:"overfetch"`
	EFSearch             int    `json:"ef_search"`
	CandidateCount       int    `json:"candidate_count"`
	PredicateEvaluations int    `json:"predicate_evaluations"`
	DistanceEvaluations  int    `json:"distance_evaluations"`
	VisitedNodes         int    `json:"visited_nodes"`
	ExactFallback        bool   `json:"exact_fallback"`
	Plan                 string `json:"plan"`
}

type Index struct {
	tools      []catalog.Tool
	model      QueryEmbedder
	graph      *hnsw.Index
	bySlug     map[string]int
	catalogSHA string
}

type VectorAudit struct {
	Vectors          int `json:"vectors"`
	Dimension        int `json:"dimension"`
	NonFiniteVectors int `json:"non_finite_vectors"`
	ZeroVectors      int `json:"zero_vectors"`
}

func New(tools []catalog.Tool, model QueryEmbedder, graph *hnsw.Index, catalogSHA string) (*Index, error) {
	if len(tools) == 0 || model == nil || graph == nil {
		return nil, fmt.Errorf("search index requires tools, model, and graph")
	}
	if graph.Len() != len(tools) {
		return nil, fmt.Errorf("graph has %d nodes for %d tools", graph.Len(), len(tools))
	}
	ownedTools := make([]catalog.Tool, len(tools))
	bySlug := make(map[string]int, len(tools))
	for position, tool := range tools {
		if position > 0 && tools[position-1].Slug >= tool.Slug {
			return nil, fmt.Errorf("tools are not strictly sorted by slug at index %d", position)
		}
		ownedTools[position] = cloneTool(tool)
		bySlug[tool.Slug] = position
	}
	return &Index{tools: ownedTools, model: model, graph: graph, bySlug: bySlug, catalogSHA: catalogSHA}, nil
}

func (index *Index) Search(query string, requestedK int, predicate Predicate) ([]Result, Trace, error) {
	return index.SearchContext(context.Background(), query, requestedK, predicate)
}

func (index *Index) SearchContext(ctx context.Context, query string, requestedK int, predicate Predicate) ([]Result, Trace, error) {
	if requestedK < 1 || requestedK > 8 {
		return nil, Trace{}, fmt.Errorf("k must be between 1 and 8")
	}
	if predicate == nil {
		predicate = func(catalog.Tool) bool { return true }
	}
	var queryVector []float32
	var err error
	if contextual, ok := index.model.(contextQueryEmbedder); ok {
		queryVector, err = contextual.EmbedQueryContext(ctx, query)
	} else if err = ctx.Err(); err == nil {
		queryVector, err = index.model.EmbedQuery(query)
	}
	if err != nil {
		return nil, Trace{}, err
	}
	eligibleBits := make([]bool, len(index.tools))
	eligibleCount := 0
	for toolIndex, tool := range index.tools {
		if predicate(tool) {
			eligibleBits[toolIndex] = true
			eligibleCount++
		}
	}
	trace := Trace{RequestedK: requestedK, EligibleTools: eligibleCount}
	if eligibleCount == 0 {
		trace.Plan = "empty_policy_domain"
		return []Result{}, trace, nil
	}
	targetK := min(requestedK, eligibleCount)
	overfetch := max(64, 16*requestedK)
	overfetch = min(overfetch, len(index.tools))
	ef := max(160, overfetch)
	trace.Overfetch = overfetch
	trace.EFSearch = ef
	eligible := func(nodeID hnsw.NodeID) bool {
		return uint64(nodeID) < uint64(len(eligibleBits)) && eligibleBits[nodeID]
	}
	result, err := index.graph.PostFilterSearch(
		queryVector,
		targetK,
		ef,
		overfetch,
		func(hnsw.NodeID) bool { return true },
		eligible,
	)
	if err != nil {
		return nil, trace, err
	}
	trace.CandidateCount = result.CandidateCount
	trace.PredicateEvaluations = result.PredicateEvaluations
	trace.DistanceEvaluations = result.SearchTrace.DistanceEvaluations
	trace.VisitedNodes = visited(result.SearchTrace)
	if len(result.Neighbors) == targetK {
		trace.Plan = "hnsw_postfilter"
		return index.fromHNSW(result.Neighbors), trace, nil
	}

	exact, exactStats, err := index.exact(queryVector, eligibleBits, targetK)
	if err != nil {
		return nil, trace, err
	}
	trace.ExactFallback = true
	trace.Plan = "hnsw_postfilter_then_exact"
	trace.DistanceEvaluations += exactStats.DistanceEvaluations
	return exact, trace, nil
}

func (index *Index) Tool(slug string) (catalog.Tool, bool) {
	position, exists := index.bySlug[slug]
	if !exists {
		return catalog.Tool{}, false
	}
	return cloneTool(index.tools[position]), true
}

func (index *Index) Tools() []catalog.Tool {
	result := make([]catalog.Tool, len(index.tools))
	for position, tool := range index.tools {
		result[position] = cloneTool(tool)
	}
	return result
}

func (index *Index) Len() int {
	return len(index.tools)
}

func (index *Index) ModelSHA256() string {
	return index.model.SHA256()
}

func (index *Index) CatalogSHA256() string {
	return index.catalogSHA
}

func (index *Index) TopologySHA256() string {
	return index.graph.TopologySHA256()
}

func (index *Index) Audit() hnsw.AuditReport {
	return index.graph.Audit()
}

func (index *Index) AuditVectors() VectorAudit {
	report := VectorAudit{Vectors: len(index.tools)}
	for node := range index.tools {
		values, exists := index.graph.Vector(hnsw.NodeID(node))
		if !exists {
			report.ZeroVectors++
			continue
		}
		if node == 0 {
			report.Dimension = len(values)
		}
		norm := float64(0)
		finite := true
		for _, value := range values {
			converted := float64(value)
			if math.IsNaN(converted) || math.IsInf(converted, 0) {
				finite = false
				break
			}
			norm += converted * converted
		}
		if !finite {
			report.NonFiniteVectors++
			continue
		}
		if norm == 0 {
			report.ZeroVectors++
		}
	}
	return report
}

func (index *Index) fromHNSW(neighbors []hnsw.Neighbor) []Result {
	results := make([]Result, 0, len(neighbors))
	for _, neighbor := range neighbors {
		if uint64(neighbor.NodeID) >= uint64(len(index.tools)) {
			continue
		}
		results = append(results, Result{Tool: cloneTool(index.tools[neighbor.NodeID]), Distance: neighbor.Distance})
	}
	return results
}

func (index *Index) exact(query []float32, eligible []bool, k int) ([]Result, vector.ExactStats, error) {
	candidates := make([]vector.Candidate, 0)
	for toolIndex, allowed := range eligible {
		if !allowed {
			continue
		}
		values, exists := index.graph.Vector(hnsw.NodeID(toolIndex))
		if !exists {
			return nil, vector.ExactStats{}, fmt.Errorf("graph vector %d is missing", toolIndex)
		}
		candidates = append(candidates, vector.Candidate{ID: index.tools[toolIndex].Slug, Vector: values})
	}
	neighbors, stats := vector.ExactSearch(index.model.Space(), query, candidates, k)
	results := make([]Result, 0, len(neighbors))
	for _, neighbor := range neighbors {
		position, exists := index.bySlug[neighbor.ID]
		if !exists {
			return nil, vector.ExactStats{}, fmt.Errorf("exact result %q is missing from catalog", neighbor.ID)
		}
		results = append(results, Result{Tool: cloneTool(index.tools[position]), Distance: neighbor.Distance})
	}
	sort.Slice(results, func(left, right int) bool {
		if results[left].Distance != results[right].Distance {
			return results[left].Distance < results[right].Distance
		}
		return results[left].Tool.Slug < results[right].Tool.Slug
	})
	return results, stats, nil
}

func visited(trace hnsw.IndexSearchTrace) int {
	total := trace.BaseLayer.VisitedNodes
	for _, level := range trace.UpperDescent {
		total += level.Trace.VisitedNodes
	}
	return total
}

func cloneTool(tool catalog.Tool) catalog.Tool {
	tool.AvailableVersions = append([]string(nil), tool.AvailableVersions...)
	tool.InputParameters = append([]byte(nil), tool.InputParameters...)
	tool.OutputParameters = append([]byte(nil), tool.OutputParameters...)
	tool.Scopes = append([]string(nil), tool.Scopes...)
	tool.ScopeRequirements = append([]byte(nil), tool.ScopeRequirements...)
	tool.Tags = append([]string(nil), tool.Tags...)
	return tool
}
