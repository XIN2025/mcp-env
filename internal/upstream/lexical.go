package upstream

import (
	"context"
	"encoding/json"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
	"vectorengine.local/poc/capabilityenvelope/internal/search"
	"vectorengine.local/poc/toolrouter/bm25"
)

type lexicalCatalog struct {
	tools      []catalog.Tool
	bySlug     map[string]catalog.Tool
	ranker     *bm25.Index
	catalogSHA string
}

func newLexicalCatalog(tools []catalog.Tool) (*lexicalCatalog, error) {
	documents := make([]bm25.Document, 0, len(tools))
	bySlug := make(map[string]catalog.Tool, len(tools))
	for _, tool := range tools {
		documents = append(documents, bm25.Document{ID: tool.Slug, Text: tool.Slug + " " + tool.Name + " " + tool.Description})
		bySlug[tool.Slug] = tool
	}
	ranker, err := bm25.New(documents)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(tools)
	if err != nil {
		return nil, err
	}
	return &lexicalCatalog{tools: tools, bySlug: bySlug, ranker: ranker, catalogSHA: canonical.BytesSHA256(encoded)}, nil
}

type eligibility struct {
	bySlug    map[string]catalog.Tool
	predicate search.Predicate
	evaluated int
}

func (e *eligibility) Allows(id string) bool {
	e.evaluated++
	return e.predicate == nil || e.predicate(e.bySlug[id])
}

func (c *lexicalCatalog) SearchContext(ctx context.Context, query string, k int, predicate search.Predicate) ([]search.Result, search.Trace, error) {
	allowed := &eligibility{bySlug: c.bySlug, predicate: predicate}
	found, err := c.ranker.Search(ctx, query, k, allowed)
	if err != nil {
		return nil, search.Trace{}, err
	}
	results := make([]search.Result, 0, len(found.Results))
	for _, hit := range found.Results {
		// Lower is closer, matching the semantic index.
		results = append(results, search.Result{Tool: c.bySlug[hit.ID], Distance: 1 / (1 + hit.Score)})
	}
	return results, search.Trace{
		RequestedK:           k,
		EligibleTools:        found.CandidatesConsidered,
		CandidateCount:       len(results),
		PredicateEvaluations: allowed.evaluated,
		Plan:                 bm25.Version,
	}, nil
}

func (c *lexicalCatalog) Tool(slug string) (catalog.Tool, bool) {
	tool, ok := c.bySlug[slug]
	return tool, ok
}

func (c *lexicalCatalog) Len() int               { return len(c.tools) }
func (c *lexicalCatalog) CatalogSHA256() string  { return c.catalogSHA }
func (c *lexicalCatalog) ModelSHA256() string    { return "" }
func (c *lexicalCatalog) TopologySHA256() string { return "" }

func (c *lexicalCatalog) Tools() []catalog.Tool {
	return append([]catalog.Tool(nil), c.tools...)
}
