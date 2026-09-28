// Package bm25 provides the exact lexical ranker used by Policy Tool Router.
// It is public so cross-project measurement code can exercise the serving
// implementation instead of copying or approximating it.
package bm25

import (
	"container/heap"
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"unicode"
)

const (
	k1               = 1.2
	b                = 0.75
	Version          = "bm25-okapi-v2-k1-1.2-b-0.75"
	TokenizerVersion = "unicode-alnum-lower-v1"
)

type Document struct {
	ID   string
	Text string
}

type Eligibility interface {
	Allows(id string) bool
}

type Result struct {
	ID    string
	Score float64
}

type SearchResult struct {
	Results              []Result
	CandidatesConsidered int
}

type document struct {
	id     string
	length int
	terms  map[string]int
}

type Index struct {
	documents      []document
	documentFreq   map[string]int
	averageDocSize float64
}

type queryTerm struct {
	term      string
	frequency int
}

type resultHeap []Result

func (items resultHeap) Len() int           { return len(items) }
func (items resultHeap) Less(i, j int) bool { return worse(items[i], items[j]) }
func (items resultHeap) Swap(i, j int)      { items[i], items[j] = items[j], items[i] }
func (items *resultHeap) Push(value any)    { *items = append(*items, value.(Result)) }
func (items *resultHeap) Pop() any {
	old := *items
	last := old[len(old)-1]
	*items = old[:len(old)-1]
	return last
}

func New(inputs []Document) (*Index, error) {
	if len(inputs) == 0 {
		return nil, errors.New("BM25 index requires at least one document")
	}
	documents := make([]document, 0, len(inputs))
	documentFreq := make(map[string]int)
	totalTerms := 0
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if input.ID == "" || strings.TrimSpace(input.Text) == "" {
			return nil, errors.New("BM25 index received an incomplete document")
		}
		if _, exists := seen[input.ID]; exists {
			return nil, errors.New("BM25 index received a duplicate document ID")
		}
		seen[input.ID] = struct{}{}
		terms := termCounts(tokenize(input.Text))
		length := 0
		for term, count := range terms {
			length += count
			documentFreq[term]++
		}
		totalTerms += length
		documents = append(documents, document{id: input.ID, length: length, terms: terms})
	}
	sort.Slice(documents, func(i, j int) bool { return documents[i].id < documents[j].id })
	return &Index{
		documents:      documents,
		documentFreq:   documentFreq,
		averageDocSize: float64(totalTerms) / float64(len(documents)),
	}, nil
}

// Search exhaustively scores every eligible document. "Exact" describes the
// exhaustive BM25 computation, not semantic or vector similarity.
func (index *Index) Search(ctx context.Context, query string, limit int, eligibility Eligibility) (SearchResult, error) {
	if err := ctx.Err(); err != nil {
		return SearchResult{}, err
	}
	if limit < 1 {
		return SearchResult{}, errors.New("BM25 result limit must be positive")
	}
	queryCounts := termCounts(tokenize(query))
	queryTerms := make([]queryTerm, 0, len(queryCounts))
	for term, frequency := range queryCounts {
		queryTerms = append(queryTerms, queryTerm{term: term, frequency: frequency})
	}
	sort.Slice(queryTerms, func(i, j int) bool { return queryTerms[i].term < queryTerms[j].term })
	if len(queryTerms) == 0 {
		considered := 0
		for position, document := range index.documents {
			if position%32 == 0 {
				if err := ctx.Err(); err != nil {
					return SearchResult{}, err
				}
			}
			if eligibility == nil || eligibility.Allows(document.id) {
				considered++
			}
		}
		return SearchResult{Results: []Result{}, CandidatesConsidered: considered}, nil
	}
	candidates := make(resultHeap, 0, min(limit, len(index.documents)))
	heap.Init(&candidates)
	considered := 0
	for position, document := range index.documents {
		if position%32 == 0 {
			if err := ctx.Err(); err != nil {
				return SearchResult{}, err
			}
		}
		if eligibility != nil && !eligibility.Allows(document.id) {
			continue
		}
		considered++
		score := index.score(document, queryTerms)
		if score > 0 {
			candidate := Result{ID: document.id, Score: score}
			if candidates.Len() < limit {
				heap.Push(&candidates, candidate)
			} else if better(candidate, candidates[0]) {
				candidates[0] = candidate
				heap.Fix(&candidates, 0)
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].ID < candidates[j].ID
		}
		return candidates[i].Score > candidates[j].Score
	})
	return SearchResult{Results: []Result(candidates), CandidatesConsidered: considered}, nil
}

func (index *Index) score(document document, queryTerms []queryTerm) float64 {
	if index.averageDocSize == 0 || document.length == 0 {
		return 0
	}
	corpusSize := float64(len(index.documents))
	score := 0.0
	for _, queryTerm := range queryTerms {
		termFrequency := document.terms[queryTerm.term]
		if termFrequency == 0 {
			continue
		}
		documentFrequency := float64(index.documentFreq[queryTerm.term])
		inverseDocumentFrequency := math.Log(1 + (corpusSize-documentFrequency+0.5)/(documentFrequency+0.5))
		numerator := float64(termFrequency) * (k1 + 1)
		denominator := float64(termFrequency) + k1*(1-b+b*float64(document.length)/index.averageDocSize)
		score += float64(queryTerm.frequency) * inverseDocumentFrequency * numerator / denominator
	}
	return score
}

func better(left, right Result) bool {
	return left.Score > right.Score || left.Score == right.Score && left.ID < right.ID
}

func worse(left, right Result) bool {
	return left.Score < right.Score || left.Score == right.Score && left.ID > right.ID
}

func termCounts(terms []string) map[string]int {
	counts := make(map[string]int, len(terms))
	for _, term := range terms {
		counts[term]++
	}
	return counts
}

func tokenize(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsDigit(character)
	})
}
