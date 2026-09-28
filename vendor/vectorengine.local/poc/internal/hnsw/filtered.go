package hnsw

import "errors"

type ResultFilterSearchResult struct {
	SearchResult
	PredicateEvaluations int
}

func (i *Index) ResultFilterSearch(
	query []float32,
	k int,
	ef int,
	eligible ResultEligibility,
) (ResultFilterSearchResult, error) {
	if eligible == nil {
		return ResultFilterSearchResult{}, errors.New("result-filter eligibility predicate is nil")
	}
	predicateEvaluations := 0
	result, err := i.Search(query, k, ef, func(nodeID NodeID) bool {
		predicateEvaluations++
		return eligible(nodeID)
	})
	if err != nil {
		return ResultFilterSearchResult{}, err
	}
	return ResultFilterSearchResult{SearchResult: result, PredicateEvaluations: predicateEvaluations}, nil
}

// May return fewer than k results.
type PostFilterSearchResult struct {
	Neighbors            []Neighbor       `json:"neighbors"`
	SearchTrace          IndexSearchTrace `json:"search_trace"`
	CandidateCount       int              `json:"candidate_count"`
	PredicateEvaluations int              `json:"predicate_evaluations"`
}

func (i *Index) PostFilterSearch(
	query []float32,
	k int,
	ef int,
	candidateK int,
	candidateEligible ResultEligibility,
	filterEligible ResultEligibility,
) (PostFilterSearchResult, error) {
	if k < 1 {
		return PostFilterSearchResult{}, errors.New("post-filter k must be at least one")
	}
	if candidateK < 1 {
		return PostFilterSearchResult{}, errors.New("post-filter candidateK must be at least one")
	}
	if candidateEligible == nil {
		return PostFilterSearchResult{}, errors.New("post-filter candidate eligibility predicate is nil")
	}
	if filterEligible == nil {
		return PostFilterSearchResult{}, errors.New("post-filter metadata predicate is nil")
	}
	candidates, err := i.Search(query, candidateK, ef, candidateEligible)
	if err != nil {
		return PostFilterSearchResult{}, err
	}
	result := PostFilterSearchResult{
		Neighbors:      make([]Neighbor, 0, k),
		SearchTrace:    candidates.Trace,
		CandidateCount: len(candidates.Neighbors),
	}
	for _, candidate := range candidates.Neighbors {
		result.PredicateEvaluations++
		if !filterEligible(candidate.NodeID) {
			continue
		}
		result.Neighbors = append(result.Neighbors, candidate)
		if len(result.Neighbors) == k {
			break
		}
	}
	return result, nil
}
