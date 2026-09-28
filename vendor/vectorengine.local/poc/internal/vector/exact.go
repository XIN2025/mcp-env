package vector

import "sort"

type Candidate struct {
	ID     string
	Vector []float32
}

type Result struct {
	ID       string
	Distance float64
}

type ExactStats struct {
	DistanceEvaluations int
}

func ExactSearch(space Space, query []float32, candidates []Candidate, k int) ([]Result, ExactStats) {
	if k > len(candidates) {
		k = len(candidates)
	}
	if k <= 0 {
		return []Result{}, ExactStats{}
	}

	best := make(worstFirstHeap, 0, k)
	for _, candidate := range candidates {
		retainBest(&best, scoredCandidate{
			id:       candidate.ID,
			distance: space.Distance(query, candidate.Vector),
		}, k)
	}

	results := make([]Result, len(best))
	for i, candidate := range best {
		results[i] = Result{ID: candidate.id, Distance: candidate.distance}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Distance != results[j].Distance {
			return results[i].Distance < results[j].Distance
		}
		return results[i].ID < results[j].ID
	})
	return results, ExactStats{DistanceEvaluations: len(candidates)}
}
