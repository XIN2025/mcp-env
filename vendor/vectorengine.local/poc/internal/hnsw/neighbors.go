package hnsw

import (
	"errors"
	"fmt"
	"sort"

	"vectorengine.local/poc/internal/vector"
)

type SelectionOptions struct {
	MaxNeighbors          int
	ExcludeNode           *NodeID
	ExtendCandidates      bool
	KeepPrunedConnections bool
}

func SelectNeighbors(
	space vector.Space,
	query []float32,
	candidates []NodeID,
	graph GraphView,
	options SelectionOptions,
) (SelectionResult, error) {
	prepared, err := space.PrepareFloat32(query)
	if err != nil {
		return SelectionResult{}, fmt.Errorf("prepare neighbour-selection query: %w", err)
	}
	return selectNeighborsPrepared(space, prepared, candidates, graph, options)
}

func selectNeighborsPrepared(
	space vector.Space,
	query []float32,
	candidates []NodeID,
	graph GraphView,
	options SelectionOptions,
) (SelectionResult, error) {
	if graph == nil {
		return SelectionResult{}, errors.New("HNSW graph is nil")
	}
	if options.MaxNeighbors < 1 {
		return SelectionResult{}, errors.New("maximum neighbours must be at least one")
	}
	if options.ExtendCandidates {
		return SelectionResult{}, errors.New("candidate extension is not enabled in HNSW version one")
	}

	trace := SelectionTrace{InputCandidates: len(candidates)}
	seen := make(map[NodeID]struct{}, len(candidates))
	ordered := make([]scoredNode, 0, len(candidates))
	for _, candidateID := range candidates {
		if options.ExcludeNode != nil && candidateID == *options.ExcludeNode {
			trace.QueryNodeCandidatesRemoved++
			continue
		}
		if _, duplicate := seen[candidateID]; duplicate {
			trace.DuplicateCandidatesRemoved++
			continue
		}
		candidateVector, exists := graph.Vector(candidateID)
		if !exists {
			return SelectionResult{}, fmt.Errorf("HNSW candidate %d does not exist", candidateID)
		}
		if len(candidateVector) != space.Dimension() {
			return SelectionResult{}, fmt.Errorf("HNSW node %d has dimension %d, want %d", candidateID, len(candidateVector), space.Dimension())
		}
		seen[candidateID] = struct{}{}
		ordered = append(ordered, scoredNode{nodeID: candidateID, distance: space.Distance(query, candidateVector)})
		trace.QueryDistanceEvaluations++
	}
	trace.UniqueCandidates = len(ordered)
	sort.Slice(ordered, func(left, right int) bool { return betterNode(ordered[left], ordered[right]) })

	accepted := make([]scoredNode, 0, options.MaxNeighbors)
	discarded := make([]scoredNode, 0, len(ordered))
	for _, candidate := range ordered {
		if len(accepted) >= options.MaxNeighbors {
			break
		}
		candidateVector, _ := graph.Vector(candidate.nodeID)
		diverse := true
		for _, selected := range accepted {
			selectedVector, _ := graph.Vector(selected.nodeID)
			trace.InterCandidateDistanceEvals++
			if space.Distance(candidateVector, selectedVector) <= candidate.distance {
				diverse = false
				break
			}
		}
		if diverse {
			accepted = append(accepted, candidate)
		} else {
			discarded = append(discarded, candidate)
		}
	}
	trace.AcceptedByDiversity = len(accepted)

	restored := make([]scoredNode, 0, options.MaxNeighbors-len(accepted))
	if options.KeepPrunedConnections {
		for _, candidate := range discarded {
			if len(accepted)+len(restored) >= options.MaxNeighbors {
				break
			}
			restored = append(restored, candidate)
		}
	}
	trace.RestoredFromDiscarded = len(restored)

	selected := append(append(make([]scoredNode, 0, len(accepted)+len(restored)), accepted...), restored...)
	sort.Slice(selected, func(left, right int) bool { return betterNode(selected[left], selected[right]) })
	return SelectionResult{
		Selected: scoredNodesToNeighbors(selected),
		Accepted: scoredNodesToNeighbors(accepted),
		Restored: scoredNodesToNeighbors(restored),
		Trace:    trace,
	}, nil
}

func scoredNodesToNeighbors(values []scoredNode) []Neighbor {
	result := make([]Neighbor, len(values))
	for index, value := range values {
		result[index] = Neighbor{NodeID: value.nodeID, Distance: value.distance}
	}
	return result
}
