package hnsw

import (
	"container/heap"
	"errors"
	"fmt"
	"sort"

	"vectorengine.local/poc/internal/vector"
)

// M caps upper-layer degree; level zero uses 2M.
type ACORNOptions struct {
	M          int
	EntryPoint NodeID
	MaxLevel   int
}

type ACORNExpansionTrace struct {
	ProviderCalls                 int `json:"provider_calls"`
	DirectNeighborsRead           int `json:"direct_neighbors_read"`
	SecondHopEdgesRead            int `json:"second_hop_edges_read"`
	CurrentNodeOccurrencesRemoved int `json:"current_node_occurrences_removed"`
	DuplicateNodesRemoved         int `json:"duplicate_nodes_removed"`
	PredicateEvaluations          int `json:"predicate_evaluations"`
	PredicateFailures             int `json:"predicate_failures"`
	EligibleBeforeTruncation      int `json:"eligible_before_truncation"`
	CandidatesAfterTruncation     int `json:"candidates_after_truncation"`
}

func (t *ACORNExpansionTrace) add(other ACORNExpansionTrace) {
	t.ProviderCalls += other.ProviderCalls
	t.DirectNeighborsRead += other.DirectNeighborsRead
	t.SecondHopEdgesRead += other.SecondHopEdgesRead
	t.CurrentNodeOccurrencesRemoved += other.CurrentNodeOccurrencesRemoved
	t.DuplicateNodesRemoved += other.DuplicateNodesRemoved
	t.PredicateEvaluations += other.PredicateEvaluations
	t.PredicateFailures += other.PredicateFailures
	t.EligibleBeforeTruncation += other.EligibleBeforeTruncation
	t.CandidatesAfterTruncation += other.CandidatesAfterTruncation
}

type ACORNLayerSearchTrace struct {
	Search           SearchTrace         `json:"search"`
	Expansion        ACORNExpansionTrace `json:"expansion"`
	BridgeExpansions int                 `json:"bridge_expansions"`
}

type ACORNGreedyLevelTrace struct {
	Level           int                   `json:"level"`
	From            NodeID                `json:"from"`
	To              Neighbor              `json:"to"`
	StartedEligible bool                  `json:"started_eligible"`
	EndedEligible   bool                  `json:"ended_eligible"`
	Trace           ACORNLayerSearchTrace `json:"trace"`
}

type ACORNIndexSearchTrace struct {
	RequestedK               int                     `json:"requested_k"`
	RequestedEF              int                     `json:"requested_ef"`
	EffectiveEF              int                     `json:"effective_ef"`
	SeedPredicateEvaluations int                     `json:"seed_predicate_evaluations"`
	SeedPredicateFailures    int                     `json:"seed_predicate_failures"`
	UpperDescent             []ACORNGreedyLevelTrace `json:"upper_descent,omitempty"`
	BaseLayer                ACORNLayerSearchTrace   `json:"base_layer"`
	DistanceEvaluations      int                     `json:"distance_evaluations"`
}

func (t ACORNIndexSearchTrace) ExpansionTotals() ACORNExpansionTrace {
	result := t.BaseLayer.Expansion
	for _, level := range t.UpperDescent {
		result.add(level.Trace.Expansion)
	}
	return result
}

func (t ACORNIndexSearchTrace) VisitedNodes() int {
	result := t.BaseLayer.Search.VisitedNodes
	for _, level := range t.UpperDescent {
		result += level.Trace.Search.VisitedNodes
	}
	return result
}

func (t ACORNIndexSearchTrace) TotalPredicateEvaluations() int {
	return t.SeedPredicateEvaluations + t.ExpansionTotals().PredicateEvaluations
}

type ACORNSearchResult struct {
	Neighbors []Neighbor            `json:"neighbors"`
	Trace     ACORNIndexSearchTrace `json:"trace"`
}

func ExpandACORNNeighbors(
	graph GraphView,
	current NodeID,
	level int,
	m int,
	eligible ResultEligibility,
) ([]NodeID, ACORNExpansionTrace, error) {
	if graph == nil {
		return nil, ACORNExpansionTrace{}, errors.New("ACORN graph is nil")
	}
	if level < 0 {
		return nil, ACORNExpansionTrace{}, errors.New("ACORN level cannot be negative")
	}
	if m < 2 || m > 64 {
		return nil, ACORNExpansionTrace{}, errors.New("ACORN M must be between 2 and 64")
	}
	if eligible == nil {
		return nil, ACORNExpansionTrace{}, errors.New("ACORN eligibility predicate is nil")
	}
	return acornExpandedNeighbors(graph, current, level, m, eligible)
}

// Never falls back to exact search.
func (i *Index) ACORNFilteredSearch(
	query []float32,
	k int,
	ef int,
	eligible ResultEligibility,
) (ACORNSearchResult, error) {
	if k < 1 {
		return ACORNSearchResult{}, errors.New("ACORN k must be at least one")
	}
	if ef < 1 {
		return ACORNSearchResult{}, errors.New("ACORN ef must be at least one")
	}
	if eligible == nil {
		return ACORNSearchResult{}, errors.New("ACORN eligibility predicate is nil")
	}
	prepared, err := i.space.PrepareFloat32(query)
	if err != nil {
		return ACORNSearchResult{}, fmt.Errorf("prepare ACORN query: %w", err)
	}
	effectiveEF := max(k, ef)
	if len(i.nodes) == 0 {
		return ACORNSearchResult{Trace: ACORNIndexSearchTrace{
			RequestedK:  k,
			RequestedEF: ef,
			EffectiveEF: effectiveEF,
		}}, nil
	}
	if !i.hasEntryPoint || uint64(i.entryPoint) >= uint64(len(i.nodes)) {
		return ACORNSearchResult{}, errors.New("ACORN index has no valid entry point")
	}
	return searchACORNPrepared(
		i.space,
		prepared,
		k,
		ef,
		i,
		ACORNOptions{M: i.config.M, EntryPoint: i.entryPoint, MaxLevel: i.maxLevel},
		eligible,
	)
}

func SearchACORN(
	space vector.Space,
	query []float32,
	k int,
	ef int,
	graph GraphView,
	options ACORNOptions,
	eligible ResultEligibility,
) (ACORNSearchResult, error) {
	prepared, err := space.PrepareFloat32(query)
	if err != nil {
		return ACORNSearchResult{}, fmt.Errorf("prepare ACORN query: %w", err)
	}
	return searchACORNPrepared(space, prepared, k, ef, graph, options, eligible)
}

func searchACORNPrepared(
	space vector.Space,
	query []float32,
	k int,
	ef int,
	graph GraphView,
	options ACORNOptions,
	eligible ResultEligibility,
) (ACORNSearchResult, error) {
	if graph == nil {
		return ACORNSearchResult{}, errors.New("ACORN graph is nil")
	}
	if eligible == nil {
		return ACORNSearchResult{}, errors.New("ACORN eligibility predicate is nil")
	}
	if k < 1 {
		return ACORNSearchResult{}, errors.New("ACORN k must be at least one")
	}
	if ef < 1 {
		return ACORNSearchResult{}, errors.New("ACORN ef must be at least one")
	}
	if options.M < 2 || options.M > 64 {
		return ACORNSearchResult{}, errors.New("ACORN M must be between 2 and 64")
	}
	if options.MaxLevel < 0 {
		return ACORNSearchResult{}, errors.New("ACORN maximum level cannot be negative")
	}
	entryVector, exists := graph.Vector(options.EntryPoint)
	if !exists {
		return ACORNSearchResult{}, fmt.Errorf("ACORN entry point %d does not exist", options.EntryPoint)
	}
	if len(entryVector) != space.Dimension() {
		return ACORNSearchResult{}, fmt.Errorf(
			"ACORN entry point %d has dimension %d, want %d",
			options.EntryPoint,
			len(entryVector),
			space.Dimension(),
		)
	}
	if _, exists := graph.Neighbors(options.EntryPoint, options.MaxLevel); !exists {
		return ACORNSearchResult{}, fmt.Errorf(
			"ACORN entry point %d does not exist at maximum level %d",
			options.EntryPoint,
			options.MaxLevel,
		)
	}

	effectiveEF := max(k, ef)
	trace := ACORNIndexSearchTrace{
		RequestedK:               k,
		RequestedEF:              ef,
		EffectiveEF:              effectiveEF,
		SeedPredicateEvaluations: 1,
		DistanceEvaluations:      1,
	}
	current := scoredNode{
		nodeID:   options.EntryPoint,
		distance: space.Distance(query, entryVector),
	}
	currentEligible := eligible(current.nodeID)
	if !currentEligible {
		trace.SeedPredicateFailures = 1
	}

	for level := options.MaxLevel; level > 0; level-- {
		from := current.nodeID
		startedEligible := currentEligible
		updated, endedEligible, levelTrace, err := acornGreedyAtLevelPrepared(
			space,
			query,
			current,
			currentEligible,
			level,
			graph,
			options.M,
			eligible,
		)
		if err != nil {
			return ACORNSearchResult{}, fmt.Errorf("descend ACORN level %d: %w", level, err)
		}
		current = updated
		currentEligible = endedEligible
		trace.DistanceEvaluations += levelTrace.Search.DistanceEvaluations
		trace.UpperDescent = append(trace.UpperDescent, ACORNGreedyLevelTrace{
			Level:           level,
			From:            from,
			To:              Neighbor{NodeID: current.nodeID, Distance: current.distance},
			StartedEligible: startedEligible,
			EndedEligible:   currentEligible,
			Trace:           levelTrace,
		})
	}

	base, err := acornSearchBasePrepared(
		space,
		query,
		current,
		currentEligible,
		effectiveEF,
		graph,
		options.M,
		eligible,
	)
	if err != nil {
		return ACORNSearchResult{}, fmt.Errorf("search ACORN base layer: %w", err)
	}
	trace.BaseLayer = base.Trace
	trace.DistanceEvaluations += base.Trace.Search.DistanceEvaluations
	neighbors := base.Neighbors
	if len(neighbors) > k {
		neighbors = neighbors[:k]
	}
	return ACORNSearchResult{Neighbors: neighbors, Trace: trace}, nil
}

type acornLayerResult struct {
	Neighbors []Neighbor
	Trace     ACORNLayerSearchTrace
}

func acornGreedyAtLevelPrepared(
	space vector.Space,
	query []float32,
	current scoredNode,
	currentEligible bool,
	level int,
	graph GraphView,
	m int,
	eligible ResultEligibility,
) (scoredNode, bool, ACORNLayerSearchTrace, error) {
	visited := map[NodeID]struct{}{current.nodeID: {}}
	trace := ACORNLayerSearchTrace{}
	for {
		if !currentEligible {
			trace.BridgeExpansions++
		}
		neighbors, expansion, err := acornExpandedNeighbors(graph, current.nodeID, level, m, eligible)
		if err != nil {
			return scoredNode{}, false, ACORNLayerSearchTrace{}, err
		}
		trace.Expansion.add(expansion)
		trace.Search.ExpandedNodes++
		best := current
		bestEligible := currentEligible
		for _, neighborID := range neighbors {
			if _, seen := visited[neighborID]; seen {
				continue
			}
			visited[neighborID] = struct{}{}
			neighborVector, exists := graph.Vector(neighborID)
			if !exists {
				return scoredNode{}, false, ACORNLayerSearchTrace{}, fmt.Errorf(
					"ACORN neighbour %d from node %d does not exist",
					neighborID,
					current.nodeID,
				)
			}
			if len(neighborVector) != space.Dimension() {
				return scoredNode{}, false, ACORNLayerSearchTrace{}, fmt.Errorf(
					"ACORN node %d has dimension %d, want %d",
					neighborID,
					len(neighborVector),
					space.Dimension(),
				)
			}
			scored := scoredNode{nodeID: neighborID, distance: space.Distance(query, neighborVector)}
			trace.Search.DistanceEvaluations++
			if !bestEligible || betterNode(scored, best) {
				best = scored
				bestEligible = true
			}
		}
		if best.nodeID == current.nodeID {
			trace.Search.VisitedNodes = len(visited)
			return current, currentEligible, trace, nil
		}
		current = best
		currentEligible = true
	}
}

func acornSearchBasePrepared(
	space vector.Space,
	query []float32,
	entry scoredNode,
	entryEligible bool,
	ef int,
	graph GraphView,
	m int,
	eligible ResultEligibility,
) (acornLayerResult, error) {
	visited := map[NodeID]struct{}{entry.nodeID: {}}
	candidates := bestFirstHeap{entry}
	heap.Init(&candidates)
	results := make(worstFirstHeap, 0, ef)
	heap.Init(&results)
	trace := ACORNLayerSearchTrace{}
	trace.Search.CandidatePushes = 1
	if entryEligible {
		heap.Push(&results, entry)
		trace.Search.ResultPushes = 1
	}

	for candidates.Len() > 0 {
		current := heap.Pop(&candidates).(scoredNode)
		if results.Len() >= ef && betterNode(results[0], current) {
			trace.Search.EarlyTerminated = true
			break
		}
		if current.nodeID == entry.nodeID && !entryEligible {
			trace.BridgeExpansions++
		}
		neighbors, expansion, err := acornExpandedNeighbors(graph, current.nodeID, 0, m, eligible)
		if err != nil {
			return acornLayerResult{}, err
		}
		trace.Expansion.add(expansion)
		trace.Search.ExpandedNodes++
		for _, neighborID := range neighbors {
			if _, seen := visited[neighborID]; seen {
				continue
			}
			visited[neighborID] = struct{}{}
			neighborVector, exists := graph.Vector(neighborID)
			if !exists {
				return acornLayerResult{}, fmt.Errorf(
					"ACORN neighbour %d from node %d does not exist",
					neighborID,
					current.nodeID,
				)
			}
			if len(neighborVector) != space.Dimension() {
				return acornLayerResult{}, fmt.Errorf(
					"ACORN node %d has dimension %d, want %d",
					neighborID,
					len(neighborVector),
					space.Dimension(),
				)
			}
			scored := scoredNode{nodeID: neighborID, distance: space.Distance(query, neighborVector)}
			trace.Search.DistanceEvaluations++
			withinResultBound := results.Len() < ef || betterNode(scored, results[0])
			if withinResultBound {
				heap.Push(&candidates, scored)
				trace.Search.CandidatePushes++
				heap.Push(&results, scored)
				trace.Search.ResultPushes++
				if results.Len() > ef {
					heap.Pop(&results)
				}
			}
		}
	}

	trace.Search.VisitedNodes = len(visited)
	neighbors := make([]Neighbor, len(results))
	for index, scored := range results {
		neighbors[index] = Neighbor{NodeID: scored.nodeID, Distance: scored.distance}
	}
	sort.Slice(neighbors, func(left, right int) bool {
		return betterNode(
			scoredNode{nodeID: neighbors[left].NodeID, distance: neighbors[left].Distance},
			scoredNode{nodeID: neighbors[right].NodeID, distance: neighbors[right].Distance},
		)
	})
	return acornLayerResult{Neighbors: neighbors, Trace: trace}, nil
}

func acornExpandedNeighbors(
	graph GraphView,
	current NodeID,
	level int,
	m int,
	eligible ResultEligibility,
) ([]NodeID, ACORNExpansionTrace, error) {
	direct, exists := graph.Neighbors(current, level)
	if !exists {
		return nil, ACORNExpansionTrace{}, fmt.Errorf(
			"ACORN node %d does not exist at level %d",
			current,
			level,
		)
	}
	trace := ACORNExpansionTrace{
		ProviderCalls:       1,
		DirectNeighborsRead: len(direct),
	}
	seen := make(map[NodeID]struct{}, len(direct)*(m+1))
	accepted := make([]NodeID, 0, len(direct))
	consider := func(candidate NodeID) {
		if candidate == current {
			trace.CurrentNodeOccurrencesRemoved++
			return
		}
		if _, duplicate := seen[candidate]; duplicate {
			trace.DuplicateNodesRemoved++
			return
		}
		seen[candidate] = struct{}{}
		trace.PredicateEvaluations++
		if !eligible(candidate) {
			trace.PredicateFailures++
			return
		}
		accepted = append(accepted, candidate)
	}
	for _, directID := range direct {
		consider(directID)
		secondHop, secondExists := graph.Neighbors(directID, level)
		if !secondExists {
			return nil, ACORNExpansionTrace{}, fmt.Errorf(
				"ACORN direct neighbour %d from node %d does not exist at level %d",
				directID,
				current,
				level,
			)
		}
		trace.SecondHopEdgesRead += len(secondHop)
		for _, secondHopID := range secondHop {
			consider(secondHopID)
		}
	}
	trace.EligibleBeforeTruncation = len(accepted)
	limit := m
	if level == 0 {
		limit = m * 2
	}
	if len(accepted) > limit {
		accepted = accepted[:limit]
	}
	trace.CandidatesAfterTruncation = len(accepted)
	return accepted, trace, nil
}
