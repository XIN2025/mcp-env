package hnsw

import (
	"container/heap"
	"errors"
	"fmt"
	"sort"

	"vectorengine.local/poc/internal/vector"
)

// Returned vectors and adjacency slices are immutable.
type GraphView interface {
	Vector(NodeID) ([]float32, bool)
	Neighbors(NodeID, int) ([]NodeID, bool)
}

type ResultEligibility func(NodeID) bool

func (i *Index) Search(query []float32, k, ef int, eligible ResultEligibility) (SearchResult, error) {
	if k < 1 {
		return SearchResult{}, errors.New("HNSW k must be at least one")
	}
	if ef < 1 {
		return SearchResult{}, errors.New("HNSW ef must be at least one")
	}
	prepared, err := i.space.PrepareFloat32(query)
	if err != nil {
		return SearchResult{}, fmt.Errorf("prepare HNSW query: %w", err)
	}
	effectiveEF := ef
	if effectiveEF < k {
		effectiveEF = k
	}
	result := SearchResult{Trace: IndexSearchTrace{
		RequestedK:  k,
		RequestedEF: ef,
		EffectiveEF: effectiveEF,
	}}
	if len(i.nodes) == 0 {
		return result, nil
	}
	if !i.hasEntryPoint || uint64(i.entryPoint) >= uint64(len(i.nodes)) {
		return SearchResult{}, errors.New("HNSW index has no valid entry point")
	}

	entryPoint := i.entryPoint
	for level := i.maxLevel; level > 0; level-- {
		from := entryPoint
		nearest, upperTrace, searchErr := greedyAtLevelPrepared(i.space, prepared, entryPoint, level, i)
		if searchErr != nil {
			return SearchResult{}, fmt.Errorf("descend HNSW level %d: %w", level, searchErr)
		}
		entryPoint = nearest.NodeID
		result.Trace.UpperDescent = append(result.Trace.UpperDescent, GreedyLevelTrace{
			Level: level,
			From:  from,
			To:    nearest,
			Trace: upperTrace,
		})
		result.Trace.DistanceEvaluations += upperTrace.DistanceEvaluations
	}
	base, err := searchLayerPrepared(i.space, prepared, []NodeID{entryPoint}, effectiveEF, 0, i, eligible)
	if err != nil {
		return SearchResult{}, fmt.Errorf("search HNSW base layer: %w", err)
	}
	result.Trace.BaseLayer = base.Trace
	result.Trace.DistanceEvaluations += base.Trace.DistanceEvaluations
	if len(base.Neighbors) > k {
		base.Neighbors = base.Neighbors[:k]
	}
	result.Neighbors = base.Neighbors
	return result, nil
}

func SearchLayer(
	space vector.Space,
	query []float32,
	entryPoints []NodeID,
	ef int,
	level int,
	graph GraphView,
	eligible ResultEligibility,
) (LayerSearchResult, error) {
	prepared, err := space.PrepareFloat32(query)
	if err != nil {
		return LayerSearchResult{}, fmt.Errorf("prepare HNSW query: %w", err)
	}
	return searchLayerPrepared(space, prepared, entryPoints, ef, level, graph, eligible)
}

func GreedyAtLevel(
	space vector.Space,
	query []float32,
	entryPoint NodeID,
	level int,
	graph GraphView,
) (Neighbor, SearchTrace, error) {
	prepared, err := space.PrepareFloat32(query)
	if err != nil {
		return Neighbor{}, SearchTrace{}, fmt.Errorf("prepare HNSW query: %w", err)
	}
	return greedyAtLevelPrepared(space, prepared, entryPoint, level, graph)
}

func greedyAtLevelPrepared(
	space vector.Space,
	query []float32,
	entryPoint NodeID,
	level int,
	graph GraphView,
) (Neighbor, SearchTrace, error) {
	result, err := searchLayerPrepared(
		space,
		query,
		[]NodeID{entryPoint},
		1,
		level,
		graph,
		func(NodeID) bool { return true },
	)
	if err != nil {
		return Neighbor{}, SearchTrace{}, err
	}
	if len(result.Neighbors) != 1 {
		return Neighbor{}, SearchTrace{}, errors.New("greedy HNSW search returned no entry point")
	}
	return result.Neighbors[0], result.Trace, nil
}

func searchLayerPrepared(
	space vector.Space,
	query []float32,
	entryPoints []NodeID,
	ef int,
	level int,
	graph GraphView,
	eligible ResultEligibility,
) (LayerSearchResult, error) {
	if graph == nil {
		return LayerSearchResult{}, errors.New("HNSW graph is nil")
	}
	if len(entryPoints) == 0 {
		return LayerSearchResult{}, errors.New("HNSW search requires at least one entry point")
	}
	if ef < 1 {
		return LayerSearchResult{}, errors.New("HNSW ef must be at least one")
	}
	if level < 0 {
		return LayerSearchResult{}, errors.New("HNSW level cannot be negative")
	}
	if eligible == nil {
		eligible = func(NodeID) bool { return true }
	}

	visited := make(map[NodeID]struct{}, ef*2)
	candidates := make(bestFirstHeap, 0, ef)
	results := make(worstFirstHeap, 0, ef)
	trace := SearchTrace{}

	for _, entryPoint := range entryPoints {
		if _, seen := visited[entryPoint]; seen {
			continue
		}
		entryVector, exists := graph.Vector(entryPoint)
		if !exists {
			return LayerSearchResult{}, fmt.Errorf("HNSW entry point %d does not exist", entryPoint)
		}
		if len(entryVector) != space.Dimension() {
			return LayerSearchResult{}, fmt.Errorf("HNSW node %d has dimension %d, want %d", entryPoint, len(entryVector), space.Dimension())
		}
		if _, levelExists := graph.Neighbors(entryPoint, level); !levelExists {
			return LayerSearchResult{}, fmt.Errorf("HNSW entry point %d does not exist at level %d", entryPoint, level)
		}
		visited[entryPoint] = struct{}{}
		scored := scoredNode{nodeID: entryPoint, distance: space.Distance(query, entryVector)}
		trace.DistanceEvaluations++
		heap.Push(&candidates, scored)
		trace.CandidatePushes++
		if eligible(entryPoint) {
			heap.Push(&results, scored)
			trace.ResultPushes++
		}
	}
	if len(candidates) == 0 {
		return LayerSearchResult{}, errors.New("HNSW entry-point set contained no nodes")
	}

	for candidates.Len() > 0 {
		current := heap.Pop(&candidates).(scoredNode)
		if results.Len() >= ef && betterNode(results[0], current) {
			trace.EarlyTerminated = true
			break
		}
		neighbors, exists := graph.Neighbors(current.nodeID, level)
		if !exists {
			return LayerSearchResult{}, fmt.Errorf("HNSW node %d does not exist at level %d", current.nodeID, level)
		}
		trace.ExpandedNodes++
		for _, neighborID := range neighbors {
			if _, seen := visited[neighborID]; seen {
				continue
			}
			neighborVector, exists := graph.Vector(neighborID)
			if !exists {
				return LayerSearchResult{}, fmt.Errorf("HNSW neighbor %d from node %d does not exist", neighborID, current.nodeID)
			}
			if len(neighborVector) != space.Dimension() {
				return LayerSearchResult{}, fmt.Errorf("HNSW node %d has dimension %d, want %d", neighborID, len(neighborVector), space.Dimension())
			}
			if _, levelExists := graph.Neighbors(neighborID, level); !levelExists {
				return LayerSearchResult{}, fmt.Errorf("HNSW neighbor %d does not exist at level %d", neighborID, level)
			}
			visited[neighborID] = struct{}{}
			scored := scoredNode{nodeID: neighborID, distance: space.Distance(query, neighborVector)}
			trace.DistanceEvaluations++
			withinResultBound := results.Len() < ef || betterNode(scored, results[0])
			if withinResultBound {
				heap.Push(&candidates, scored)
				trace.CandidatePushes++
			}
			if eligible(neighborID) && withinResultBound {
				heap.Push(&results, scored)
				trace.ResultPushes++
				if results.Len() > ef {
					heap.Pop(&results)
				}
			}
		}
	}

	trace.VisitedNodes = len(visited)
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
	return LayerSearchResult{Neighbors: neighbors, Trace: trace}, nil
}

type scoredNode struct {
	nodeID   NodeID
	distance float64
}

func betterNode(left, right scoredNode) bool {
	if left.distance != right.distance {
		return left.distance < right.distance
	}
	return left.nodeID < right.nodeID
}

type bestFirstHeap []scoredNode

func (h bestFirstHeap) Len() int                  { return len(h) }
func (h bestFirstHeap) Less(left, right int) bool { return betterNode(h[left], h[right]) }
func (h bestFirstHeap) Swap(left, right int)      { h[left], h[right] = h[right], h[left] }

func (h *bestFirstHeap) Push(value any) {
	*h = append(*h, value.(scoredNode))
}

func (h *bestFirstHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	*h = old[:last]
	return value
}

type worstFirstHeap []scoredNode

func (h worstFirstHeap) Len() int                  { return len(h) }
func (h worstFirstHeap) Less(left, right int) bool { return betterNode(h[right], h[left]) }
func (h worstFirstHeap) Swap(left, right int)      { h[left], h[right] = h[right], h[left] }

func (h *worstFirstHeap) Push(value any) {
	*h = append(*h, value.(scoredNode))
}

func (h *worstFirstHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	*h = old[:last]
	return value
}
