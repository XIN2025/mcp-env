package hnsw

import (
	"errors"
	"fmt"
	"math"
)

// An error after validation means the graph is corrupt; discard the index.
func (i *Index) Insert(values []float32) (NodeID, InsertTrace, error) {
	prepared, err := i.space.RestoreFloat32(values)
	if err != nil {
		return 0, InsertTrace{}, fmt.Errorf("validate HNSW vector: %w", err)
	}
	if uint64(len(i.nodes)) > uint64(math.MaxUint32) {
		return 0, InsertTrace{}, errors.New("HNSW node ID space exhausted")
	}

	levelSample := i.nextLevel()
	id := NodeID(len(i.nodes))
	trace := InsertTrace{
		NodeID:        id,
		AssignedLevel: levelSample.Level,
		LevelSample:   levelSample,
		FirstNode:     len(i.nodes) == 0,
	}
	if len(i.nodes) == 0 {
		i.nodes = append(i.nodes, node{
			vector:    prepared,
			maxLevel:  levelSample.Level,
			neighbors: make([][]NodeID, levelSample.Level+1),
		})
		i.entryPoint = id
		i.hasEntryPoint = true
		i.maxLevel = levelSample.Level
		i.levelHistogram[levelSample.Level]++
		return id, trace, nil
	}

	entryPoint := i.entryPoint
	for level := i.maxLevel; level > levelSample.Level; level-- {
		from := entryPoint
		nearest, searchTrace, searchErr := greedyAtLevelPrepared(i.space, prepared, entryPoint, level, i)
		if searchErr != nil {
			return 0, trace, fmt.Errorf("descend HNSW level %d: %w", level, searchErr)
		}
		entryPoint = nearest.NodeID
		trace.UpperDescent = append(trace.UpperDescent, GreedyLevelTrace{
			Level: level,
			From:  from,
			To:    nearest,
			Trace: searchTrace,
		})
		trace.DistanceEvaluations += searchTrace.DistanceEvaluations
	}

	i.nodes = append(i.nodes, node{
		vector:    prepared,
		maxLevel:  levelSample.Level,
		neighbors: make([][]NodeID, levelSample.Level+1),
	})

	entryPoints := []NodeID{entryPoint}
	startLevel := levelSample.Level
	if startLevel > i.maxLevel {
		startLevel = i.maxLevel
	}
	for level := startLevel; level >= 0; level-- {
		layer, searchErr := searchLayerPrepared(
			i.space,
			prepared,
			entryPoints,
			i.config.EFConstruction,
			level,
			i,
			func(candidate NodeID) bool { return candidate != id },
		)
		if searchErr != nil {
			return 0, trace, fmt.Errorf("search HNSW insertion candidates at level %d: %w", level, searchErr)
		}
		candidateIDs := neighborIDs(layer.Neighbors)
		selection, selectionErr := selectNeighborsPrepared(
			i.space,
			prepared,
			candidateIDs,
			i,
			SelectionOptions{
				MaxNeighbors:          i.config.M,
				ExcludeNode:           &id,
				KeepPrunedConnections: true,
			},
		)
		if selectionErr != nil {
			return 0, trace, fmt.Errorf("select HNSW neighbours at level %d: %w", level, selectionErr)
		}

		layerTrace := InsertLayerTrace{
			Level:           level,
			EntryPointCount: len(entryPoints),
			CandidateCount:  len(candidateIDs),
			Selected:        neighborIDs(selection.Selected),
			Search:          layer.Trace,
			Selection:       selection.Trace,
		}
		trace.DistanceEvaluations += layer.Trace.DistanceEvaluations
		trace.DistanceEvaluations += selection.Trace.QueryDistanceEvaluations
		trace.DistanceEvaluations += selection.Trace.InterCandidateDistanceEvals

		for _, selected := range selection.Selected {
			neighborID := selected.NodeID
			if !i.nodeExistsAtLevel(neighborID, level) {
				return 0, trace, fmt.Errorf("selected HNSW neighbour %d is absent at level %d", neighborID, level)
			}
			if i.addNeighbor(id, neighborID, level) {
				layerTrace.DirectedEdgesAdded++
			}
			if i.addNeighbor(neighborID, id, level) {
				layerTrace.DirectedEdgesAdded++
			}

			capacity := i.degreeLimit(level)
			if len(i.nodes[neighborID].neighbors[level]) <= capacity {
				continue
			}
			pruneCandidates := append([]NodeID(nil), i.nodes[neighborID].neighbors[level]...)
			pruneSelection, pruneErr := selectNeighborsPrepared(
				i.space,
				i.nodes[neighborID].vector,
				pruneCandidates,
				i,
				SelectionOptions{
					MaxNeighbors:          capacity,
					ExcludeNode:           &neighborID,
					KeepPrunedConnections: true,
				},
			)
			if pruneErr != nil {
				return 0, trace, fmt.Errorf("prune HNSW node %d at level %d: %w", neighborID, level, pruneErr)
			}
			removed := i.replaceNeighbors(neighborID, level, neighborIDs(pruneSelection.Selected))
			layerTrace.ExistingNodesPruned++
			layerTrace.DirectedEdgesRemoved += len(removed) * 2
			trace.DistanceEvaluations += pruneSelection.Trace.QueryDistanceEvaluations
			trace.DistanceEvaluations += pruneSelection.Trace.InterCandidateDistanceEvals
		}

		trace.DirectedEdgesAdded += layerTrace.DirectedEdgesAdded
		trace.DirectedEdgesRemoved += layerTrace.DirectedEdgesRemoved
		trace.ExistingNodesPruned += layerTrace.ExistingNodesPruned
		trace.LayerInsertions = append(trace.LayerInsertions, layerTrace)
		entryPoints = candidateIDs
	}

	if levelSample.Level > i.maxLevel {
		i.entryPoint = id
		i.maxLevel = levelSample.Level
	}
	i.levelHistogram[levelSample.Level]++
	return id, trace, nil
}

func (i *Index) degreeLimit(level int) int {
	if level == 0 {
		return i.config.M * 2
	}
	return i.config.M
}

func (i *Index) nodeExistsAtLevel(id NodeID, level int) bool {
	return uint64(id) < uint64(len(i.nodes)) && level >= 0 && level <= i.nodes[id].maxLevel
}

func (i *Index) addNeighbor(source, target NodeID, level int) bool {
	adjacency := i.nodes[source].neighbors[level]
	for _, existing := range adjacency {
		if existing == target {
			return false
		}
	}
	i.nodes[source].neighbors[level] = append(adjacency, target)
	return true
}

func (i *Index) removeNeighbor(source, target NodeID, level int) bool {
	if !i.nodeExistsAtLevel(source, level) {
		return false
	}
	adjacency := i.nodes[source].neighbors[level]
	for index, existing := range adjacency {
		if existing != target {
			continue
		}
		copy(adjacency[index:], adjacency[index+1:])
		i.nodes[source].neighbors[level] = adjacency[:len(adjacency)-1]
		return true
	}
	return false
}

func (i *Index) replaceNeighbors(source NodeID, level int, replacements []NodeID) []NodeID {
	keep := make(map[NodeID]struct{}, len(replacements))
	for _, replacement := range replacements {
		keep[replacement] = struct{}{}
	}
	old := i.nodes[source].neighbors[level]
	removed := make([]NodeID, 0, len(old))
	for _, previous := range old {
		if _, retained := keep[previous]; retained {
			continue
		}
		removed = append(removed, previous)
		i.removeNeighbor(previous, source, level)
	}
	i.nodes[source].neighbors[level] = append([]NodeID(nil), replacements...)
	return removed
}

func neighborIDs(neighbors []Neighbor) []NodeID {
	ids := make([]NodeID, len(neighbors))
	for index, neighbor := range neighbors {
		ids[index] = neighbor.NodeID
	}
	return ids
}
