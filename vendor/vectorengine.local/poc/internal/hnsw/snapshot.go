package hnsw

import (
	"errors"
	"fmt"
	"math"

	"vectorengine.local/poc/internal/vector"
)

const maxSnapshotLevel = 64

type SnapshotNode struct {
	Vector    []float32
	MaxLevel  int
	Neighbors [][]NodeID
}

type Snapshot struct {
	RandomState    uint64
	HasEntryPoint  bool
	EntryPoint     NodeID
	MaxLevel       int
	Nodes          []SnapshotNode
	OldNodeIDs     []NodeID
	DroppedNodeIDs []NodeID
}

// Keeps edge order so an all-live snapshot has the same topology digest.
func (i *Index) CompactSnapshot(live func(NodeID) bool) (Snapshot, error) {
	if live == nil {
		live = func(NodeID) bool { return true }
	}
	result := Snapshot{RandomState: i.random.state, MaxLevel: -1}
	remap := make(map[NodeID]NodeID, len(i.nodes))
	for oldIndex := range i.nodes {
		oldID := NodeID(oldIndex)
		if !live(oldID) {
			result.DroppedNodeIDs = append(result.DroppedNodeIDs, oldID)
			continue
		}
		if uint64(len(result.OldNodeIDs)) > uint64(math.MaxUint32) {
			return Snapshot{}, errors.New("compact HNSW node ID space exhausted")
		}
		remap[oldID] = NodeID(len(result.OldNodeIDs))
		result.OldNodeIDs = append(result.OldNodeIDs, oldID)
	}
	result.Nodes = make([]SnapshotNode, len(result.OldNodeIDs))
	for newIndex, oldID := range result.OldNodeIDs {
		old := i.nodes[oldID]
		compact := SnapshotNode{
			Vector:    append([]float32(nil), old.vector...),
			MaxLevel:  old.maxLevel,
			Neighbors: make([][]NodeID, len(old.neighbors)),
		}
		for level, adjacency := range old.neighbors {
			for _, oldNeighbor := range adjacency {
				newNeighbor, retained := remap[oldNeighbor]
				if retained {
					compact.Neighbors[level] = append(compact.Neighbors[level], newNeighbor)
				}
			}
		}
		result.Nodes[newIndex] = compact
	}
	if len(result.Nodes) == 0 {
		return result, nil
	}
	result.HasEntryPoint = true
	if current, retained := remap[i.entryPoint]; retained {
		result.EntryPoint = current
		result.MaxLevel = result.Nodes[current].MaxLevel
	} else {
		result.EntryPoint = 0
		result.MaxLevel = result.Nodes[0].MaxLevel
		for nodeID := 1; nodeID < len(result.Nodes); nodeID++ {
			if result.Nodes[nodeID].MaxLevel > result.MaxLevel {
				result.EntryPoint = NodeID(nodeID)
				result.MaxLevel = result.Nodes[nodeID].MaxLevel
			}
		}
	}
	return result, nil
}

func RestoreSnapshot(space vector.Space, config Config, snapshot Snapshot) (*Index, error) {
	index, err := New(space, config)
	if err != nil {
		return nil, err
	}
	index.random.state = snapshot.RandomState
	if len(snapshot.Nodes) == 0 {
		if snapshot.HasEntryPoint || snapshot.MaxLevel != -1 {
			return nil, errors.New("empty HNSW snapshot has an entry point or maximum level")
		}
		return index, nil
	}
	if !snapshot.HasEntryPoint || uint64(snapshot.EntryPoint) >= uint64(len(snapshot.Nodes)) {
		return nil, errors.New("HNSW snapshot entry point is absent or out of range")
	}
	index.nodes = make([]node, len(snapshot.Nodes))
	for nodeIndex, source := range snapshot.Nodes {
		if source.MaxLevel < 0 || source.MaxLevel > maxSnapshotLevel || len(source.Neighbors) != source.MaxLevel+1 {
			return nil, fmt.Errorf("HNSW snapshot node %d has an invalid level array", nodeIndex)
		}
		prepared, err := space.RestoreFloat32(source.Vector)
		if err != nil {
			return nil, fmt.Errorf("restore HNSW snapshot vector %d: %w", nodeIndex, err)
		}
		index.nodes[nodeIndex] = node{
			vector:    prepared,
			maxLevel:  source.MaxLevel,
			neighbors: make([][]NodeID, len(source.Neighbors)),
		}
		for level, adjacency := range source.Neighbors {
			index.nodes[nodeIndex].neighbors[level] = append([]NodeID(nil), adjacency...)
		}
		index.levelHistogram[source.MaxLevel]++
	}
	index.hasEntryPoint = true
	index.entryPoint = snapshot.EntryPoint
	index.maxLevel = snapshot.MaxLevel
	audit := index.Audit()
	if !audit.Valid {
		return nil, fmt.Errorf("restored HNSW snapshot failed structural audit: %v", audit.Violations)
	}
	return index, nil
}
