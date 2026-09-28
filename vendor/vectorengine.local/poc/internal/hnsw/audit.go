package hnsw

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

const maxAuditViolations = 32

// Read-only: it never repairs the graph.
func (i *Index) Audit() AuditReport {
	report := AuditReport{
		Nodes:         len(i.nodes),
		DirectedEdges: i.directedEdgeCount(),
		LevelDegrees:  make(map[int]DegreeSummary),
	}
	if len(i.nodes) == 0 {
		report.EntryPointValid = !i.hasEntryPoint && i.maxLevel == -1
		report.MaxLevelMatches = i.maxLevel == -1
		report.LevelHistogramMatches = len(i.levelHistogram) == 0
		report.Valid = report.EntryPointValid && report.MaxLevelMatches && report.LevelHistogramMatches
		return report
	}

	report.EntryPointValid = i.hasEntryPoint && uint64(i.entryPoint) < uint64(len(i.nodes))
	actualMaxLevel := -1
	actualHistogram := make(map[int]int)
	degreeValues := make(map[int][]int)
	for sourceIndex := range i.nodes {
		sourceID := NodeID(sourceIndex)
		source := &i.nodes[sourceIndex]
		if source.maxLevel > actualMaxLevel {
			actualMaxLevel = source.maxLevel
		}
		actualHistogram[source.maxLevel]++
		if len(source.neighbors) != source.maxLevel+1 || source.maxLevel < 0 {
			report.MalformedLevelArrays++
			report.addViolation("node %d has maxLevel=%d and %d adjacency levels", sourceID, source.maxLevel, len(source.neighbors))
		}
		if _, err := i.space.RestoreFloat32(source.vector); err != nil {
			report.InvalidVectors++
			report.addViolation("node %d has invalid vector: %v", sourceID, err)
		}
		for level, adjacency := range source.neighbors {
			degreeValues[level] = append(degreeValues[level], len(adjacency))
			if len(adjacency) > i.degreeLimit(level) {
				report.DegreeViolations++
				report.addViolation("node %d level %d degree %d exceeds %d", sourceID, level, len(adjacency), i.degreeLimit(level))
			}
			seen := make(map[NodeID]struct{}, len(adjacency))
			for _, targetID := range adjacency {
				if targetID == sourceID {
					report.SelfEdges++
					report.addViolation("node %d has a self-edge at level %d", sourceID, level)
				}
				if _, duplicate := seen[targetID]; duplicate {
					report.DuplicateEdges++
					report.addViolation("node %d repeats neighbour %d at level %d", sourceID, targetID, level)
					continue
				}
				seen[targetID] = struct{}{}
				if !i.nodeExistsAtLevel(targetID, level) {
					report.DanglingEdges++
					report.addViolation("node %d targets absent node %d at level %d", sourceID, targetID, level)
					continue
				}
				if !containsID(i.nodes[targetID].neighbors[level], sourceID) {
					report.MissingReciprocals++
					report.addViolation("edge %d -> %d at level %d lacks reciprocal", sourceID, targetID, level)
				}
			}
		}
	}

	report.MaxLevelMatches = actualMaxLevel == i.maxLevel && report.EntryPointValid && i.nodes[i.entryPoint].maxLevel == i.maxLevel
	report.LevelHistogramMatches = equalHistogram(actualHistogram, i.levelHistogram)
	report.LevelZeroReachable = i.levelZeroReachable()
	report.LevelZeroUnreachable = len(i.nodes) - report.LevelZeroReachable
	report.UndirectedEdges = report.DirectedEdges / 2
	for level, degrees := range degreeValues {
		total := 0
		minimum := math.MaxInt
		maximum := 0
		for _, degree := range degrees {
			total += degree
			if degree < minimum {
				minimum = degree
			}
			if degree > maximum {
				maximum = degree
			}
		}
		if minimum == math.MaxInt {
			minimum = 0
		}
		report.LevelDegrees[level] = DegreeSummary{
			Nodes:    len(degrees),
			Min:      minimum,
			Max:      maximum,
			Mean:     float64(total) / float64(len(degrees)),
			Capacity: i.degreeLimit(level),
		}
	}

	report.Valid = report.EntryPointValid &&
		report.MaxLevelMatches &&
		report.LevelHistogramMatches &&
		report.SelfEdges == 0 &&
		report.DuplicateEdges == 0 &&
		report.DanglingEdges == 0 &&
		report.MissingReciprocals == 0 &&
		report.DegreeViolations == 0 &&
		report.InvalidVectors == 0 &&
		report.MalformedLevelArrays == 0
	return report
}

func (r *AuditReport) addViolation(format string, args ...any) {
	if len(r.Violations) < maxAuditViolations {
		r.Violations = append(r.Violations, fmt.Sprintf(format, args...))
	}
}

func (i *Index) levelZeroReachable() int {
	if !i.hasEntryPoint || len(i.nodes) == 0 || !i.nodeExistsAtLevel(i.entryPoint, 0) {
		return 0
	}
	visited := map[NodeID]struct{}{i.entryPoint: {}}
	queue := []NodeID{i.entryPoint}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, neighbor := range i.nodes[current].neighbors[0] {
			if uint64(neighbor) >= uint64(len(i.nodes)) {
				continue
			}
			if _, seen := visited[neighbor]; seen {
				continue
			}
			visited[neighbor] = struct{}{}
			queue = append(queue, neighbor)
		}
	}
	return len(visited)
}

func containsID(values []NodeID, target NodeID) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalHistogram(left, right map[int]int) bool {
	if len(left) != len(right) {
		return false
	}
	for level, count := range left {
		if right[level] != count {
			return false
		}
	}
	return true
}

// Excludes vector bytes; receipts record dataset identity separately.
func (i *Index) TopologySHA256() string {
	digest := sha256.New()
	writeUint64 := func(value uint64) {
		var encoded [8]byte
		binary.LittleEndian.PutUint64(encoded[:], value)
		_, _ = digest.Write(encoded[:])
	}
	writeUint64(uint64(i.config.M))
	writeUint64(uint64(i.config.EFConstruction))
	writeUint64(i.config.RandomSeed)
	writeUint64(uint64(len(i.nodes)))
	writeUint64(uint64(i.entryPoint))
	writeUint64(uint64(i.maxLevel + 1))
	for sourceIndex := range i.nodes {
		source := &i.nodes[sourceIndex]
		writeUint64(uint64(source.maxLevel + 1))
		for level, adjacency := range source.neighbors {
			writeUint64(uint64(level))
			sorted := append([]NodeID(nil), adjacency...)
			sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
			writeUint64(uint64(len(sorted)))
			for _, target := range sorted {
				writeUint64(uint64(target))
			}
		}
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}
