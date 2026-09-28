package hnsw

import (
	"errors"
	"fmt"
	"math"

	"vectorengine.local/poc/internal/vector"
)

type NodeID uint32

type Config struct {
	M              int
	EFConstruction int
	RandomSeed     uint64
}

func (c Config) validate() error {
	if c.M < 2 || c.M > 64 {
		return errors.New("M must be between 2 and 64")
	}
	if c.EFConstruction < c.M || c.EFConstruction > 4096 {
		return errors.New("efConstruction must be at least M and at most 4096")
	}
	return nil
}

type node struct {
	vector    []float32
	maxLevel  int
	neighbors [][]NodeID
}

type Index struct {
	space          vector.Space
	config         Config
	nodes          []node
	entryPoint     NodeID
	hasEntryPoint  bool
	maxLevel       int
	levelHistogram map[int]int
	random         splitMix64
}

func New(space vector.Space, config Config) (*Index, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid HNSW config: %w", err)
	}
	return &Index{
		space:          space,
		config:         config,
		maxLevel:       -1,
		levelHistogram: make(map[int]int),
		random:         splitMix64{state: config.RandomSeed},
	}, nil
}

func (i *Index) Len() int {
	return len(i.nodes)
}

// Callers must not modify the returned slice.
func (i *Index) Vector(id NodeID) ([]float32, bool) {
	if uint64(id) >= uint64(len(i.nodes)) {
		return nil, false
	}
	return i.nodes[id].vector, true
}

// Callers must not modify the returned slice.
func (i *Index) Neighbors(id NodeID, level int) ([]NodeID, bool) {
	if uint64(id) >= uint64(len(i.nodes)) || level < 0 || level > i.nodes[id].maxLevel {
		return nil, false
	}
	return i.nodes[id].neighbors[level], true
}

func (i *Index) Stats() Stats {
	histogram := make(map[int]int, len(i.levelHistogram))
	for level, count := range i.levelHistogram {
		histogram[level] = count
	}
	return Stats{
		Nodes:          len(i.nodes),
		EntryPoint:     i.entryPoint,
		HasEntryPoint:  i.hasEntryPoint,
		MaxLevel:       i.maxLevel,
		LevelHistogram: histogram,
		DirectedEdges:  i.directedEdgeCount(),
	}
}

func (i *Index) directedEdgeCount() int {
	total := 0
	for nodeIndex := range i.nodes {
		for level := range i.nodes[nodeIndex].neighbors {
			total += len(i.nodes[nodeIndex].neighbors[level])
		}
	}
	return total
}

func (i *Index) nextLevel() LevelSample {
	const twoTo53 = float64(uint64(1) << 53)
	randomBits := i.random.next() >> 11
	uniform := float64(randomBits+1) / twoTo53
	multiplier := 1 / math.Log(float64(i.config.M))
	level := int(math.Floor(-math.Log(uniform) * multiplier))
	return LevelSample{
		RandomBits53: randomBits,
		Uniform:      uniform,
		Multiplier:   multiplier,
		Level:        level,
	}
}

type splitMix64 struct {
	state uint64
}

func (r *splitMix64) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	value := r.state
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	return value ^ (value >> 31)
}
