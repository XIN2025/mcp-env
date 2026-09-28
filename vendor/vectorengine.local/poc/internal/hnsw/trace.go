package hnsw

type LevelSample struct {
	RandomBits53 uint64  `json:"random_bits_53"`
	Uniform      float64 `json:"uniform_open_closed"`
	Multiplier   float64 `json:"level_multiplier"`
	Level        int     `json:"level"`
}

type InsertTrace struct {
	NodeID               NodeID             `json:"node_id"`
	AssignedLevel        int                `json:"assigned_level"`
	LevelSample          LevelSample        `json:"level_sample"`
	FirstNode            bool               `json:"first_node"`
	UpperDescent         []GreedyLevelTrace `json:"upper_descent,omitempty"`
	LayerInsertions      []InsertLayerTrace `json:"layer_insertions,omitempty"`
	DirectedEdgesAdded   int                `json:"directed_edges_added"`
	DirectedEdgesRemoved int                `json:"directed_edges_removed"`
	ExistingNodesPruned  int                `json:"existing_nodes_pruned"`
	DistanceEvaluations  int                `json:"distance_evaluations"`
}

type GreedyLevelTrace struct {
	Level int         `json:"level"`
	From  NodeID      `json:"from"`
	To    Neighbor    `json:"to"`
	Trace SearchTrace `json:"trace"`
}

type InsertLayerTrace struct {
	Level                int            `json:"level"`
	EntryPointCount      int            `json:"entry_point_count"`
	CandidateCount       int            `json:"candidate_count"`
	Selected             []NodeID       `json:"selected"`
	Search               SearchTrace    `json:"search"`
	Selection            SelectionTrace `json:"selection"`
	ExistingNodesPruned  int            `json:"existing_nodes_pruned"`
	DirectedEdgesAdded   int            `json:"directed_edges_added"`
	DirectedEdgesRemoved int            `json:"directed_edges_removed"`
}

type Stats struct {
	Nodes          int         `json:"nodes"`
	EntryPoint     NodeID      `json:"entry_point"`
	HasEntryPoint  bool        `json:"has_entry_point"`
	MaxLevel       int         `json:"max_level"`
	LevelHistogram map[int]int `json:"level_histogram"`
	DirectedEdges  int         `json:"directed_edges"`
}

type Neighbor struct {
	NodeID   NodeID  `json:"node_id"`
	Distance float64 `json:"distance"`
}

type SearchTrace struct {
	VisitedNodes        int  `json:"visited_nodes"`
	DistanceEvaluations int  `json:"distance_evaluations"`
	ExpandedNodes       int  `json:"expanded_nodes"`
	CandidatePushes     int  `json:"candidate_pushes"`
	ResultPushes        int  `json:"result_pushes"`
	EarlyTerminated     bool `json:"early_terminated"`
}

type LayerSearchResult struct {
	Neighbors []Neighbor  `json:"neighbors"`
	Trace     SearchTrace `json:"trace"`
}

type IndexSearchTrace struct {
	RequestedK          int                `json:"requested_k"`
	RequestedEF         int                `json:"requested_ef"`
	EffectiveEF         int                `json:"effective_ef"`
	UpperDescent        []GreedyLevelTrace `json:"upper_descent,omitempty"`
	BaseLayer           SearchTrace        `json:"base_layer"`
	DistanceEvaluations int                `json:"distance_evaluations"`
}

type SearchResult struct {
	Neighbors []Neighbor       `json:"neighbors"`
	Trace     IndexSearchTrace `json:"trace"`
}

type DegreeSummary struct {
	Nodes    int     `json:"nodes"`
	Min      int     `json:"min"`
	Max      int     `json:"max"`
	Mean     float64 `json:"mean"`
	Capacity int     `json:"capacity"`
}

type AuditReport struct {
	Valid                 bool                  `json:"valid"`
	Nodes                 int                   `json:"nodes"`
	DirectedEdges         int                   `json:"directed_edges"`
	UndirectedEdges       int                   `json:"undirected_edges"`
	EntryPointValid       bool                  `json:"entry_point_valid"`
	MaxLevelMatches       bool                  `json:"max_level_matches"`
	LevelHistogramMatches bool                  `json:"level_histogram_matches"`
	LevelZeroReachable    int                   `json:"level_zero_reachable"`
	LevelZeroUnreachable  int                   `json:"level_zero_unreachable"`
	SelfEdges             int                   `json:"self_edges"`
	DuplicateEdges        int                   `json:"duplicate_edges"`
	DanglingEdges         int                   `json:"dangling_edges"`
	MissingReciprocals    int                   `json:"missing_reciprocals"`
	DegreeViolations      int                   `json:"degree_violations"`
	InvalidVectors        int                   `json:"invalid_vectors"`
	MalformedLevelArrays  int                   `json:"malformed_level_arrays"`
	LevelDegrees          map[int]DegreeSummary `json:"level_degrees"`
	Violations            []string              `json:"violations,omitempty"`
}

type SelectionTrace struct {
	InputCandidates             int `json:"input_candidates"`
	UniqueCandidates            int `json:"unique_candidates"`
	DuplicateCandidatesRemoved  int `json:"duplicate_candidates_removed"`
	QueryNodeCandidatesRemoved  int `json:"query_node_candidates_removed"`
	QueryDistanceEvaluations    int `json:"query_distance_evaluations"`
	AcceptedByDiversity         int `json:"accepted_by_diversity"`
	RestoredFromDiscarded       int `json:"restored_from_discarded"`
	InterCandidateDistanceEvals int `json:"inter_candidate_distance_evaluations"`
}

type SelectionResult struct {
	Selected []Neighbor     `json:"selected"`
	Accepted []Neighbor     `json:"accepted"`
	Restored []Neighbor     `json:"restored"`
	Trace    SelectionTrace `json:"trace"`
}
