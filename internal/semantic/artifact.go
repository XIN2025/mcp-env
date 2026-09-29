package semantic

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
	"vectorengine.local/poc/capabilityenvelope/internal/search"
	"vectorengine.local/poc/internal/hnsw"
	"vectorengine.local/poc/internal/vector"
)

const (
	ArtifactVersion = 1
	GraphSeed       = uint64(2026082317)
	HNSWM           = 16
	EFConstruction  = 200
)

type Artifact struct {
	Version             int
	CatalogSHA256       string
	EmbeddingSHA256     string
	ModelIdentitySHA256 string
	ModelSnapshotSHA256 string
	ToolSlugs           []string
	Graph               hnsw.Snapshot
}

type BuildReceipt struct {
	SchemaVersion            int              `json:"schema_version"`
	Attempt                  int              `json:"attempt"`
	Verdict                  string           `json:"verdict"`
	FailureReason            string           `json:"failure_reason,omitempty"`
	StartedAt                string           `json:"started_at"`
	CompletedAt              string           `json:"completed_at"`
	DurationMS               int64            `json:"duration_ms"`
	GoVersion                string           `json:"go_version"`
	OS                       string           `json:"os"`
	Arch                     string           `json:"arch"`
	CatalogPath              string           `json:"catalog_path"`
	CatalogSHA256            string           `json:"catalog_sha256"`
	Tools                    int              `json:"tools"`
	EmbeddingPath            string           `json:"embedding_path"`
	EmbeddingBytes           int64            `json:"embedding_bytes"`
	EmbeddingSHA256          string           `json:"embedding_sha256"`
	VectorAudit              VectorAudit      `json:"vector_audit"`
	Model                    ModelIdentity    `json:"model"`
	ModelIdentitySHA256      string           `json:"model_identity_sha256"`
	ModelSnapshotSHA256      string           `json:"model_snapshot_sha256"`
	GraphSeed                uint64           `json:"graph_seed"`
	HNSWM                    int              `json:"hnsw_m"`
	EFConstruction           int              `json:"ef_construction"`
	BuildDistanceEvaluations int              `json:"build_distance_evaluations"`
	TopologySHA256           string           `json:"topology_sha256"`
	Audit                    hnsw.AuditReport `json:"audit"`
	ArtifactPath             string           `json:"artifact_path"`
	ArtifactBytes            int64            `json:"artifact_bytes"`
	ArtifactSHA256           string           `json:"artifact_sha256"`
}

func Build(
	tools []catalog.Tool,
	vectors [][]float32,
	vectorAudit VectorAudit,
	catalogPath, catalogSHA, embeddingPath, modelSnapshotSHA, artifactPath string,
	attempt int,
) (BuildReceipt, error) {
	started := time.Now().UTC()
	receipt := BuildReceipt{
		SchemaVersion:       1,
		Attempt:             attempt,
		Verdict:             "INVALID",
		StartedAt:           started.Format(time.RFC3339Nano),
		GoVersion:           runtime.Version(),
		OS:                  runtime.GOOS,
		Arch:                runtime.GOARCH,
		CatalogPath:         filepath.ToSlash(catalogPath),
		CatalogSHA256:       catalogSHA,
		Tools:               len(tools),
		EmbeddingPath:       filepath.ToSlash(embeddingPath),
		VectorAudit:         vectorAudit,
		Model:               Identity(),
		ModelIdentitySHA256: IdentitySHA256(),
		ModelSnapshotSHA256: modelSnapshotSHA,
		GraphSeed:           GraphSeed,
		HNSWM:               HNSWM,
		EFConstruction:      EFConstruction,
		ArtifactPath:        filepath.ToSlash(artifactPath),
	}
	finish := func() {
		completed := time.Now().UTC()
		receipt.CompletedAt = completed.Format(time.RFC3339Nano)
		receipt.DurationMS = completed.Sub(started).Milliseconds()
	}
	if len(tools) == 0 || len(vectors) != len(tools) {
		finish()
		return receipt, fmt.Errorf("semantic vectors and catalog length differ")
	}
	if vectorAudit.Vectors != len(tools) || vectorAudit.Dimension != Dimension || vectorAudit.NonFiniteVectors != 0 || vectorAudit.ZeroVectors != 0 || vectorAudit.UnitNormFailures != 0 {
		finish()
		return receipt, fmt.Errorf("semantic vectors failed validity audit")
	}
	var err error
	receipt.EmbeddingSHA256, receipt.EmbeddingBytes, err = fileIdentity(embeddingPath)
	if err != nil {
		finish()
		return receipt, fmt.Errorf("identify semantic embedding file: %w", err)
	}
	space, err := vector.NewSpace(Dimension, vector.Cosine)
	if err != nil {
		finish()
		return receipt, err
	}
	graph, err := hnsw.New(space, hnsw.Config{M: HNSWM, EFConstruction: EFConstruction, RandomSeed: GraphSeed})
	if err != nil {
		finish()
		return receipt, err
	}
	for index, values := range vectors {
		nodeID, trace, insertErr := graph.Insert(values)
		if insertErr != nil {
			finish()
			return receipt, fmt.Errorf("insert semantic tool %d: %w", index, insertErr)
		}
		if int(nodeID) != index {
			finish()
			return receipt, fmt.Errorf("semantic node ID %d differs from tool index %d", nodeID, index)
		}
		receipt.BuildDistanceEvaluations += trace.DistanceEvaluations
	}
	receipt.Audit = graph.Audit()
	receipt.TopologySHA256 = graph.TopologySHA256()
	if !receipt.Audit.Valid {
		finish()
		return receipt, fmt.Errorf("semantic graph failed audit: %v", receipt.Audit.Violations)
	}
	snapshot, err := graph.CompactSnapshot(nil)
	if err != nil {
		finish()
		return receipt, err
	}
	artifact := Artifact{
		Version:             ArtifactVersion,
		CatalogSHA256:       catalogSHA,
		EmbeddingSHA256:     receipt.EmbeddingSHA256,
		ModelIdentitySHA256: receipt.ModelIdentitySHA256,
		ModelSnapshotSHA256: modelSnapshotSHA,
		ToolSlugs:           make([]string, len(tools)),
		Graph:               snapshot,
	}
	for index, tool := range tools {
		artifact.ToolSlugs[index] = tool.Slug
	}
	if err := writeArtifact(artifactPath, artifact); err != nil {
		finish()
		return receipt, err
	}
	receipt.ArtifactSHA256, receipt.ArtifactBytes, err = fileIdentity(artifactPath)
	if err != nil {
		finish()
		return receipt, err
	}
	receipt.Verdict = "PASS"
	finish()
	return receipt, nil
}

func ReadArtifact(path string) (Artifact, error) {
	file, err := os.Open(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("open semantic artifact: %w", err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return Artifact{}, err
	}
	defer compressed.Close()
	var artifact Artifact
	if err := gob.NewDecoder(compressed).Decode(&artifact); err != nil {
		return Artifact{}, fmt.Errorf("decode semantic artifact: %w", err)
	}
	if artifact.Version != ArtifactVersion {
		return Artifact{}, fmt.Errorf("semantic artifact version %d is unsupported", artifact.Version)
	}
	return artifact, nil
}

func RestoreArtifact(artifact Artifact, tools []catalog.Tool, catalogSHA string, model search.QueryEmbedder) (*search.Index, error) {
	if artifact.CatalogSHA256 != catalogSHA {
		return nil, fmt.Errorf("semantic artifact catalog hash mismatch")
	}
	if artifact.ModelIdentitySHA256 != IdentitySHA256() || model.SHA256() != IdentitySHA256() {
		return nil, fmt.Errorf("semantic artifact model identity mismatch")
	}
	if len(artifact.ToolSlugs) != len(tools) {
		return nil, fmt.Errorf("semantic artifact tool count mismatch")
	}
	for index, slug := range artifact.ToolSlugs {
		if slug != tools[index].Slug {
			return nil, fmt.Errorf("semantic artifact slug mismatch at %d", index)
		}
	}
	graph, err := hnsw.RestoreSnapshot(
		model.Space(),
		hnsw.Config{M: HNSWM, EFConstruction: EFConstruction, RandomSeed: GraphSeed},
		artifact.Graph,
	)
	if err != nil {
		return nil, err
	}
	return search.New(tools, model, graph, catalogSHA)
}

func writeArtifact(path string, artifact Artifact) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite semantic artifact %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary := path + ".partial"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(temporary)
		}
	}()
	compressed, err := gzip.NewWriterLevel(file, gzip.BestSpeed)
	if err != nil {
		_ = file.Close()
		return err
	}
	if err := gob.NewEncoder(compressed).Encode(artifact); err != nil {
		_ = compressed.Close()
		_ = file.Close()
		return err
	}
	if err := compressed.Close(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	complete = true
	return nil
}

func fileIdentity(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), stat.Size(), nil
}
