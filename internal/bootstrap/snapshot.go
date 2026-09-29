package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
	"vectorengine.local/poc/capabilityenvelope/internal/search"
	"vectorengine.local/poc/capabilityenvelope/internal/semantic"
)

type Snapshot struct {
	Index         *search.Index
	CatalogSHA256 string
	CatalogBytes  int64
}

type SemanticSnapshot struct {
	*Snapshot
	Model *semantic.QueryModel
}

func LoadSemanticSnapshot(catalogPath, artifactPath, pythonPath, scriptPath, cachePath string) (*SemanticSnapshot, error) {
	catalogSHA, catalogBytes, err := FileIdentity(catalogPath)
	if err != nil {
		return nil, err
	}
	tools, err := catalog.Load(catalogPath)
	if err != nil {
		return nil, err
	}
	artifact, err := semantic.ReadArtifact(artifactPath)
	if err != nil {
		return nil, err
	}
	model, err := semantic.NewQueryModel(pythonPath, scriptPath, cachePath, artifact.ModelSnapshotSHA256)
	if err != nil {
		return nil, err
	}
	index, err := semantic.RestoreArtifact(artifact, tools, catalogSHA, model)
	if err != nil {
		_ = model.Close()
		return nil, fmt.Errorf("restore pinned semantic index: %w", err)
	}
	if audit := index.Audit(); !audit.Valid {
		_ = model.Close()
		return nil, fmt.Errorf("pinned semantic HNSW graph failed runtime audit: %v", audit.Violations)
	}
	return &SemanticSnapshot{
		Snapshot: &Snapshot{Index: index, CatalogSHA256: catalogSHA, CatalogBytes: catalogBytes},
		Model:    model,
	}, nil
}

func FileIdentity(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
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
