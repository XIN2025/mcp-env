package semantic

import (
	"context"
	"fmt"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
	"vectorengine.local/poc/internal/vector"
)

const (
	ModelID              = "sentence-transformers/all-MiniLM-L6-v2"
	ModelRevision        = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
	Dimension            = 384
	SentenceTransformers = "5.1.0"
	Transformers         = "4.56.0"
	Torch                = "2.8.0+cpu"
	DocumentRecipe       = "Toolkit: <toolkit name> (<toolkit slug>).\nTool: <tool name>.\nAction identifier: <tool slug with underscores replaced by spaces>.\nDescription: <tool description>"
	QueryRecipe          = "raw-task-v1"
)

type ModelIdentity struct {
	ModelID              string `json:"model_id"`
	ModelRevision        string `json:"model_revision"`
	Dimension            int    `json:"dimension"`
	Normalized           bool   `json:"normalized"`
	SentenceTransformers string `json:"sentence_transformers"`
	Transformers         string `json:"transformers"`
	Torch                string `json:"torch"`
	DocumentRecipe       string `json:"document_recipe"`
	QueryRecipe          string `json:"query_recipe"`
}

func Identity() ModelIdentity {
	return ModelIdentity{
		ModelID:              ModelID,
		ModelRevision:        ModelRevision,
		Dimension:            Dimension,
		Normalized:           true,
		SentenceTransformers: SentenceTransformers,
		Transformers:         Transformers,
		Torch:                Torch,
		DocumentRecipe:       DocumentRecipe,
		QueryRecipe:          QueryRecipe,
	}
}

func IdentitySHA256() string {
	digest, err := canonical.SHA256(Identity())
	if err != nil {
		panic(err)
	}
	return digest
}

type QueryModel struct {
	space  vector.Space
	worker *Worker
	digest string
}

func NewQueryModel(pythonPath, scriptPath, cachePath, expectedSnapshotSHA string) (*QueryModel, error) {
	space, err := vector.NewSpace(Dimension, vector.Cosine)
	if err != nil {
		return nil, err
	}
	worker, err := StartWorker(pythonPath, scriptPath, cachePath, expectedSnapshotSHA)
	if err != nil {
		return nil, err
	}
	return &QueryModel{space: space, worker: worker, digest: IdentitySHA256()}, nil
}

func (model *QueryModel) EmbedQuery(text string) ([]float32, error) {
	return model.EmbedQueryContext(context.Background(), text)
}

func (model *QueryModel) EmbedQueryContext(ctx context.Context, text string) ([]float32, error) {
	values, err := model.worker.EmbedContext(ctx, text)
	if err != nil {
		return nil, err
	}
	prepared, err := model.space.PrepareFloat32(values)
	if err != nil {
		return nil, fmt.Errorf("prepare semantic query: %w", err)
	}
	return prepared, nil
}

func (model *QueryModel) Space() vector.Space {
	return model.space
}

func (model *QueryModel) SHA256() string {
	return model.digest
}

func (model *QueryModel) Close() error {
	return model.worker.Close()
}
