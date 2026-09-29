package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/bootstrap"
	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
	"vectorengine.local/poc/capabilityenvelope/internal/semantic"
)

type metadata struct {
	ModelID        string `json:"model_id"`
	ModelRevision  string `json:"model_revision"`
	DocumentRecipe string `json:"document_recipe"`
	Normalized     bool   `json:"normalized"`
	Versions       struct {
		SentenceTransformers string `json:"sentence_transformers"`
		Transformers         string `json:"transformers"`
		Torch                string `json:"torch"`
	} `json:"versions"`
	ModelSnapshot struct {
		Files  int    `json:"files"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"model_snapshot"`
	ModelSnapshotPath string               `json:"model_snapshot_path"`
	CatalogTools      int                  `json:"catalog_tools"`
	FirstSlug         string               `json:"first_slug"`
	LastSlug          string               `json:"last_slug"`
	VectorAudit       semantic.VectorAudit `json:"vector_audit"`
	DurationMS        int64                `json:"duration_ms"`
}

type buildReceipt struct {
	SchemaVersion       int                    `json:"schema_version"`
	Attempt             int                    `json:"attempt"`
	Verdict             string                 `json:"verdict"`
	FailureReason       string                 `json:"failure_reason,omitempty"`
	StartedAt           string                 `json:"started_at"`
	CompletedAt         string                 `json:"completed_at"`
	DurationMS          int64                  `json:"duration_ms"`
	GoVersion           string                 `json:"go_version"`
	OS                  string                 `json:"os"`
	Arch                string                 `json:"arch"`
	PythonCommand       string                 `json:"python_command"`
	ScriptPath          string                 `json:"script_path"`
	ScriptSHA256        string                 `json:"script_sha256"`
	CatalogPath         string                 `json:"catalog_path"`
	CatalogBytes        int64                  `json:"catalog_bytes"`
	CatalogSHA256       string                 `json:"catalog_sha256"`
	CatalogTools        int                    `json:"catalog_tools"`
	OutputPath          string                 `json:"output_path"`
	OutputBytes         int64                  `json:"output_bytes"`
	OutputSHA256        string                 `json:"output_sha256"`
	Model               semantic.ModelIdentity `json:"model"`
	ModelIdentitySHA256 string                 `json:"model_identity_sha256"`
	Metadata            metadata               `json:"metadata"`
	ReusedFromPath      string                 `json:"reused_from_path,omitempty"`
	ReusedFromSHA256    string                 `json:"reused_from_sha256,omitempty"`
}

func main() {
	rootFlag := flag.String("root", ".", "project root")
	attemptFlag := flag.Int("attempt", 1, "retained semantic embedding attempt")
	pythonFlag := flag.String("python", "python", "Python command")
	batchFlag := flag.Int("batch-size", 64, "CPU encoding batch size")
	reuseAttemptFlag := flag.Int("reuse-attempt", 0, "reuse a fully written embedding matrix from an invalid receipt attempt")
	flag.Parse()
	if *attemptFlag < 1 {
		fatalf("attempt must be at least one")
	}
	if *batchFlag < 1 {
		fatalf("batch size must be positive")
	}
	if *reuseAttemptFlag < 0 || *reuseAttemptFlag == *attemptFlag {
		fatalf("reuse attempt must be zero or a different positive attempt")
	}
	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		fatalf("resolve root: %v", err)
	}
	catalogPath := filepath.Join(root, "data", "derived", "catalog-attempt-002.jsonl")
	scriptPath := filepath.Join(root, "scripts", "semantic_embeddings.py")
	cachePath := filepath.Join(root, "data", "models")
	outputPath := filepath.Join(root, "data", "derived", fmt.Sprintf("semantic-embeddings-attempt-%03d.f32", *attemptFlag))
	receiptPath := filepath.Join(root, "receipts", fmt.Sprintf("semantic-embedding-attempt-%03d.json", *attemptFlag))
	for _, path := range []string{outputPath, receiptPath} {
		if _, statErr := os.Stat(path); statErr == nil {
			fatalf("refusing to overwrite %s", path)
		} else if !os.IsNotExist(statErr) {
			fatalf("inspect output: %v", statErr)
		}
	}
	started := time.Now().UTC()
	receipt := buildReceipt{
		SchemaVersion:       1,
		Attempt:             *attemptFlag,
		Verdict:             "INVALID",
		StartedAt:           started.Format(time.RFC3339Nano),
		GoVersion:           runtime.Version(),
		OS:                  runtime.GOOS,
		Arch:                runtime.GOARCH,
		PythonCommand:       *pythonFlag,
		ScriptPath:          filepath.ToSlash(scriptPath),
		CatalogPath:         filepath.ToSlash(catalogPath),
		OutputPath:          filepath.ToSlash(outputPath),
		Model:               semantic.Identity(),
		ModelIdentitySHA256: semantic.IdentitySHA256(),
	}
	receipt.ScriptSHA256, _, err = bootstrap.FileIdentity(scriptPath)
	if err == nil {
		receipt.CatalogSHA256, receipt.CatalogBytes, err = bootstrap.FileIdentity(catalogPath)
	}
	if err == nil {
		var tools []catalog.Tool
		tools, err = catalog.Load(catalogPath)
		receipt.CatalogTools = len(tools)
	}
	if err == nil && *reuseAttemptFlag > 0 {
		reusePath := filepath.Join(root, "data", "derived", fmt.Sprintf("semantic-embeddings-attempt-%03d.f32", *reuseAttemptFlag))
		receipt.ReusedFromPath = filepath.ToSlash(reusePath)
		receipt.ReusedFromSHA256, _, err = bootstrap.FileIdentity(reusePath)
	}
	if err == nil {
		err = runPython(*pythonFlag, scriptPath, catalogPath, outputPath, cachePath, receipt.ReusedFromPath, *batchFlag, &receipt.Metadata)
	}
	if err == nil {
		receipt.OutputSHA256, receipt.OutputBytes, err = bootstrap.FileIdentity(outputPath)
	}
	if err == nil {
		err = validate(receipt)
	}
	if err != nil {
		receipt.FailureReason = err.Error()
	} else {
		receipt.Verdict = "PASS"
	}
	completed := time.Now().UTC()
	receipt.CompletedAt = completed.Format(time.RFC3339Nano)
	receipt.DurationMS = completed.Sub(started).Milliseconds()
	if writeErr := writeJSON(receiptPath, receipt); writeErr != nil {
		fatalf("write receipt: %v", writeErr)
	}
	fmt.Printf("Semantic embedding verdict: %s\n", receipt.Verdict)
	fmt.Printf("Vectors: %d, output: %s\n", receipt.Metadata.VectorAudit.Vectors, outputPath)
	fmt.Printf("Receipt: %s\n", receiptPath)
	if receipt.Verdict != "PASS" {
		os.Exit(1)
	}
}

func runPython(python, script, catalog, output, cache, reuse string, batch int, value *metadata) error {
	arguments := []string{
		"-u", script, "build",
		"--catalog", catalog,
		"--output", output,
		"--cache", cache,
		"--batch-size", fmt.Sprintf("%d", batch),
		"--offline",
	}
	if reuse != "" {
		arguments = append(arguments, "--reuse", reuse)
	}
	command := exec.Command(python, arguments...)
	command.Stderr = os.Stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	found := false
	var metadataErr error
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
		if strings.HasPrefix(line, "SEMANTIC_METADATA ") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "SEMANTIC_METADATA ")), value); err != nil {
				metadataErr = err
				continue
			}
			found = true
		}
	}
	scanErr := scanner.Err()
	waitErr := command.Wait()
	if scanErr != nil {
		return scanErr
	}
	if waitErr != nil {
		return fmt.Errorf("semantic embedding process: %w", waitErr)
	}
	if metadataErr != nil {
		return fmt.Errorf("decode semantic metadata: %w", metadataErr)
	}
	if !found {
		return fmt.Errorf("semantic embedding process returned no metadata")
	}
	return nil
}

func validate(receipt buildReceipt) error {
	metadata := receipt.Metadata
	if receipt.CatalogSHA256 == "" || receipt.CatalogTools < 1 {
		return fmt.Errorf("catalog identity is incomplete")
	}
	if metadata.ModelID != semantic.ModelID || metadata.ModelRevision != semantic.ModelRevision || metadata.DocumentRecipe != semantic.DocumentRecipe || !metadata.Normalized {
		return fmt.Errorf("semantic model metadata differs from contract")
	}
	if metadata.Versions.SentenceTransformers != semantic.SentenceTransformers || metadata.Versions.Transformers != semantic.Transformers || metadata.Versions.Torch != semantic.Torch {
		return fmt.Errorf("semantic library versions differ from contract")
	}
	if metadata.CatalogTools != receipt.CatalogTools || metadata.VectorAudit.Vectors != receipt.CatalogTools || metadata.VectorAudit.Dimension != semantic.Dimension || metadata.VectorAudit.NonFiniteVectors != 0 || metadata.VectorAudit.ZeroVectors != 0 || metadata.VectorAudit.UnitNormFailures != 0 {
		return fmt.Errorf("semantic vector audit failed")
	}
	if metadata.ModelSnapshot.Files == 0 || metadata.ModelSnapshot.Bytes == 0 || metadata.ModelSnapshot.SHA256 == "" {
		return fmt.Errorf("semantic model-cache identity is incomplete")
	}
	return nil
}

func writeJSON(path string, value any) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
