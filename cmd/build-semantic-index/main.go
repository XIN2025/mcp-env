package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"vectorengine.local/poc/capabilityenvelope/internal/bootstrap"
	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
	"vectorengine.local/poc/capabilityenvelope/internal/semantic"
)

type embeddingReceipt struct {
	Verdict             string `json:"verdict"`
	CatalogSHA256       string `json:"catalog_sha256"`
	CatalogBytes        int64  `json:"catalog_bytes"`
	CatalogTools        int    `json:"catalog_tools"`
	OutputSHA256        string `json:"output_sha256"`
	OutputBytes         int64  `json:"output_bytes"`
	ModelIdentitySHA256 string `json:"model_identity_sha256"`
	Metadata            struct {
		CatalogTools  int `json:"catalog_tools"`
		ModelSnapshot struct {
			SHA256 string `json:"sha256"`
		} `json:"model_snapshot"`
	} `json:"metadata"`
}

func main() {
	rootFlag := flag.String("root", ".", "project root")
	attemptFlag := flag.Int("attempt", 1, "retained semantic index attempt")
	embeddingAttemptFlag := flag.Int("embedding-attempt", 1, "retained semantic embedding attempt")
	flag.Parse()
	if *attemptFlag < 1 || *embeddingAttemptFlag < 1 {
		fatalf("attempt numbers must be at least one")
	}
	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		fatalf("resolve root: %v", err)
	}
	catalogPath := filepath.Join(root, "data", "derived", "catalog-attempt-002.jsonl")
	embeddingPath := filepath.Join(root, "data", "derived", fmt.Sprintf("semantic-embeddings-attempt-%03d.f32", *embeddingAttemptFlag))
	embeddingReceiptPath := filepath.Join(root, "receipts", fmt.Sprintf("semantic-embedding-attempt-%03d.json", *embeddingAttemptFlag))
	artifactPath := filepath.Join(root, "data", "derived", fmt.Sprintf("semantic-index-attempt-%03d.gob.gz", *attemptFlag))
	receiptPath := filepath.Join(root, "receipts", fmt.Sprintf("semantic-index-attempt-%03d.json", *attemptFlag))
	for _, path := range []string{artifactPath, receiptPath} {
		if _, statErr := os.Stat(path); statErr == nil {
			fatalf("refusing to overwrite %s", path)
		} else if !os.IsNotExist(statErr) {
			fatalf("inspect output: %v", statErr)
		}
	}
	catalogSHA, catalogBytes, err := bootstrap.FileIdentity(catalogPath)
	if err != nil {
		fatalf("identify catalog: %v", err)
	}
	tools, err := catalog.Load(catalogPath)
	if err != nil {
		fatalf("load catalog: %v", err)
	}
	vectors, audit, err := semantic.LoadEmbeddings(embeddingPath)
	if err != nil {
		fatalf("load semantic embeddings: %v", err)
	}
	var source embeddingReceipt
	if err := readJSON(embeddingReceiptPath, &source); err != nil {
		fatalf("load embedding receipt: %v", err)
	}
	embeddingSHA, embeddingBytes, err := bootstrap.FileIdentity(embeddingPath)
	if err != nil {
		fatalf("identify semantic embeddings: %v", err)
	}
	receiptCatalogTools := source.CatalogTools
	if receiptCatalogTools == 0 {
		receiptCatalogTools = source.Metadata.CatalogTools
	}
	if source.Verdict != "PASS" || source.Metadata.ModelSnapshot.SHA256 == "" ||
		source.CatalogSHA256 != catalogSHA || source.CatalogBytes != catalogBytes || receiptCatalogTools != len(tools) ||
		source.OutputSHA256 != embeddingSHA || source.OutputBytes != embeddingBytes || source.ModelIdentitySHA256 != semantic.IdentitySHA256() {
		fatalf("embedding receipt does not bind the selected catalog, vectors, and model")
	}
	receipt, buildErr := semantic.Build(
		tools,
		vectors,
		audit,
		catalogPath,
		catalogSHA,
		embeddingPath,
		source.Metadata.ModelSnapshot.SHA256,
		artifactPath,
		*attemptFlag,
	)
	if buildErr != nil {
		receipt.FailureReason = buildErr.Error()
	}
	if err := writeJSON(receiptPath, receipt); err != nil {
		fatalf("write semantic index receipt: %v", err)
	}
	fmt.Printf("Semantic index verdict: %s\n", receipt.Verdict)
	fmt.Printf("Topology: %s\n", receipt.TopologySHA256)
	fmt.Printf("Artifact: %s\n", artifactPath)
	fmt.Printf("Receipt: %s\n", receiptPath)
	if buildErr != nil || receipt.Verdict != "PASS" {
		os.Exit(1)
	}
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("receipt contains multiple JSON values")
		}
		return err
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
