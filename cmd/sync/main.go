package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/catalog"
)

func main() {
	rootFlag := flag.String("root", ".", "project root")
	envFileFlag := flag.String("env-file", "", "optional env file containing catalog adapter settings")
	attemptFlag := flag.Int("attempt", 1, "retained sync attempt number")
	flag.Parse()
	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		fatalf("resolve root: %v", err)
	}
	receiptPath := filepath.Join(root, "receipts", fmt.Sprintf("catalog-sync-attempt-%03d.json", *attemptFlag))
	if _, err := os.Stat(receiptPath); err == nil {
		fatalf("refusing to overwrite retained receipt %s", receiptPath)
	} else if !os.IsNotExist(err) {
		fatalf("inspect retained receipt: %v", err)
	}
	endpoint := strings.TrimSpace(os.Getenv("CAPABILITY_CATALOG_URL"))
	apiKey := strings.TrimSpace(os.Getenv("CAPABILITY_CATALOG_API_KEY"))
	if apiKey == "" && *envFileFlag != "" {
		apiKey, err = readEnvValue(*envFileFlag, "CAPABILITY_CATALOG_API_KEY")
		if err != nil {
			fatalf("read API key: %v", err)
		}
	}
	if endpoint == "" && *envFileFlag != "" {
		endpoint, err = readEnvValue(*envFileFlag, "CAPABILITY_CATALOG_URL")
		if err != nil {
			fatalf("read catalog URL: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	receipt, syncErr := catalog.Sync(ctx, catalog.SyncOptions{
		Root:     root,
		Endpoint: endpoint,
		APIKey:   apiKey,
		Attempt:  *attemptFlag,
	})
	if syncErr != nil {
		receipt.Verdict = "INVALID"
		receipt.FailureReason = syncErr.Error()
	}
	if err := writeReceipt(receiptPath, receipt); err != nil {
		fatalf("write sync receipt: %v", err)
	}
	fmt.Printf("Catalog sync verdict: %s\n", receipt.Verdict)
	fmt.Printf("Pages: %d, tools: %d, tagged: %.4f\n", len(receipt.Pages), receipt.UniqueTools, receipt.TaggedFraction)
	fmt.Printf("Receipt: %s\n", receiptPath)
	if receipt.Derived.Path != "" {
		fmt.Printf("Catalog: %s\n", filepath.Join(root, filepath.FromSlash(receipt.Derived.Path)))
	}
	if receipt.FailureReason != "" {
		fmt.Printf("Reason: %s\n", receipt.FailureReason)
	}
	if syncErr != nil || receipt.Verdict != "PASS" {
		os.Exit(1)
	}
}

func readEnvValue(path, key string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, value, exists := strings.Cut(line, "=")
		if !exists || strings.TrimSpace(name) != key {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if value == "" {
			return "", fmt.Errorf("%s is empty in %s", key, path)
		}
		return value, nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s was not found in %s", key, path)
}

func writeReceipt(path string, receipt catalog.SyncReceipt) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(receipt); err != nil {
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
