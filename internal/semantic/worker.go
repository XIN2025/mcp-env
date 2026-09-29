package semantic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
)

type workerReady struct {
	Type          string `json:"type"`
	ModelID       string `json:"model_id"`
	ModelRevision string `json:"model_revision"`
	Dimension     int    `json:"dimension"`
	Normalized    bool   `json:"normalized"`
	Versions      struct {
		SentenceTransformers string `json:"sentence_transformers"`
		Transformers         string `json:"transformers"`
		Torch                string `json:"torch"`
	} `json:"versions"`
	ModelSnapshot struct {
		SHA256 string `json:"sha256"`
	} `json:"model_snapshot"`
}

type workerResponse struct {
	ID        string    `json:"id"`
	Embedding []float32 `json:"embedding"`
	Error     string    `json:"error"`
}

type Worker struct {
	command  *exec.Cmd
	stdin    *bufio.Writer
	lines    <-chan []byte
	scanDone <-chan struct{}
	exitDone <-chan struct{}
	stop     chan struct{}
	mu       sync.Mutex
	stateMu  sync.Mutex
	nextID   uint64
	closed   bool
	scanErr  error
	exitErr  error
}

func StartWorker(pythonPath, scriptPath, cachePath, expectedSnapshotSHA string) (*Worker, error) {
	if strings.TrimSpace(pythonPath) == "" {
		pythonPath = "python"
	}
	command := exec.Command(pythonPath, "-u", scriptPath, "worker", "--cache", cachePath)
	command.Stderr = os.Stderr
	stdinPipe, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start semantic embedding worker: %w", err)
	}
	lines := make(chan []byte, 8)
	scanDone := make(chan struct{})
	exitDone := make(chan struct{})
	stop := make(chan struct{})
	worker := &Worker{
		command:  command,
		stdin:    bufio.NewWriter(stdinPipe),
		lines:    lines,
		scanDone: scanDone,
		exitDone: exitDone,
		stop:     stop,
	}
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			select {
			case lines <- bytes.Clone(scanner.Bytes()):
			case <-stop:
				close(lines)
				close(scanDone)
				return
			}
		}
		worker.stateMu.Lock()
		worker.scanErr = scanner.Err()
		worker.stateMu.Unlock()
		close(lines)
		close(scanDone)
	}()
	go func() {
		exitErr := command.Wait()
		worker.stateMu.Lock()
		worker.exitErr = exitErr
		worker.stateMu.Unlock()
		close(exitDone)
	}()
	timer := time.NewTimer(3 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case line, open := <-lines:
			if !open {
				_ = worker.Close()
				return nil, worker.outputClosedError("semantic worker exited before readiness")
			}
			var ready workerReady
			if json.Unmarshal(line, &ready) != nil || ready.Type != "ready" {
				continue
			}
			if err := validateReady(ready, expectedSnapshotSHA); err != nil {
				_ = worker.Close()
				return nil, err
			}
			return worker, nil
		case <-exitDone:
			return nil, worker.processExitError("semantic worker exited before readiness")
		case <-timer.C:
			_ = worker.Close()
			return nil, fmt.Errorf("semantic worker readiness timed out")
		}
	}
}

func validateReady(ready workerReady, expectedSnapshotSHA string) error {
	if ready.ModelID != ModelID || ready.ModelRevision != ModelRevision || ready.Dimension != Dimension || !ready.Normalized {
		return fmt.Errorf("semantic worker model identity differs from contract")
	}
	if ready.Versions.SentenceTransformers != SentenceTransformers || ready.Versions.Transformers != Transformers || ready.Versions.Torch != Torch {
		return fmt.Errorf("semantic worker library versions differ from contract")
	}
	if expectedSnapshotSHA != "" && ready.ModelSnapshot.SHA256 != expectedSnapshotSHA {
		return fmt.Errorf("semantic worker model-cache snapshot hash mismatch")
	}
	return nil
}

func (worker *Worker) Embed(text string) ([]float32, error) {
	return worker.EmbedContext(context.Background(), text)
}

func (worker *Worker) EmbedContext(ctx context.Context, text string) ([]float32, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("semantic query is required")
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.closed {
		return nil, fmt.Errorf("semantic worker is closed")
	}
	worker.nextID++
	id := fmt.Sprintf("q-%d", worker.nextID)
	request, err := canonical.Encode(map[string]any{"id": id, "text": text})
	if err != nil {
		return nil, err
	}
	if _, err := worker.stdin.Write(append(request, '\n')); err != nil {
		return nil, fmt.Errorf("write semantic query: %w", err)
	}
	if err := worker.stdin.Flush(); err != nil {
		return nil, fmt.Errorf("flush semantic query: %w", err)
	}
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case line, open := <-worker.lines:
			if !open {
				return nil, worker.outputClosedError("semantic worker closed its output")
			}
			var response workerResponse
			if json.Unmarshal(line, &response) != nil || response.ID != id {
				continue
			}
			if response.Error != "" {
				return nil, fmt.Errorf("semantic worker: %s", response.Error)
			}
			if len(response.Embedding) != Dimension {
				return nil, fmt.Errorf("semantic worker returned dimension %d", len(response.Embedding))
			}
			return response.Embedding, nil
		case <-worker.exitDone:
			return nil, worker.processExitError("semantic worker exited")
		case <-timer.C:
			return nil, fmt.Errorf("semantic query timed out")
		}
	}
}

func (worker *Worker) Close() error {
	worker.mu.Lock()
	if worker.closed {
		worker.mu.Unlock()
		return nil
	}
	worker.closed = true
	close(worker.stop)
	_ = worker.stdin.Flush()
	if worker.command.Process != nil {
		_ = worker.command.Process.Kill()
	}
	worker.mu.Unlock()
	select {
	case <-worker.exitDone:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("semantic worker did not exit after termination")
	}
	return nil
}

func (worker *Worker) outputClosedError(message string) error {
	<-worker.scanDone
	worker.stateMu.Lock()
	defer worker.stateMu.Unlock()
	if worker.scanErr != nil {
		return fmt.Errorf("%s: %w", message, worker.scanErr)
	}
	return fmt.Errorf("%s", message)
}

func (worker *Worker) processExitError(message string) error {
	worker.stateMu.Lock()
	defer worker.stateMu.Unlock()
	if worker.exitErr != nil {
		return fmt.Errorf("%s: %w", message, worker.exitErr)
	}
	return fmt.Errorf("%s", message)
}
