package receipt

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"vectorengine.local/poc/capabilityenvelope/internal/canonical"
)

const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

type Row struct {
	Sequence       uint64         `json:"sequence"`
	Timestamp      string         `json:"timestamp"`
	Event          string         `json:"event"`
	Fields         map[string]any `json:"fields"`
	PreviousDigest string         `json:"previous_digest"`
	Digest         string         `json:"digest"`
}

type unsignedRow struct {
	Sequence       uint64         `json:"sequence"`
	Timestamp      string         `json:"timestamp"`
	Event          string         `json:"event"`
	Fields         map[string]any `json:"fields"`
	PreviousDigest string         `json:"previous_digest"`
}

type Log struct {
	mu       sync.Mutex
	path     string
	rows     []Row
	previous string
	clock    func() time.Time
}

func Open(path string, clock func() time.Time) (*Log, error) {
	if clock == nil {
		clock = time.Now
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("decision log path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create decision log directory: %w", err)
	}
	rows, err := ReadAndVerify(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	previous := zeroDigest
	if len(rows) > 0 {
		previous = rows[len(rows)-1].Digest
	}
	return &Log{path: path, rows: rows, previous: previous, clock: clock}, nil
}

func (log *Log) Append(event string, fields map[string]any) (Row, error) {
	event = strings.TrimSpace(event)
	if event == "" {
		return Row{}, fmt.Errorf("receipt event is required")
	}
	if fields == nil {
		fields = map[string]any{}
	}
	if err := rejectSensitive(fields, "fields"); err != nil {
		return Row{}, err
	}
	fields = cloneMap(fields)
	log.mu.Lock()
	defer log.mu.Unlock()
	unsigned := unsignedRow{
		Sequence:       uint64(len(log.rows) + 1),
		Timestamp:      log.clock().UTC().Format(time.RFC3339Nano),
		Event:          event,
		Fields:         fields,
		PreviousDigest: log.previous,
	}
	encoded, err := canonical.Encode(unsigned)
	if err != nil {
		return Row{}, err
	}
	digest := sha256.New()
	digest.Write([]byte(log.previous))
	digest.Write(encoded)
	row := Row{
		Sequence:       unsigned.Sequence,
		Timestamp:      unsigned.Timestamp,
		Event:          unsigned.Event,
		Fields:         unsigned.Fields,
		PreviousDigest: unsigned.PreviousDigest,
		Digest:         hex.EncodeToString(digest.Sum(nil)),
	}
	rowBytes, err := canonical.Encode(row)
	if err != nil {
		return Row{}, err
	}
	file, err := os.OpenFile(log.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return Row{}, fmt.Errorf("open decision log: %w", err)
	}
	if _, err := file.Write(append(rowBytes, '\n')); err != nil {
		_ = file.Close()
		return Row{}, fmt.Errorf("append decision log: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return Row{}, fmt.Errorf("sync decision log: %w", err)
	}
	if err := file.Close(); err != nil {
		return Row{}, err
	}
	log.rows = append(log.rows, row)
	log.previous = row.Digest
	return cloneRow(row), nil
}

func (log *Log) Rows() []Row {
	log.mu.Lock()
	defer log.mu.Unlock()
	result := make([]Row, len(log.rows))
	for index, row := range log.rows {
		result[index] = cloneRow(row)
	}
	return result
}

func (log *Log) Verify() error {
	log.mu.Lock()
	defer log.mu.Unlock()
	return verifyRows(log.rows)
}

func ReadAndVerify(path string) ([]Row, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	rows := make([]Row, 0)
	for line := 1; scanner.Scan(); line++ {
		var row Row
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("decode decision log line %d: %w", line, err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := verifyRows(rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func verifyRows(rows []Row) error {
	previous := zeroDigest
	for index, row := range rows {
		if row.Sequence != uint64(index+1) {
			return fmt.Errorf("decision row %d has sequence %d", index+1, row.Sequence)
		}
		if row.PreviousDigest != previous {
			return fmt.Errorf("decision row %d previous digest mismatch", index+1)
		}
		unsigned := unsignedRow{
			Sequence:       row.Sequence,
			Timestamp:      row.Timestamp,
			Event:          row.Event,
			Fields:         row.Fields,
			PreviousDigest: row.PreviousDigest,
		}
		encoded, err := canonical.Encode(unsigned)
		if err != nil {
			return err
		}
		digest := sha256.New()
		digest.Write([]byte(previous))
		digest.Write(encoded)
		expected := hex.EncodeToString(digest.Sum(nil))
		if row.Digest != expected {
			return fmt.Errorf("decision row %d digest mismatch", index+1)
		}
		previous = row.Digest
	}
	return nil
}

func rejectSensitive(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			lower := strings.ToLower(key)
			forbidden := []string{"api_key", "apikey", "secret", "signature", "token", "authorization", "headers"}
			for _, fragment := range forbidden {
				if strings.Contains(lower, fragment) {
					return fmt.Errorf("receipt field %s.%s is sensitive", path, key)
				}
			}
			if err := rejectSensitive(typed[key], path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for index, item := range typed {
			if err := rejectSensitive(item, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func cloneRow(row Row) Row {
	row.Fields = cloneMap(row.Fields)
	return row
}

func cloneMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = cloneValue(value)
	}
	return result
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneValue(item)
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	case json.RawMessage:
		return append(json.RawMessage(nil), typed...)
	default:
		return value
	}
}
