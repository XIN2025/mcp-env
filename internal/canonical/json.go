package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

func Encode(value any) ([]byte, error) {
	initial, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON value: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(initial))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("normalize JSON value: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, fmt.Errorf("encode canonical JSON: %w", err)
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func NormalizeRaw(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return json.RawMessage("{}"), nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode raw JSON: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	encoded, err := Encode(value)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

func SHA256(value any) (string, error) {
	encoded, err := Encode(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func BytesSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	return fmt.Errorf("decode trailing JSON: %w", err)
}
