package semantic

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
)

var embeddingMagic = [8]byte{'C', 'E', 'S', 'E', 'M', '0', '1', 0}

type VectorAudit struct {
	Vectors          int     `json:"vectors"`
	Dimension        int     `json:"dimension"`
	NonFiniteVectors int     `json:"non_finite_vectors"`
	ZeroVectors      int     `json:"zero_vectors"`
	UnitNormFailures int     `json:"unit_norm_failures"`
	NormMin          float64 `json:"norm_min"`
	NormMax          float64 `json:"norm_max"`
}

func LoadEmbeddings(path string) ([][]float32, VectorAudit, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, VectorAudit{}, err
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 1024*1024)
	var magic [8]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		return nil, VectorAudit{}, err
	}
	if !bytes.Equal(magic[:], embeddingMagic[:]) {
		return nil, VectorAudit{}, fmt.Errorf("semantic embedding file magic mismatch")
	}
	var count uint32
	var dimension uint32
	if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
		return nil, VectorAudit{}, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &dimension); err != nil {
		return nil, VectorAudit{}, err
	}
	if count == 0 || dimension != Dimension {
		return nil, VectorAudit{}, fmt.Errorf("semantic embedding header reports count=%d dimension=%d", count, dimension)
	}
	vectors := make([][]float32, int(count))
	report := VectorAudit{Vectors: int(count), Dimension: int(dimension), NormMin: math.Inf(1), NormMax: math.Inf(-1)}
	for index := range vectors {
		values := make([]float32, int(dimension))
		if err := binary.Read(reader, binary.LittleEndian, values); err != nil {
			return nil, VectorAudit{}, fmt.Errorf("read semantic vector %d: %w", index, err)
		}
		norm := float64(0)
		finite := true
		for _, value := range values {
			converted := float64(value)
			if math.IsNaN(converted) || math.IsInf(converted, 0) {
				finite = false
				break
			}
			norm += converted * converted
		}
		if !finite {
			report.NonFiniteVectors++
		} else {
			norm = math.Sqrt(norm)
			if norm == 0 {
				report.ZeroVectors++
			}
			if math.Abs(norm-1) > 1e-4 {
				report.UnitNormFailures++
			}
			report.NormMin = min(report.NormMin, norm)
			report.NormMax = max(report.NormMax, norm)
		}
		vectors[index] = values
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		if err == nil {
			return nil, VectorAudit{}, fmt.Errorf("semantic embedding file has trailing bytes")
		}
		return nil, VectorAudit{}, err
	}
	return vectors, report, nil
}
