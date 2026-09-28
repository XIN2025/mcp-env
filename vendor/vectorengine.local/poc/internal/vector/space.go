package vector

import (
	"errors"
	"fmt"
	"math"
)

type Metric string

const (
	Euclidean    Metric = "euclidean"
	Cosine       Metric = "cosine"
	InnerProduct Metric = "inner_product"
)

var (
	ErrDimensionMismatch = errors.New("vector dimension does not match collection")
	ErrNonFinite         = errors.New("vector contains a non-finite value")
	ErrZeroNorm          = errors.New("cosine vector has zero norm")
)

type Space struct {
	dimension int
	metric    Metric
}

func NewSpace(dimension int, metric Metric) (Space, error) {
	if dimension < 1 || dimension > 4096 {
		return Space{}, fmt.Errorf("dimension must be between 1 and 4096")
	}
	switch metric {
	case Euclidean, Cosine, InnerProduct:
	default:
		return Space{}, fmt.Errorf("unsupported distance metric %q", metric)
	}
	return Space{dimension: dimension, metric: metric}, nil
}

func (s Space) Dimension() int {
	return s.dimension
}

func (s Space) Metric() Metric {
	return s.metric
}

func (s Space) PrepareFloat64(values []float64) ([]float32, error) {
	if len(values) != s.dimension {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrDimensionMismatch, len(values), s.dimension)
	}
	prepared := make([]float32, len(values))
	for i, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, fmt.Errorf("%w at position %d", ErrNonFinite, i)
		}
		converted := float32(value)
		if math.IsInf(float64(converted), 0) {
			return nil, fmt.Errorf("value at position %d exceeds float32 range", i)
		}
		prepared[i] = converted
	}
	return s.prepareFloat32InPlace(prepared)
}

func (s Space) PrepareFloat32(values []float32) ([]float32, error) {
	if len(values) != s.dimension {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrDimensionMismatch, len(values), s.dimension)
	}
	prepared := append([]float32(nil), values...)
	return s.prepareFloat32InPlace(prepared)
}

// Does not renormalize; cosine payloads must already be unit length.
func (s Space) RestoreFloat32(values []float32) ([]float32, error) {
	if len(values) != s.dimension {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrDimensionMismatch, len(values), s.dimension)
	}
	restored := append([]float32(nil), values...)
	var squaredNorm float64
	for i, value := range restored {
		value64 := float64(value)
		if math.IsNaN(value64) || math.IsInf(value64, 0) {
			return nil, fmt.Errorf("%w at position %d", ErrNonFinite, i)
		}
		if s.metric == Cosine {
			squaredNorm += value64 * value64
		}
	}
	if s.metric == Cosine && math.Abs(squaredNorm-1) > 1e-4 {
		return nil, fmt.Errorf("persisted cosine vector has squared norm %.8f", squaredNorm)
	}
	return restored, nil
}

func (s Space) prepareFloat32InPlace(values []float32) ([]float32, error) {
	var squaredNorm float64
	for i, value := range values {
		value64 := float64(value)
		if math.IsNaN(value64) || math.IsInf(value64, 0) {
			return nil, fmt.Errorf("%w at position %d", ErrNonFinite, i)
		}
		if s.metric == Cosine {
			squaredNorm += value64 * value64
		}
	}
	if s.metric != Cosine {
		return values, nil
	}
	if squaredNorm == 0 {
		return nil, ErrZeroNorm
	}
	inverseNorm := 1 / math.Sqrt(squaredNorm)
	for i := range values {
		values[i] = float32(float64(values[i]) * inverseNorm)
	}
	return values, nil
}

// Assumes both vectors passed validation. Smaller is always better.
func (s Space) Distance(left, right []float32) float64 {
	switch s.metric {
	case Euclidean:
		var total float64
		for i := range left {
			delta := float64(left[i]) - float64(right[i])
			total += delta * delta
		}
		return total
	case Cosine:
		var dot float64
		for i := range left {
			dot += float64(left[i]) * float64(right[i])
		}
		return 1 - dot
	case InnerProduct:
		var dot float64
		for i := range left {
			dot += float64(left[i]) * float64(right[i])
		}
		return -dot
	default:
		panic("vector.Space contains an invalid metric")
	}
}
