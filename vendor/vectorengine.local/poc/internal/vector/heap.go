package vector

import "container/heap"

type scoredCandidate struct {
	id       string
	distance float64
}

func better(left, right scoredCandidate) bool {
	if left.distance != right.distance {
		return left.distance < right.distance
	}
	return left.id < right.id
}

type worstFirstHeap []scoredCandidate

func (h worstFirstHeap) Len() int { return len(h) }

func (h worstFirstHeap) Less(i, j int) bool {
	return better(h[j], h[i])
}

func (h worstFirstHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *worstFirstHeap) Push(value any) {
	*h = append(*h, value.(scoredCandidate))
}

func (h *worstFirstHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	*h = old[:last]
	return value
}

func retainBest(h *worstFirstHeap, candidate scoredCandidate, k int) {
	if h.Len() < k {
		heap.Push(h, candidate)
		return
	}
	if better(candidate, (*h)[0]) {
		heap.Pop(h)
		heap.Push(h, candidate)
	}
}
