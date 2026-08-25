package controller

import "testing"

func TestFirstNonZero(t *testing.T) {
	cases := []struct {
		name string
		vals []int
		want int
	}{
		{"local first", []int{100, 180, 60}, 100},
		{"panel second", []int{0, 180, 60}, 180},
		{"legacy third", []int{0, 0, 90}, 90},
		{"all zero", []int{0, 0, 0}, 0},
		{"empty", []int{}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstNonZero(c.vals...); got != c.want {
				t.Errorf("firstNonZero(%v) = %d, want %d", c.vals, got, c.want)
			}
		})
	}
}

func TestIntervalResolution(t *testing.T) {
	const fallback = defaultUpdatePeriodic
	// local > panel > legacy > default
	if got := firstNonZero(100, 180, 90, fallback); got != 100 {
		t.Errorf("local override: got %d", got)
	}
	if got := firstNonZero(0, 180, 90, fallback); got != 180 {
		t.Errorf("panel passthrough: got %d", got)
	}
	if got := firstNonZero(0, 0, 90, fallback); got != 90 {
		t.Errorf("legacy UpdatePeriodic: got %d", got)
	}
	if got := firstNonZero(0, 0, 0, fallback); got != 60 {
		t.Errorf("final fallback: got %d", got)
	}
}
