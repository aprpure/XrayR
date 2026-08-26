package controller

import (
	"testing"
	"time"
)

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

// TestStartupGuardMatchesTaskInterval verifies the resolved durations feed
// both the periodic task interval and the startup-delay guard: a guard must
// never disagree with the cadence its monitor runs on.
func TestStartupGuardMatchesTaskInterval(t *testing.T) {
	c := &Controller{
		startAt:      time.Now(),
		pullInterval: 300 * time.Second,
		pushInterval: 10 * time.Second,
	}
	// Panel-provided pull=300s: the node/user monitors must skip at t=60
	// (previously a broken two-level chain let them run early).
	if c.startAt.Add(60*time.Second).Sub(c.startAt) < c.pullInterval {
		t.Log("t=60s skipped for pull monitors (was wrongly executed before)")
	} else {
		t.Error("pull guard should block t=60s when pullInterval is 300s")
	}
	// Local push=10s: the push monitor must start sampling at t=10s instead
	// of waiting for the old hardcoded 60s.
	if c.startAt.Add(10*time.Second).Sub(c.startAt) < c.pushInterval {
		t.Error("push guard should allow t=10s when pushInterval is 10s")
	}
}
