package rule

import (
	"regexp"
	"sync"
	"testing"

	"github.com/aprpure/XrayR/api"
)

func makeRules(patterns ...string) []api.DetectRule {
	rules := make([]api.DetectRule, len(patterns))
	for i, p := range patterns {
		rules[i] = api.DetectRule{ID: i + 1, Pattern: regexp.MustCompile(p)}
	}
	return rules
}

func TestDetectRejectAndRecord(t *testing.T) {
	m := New()
	const tag = "V2ray_1.2.3.4_443"
	if err := m.UpdateRule(tag, makeRules(`google\.com`, `baidu\.com`)); err != nil {
		t.Fatal(err)
	}

	if m.Detect(tag, "https://example.com/", "tag|user@x|42") {
		t.Error("non-matching destination must not be rejected")
	}
	if !m.Detect(tag, "https://www.google.com/search", "tag|user@x|42") {
		t.Error("matching destination must be rejected")
	}

	results, err := m.GetDetectResult(tag)
	if err != nil {
		t.Fatal(err)
	}
	if len(*results) != 1 || (*results)[0].UID != 42 || (*results)[0].RuleID != 1 {
		t.Fatalf("unexpected detect results: %+v", *results)
	}
	// Results are consumed: second read is empty.
	results2, _ := m.GetDetectResult(tag)
	if len(*results2) != 0 {
		t.Fatalf("detect results not cleared: %+v", *results2)
	}
}

func TestDetectDedupsResults(t *testing.T) {
	m := New()
	const tag = "Trojan_1.2.3.4_443"
	if err := m.UpdateRule(tag, makeRules(`ads\.io`)); err != nil {
		t.Fatal(err)
	}
	m.Detect(tag, "http://ads.io/x", "t|u@x|7")
	m.Detect(tag, "http://ads.io/y", "t|u@x|7") // same uid+rule -> deduped
	results, _ := m.GetDetectResult(tag)
	if len(*results) != 1 {
		t.Fatalf("expected dedup to 1 result, got %d", len(*results))
	}
}

func TestDetectBadEmail(t *testing.T) {
	m := New()
	const tag = "V2ray_1.2.3.4_443"
	if err := m.UpdateRule(tag, makeRules(`blocked\.net`)); err != nil {
		t.Fatal(err)
	}
	if !m.Detect(tag, "http://blocked.net/", "no-uid-email") {
		t.Error("destination matching rule must still be rejected even if uid parse fails")
	}
	results, _ := m.GetDetectResult(tag)
	if len(*results) != 0 {
		t.Fatalf("unparseable email must not record a result: %+v", *results)
	}
}

func TestRemoveInbound(t *testing.T) {
	m := New()
	tag := "SSpanel_1.2.3.4_443"
	if err := m.UpdateRule(tag, makeRules(`a\.com`, `b\.com`)); err != nil {
		t.Fatal(err)
	}
	m.Detect(tag, "http://a.com/", "t|u|x|9")
	m.RemoveInbound(tag)
	if _, ok := m.InboundRule.Load(tag); ok {
		t.Error("rules not removed")
	}
	if _, ok := m.InboundDetectResult.Load(tag); ok {
		t.Error("detect results not removed")
	}
	if m.Detect(tag, "http://a.com/", "t|u|x|9") {
		t.Error("removed inbound must not match anymore")
	}
}

func TestCombinedMatchesSingleRuleBehavior(t *testing.T) {
	patterns := []string{"one\\.io", "two\\.io", "three\\.io"}
	for _, tc := range []struct {
		dest string
		want int // rule ID expected to hit, -1 for no match
	}{
		{"http://one.io/", 1},
		{"http://two.io/", 2},
		{"http://three.io/", 3},
		{"http://four.io/", -1},
	} {
		// Combined path (>1 rules).
		m := New()
		if err := m.UpdateRule("multi", makeRules(patterns...)); err != nil {
			t.Fatal(err)
		}
		if got := m.Detect("multi", tc.dest, "t|u|1"); got != (tc.want != -1) {
			t.Errorf("combined Detect(%q) = %v, want %v", tc.dest, got, tc.want != -1)
		}
		results, _ := m.GetDetectResult("multi")
		if tc.want == -1 {
			if len(*results) != 0 {
				t.Errorf("no-match case must not record a result: %+v", *results)
			}
		} else if len(*results) != 1 || (*results)[0].RuleID != tc.want {
			t.Errorf("combined Detect(%q) recorded %+v, want RuleID %d", tc.dest, *results, tc.want)
		}

		// Fallback path: single rule never builds the combined regexp.
		m2 := New()
		if err := m2.UpdateRule("single", makeRules(patterns[0])); err != nil {
			t.Fatal(err)
		}
		if got := m2.Detect("single", tc.dest, "t|u|1"); got != (tc.want == 1) {
			t.Errorf("single Detect(%q) = %v, want %v", tc.dest, got, tc.want == 1)
		}
	}
}

func TestConcurrentDetect(t *testing.T) {
	m := New()
	const tag = "V2ray_1.2.3.4_444"
	if err := m.UpdateRule(tag, makeRules(`a\.com`, `b\.com`, `c\.com`)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				m.Detect(tag, "http://a.com/", "t|u|1")
				m.GetDetectResult(tag)
				m.UpdateRule(tag, makeRules(`a\.com`, `d\.com`))
			}
		}(i)
	}
	wg.Wait()
}
