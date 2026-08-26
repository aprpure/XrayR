// Package rule is to control the audit rule behaviors
package rule

import (
	"regexp"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/aprpure/XrayR/api"
)

type inboundRules struct {
	rules []api.DetectRule
	// combined matches all rule patterns in a single regexp; nil when there is
	// only one rule (or joining them failed to compile) and Detect falls back
	// to scanning rules one by one.
	combined *regexp.Regexp
}

type Manager struct {
	InboundRule         *sync.Map // Key: Tag, Value: *inboundRules
	InboundDetectResult *sync.Map // key: Tag, Value: map[api.DetectResult]struct{}
}

func New() *Manager {
	return &Manager{
		InboundRule:         new(sync.Map),
		InboundDetectResult: new(sync.Map),
	}
}

func (r *Manager) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	inbound := &inboundRules{rules: newRuleList}
	if len(newRuleList) > 1 {
		patterns := make([]string, len(newRuleList))
		for i := range newRuleList {
			patterns[i] = newRuleList[i].Pattern.String()
		}
		if combined, err := regexp.Compile(strings.Join(patterns, "|")); err == nil {
			inbound.combined = combined
		} else {
			log.Debug("combine audit rules failed, falling back to per-rule scan: ", err)
		}
	}
	r.InboundRule.Store(tag, inbound)
	return nil
}

// RemoveInbound drops all state for an inbound tag. Must be paired with
// limiter.DeleteInboundLimiter when a node tag is replaced, otherwise the old
// rules and detect results leak.
func (r *Manager) RemoveInbound(tag string) {
	r.InboundRule.Delete(tag)
	r.InboundDetectResult.Delete(tag)
}

func (r *Manager) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	detectResult := make([]api.DetectResult, 0)
	if value, ok := r.InboundDetectResult.LoadAndDelete(tag); ok {
		resultSet := value.(map[api.DetectResult]struct{})
		for result := range resultSet {
			detectResult = append(detectResult, result)
		}
	}
	return &detectResult, nil
}

func (r *Manager) Detect(tag string, destination string, email string) (reject bool) {
	value, ok := r.InboundRule.Load(tag)
	if !ok {
		return false
	}
	inbound := value.(*inboundRules)

	hit := -1
	if inbound.combined != nil {
		// Single pass over all patterns; locate the hit rule only on a match.
		if inbound.combined.MatchString(destination) {
			for i := range inbound.rules {
				if inbound.rules[i].Pattern.MatchString(destination) {
					hit = inbound.rules[i].ID
					break
				}
			}
		}
	} else {
		for i := range inbound.rules {
			if inbound.rules[i].Pattern.MatchString(destination) {
				hit = inbound.rules[i].ID
				break
			}
		}
	}
	if hit == -1 {
		return false
	}
	reject = true

	l := strings.Split(email, "|")
	uid, err := strconv.Atoi(l[len(l)-1])
	if err != nil {
		log.Debug("Record illegal behavior failed! Cannot find user's uid: ", email)
		return reject
	}
	newResult := api.DetectResult{UID: uid, RuleID: hit}
	newSet := map[api.DetectResult]struct{}{newResult: {}}
	// If there are any hit history
	if v, ok := r.InboundDetectResult.LoadOrStore(tag, newSet); ok {
		resultSet := v.(map[api.DetectResult]struct{})
		// If this is a new record
		if _, exists := resultSet[newResult]; !exists {
			resultSet[newResult] = struct{}{}
			r.InboundDetectResult.Store(tag, resultSet)
		}
	}
	return reject
}
