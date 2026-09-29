package service

import (
	"context"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/repository"
	"slices"
	"time"
)

// Rule is the interface every event-based detection rule must satisfy.
type Rule interface {
	Name() string
	Evaluate(ctx context.Context, event domain.Event, repo repository.EventRepository) (*domain.Alert, bool)
}

// Correlator is evaluated after all Rules. It sees the alerts the current event
// produced plus the alert history of the source IP within its Window.
type Correlator interface {
	Name() string
	Window() time.Duration
	Correlate(event domain.Event, fired []*domain.Alert, history []domain.Alert) (*domain.Alert, bool)
}

// cooldowner is implemented by rules that suppress repeated alerts for the same IP.
type cooldowner interface {
	Cooldown() time.Duration
}

// Pruner is implemented by rules that keep per-IP state in memory.
// DetectionEngine.Prune forwards to it so idle state is released.
type Pruner interface {
	Prune(now time.Time)
}

// RuleSet is the set of rules a DetectionEngine runs.
type RuleSet struct {
	Rules       []Rule
	Correlators []Correlator
}

// Len returns the total number of rules and correlators.
func (s RuleSet) Len() int { return len(s.Rules) + len(s.Correlators) }

// DetectionEngine runs all registered rules against an incoming event.
type DetectionEngine struct {
	rules       []Rule
	correlators []Correlator
	cooldowns   map[string]time.Duration
	// lookback is how far back the alert history of an IP is needed
	// (max of all cooldowns and correlation windows).
	lookback time.Duration
}

// NewDetectionEngine creates a DetectionEngine from a RuleSet.
// Rule names must be unique because cooldowns and correlation key on them.
func NewDetectionEngine(set RuleSet) (*DetectionEngine, error) {
	e := &DetectionEngine{
		rules:       set.Rules,
		correlators: set.Correlators,
		cooldowns:   make(map[string]time.Duration),
	}

	seen := make(map[string]bool)
	register := func(name string, r any) error {
		if seen[name] {
			return fmt.Errorf("duplicate rule name %q", name)
		}
		seen[name] = true
		if c, ok := r.(cooldowner); ok && c.Cooldown() > 0 {
			e.cooldowns[name] = c.Cooldown()
			e.lookback = max(e.lookback, c.Cooldown())
		}
		return nil
	}
	for _, r := range set.Rules {
		if err := register(r.Name(), r); err != nil {
			return nil, err
		}
	}
	for _, c := range set.Correlators {
		if err := register(c.Name(), c); err != nil {
			return nil, err
		}
		e.lookback = max(e.lookback, c.Window())
	}
	return e, nil
}

// AlertLookback is how far back the alert history must reach for cooldowns and
// correlation to work. Alert retention must not be shorter.
func (e *DetectionEngine) AlertLookback() time.Duration { return e.lookback }

// Prune releases in-memory rule state that is older than the rules' windows.
func (e *DetectionEngine) Prune(now time.Time) {
	for _, r := range e.rules {
		if p, ok := r.(Pruner); ok {
			p.Prune(now)
		}
	}
}

// Evaluate runs every rule and correlator against the event. Alerts that are still
// in their cooldown for this IP are dropped. The remaining alert with the highest
// severity is returned (ties go to the rule defined first); the names of the other
// rules that fired are listed in its RelatedRules.
func (e *DetectionEngine) Evaluate(
	ctx context.Context,
	event domain.Event,
	events repository.EventRepository,
	alerts repository.AlertRepository,
) (*domain.Alert, bool) {
	var fired []*domain.Alert
	for _, rule := range e.rules {
		if alert, triggered := rule.Evaluate(ctx, event, events); triggered {
			fired = append(fired, alert)
		}
	}
	if len(fired) == 0 {
		return nil, false
	}

	var history []domain.Alert
	if alerts != nil && e.lookback > 0 {
		// On error we continue without history: a duplicate alert is better than a missed one.
		history, _ = alerts.FindAlertsByIPSince(ctx, event.IP, event.Timestamp.Add(-e.lookback))
	}

	candidates := fired
	for _, c := range e.correlators {
		if alert, triggered := c.Correlate(event, fired, history); triggered {
			candidates = append(candidates, alert)
		}
	}

	var kept []*domain.Alert
	for _, a := range candidates {
		if !e.inCooldown(a, history, event.Timestamp) {
			kept = append(kept, a)
		}
	}
	if len(kept) == 0 {
		return nil, false
	}

	primary := kept[0]
	for _, a := range kept[1:] {
		if a.Severity.Rank() > primary.Severity.Rank() {
			primary = a
		}
	}
	for _, a := range kept {
		if a != primary {
			primary.RelatedRules = append(primary.RelatedRules, a.TriggerRule)
		}
	}
	return primary, true
}

// inCooldown reports whether the alert's rule already alerted for this IP within its cooldown.
func (e *DetectionEngine) inCooldown(alert *domain.Alert, history []domain.Alert, now time.Time) bool {
	cooldown, ok := e.cooldowns[alert.TriggerRule]
	if !ok {
		return false
	}
	since := now.Add(-cooldown)
	for _, h := range history {
		if !h.Timestamp.After(since) {
			continue
		}
		if h.TriggerRule == alert.TriggerRule || slices.Contains(h.RelatedRules, alert.TriggerRule) {
			return true
		}
	}
	return false
}
