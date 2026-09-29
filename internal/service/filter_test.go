package service_test

import (
	"context"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"testing"
	"time"
)

func TestLoadRules_FilterAndKindValidation(t *testing.T) {
	cases := map[string]string{
		"unknown match field":     `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "contains": ["x"], "when": {"match": {"body": ["x"]}}}]}`,
		"empty except":            `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "contains": ["x"], "when": {"except": [{}]}}]}`,
		"invalid CIDR":            `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "contains": ["x"], "when": {"except": [{"dst_ip": ["10.0.0.0/33"]}]}}]}`,
		"unknown placeholder":     `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "contains": ["x"], "reason": "{event.body}"}]}`,
		"unknown group_by":        `{"rules": [{"name": "A", "kind": "threshold", "severity": "low", "threshold": 1, "window": "1m", "group_by": "body"}]}`,
		"beacon too few":          `{"rules": [{"name": "A", "kind": "beacon", "severity": "low", "threshold": 2, "window": "1h", "min_interval": "10s", "max_jitter": 0.1}]}`,
		"beacon no jitter":        `{"rules": [{"name": "A", "kind": "beacon", "severity": "low", "threshold": 5, "window": "1h", "min_interval": "10s"}]}`,
		"beacon window too short": `{"rules": [{"name": "A", "kind": "beacon", "severity": "low", "threshold": 5, "window": "30s", "min_interval": "10s", "max_jitter": 0.1}]}`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadRules(t, js); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestEventFilter_MatchAndExcept(t *testing.T) {
	rules, err := loadRules(t, `{"rules": [{
		"name": "ExternalSSH", "kind": "signature", "severity": "low", "fields": ["port"], "regex": ["^22$"],
		"when": {
			"match":  {"direction": ["INBOUND"]},
			"except": [{"ip": ["10.0.0.0/8", "2001:db8::/32"]}, {"metadata.user": ["backup"]}]
		}
	}]}`)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := service.NewDetectionEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	store := repository.NewMemoryStore()
	cases := map[string]struct {
		event domain.Event
		want  bool
	}{
		"external inbound":        {domain.Event{IP: "203.0.113.1", Port: 22, Direction: "inbound"}, true},
		"outbound":                {domain.Event{IP: "203.0.113.1", Port: 22, Direction: "outbound"}, false},
		"internal IPv4":           {domain.Event{IP: "10.1.2.3", Port: 22, Direction: "inbound"}, false},
		"internal IPv6":           {domain.Event{IP: "2001:db8::7", Port: 22, Direction: "inbound"}, false},
		"allowlisted by metadata": {domain.Event{IP: "203.0.113.2", Port: 22, Direction: "inbound", Metadata: map[string]string{"user": "backup"}}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tc.event.Timestamp = time.Now()
			if _, got := engine.Evaluate(context.Background(), tc.event, store, store); got != tc.want {
				t.Errorf("triggered = %v, want %v", got, tc.want)
			}
		})
	}
}
