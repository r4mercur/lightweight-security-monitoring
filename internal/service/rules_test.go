package service_test

import (
	"context"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"strings"
	"testing"
)

func loadRules(t *testing.T, js string) (service.RuleSet, error) {
	t.Helper()
	return service.LoadRules(strings.NewReader(js))
}

func TestLoadRules_CustomSignatureRule(t *testing.T) {
	rules, err := loadRules(t, `{
		"rules": [{
			"name": "ForbiddenHeader",
			"kind": "signature",
			"severity": "low",
			"fields": ["metadata.x-debug"],
			"contains": ["enabled"],
			"reason": "{rule}: {field} from {ip}"
		}]
	}`)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	engine, err := service.NewDetectionEngine(rules)
	if err != nil {
		t.Fatal(err)
	}

	store := repository.NewMemoryStore()
	event := newEvent("10.1.0.1", domain.EventHTTPRequest, func(e *domain.Event) {
		e.Metadata = map[string]string{"x-debug": "Enabled"}
	})
	alert, triggered := engine.Evaluate(context.Background(), event, store, store)
	if !triggered {
		t.Fatal("expected custom rule to fire")
	}
	if want := "ForbiddenHeader: metadata.x-debug from 10.1.0.1"; alert.Reason != want {
		t.Errorf("reason = %q, want %q", alert.Reason, want)
	}
}

func TestLoadRules_DisabledRulesAreSkipped(t *testing.T) {
	rules, err := loadRules(t, `{"rules": [
		{"name": "A", "kind": "signature", "severity": "low", "contains": ["a"], "disabled": true},
		{"name": "B", "kind": "signature", "severity": "low", "contains": ["b"]}
	]}`)
	if err != nil {
		t.Fatal(err)
	}
	if rules.Len() != 1 || rules.Rules[0].Name() != "B" {
		t.Errorf("expected only rule B, got %d rules", rules.Len())
	}
}

func TestLoadRules_ValidationErrors(t *testing.T) {
	cases := map[string]string{
		"unknown json field": `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "contians": ["x"]}]}`,
		"unknown kind":       `{"rules": [{"name": "A", "kind": "magic", "severity": "low"}]}`,
		"invalid severity":   `{"rules": [{"name": "A", "kind": "signature", "severity": "urgent", "contains": ["x"]}]}`,
		"invalid regex":      `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "regex": ["(unclosed"]}]}`,
		"no patterns":        `{"rules": [{"name": "A", "kind": "signature", "severity": "low"}]}`,
		"unknown field":      `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "fields": ["body"], "contains": ["x"]}]}`,
		"missing window":     `{"rules": [{"name": "A", "kind": "threshold", "severity": "low", "threshold": 3}]}`,
		"bad duration":       `{"rules": [{"name": "A", "kind": "threshold", "severity": "low", "threshold": 3, "window": "soon"}]}`,
		"path without slash": `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "paths": ["admin"]}]}`,
		"no rules":           `{"rules": []}`,
		// Strict parsing (encoding/json/v2): mistakes must not silently drop parts of a rule.
		"duplicate key":    `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "regex": ["a"], "regex": ["b"]}]}`,
		"mis-cased key":    `{"rules": [{"Name": "A", "kind": "signature", "severity": "low", "contains": ["x"]}]}`,
		"trailing content": `{"rules": [{"name": "A", "kind": "signature", "severity": "low", "contains": ["x"]}]} {"rules": []}`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadRules(t, js); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestNewDetectionEngine_DuplicateNames(t *testing.T) {
	rules, err := loadRules(t, `{"rules": [
		{"name": "A", "kind": "signature", "severity": "low", "contains": ["a"]},
		{"name": "A", "kind": "signature", "severity": "low", "contains": ["b"]}
	]}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.NewDetectionEngine(rules); err == nil {
		t.Error("expected duplicate rule names to be rejected")
	}
}

// methodRule is a custom kind implemented in Go, registered via RegisterRuleKind.
type methodRule struct {
	service.RuleBase
	method string
}

func (r *methodRule) Evaluate(_ context.Context, e domain.Event, _ repository.EventRepository) (*domain.Alert, bool) {
	if e.Metadata["method"] != r.method {
		return nil, false
	}
	return r.Alert(e, 1, map[string]string{"method": r.method}), true
}

func TestRegisterRuleKind_CustomKind(t *testing.T) {
	service.RegisterRuleKind("http_method", func(spec service.RuleSpec) (service.Rule, error) {
		base, err := service.NewRuleBase(spec, "{method} request from {ip}")
		if err != nil {
			return nil, err
		}
		return &methodRule{RuleBase: base, method: spec.Contains[0]}, nil
	})

	rules, err := loadRules(t, `{"rules": [{"name": "Trace", "kind": "http_method", "severity": "low", "contains": ["TRACE"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := service.NewDetectionEngine(rules)
	if err != nil {
		t.Fatal(err)
	}

	store := repository.NewMemoryStore()
	event := newEvent("10.1.0.2", domain.EventHTTPRequest, func(e *domain.Event) {
		e.Metadata = map[string]string{"method": "TRACE"}
	})
	alert, triggered := engine.Evaluate(context.Background(), event, store, store)
	if !triggered || alert.Reason != "TRACE request from 10.1.0.2" {
		t.Fatalf("expected custom kind to fire, got %+v", alert)
	}
}
