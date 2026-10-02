package service

import (
	"bytes"
	_ "embed"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"lightweight-security-monitoring/internal/domain"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed rules/default.json
var defaultRulesJSON []byte

// defaultCooldown applies to every rule that does not set its own cooldown
// and the rule file does not set "default_cooldown".
const defaultCooldown = time.Minute

// ─────────────────────────────────────────────────────────────────────────────
// Rule file format
// ─────────────────────────────────────────────────────────────────────────────

// RuleFile is the top-level structure of a JSON rule file.
type RuleFile struct {
	DefaultCooldown *Duration  `json:"default_cooldown,omitempty"`
	Rules           []RuleSpec `json:"rules"`
}

// RuleSpec describes a single rule. Which fields are used depends on Kind.
type RuleSpec struct {
	Name        string           `json:"name"`
	Kind        string           `json:"kind"`
	Description string           `json:"description,omitempty"`
	Severity    domain.Severity  `json:"severity"`
	AlertType   domain.EventType `json:"alert_type,omitempty"`
	Reason      string           `json:"reason,omitempty"`
	Disabled    bool             `json:"disabled,omitempty"`
	Cooldown    *Duration        `json:"cooldown,omitempty"`
	When        EventFilter      `json:"when"`

	// kind "signature"
	Fields   []string `json:"fields,omitempty"`
	Contains []string `json:"contains,omitempty"`
	Regex    []string `json:"regex,omitempty"`
	Paths    []string `json:"paths,omitempty"`

	// kind "threshold", "beacon" and "correlation"
	Threshold int      `json:"threshold,omitempty"`
	Window    Duration `json:"window,omitempty"`
	Distinct  string   `json:"distinct,omitempty"`
	// GroupBy keeps a separate window per value of this field (in addition to the IP).
	GroupBy string `json:"group_by,omitempty"`

	// kind "beacon"
	MinInterval Duration `json:"min_interval,omitempty"`
	MaxJitter   float64  `json:"max_jitter,omitempty"`
}

// Duration is a time.Duration that is written as a string ("30s", "1m") in JSON.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// EventFilter restricts which events a rule looks at. Empty fields match everything.
type EventFilter struct {
	EventTypes  []domain.EventType `json:"event_types,omitempty"`
	StatusCodes []int              `json:"status_codes,omitempty"`
	// Match requires every listed field to have one of its values.
	Match FieldConditions `json:"match,omitempty"`
	// Except drops the event when any of the condition sets matches.
	Except []FieldConditions `json:"except,omitempty"`
}

// FieldConditions maps event fields to accepted values. A value matches when
// it equals the field (case-insensitive) or, written as a CIDR prefix such as
// "10.0.0.0/8", contains the field's IP address. A set of conditions matches
// when every listed field matches one of its values.
type FieldConditions map[string][]string

// Matches reports whether the event passes the filter.
func (f EventFilter) Matches(e domain.Event) bool {
	if len(f.EventTypes) > 0 && !slices.Contains(f.EventTypes, e.EventType) {
		return false
	}
	if len(f.StatusCodes) > 0 && !slices.Contains(f.StatusCodes, e.StatusCode) {
		return false
	}
	if !f.Match.matches(e) {
		return false
	}
	for _, except := range f.Except {
		if except.matches(e) {
			return false
		}
	}
	return true
}

func (c FieldConditions) matches(e domain.Event) bool {
	for field, values := range c {
		if !matchesAny(fieldValue(e, field), values) {
			return false
		}
	}
	return true
}

func matchesAny(value string, patterns []string) bool {
	for _, p := range patterns {
		if prefix, ok := parsePrefix(p); ok {
			if addr, err := netip.ParseAddr(value); err == nil && prefix.Contains(addr.Unmap()) {
				return true
			}
			continue
		}
		if strings.EqualFold(value, p) {
			return true
		}
	}
	return false
}

// parsePrefix recognizes CIDR notation; other values (e.g. paths) are compared literally.
func parsePrefix(s string) (netip.Prefix, bool) {
	if !strings.Contains(s, "/") || strings.HasPrefix(s, "/") {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err == nil
}

func (f EventFilter) validate() error {
	if slices.Contains(f.EventTypes, "") {
		return errors.New("when.event_types contains an empty value")
	}
	for _, c := range f.StatusCodes {
		if c < 100 || c > 599 {
			return fmt.Errorf("when.status_codes: %d is not a valid HTTP status code", c)
		}
	}
	if err := f.Match.validate("when.match"); err != nil {
		return err
	}
	for i, except := range f.Except {
		if len(except) == 0 {
			return fmt.Errorf("when.except[%d] is empty", i)
		}
		if err := except.validate(fmt.Sprintf("when.except[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func (c FieldConditions) validate(where string) error {
	for field, values := range c {
		if err := validateField(field); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if len(values) == 0 {
			return fmt.Errorf("%s.%s: needs at least one value", where, field)
		}
		for _, v := range values {
			// A value that looks like CIDR on an IP field must be a valid prefix.
			if (field == "ip" || field == "dst_ip") && strings.Contains(v, "/") {
				if _, ok := parsePrefix(v); !ok {
					return fmt.Errorf("%s.%s: %q is not a valid CIDR prefix", where, field, v)
				}
			}
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Loading
// ─────────────────────────────────────────────────────────────────────────────

// DefaultRules returns the rules embedded in the binary (rules/default.json).
func DefaultRules() (RuleSet, error) {
	return LoadRules(bytes.NewReader(defaultRulesJSON))
}

// LoadRulesFile reads a JSON rule file from disk.
func LoadRulesFile(path string) (RuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return RuleSet{}, fmt.Errorf("opening rule file: %w", err)
	}
	defer f.Close()
	return LoadRules(f)
}

// LoadRules parses and validates a JSON rule file. Parsing is strict so that a
// mistake cannot silently disable part of a rule: unknown or mis-cased keys,
// duplicate keys (e.g. "regex" twice after copy-paste) and trailing content
// are all rejected (encoding/json/v2 defaults plus RejectUnknownMembers).
func LoadRules(r io.Reader) (RuleSet, error) {
	var file RuleFile
	if err := jsonv2.UnmarshalRead(r, &file, jsonv2.RejectUnknownMembers(true)); err != nil {
		return RuleSet{}, fmt.Errorf("decoding rule file: %w", err)
	}

	cooldown := Duration(defaultCooldown)
	if file.DefaultCooldown != nil {
		cooldown = *file.DefaultCooldown
	}

	var set RuleSet
	var errs []error
	for i, spec := range file.Rules {
		if spec.Cooldown == nil {
			spec.Cooldown = &cooldown
		}
		set.Specs = append(set.Specs, spec)
		if spec.Disabled {
			continue
		}
		if err := addRule(&set, spec); err != nil {
			errs = append(errs, fmt.Errorf("rule #%d %q: %w", i+1, spec.Name, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return RuleSet{}, err
	}
	if set.Len() == 0 {
		return RuleSet{}, errors.New("rule file contains no enabled rules")
	}
	return set, nil
}

func addRule(set *RuleSet, spec RuleSpec) error {
	if spec.Kind == kindCorrelation {
		c, err := newCorrelationRule(spec)
		if err != nil {
			return err
		}
		set.Correlators = append(set.Correlators, c)
		return nil
	}

	factory, ok := lookupRuleKind(spec.Kind)
	if !ok {
		return fmt.Errorf("unknown kind %q", spec.Kind)
	}
	rule, err := factory(spec)
	if err != nil {
		return err
	}
	set.Rules = append(set.Rules, rule)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Kind registry
// ─────────────────────────────────────────────────────────────────────────────

// RuleFactory builds a Rule from its JSON spec.
type RuleFactory func(spec RuleSpec) (Rule, error)

const (
	kindSignature   = "signature"
	kindThreshold   = "threshold"
	kindBeacon      = "beacon"
	kindCorrelation = "correlation"
)

var (
	ruleKindsMu sync.RWMutex
	ruleKinds   = map[string]RuleFactory{
		kindSignature: newSignatureRule,
		kindThreshold: newThresholdRule,
		kindBeacon:    newBeaconRule,
	}
)

// RegisterRuleKind makes a custom rule kind available to rule files. Use it for
// detection logic that cannot be expressed with the built-in kinds; the
// implementation can embed RuleBase to get name, severity, cooldown and reason
// handling for free. Register before loading rules.
func RegisterRuleKind(kind string, factory RuleFactory) {
	ruleKindsMu.Lock()
	defer ruleKindsMu.Unlock()
	ruleKinds[kind] = factory
}

func lookupRuleKind(kind string) (RuleFactory, bool) {
	ruleKindsMu.RLock()
	defer ruleKindsMu.RUnlock()
	f, ok := ruleKinds[kind]
	return f, ok
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleBase – shared behaviour of all rule kinds
// ─────────────────────────────────────────────────────────────────────────────

// RuleBase holds the settings every rule kind shares and builds its alerts.
type RuleBase struct {
	name        string
	description string
	severity    domain.Severity
	alertType   domain.EventType
	reason      string
	cooldown    time.Duration
}

// NewRuleBase validates the common fields of a spec. defaultReason is used when
// the spec sets no reason template.
func NewRuleBase(spec RuleSpec, defaultReason string) (RuleBase, error) {
	if strings.TrimSpace(spec.Name) == "" {
		return RuleBase{}, errors.New("name is required")
	}
	if !spec.Severity.Valid() {
		return RuleBase{}, fmt.Errorf("invalid severity %q (use low, medium, high or critical)", spec.Severity)
	}
	var cooldown time.Duration
	if spec.Cooldown != nil {
		cooldown = time.Duration(*spec.Cooldown)
	}
	if cooldown < 0 {
		return RuleBase{}, errors.New("cooldown must not be negative")
	}

	b := RuleBase{
		name:        spec.Name,
		description: spec.Description,
		severity:    spec.Severity,
		alertType:   spec.AlertType,
		reason:      spec.Reason,
		cooldown:    cooldown,
	}
	if b.description == "" {
		b.description = spec.Name
	}
	if b.reason == "" {
		b.reason = defaultReason
	}
	for _, m := range eventPlaceholder.FindAllStringSubmatch(b.reason, -1) {
		if err := validateField(m[1]); err != nil {
			return RuleBase{}, fmt.Errorf("reason placeholder %s: %w", m[0], err)
		}
	}
	return b, nil
}

// eventPlaceholder matches "{event.<field>}" in reason templates.
var eventPlaceholder = regexp.MustCompile(`\{event\.([^{}]+)\}`)

func (b RuleBase) Name() string            { return b.name }
func (b RuleBase) Cooldown() time.Duration { return b.cooldown }

// Alert builds an alert for event. The reason template may use {rule},
// {description}, {ip}, {count}, every key of vars in braces and
// {event.<field>} for any event field (e.g. {event.port}, {event.metadata.process}).
func (b RuleBase) Alert(event domain.Event, count int, vars map[string]string) *domain.Alert {
	pairs := []string{
		"{rule}", b.name,
		"{description}", b.description,
		"{ip}", event.IP,
		"{count}", strconv.Itoa(count),
	}
	for k, v := range vars {
		pairs = append(pairs, "{"+k+"}", v)
	}

	alertType := b.alertType
	if alertType == "" {
		alertType = event.EventType
	}
	return &domain.Alert{
		Timestamp:   event.Timestamp,
		IP:          event.IP,
		EventType:   alertType,
		Severity:    b.severity,
		Reason:      b.renderReason(event, pairs),
		EventCount:  count,
		TriggerRule: b.name,
	}
}

// renderReason fills the template. Event values are substituted last so that
// attacker-controlled content is never interpreted as a placeholder.
func (b RuleBase) renderReason(event domain.Event, pairs []string) string {
	reason := strings.NewReplacer(pairs...).Replace(b.reason)
	return eventPlaceholder.ReplaceAllStringFunc(reason, func(m string) string {
		return fieldValue(event, m[len("{event."):len(m)-1])
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Event field access
// ─────────────────────────────────────────────────────────────────────────────

var eventFields = []string{
	"ip", "event_type", "path", "message", "user_agent", "port", "status_code",
	"dst_ip", "src_port", "protocol", "direction", "domain",
}

// fieldValue returns the named event field as a string ("" when unset).
// "metadata.<key>" reads from Event.Metadata.
func fieldValue(e domain.Event, field string) string {
	switch field {
	case "ip":
		return e.IP
	case "event_type":
		return string(e.EventType)
	case "path":
		return e.Path
	case "message":
		return e.Message
	case "user_agent":
		return e.UserAgent
	case "port":
		return itoaNonZero(e.Port)
	case "status_code":
		return itoaNonZero(e.StatusCode)
	case "dst_ip":
		return e.DstIP
	case "src_port":
		return itoaNonZero(e.SrcPort)
	case "protocol":
		return e.Protocol
	case "direction":
		return e.Direction
	case "domain":
		return e.Domain
	}
	if key, ok := strings.CutPrefix(field, "metadata."); ok {
		return e.Metadata[key]
	}
	return ""
}

func itoaNonZero(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func validateField(field string) error {
	if slices.Contains(eventFields, field) {
		return nil
	}
	if key, ok := strings.CutPrefix(field, "metadata."); ok && key != "" {
		return nil
	}
	return fmt.Errorf("unknown field %q (use %s or metadata.<key>)", field, strings.Join(eventFields, ", "))
}
