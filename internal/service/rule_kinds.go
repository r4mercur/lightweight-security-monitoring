package service

import (
	"context"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/repository"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Kind: signature
// Fires when one of the configured fields matches a pattern. Values are matched
// case-insensitively, both raw and URL-decoded (up to two times, to catch
// double encoding).
//
//	contains – plain substring
//	regex    – regular expression
//	paths    – path segment: "/admin" matches "/admin", "/api/admin/x",
//	           "/admin.php" but not "/administration"
// ─────────────────────────────────────────────────────────────────────────────

type signatureRule struct {
	RuleBase
	when     EventFilter
	fields   []string
	contains []string
	paths    []string
	regexes  []*regexp.Regexp
	regexSrc []string
}

func newSignatureRule(spec RuleSpec) (Rule, error) {
	base, err := NewRuleBase(spec, `{description} from {ip}: pattern "{pattern}" matched in {field}`)
	if err != nil {
		return nil, err
	}
	if err := spec.When.validate(); err != nil {
		return nil, err
	}
	if len(spec.Contains)+len(spec.Regex)+len(spec.Paths) == 0 {
		return nil, errors.New("signature rule needs at least one of contains, regex or paths")
	}

	r := &signatureRule{RuleBase: base, when: spec.When, fields: spec.Fields}
	if len(r.fields) == 0 {
		r.fields = []string{"path", "message"}
	}
	for _, f := range r.fields {
		if err := validateField(f); err != nil {
			return nil, err
		}
	}
	for _, p := range spec.Contains {
		if p == "" {
			return nil, errors.New("contains has an empty pattern")
		}
		r.contains = append(r.contains, strings.ToLower(p))
	}
	for _, p := range spec.Paths {
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("path pattern %q must start with /", p)
		}
		r.paths = append(r.paths, strings.ToLower(p))
	}
	for _, p := range spec.Regex {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", p, err)
		}
		r.regexes = append(r.regexes, re)
		r.regexSrc = append(r.regexSrc, p)
	}
	return r, nil
}

func (r *signatureRule) Evaluate(_ context.Context, event domain.Event, _ repository.EventRepository) (*domain.Alert, bool) {
	if !r.when.Matches(event) {
		return nil, false
	}
	for _, field := range r.fields {
		value := fieldValue(event, field)
		if value == "" {
			continue
		}
		for _, candidate := range decodedVariants(value) {
			if pattern, ok := r.match(candidate); ok {
				return r.Alert(event, 1, map[string]string{"pattern": pattern, "field": field}), true
			}
		}
	}
	return nil, false
}

func (r *signatureRule) match(s string) (string, bool) {
	for _, p := range r.contains {
		if strings.Contains(s, p) {
			return p, true
		}
	}
	for _, p := range r.paths {
		if containsPathSegment(s, p) {
			return p, true
		}
	}
	for i, re := range r.regexes {
		if re.MatchString(s) {
			return r.regexSrc[i], true
		}
	}
	return "", false
}

// containsPathSegment reports whether p occurs in s and is followed by a
// segment boundary (end, '/', '?', '#', '.', ';').
func containsPathSegment(s, p string) bool {
	for offset := 0; ; {
		i := strings.Index(s[offset:], p)
		if i < 0 {
			return false
		}
		end := offset + i + len(p)
		if end == len(s) || strings.IndexByte("/?#.;", s[end]) >= 0 {
			return true
		}
		offset += i + 1
	}
}

// decodedVariants returns the lower-cased value plus its URL-decoded forms
// (at most two decoding rounds), without duplicates.
func decodedVariants(value string) []string {
	variants := []string{strings.ToLower(value)}
	current := value
	for range 2 {
		decoded := percentDecode(current)
		if decoded == current {
			break
		}
		current = decoded
		variants = append(variants, strings.ToLower(decoded))
	}
	return variants
}

// percentDecode decodes valid %XX sequences and '+' and leaves everything else
// untouched. Unlike url.QueryUnescape it never fails, so a single malformed
// escape cannot hide the rest of a payload.
func percentDecode(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			n, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(n))
			i += 2
		case c == '+':
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// ─────────────────────────────────────────────────────────────────────────────
// Kind: threshold
// Fires when an IP produces >= threshold events matching "when" within the
// window. With "distinct" set, the number of distinct values of that field is
// counted instead (e.g. distinct ports for port-scan detection). With
// "group_by" set, a separate window is kept per IP and value of that field
// (e.g. distinct subdomains per base domain for DNS tunneling).
//
// Each rule keeps a sliding window per IP instead of querying the event store,
// so the cost per event is independent of how many events are stored. Events
// that arrive more than one window out of order may be undercounted.
// ─────────────────────────────────────────────────────────────────────────────

type thresholdRule struct {
	RuleBase
	when      EventFilter
	threshold int
	window    time.Duration
	distinct  string
	groupBy   string

	mu      sync.Mutex
	windows map[string]*slidingWindow // by IP (+ group value)
}

func newThresholdRule(spec RuleSpec) (Rule, error) {
	reason := "{description}: {count} events from {ip} within {window}"
	if spec.Distinct != "" {
		reason = "{description}: {count} distinct {distinct} values from {ip} within {window}"
	}
	base, err := NewRuleBase(spec, reason)
	if err != nil {
		return nil, err
	}
	if err := spec.When.validate(); err != nil {
		return nil, err
	}
	if spec.Threshold <= 0 {
		return nil, errors.New("threshold must be > 0")
	}
	if spec.Window <= 0 {
		return nil, errors.New("window must be > 0")
	}
	if spec.Distinct != "" {
		if err := validateField(spec.Distinct); err != nil {
			return nil, fmt.Errorf("distinct: %w", err)
		}
	}
	if spec.GroupBy != "" {
		if err := validateField(spec.GroupBy); err != nil {
			return nil, fmt.Errorf("group_by: %w", err)
		}
	}
	return &thresholdRule{
		RuleBase:  base,
		when:      spec.When,
		threshold: spec.Threshold,
		window:    time.Duration(spec.Window),
		distinct:  spec.Distinct,
		groupBy:   spec.GroupBy,
		windows:   make(map[string]*slidingWindow),
	}, nil
}

func (r *thresholdRule) Evaluate(_ context.Context, event domain.Event, _ repository.EventRepository) (*domain.Alert, bool) {
	if !r.when.Matches(event) {
		return nil, false
	}
	var value string
	if r.distinct != "" {
		if value = fieldValue(event, r.distinct); value == "" {
			return nil, false
		}
	}

	key, group, ok := windowKey(event, r.groupBy)
	if !ok {
		return nil, false
	}

	r.mu.Lock()
	w := r.windows[key]
	if w == nil {
		w = newSlidingWindow(r.distinct != "")
		r.windows[key] = w
	}
	w.add(event.Timestamp, value)
	w.expire(event.Timestamp.Add(-r.window))
	count := w.count()
	r.mu.Unlock()

	if count < r.threshold {
		return nil, false
	}
	return r.Alert(event, count, map[string]string{
		"window":    r.window.String(),
		"threshold": strconv.Itoa(r.threshold),
		"distinct":  r.distinct,
		"group":     group,
	}), true
}

// keySeparator joins IP and group value; it cannot occur in either.
const keySeparator = "\x00"

// windowKey returns the state key of an event: its IP, plus the value of the
// group_by field if set. ok is false when the group field is empty.
func windowKey(event domain.Event, groupBy string) (key, group string, ok bool) {
	if groupBy == "" {
		return event.IP, "", true
	}
	group = fieldValue(event, groupBy)
	if group == "" {
		return "", "", false
	}
	return event.IP + keySeparator + group, group, true
}

// Prune drops the windows of IPs that have been quiet for longer than the window.
func (r *thresholdRule) Prune(now time.Time) {
	cutoff := now.Add(-r.window)
	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, w := range r.windows {
		if w.expire(cutoff); w.count() == 0 {
			delete(r.windows, ip)
		}
	}
}

// slidingWindow holds the observations of one IP, sorted by time.
type slidingWindow struct {
	obs  []observation // obs[head:] are live
	head int
	// last is the newest timestamp per value; only used when counting distinct values.
	last map[string]time.Time
}

type observation struct {
	ts    time.Time
	value string
}

func newSlidingWindow(distinct bool) *slidingWindow {
	w := &slidingWindow{}
	if distinct {
		w.last = make(map[string]time.Time)
	}
	return w
}

func (w *slidingWindow) add(ts time.Time, value string) {
	live := w.obs[w.head:]
	// Insert after all observations with ts <= new ts; for in-order data this is an append.
	i := w.head + sort.Search(len(live), func(i int) bool { return live[i].ts.After(ts) })
	w.obs = slices.Insert(w.obs, i, observation{ts: ts, value: value})
	if w.last != nil && ts.After(w.last[value]) {
		w.last[value] = ts
	}
}

// expire removes observations at or before cutoff.
func (w *slidingWindow) expire(cutoff time.Time) {
	for w.head < len(w.obs) && !w.obs[w.head].ts.After(cutoff) {
		if w.last != nil {
			v := w.obs[w.head].value
			if !w.last[v].After(cutoff) {
				delete(w.last, v)
			}
		}
		w.obs[w.head] = observation{}
		w.head++
	}
	// Reuse the slice once more than half of it is expired.
	if w.head > 32 && w.head > len(w.obs)/2 {
		n := copy(w.obs, w.obs[w.head:])
		clear(w.obs[n:])
		w.obs, w.head = w.obs[:n], 0
	}
}

func (w *slidingWindow) count() int {
	if w.last != nil {
		return len(w.last)
	}
	return len(w.obs) - w.head
}

// ─────────────────────────────────────────────────────────────────────────────
// Kind: correlation
// Fires when an IP has triggered >= threshold different rules within the
// window, counting the rules fired by the current event and the IP's stored
// alerts (including their related rules).
// ─────────────────────────────────────────────────────────────────────────────

type correlationRule struct {
	RuleBase
	threshold int
	window    time.Duration
}

func newCorrelationRule(spec RuleSpec) (*correlationRule, error) {
	base, err := NewRuleBase(spec, "{description}: {count} different rules triggered by {ip} within {window} ({rules})")
	if err != nil {
		return nil, err
	}
	if spec.Threshold < 2 {
		return nil, errors.New("threshold must be >= 2 for a correlation rule")
	}
	if spec.Window <= 0 {
		return nil, errors.New("window must be > 0")
	}
	return &correlationRule{RuleBase: base, threshold: spec.Threshold, window: time.Duration(spec.Window)}, nil
}

func (r *correlationRule) Window() time.Duration { return r.window }

func (r *correlationRule) Correlate(event domain.Event, fired []*domain.Alert, history []domain.Alert) (*domain.Alert, bool) {
	if len(fired) == 0 {
		return nil, false
	}

	rules := make(map[string]struct{})
	add := func(name string) {
		if name != "" && name != r.Name() {
			rules[name] = struct{}{}
		}
	}
	for _, a := range fired {
		add(a.TriggerRule)
	}
	since := event.Timestamp.Add(-r.window)
	for _, h := range history {
		if !h.Timestamp.After(since) {
			continue
		}
		add(h.TriggerRule)
		for _, related := range h.RelatedRules {
			add(related)
		}
	}

	if len(rules) < r.threshold {
		return nil, false
	}
	names := make([]string, 0, len(rules))
	for name := range rules {
		names = append(names, name)
	}
	slices.Sort(names)
	return r.Alert(event, len(names), map[string]string{
		"window": r.window.String(),
		"rules":  strings.Join(names, ", "),
	}), true
}

// ─────────────────────────────────────────────────────────────────────────────
// Kind: beacon
// Fires when an IP contacts the same target (group_by, default dst_ip) at
// regular intervals: the last "threshold" contacts within "window" are at
// least "min_interval" apart on average and their intervals deviate by at most
// "max_jitter" (standard deviation / mean). Malware command-and-control
// channels typically behave like this; people and most applications do not.
// Contacts closer together than min_interval/2 count as one (e.g. parallel
// connections opened at once).
// ─────────────────────────────────────────────────────────────────────────────

type beaconRule struct {
	RuleBase
	when        EventFilter
	groupBy     string
	contacts    int
	window      time.Duration
	minInterval time.Duration
	maxJitter   float64

	mu     sync.Mutex
	series map[string][]time.Time // by IP + target, sorted, at most contacts entries
}

func newBeaconRule(spec RuleSpec) (Rule, error) {
	base, err := NewRuleBase(spec, "{description}: {count} contacts from {ip} to {group} every ~{interval} (jitter {jitter})")
	if err != nil {
		return nil, err
	}
	if err := spec.When.validate(); err != nil {
		return nil, err
	}
	r := &beaconRule{
		RuleBase:    base,
		when:        spec.When,
		groupBy:     spec.GroupBy,
		contacts:    spec.Threshold,
		window:      time.Duration(spec.Window),
		minInterval: time.Duration(spec.MinInterval),
		maxJitter:   spec.MaxJitter,
		series:      make(map[string][]time.Time),
	}
	if r.groupBy == "" {
		r.groupBy = "dst_ip"
	}
	if err := validateField(r.groupBy); err != nil {
		return nil, fmt.Errorf("group_by: %w", err)
	}
	switch {
	case r.contacts < 3:
		return nil, errors.New("threshold (number of contacts) must be >= 3 for a beacon rule")
	case r.minInterval <= 0:
		return nil, errors.New("min_interval must be > 0")
	case r.maxJitter <= 0 || r.maxJitter > 1:
		return nil, errors.New("max_jitter must be > 0 and <= 1 (e.g. 0.15 for 15 %)")
	case r.window < r.minInterval*time.Duration(r.contacts-1):
		return nil, fmt.Errorf("window must be at least min_interval × (threshold-1) = %s", r.minInterval*time.Duration(r.contacts-1))
	}
	return r, nil
}

func (r *beaconRule) Evaluate(_ context.Context, event domain.Event, _ repository.EventRepository) (*domain.Alert, bool) {
	if !r.when.Matches(event) {
		return nil, false
	}
	key, target, ok := windowKey(event, r.groupBy)
	if !ok {
		return nil, false
	}

	r.mu.Lock()
	s, added := r.add(r.series[key], event.Timestamp)
	r.series[key] = s
	var mean time.Duration
	var jitter float64
	full := added && len(s) >= r.contacts
	if full {
		mean, jitter = intervalStats(s)
	}
	r.mu.Unlock()

	if !full || mean < r.minInterval || jitter > r.maxJitter {
		return nil, false
	}
	return r.Alert(event, len(s), map[string]string{
		"group":    target,
		"interval": mean.Round(time.Second).String(),
		"jitter":   fmt.Sprintf("%.0f%%", jitter*100),
		"window":   r.window.String(),
	}), true
}

// add inserts ts into the sorted series unless it belongs to a burst, drops
// contacts outside the window and keeps at most r.contacts entries.
func (r *beaconRule) add(s []time.Time, ts time.Time) ([]time.Time, bool) {
	i := sort.Search(len(s), func(i int) bool { return s[i].After(ts) })
	burst := r.minInterval / 2
	if (i > 0 && ts.Sub(s[i-1]) < burst) || (i < len(s) && s[i].Sub(ts) < burst) {
		return s, false
	}
	s = slices.Insert(s, i, ts)

	newest := s[len(s)-1]
	cut := sort.Search(len(s), func(i int) bool { return s[i].After(newest.Add(-r.window)) })
	if keep := len(s) - r.contacts; keep > cut {
		cut = keep
	}
	if cut > 0 {
		n := copy(s, s[cut:])
		s = s[:n]
	}
	return s, true
}

// intervalStats returns the mean interval between consecutive contacts and the
// coefficient of variation (standard deviation / mean) of the intervals.
func intervalStats(s []time.Time) (time.Duration, float64) {
	n := float64(len(s) - 1)
	var sum float64
	for i := 1; i < len(s); i++ {
		sum += s[i].Sub(s[i-1]).Seconds()
	}
	mean := sum / n
	var variance float64
	for i := 1; i < len(s); i++ {
		d := s[i].Sub(s[i-1]).Seconds() - mean
		variance += d * d
	}
	variance /= n
	if mean == 0 {
		return 0, math.Inf(1)
	}
	return time.Duration(mean * float64(time.Second)), math.Sqrt(variance) / mean
}

// Prune drops the series of targets that have not been contacted within the window.
func (r *beaconRule) Prune(now time.Time) {
	cutoff := now.Add(-r.window)
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, s := range r.series {
		if len(s) == 0 || !s[len(s)-1].After(cutoff) {
			delete(r.series, key)
		}
	}
}
