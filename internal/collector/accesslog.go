package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// accessRecord is the format-independent content of one access log line.
type accessRecord struct {
	IP        string
	Time      time.Time
	Method    string
	Path      string
	Request   string // full request line, if the format has one
	Status    int
	UserAgent string
	Referer   string
	Host      string
}

// AccessLogConfig describes one web server access log to follow.
type AccessLogConfig struct {
	fileOptions
	// Format is one of "combined", "json" (Nginx JSON), "caddy" or "traefik".
	Format string `json:"format"`
	// Fields overrides the JSON field mapping of the chosen format.
	Fields      map[string]string  `json:"fields,omitempty"`
	FailedLogin *FailedLoginConfig `json:"failed_login,omitempty"`
}

func newAccessLogDecoder(cfg AccessLogConfig) (decodeFunc, error) {
	var parser lineParser
	switch {
	case cfg.Format == "combined":
		if len(cfg.Fields) > 0 {
			return nil, errors.New(`fields can only be used with JSON formats`)
		}
		parser = combinedParser{}
	case jsonPresets[cfg.Format] != nil:
		p, err := newJSONParser(cfg.Format, cfg.Fields)
		if err != nil {
			return nil, err
		}
		parser = p
	default:
		return nil, fmt.Errorf("unknown format %q (use combined, json, caddy or traefik)", cfg.Format)
	}

	if cfg.FailedLogin != nil {
		if err := cfg.FailedLogin.validate(); err != nil {
			return nil, err
		}
	}

	return func(line, source string) (domain.Event, error) {
		rec, err := parser.parse(line)
		if err != nil {
			return domain.Event{}, err
		}
		return toEvent(rec, source, cfg.FailedLogin)
	}, nil
}

// lineParser turns one log line into an accessRecord.
type lineParser interface {
	parse(line string) (accessRecord, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// Format: combined (Nginx / Apache default)
//   $remote_addr - $remote_user [$time_local] "$request" $status $bytes "$referer" "$user_agent"
// ─────────────────────────────────────────────────────────────────────────────

var combinedRe = regexp.MustCompile(
	`^(\S+) \S+ \S+ \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) \S+(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?`,
)

type combinedParser struct{}

func (combinedParser) parse(line string) (accessRecord, error) {
	m := combinedRe.FindStringSubmatch(line)
	if m == nil {
		return accessRecord{}, errors.New("line does not match combined log format")
	}
	status, _ := strconv.Atoi(m[4])
	rec := accessRecord{
		IP:        m[1],
		Request:   unescapeLogString(m[3]),
		Status:    status,
		Referer:   unescapeLogString(m[5]),
		UserAgent: unescapeLogString(m[6]),
	}
	rec.Time, _ = time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	// "GET /path HTTP/1.1"; malformed requests (TLS probes, "-") keep only Request.
	if parts := strings.SplitN(rec.Request, " ", 3); len(parts) >= 2 {
		rec.Method, rec.Path = parts[0], parts[1]
	}
	return rec, nil
}

// unescapeLogString reverses the escaping Nginx (\xHH) and Apache (\" and \\)
// apply to quoted log fields.
func unescapeLogString(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch next := s[i+1]; {
		case next == 'x' && i+3 < len(s):
			if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
			b.WriteByte(s[i])
		case next == '"' || next == '\\':
			b.WriteByte(next)
			i++
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// Format: JSON with a field mapping
// Each mapping value is a dotted path into the JSON object ("request.uri").
// Alternatives are separated by "|" and the first non-empty one wins.
// Arrays yield their first element (Caddy logs headers as arrays).
// ─────────────────────────────────────────────────────────────────────────────

// jsonFieldKeys are the record fields a JSON mapping can set.
var jsonFieldKeys = []string{"ip", "timestamp", "method", "path", "status", "user_agent", "referer", "host"}

// jsonPresets are the built-in mappings for common web servers.
var jsonPresets = map[string]map[string]string{
	// Nginx with the log_format documented in the README.
	"json": {
		"ip": "remote_addr", "timestamp": "time_iso8601", "method": "request_method", "path": "request_uri",
		"status": "status", "user_agent": "http_user_agent", "referer": "http_referer", "host": "host",
	},
	"caddy": {
		"ip": "request.client_ip|request.remote_ip", "timestamp": "ts", "method": "request.method",
		"path": "request.uri", "status": "status", "user_agent": "request.headers.User-Agent",
		"referer": "request.headers.Referer", "host": "request.host",
	},
	// Traefik only logs headers that are kept via accessLog.fields.headers.names.
	"traefik": {
		"ip": "ClientHost", "timestamp": "StartUTC", "method": "RequestMethod", "path": "RequestPath",
		"status": "DownstreamStatus", "user_agent": "request_User-Agent", "referer": "request_Referer",
		"host": "RequestHost",
	},
}

type jsonParser struct {
	fields map[string][]string // record field → alternative paths
}

func newJSONParser(preset string, overrides map[string]string) (*jsonParser, error) {
	mapping := make(map[string]string)
	maps.Copy(mapping, jsonPresets[preset])
	for k, v := range overrides {
		if !slices.Contains(jsonFieldKeys, k) {
			return nil, fmt.Errorf("unknown field %q in fields (use %s)", k, strings.Join(jsonFieldKeys, ", "))
		}
		mapping[k] = v
	}
	if mapping["ip"] == "" {
		return nil, errors.New(`fields must map "ip"`)
	}

	p := &jsonParser{fields: make(map[string][]string)}
	for k, v := range mapping {
		if v != "" {
			p.fields[k] = strings.Split(v, "|")
		}
	}
	return p, nil
}

func (p *jsonParser) parse(line string) (accessRecord, error) {
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return accessRecord{}, fmt.Errorf("invalid JSON: %w", err)
	}

	get := func(field string) string {
		for _, path := range p.fields[field] {
			if v := stringify(lookup(obj, path)); v != "" {
				return v
			}
		}
		return ""
	}

	rec := accessRecord{
		IP:        get("ip"),
		Method:    get("method"),
		Path:      get("path"),
		UserAgent: get("user_agent"),
		Referer:   get("referer"),
		Host:      get("host"),
		Time:      parseTimestamp(get("timestamp")),
	}
	rec.Status, _ = strconv.Atoi(get("status"))
	return rec, nil
}

// lookup resolves a dotted path. A key that itself contains dots is matched
// before the path is split.
func lookup(obj map[string]any, path string) any {
	if v, ok := obj[path]; ok {
		return v
	}
	head, rest, found := strings.Cut(path, ".")
	if !found {
		return nil
	}
	child, ok := obj[head].(map[string]any)
	if !ok {
		return nil
	}
	return lookup(child, rest)
}

func stringify(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	case []any:
		if len(v) > 0 {
			return stringify(v[0])
		}
	}
	return ""
}

// parseTimestamp accepts RFC 3339, the Nginx/Apache time_local format and Unix
// seconds (with fraction, as Caddy writes them). Unknown formats yield the zero
// time, which the ingestion service replaces with the current time.
func parseTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", s); err == nil {
		return t
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f > 0 {
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC()
	}
	return time.Time{}
}

// ─────────────────────────────────────────────────────────────────────────────
// Mapping records to events
// ─────────────────────────────────────────────────────────────────────────────

// FailedLoginConfig turns matching requests into failed_login events so that
// the BruteForce rule works on plain access logs.
type FailedLoginConfig struct {
	// Paths are login endpoints, compared without query string and trailing slash.
	Paths []string `json:"paths"`
	// StatusCodes that mean "login failed". Defaults to [401].
	StatusCodes []int `json:"status_codes,omitempty"`
}

func (c *FailedLoginConfig) validate() error {
	if len(c.Paths) == 0 {
		return errors.New("failed_login.paths must not be empty")
	}
	for _, p := range c.Paths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("failed_login path %q must start with /", p)
		}
	}
	if len(c.StatusCodes) == 0 {
		c.StatusCodes = []int{401}
	}
	return nil
}

func (c *FailedLoginConfig) matches(rec accessRecord) bool {
	if c == nil || !slices.Contains(c.StatusCodes, rec.Status) {
		return false
	}
	path, _, _ := strings.Cut(rec.Path, "?")
	path = strings.ToLower(strings.TrimSuffix(path, "/"))
	for _, p := range c.Paths {
		if strings.ToLower(strings.TrimSuffix(p, "/")) == path {
			return true
		}
	}
	return false
}

// toEvent converts a record into an Event. It fails when the record has no
// valid client IP, since every rule keys on it.
func toEvent(rec accessRecord, source string, failedLogin *FailedLoginConfig) (domain.Event, error) {
	ip, err := parseIP(rec.IP)
	if err != nil {
		return domain.Event{}, err
	}

	event := domain.Event{
		Timestamp:  rec.Time,
		IP:         ip,
		EventType:  domain.EventHTTPRequest,
		UserAgent:  dash(rec.UserAgent),
		Path:       rec.Path,
		StatusCode: rec.Status,
		Message:    rec.Request,
		Metadata:   map[string]string{"source": source},
	}
	if event.Message == "" && rec.Method != "" {
		event.Message = rec.Method + " " + rec.Path
	}
	for k, v := range map[string]string{"method": rec.Method, "referer": dash(rec.Referer), "host": rec.Host} {
		if v != "" {
			event.Metadata[k] = v
		}
	}
	if failedLogin.matches(rec) {
		event.EventType = domain.EventFailedLogin
	}
	return event, nil
}

// parseIP accepts "1.2.3.4", "::1" and "1.2.3.4:5678" / "[::1]:5678".
func parseIP(s string) (string, error) {
	if ip, err := domain.NormalizeIP(s); err == nil {
		return ip, nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return domain.NormalizeIP(ap.Addr().String())
	}
	return "", fmt.Errorf("invalid client IP %q", s)
}

// dash maps the "-" placeholder of access logs to an empty string.
func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
