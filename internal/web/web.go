// Package web serves a read-only browser UI for alerts and events: server
// rendered HTML templates, made interactive with htmx (filters without page
// reloads, live notice of new alerts). It needs no JavaScript build step and
// no external resources; templates, htmx and CSS are embedded in the binary.
package web

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Store is what the UI reads; MemoryStore and SQLiteStore implement it.
type Store interface {
	ListEvents(ctx context.Context, q repository.ListQuery) (repository.ListResult[domain.Event], error)
	ListAlerts(ctx context.Context, q repository.ListQuery) (repository.ListResult[domain.Alert], error)
	SummarizeAlerts(ctx context.Context, since time.Time) (repository.AlertSummary, error)
	Stats() repository.Stats
}

// Config configures the UI.
type Config struct {
	User, Password string // HTTP Basic Auth credentials; the password is required
	Store          Store
	Rules          []service.RuleSpec // shown on the rules page
	Logger         *slog.Logger
	Location       *time.Location   // time zone for displayed times; default time.Local
	Now            func() time.Time // default time.Now
}

// Prefix is the path the UI is served under.
const Prefix = "/ui/"

const (
	summaryWindow    = 24 * time.Hour
	defaultLimit     = 100
	ipPageAlerts     = 100
	ipPageEvents     = 200
	overviewAlerts   = 10
	alertPollSeconds = 5
	overviewRefresh  = 15
)

var limits = []int{50, 100, 250, 500, 1000}

type ui struct {
	cfg   Config
	pages map[string]*template.Template
	// static maps a file name to its URL with a content hash, so browsers
	// may cache the files and still load new versions after an update.
	static map[string]string
}

// New returns the UI handler for the paths below Prefix, protected by Basic Auth.
func New(cfg Config) (http.Handler, error) {
	if cfg.Password == "" {
		return nil, errors.New("web UI: a password is required")
	}
	if cfg.Store == nil || cfg.Logger == nil {
		return nil, errors.New("web UI: store and logger are required")
	}
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	u := &ui{cfg: cfg, pages: map[string]*template.Template{}, static: map[string]string{}}
	for _, name := range []string{"app.css", "htmx.min.js", "table.js", "logo.svg"} {
		data, err := fs.ReadFile(static, name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		u.static[name] = Prefix + "static/" + name + "?v=" + hex.EncodeToString(sum[:6])
	}
	if err := u.parseTemplates(); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ui/{$}", u.overview)
	mux.HandleFunc("GET /ui/alerts", u.alerts)
	mux.HandleFunc("GET /ui/alerts/poll", u.pollAlerts)
	mux.HandleFunc("GET /ui/events", u.events)
	mux.HandleFunc("GET /ui/ips/{ip}", u.ip)
	mux.HandleFunc("GET /ui/rules", u.rules)
	mux.Handle("GET /ui/static/", cacheFor(30*24*time.Hour, http.StripPrefix("/ui/static/", http.FileServerFS(static))))

	return securityHeaders(basicAuth(cfg.User, cfg.Password, cfg.Logger, mux)), nil
}

func cacheFor(d time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", fmt.Sprintf("private, max-age=%d", int(d.Seconds())))
		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Templates
// ─────────────────────────────────────────────────────────────────────────────

func (u *ui) parseTemplates() error {
	funcs := template.FuncMap{
		"static":      func(name string) string { return u.static[name] },
		"time":        u.formatTime,
		"ago":         u.ago,
		"ipURL":       func(ip string) string { return Prefix + "ips/" + url.PathEscape(ip) },
		"alertsURL":   func(params ...string) string { return withQuery(Prefix+"alerts", params...) },
		"eventsURL":   func(params ...string) string { return withQuery(Prefix+"events", params...) },
		"severities":  func() []domain.Severity { return severities },
		"limits":      func() []int { return limits },
		"join":        strings.Join,
		"eventDetail": eventDetail,
		"destination": destination,
		"metadata":    metadata,
		"duration":    func(d service.Duration) string { return shortDuration(time.Duration(d)) },
		"condition":   condition,
	}
	base, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html")
	if err != nil {
		return err
	}
	for _, page := range []string{"overview", "alerts", "events", "ip", "rules"} {
		t, err := base.Clone()
		if err != nil {
			return err
		}
		if u.pages[page], err = t.ParseFS(templateFS, "templates/"+page+".html"); err != nil {
			return err
		}
	}
	return nil
}

var severities = []domain.Severity{domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical}

// render writes the page, or only its "results" block when htmx asks for it
// (filter changes, refreshes). A history restore needs the full page.
func (u *ui) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	name := "layout"
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Target") == "results" &&
		r.Header.Get("HX-History-Restore-Request") != "true" {
		name = "results"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "HX-Request, HX-Target")
	if err := u.pages[page].ExecuteTemplate(w, name, data); err != nil {
		u.cfg.Logger.ErrorContext(r.Context(), "rendering web UI page failed",
			slog.String("page", page), slog.String("error", err.Error()))
	}
}

func (u *ui) fail(w http.ResponseWriter, r *http.Request, err error) {
	u.cfg.Logger.ErrorContext(r.Context(), "web UI query failed", slog.String("path", r.URL.Path), slog.String("error", err.Error()))
	http.Error(w, "could not load data", http.StatusInternalServerError)
}

func (u *ui) formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(u.cfg.Location).Format("2006-01-02 15:04:05 MST")
}

// ago formats the time since t coarsely: "45s", "12m", "3h", "2d".
func (u *ui) ago(t time.Time) string {
	d := u.cfg.Now().Sub(t)
	switch {
	case d < 0:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// withQuery appends key/value pairs with a non-empty value as query string.
func withQuery(path string, kv ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			q.Set(kv[i], kv[i+1])
		}
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

// eventDetail is the most telling field of an event for a one-line list.
func eventDetail(e domain.Event) string {
	switch {
	case e.Path != "":
		if m := e.Metadata["method"]; m != "" {
			return m + " " + e.Path
		}
		return e.Path
	case e.Domain != "":
		return e.Domain
	default:
		return e.Message
	}
}

func destination(e domain.Event) string {
	switch {
	case e.DstIP != "" && e.Port != 0:
		if strings.Contains(e.DstIP, ":") {
			return "[" + e.DstIP + "]:" + strconv.Itoa(e.Port)
		}
		return e.DstIP + ":" + strconv.Itoa(e.Port)
	case e.DstIP != "":
		return e.DstIP
	case e.Port != 0:
		return ":" + strconv.Itoa(e.Port)
	}
	return ""
}

// shortDuration drops zero units: "1m" instead of "1m0s", "2h" instead of "2h0m0s".
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// condition describes in one line when a rule fires.
func condition(spec service.RuleSpec) string {
	var parts []string
	switch spec.Kind {
	case "signature":
		n := len(spec.Contains) + len(spec.Regex) + len(spec.Paths)
		fields := spec.Fields
		if len(fields) == 0 {
			fields = []string{"path", "message"}
		}
		parts = append(parts, fmt.Sprintf("%s in %s", plural(n, "pattern"), strings.Join(fields, ", ")))
	case "threshold":
		what := plural(spec.Threshold, "event")
		if spec.Distinct != "" {
			what = fmt.Sprintf("%d distinct %s", spec.Threshold, spec.Distinct)
		}
		parts = append(parts, fmt.Sprintf("≥ %s in %s", what, shortDuration(time.Duration(spec.Window))))
	case "beacon":
		parts = append(parts, fmt.Sprintf("≥ %d regular contacts in %s", spec.Threshold, shortDuration(time.Duration(spec.Window))))
	case "correlation":
		parts = append(parts, fmt.Sprintf("≥ %d different rules in %s", spec.Threshold, shortDuration(time.Duration(spec.Window))))
	}
	if spec.GroupBy != "" {
		parts = append(parts, "per "+spec.GroupBy)
	}
	if types := spec.When.EventTypes; len(types) > 0 {
		names := make([]string, len(types))
		for i, t := range types {
			names[i] = string(t)
		}
		parts = append(parts, "on "+strings.Join(names, ", "))
	}
	if codes := spec.When.StatusCodes; len(codes) > 0 {
		names := make([]string, len(codes))
		for i, c := range codes {
			names[i] = strconv.Itoa(c)
		}
		parts = append(parts, "status "+strings.Join(names, "/"))
	}
	return strings.Join(parts, ", ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func metadata(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, " ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Pages
// ─────────────────────────────────────────────────────────────────────────────

type page struct {
	Title, Nav string
}

type overviewPage struct {
	page
	Stats          repository.Stats
	Summary        repository.AlertSummary
	Critical       int
	SummaryHours   int
	Latest         []domain.Alert
	RefreshSeconds int
}

func (u *ui) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sum, err := u.cfg.Store.SummarizeAlerts(ctx, u.cfg.Now().Add(-summaryWindow))
	if err != nil {
		u.fail(w, r, err)
		return
	}
	latest, err := u.cfg.Store.ListAlerts(ctx, repository.ListQuery{Limit: overviewAlerts})
	if err != nil {
		u.fail(w, r, err)
		return
	}
	u.render(w, r, "overview", overviewPage{
		page:           page{Title: "Overview", Nav: "overview"},
		Stats:          u.cfg.Store.Stats(),
		Summary:        sum,
		Critical:       sum.BySeverity[domain.SeverityCritical],
		SummaryHours:   int(summaryWindow.Hours()),
		Latest:         latest.Items,
		RefreshSeconds: overviewRefresh,
	})
}

// listForm holds the filter form values as entered, to show them again.
type listForm struct {
	IP, Type, Severity, Rule string
	Limit                    int
}

// parseForm reads the filters. Invalid values are reported in errs and left
// out of the query, so the page still renders.
func parseForm(r *http.Request) (f listForm, q repository.ListQuery, errs []string) {
	v := r.URL.Query()
	f = listForm{IP: strings.TrimSpace(v.Get("ip")), Type: strings.TrimSpace(v.Get("type")),
		Severity: v.Get("severity"), Rule: v.Get("rule"), Limit: defaultLimit}
	q = repository.ListQuery{Limit: defaultLimit, EventType: domain.EventType(f.Type), Rule: f.Rule}

	if f.IP != "" {
		ip, err := domain.NormalizeIP(f.IP)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%q is not a valid IP address", f.IP))
		} else {
			q.IP = ip
		}
	}
	if f.Severity != "" {
		if sev := domain.Severity(f.Severity); sev.Valid() {
			q.MinSeverity = sev
		} else {
			errs = append(errs, fmt.Sprintf("unknown severity %q", f.Severity))
			f.Severity = ""
		}
	}
	if s := v.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && slices.Contains(limits, n) {
			f.Limit, q.Limit = n, n
		}
	}
	return f, q, errs
}

type alertsPage struct {
	page
	Form        listForm
	Errors      []string
	Rules       []string
	Result      repository.ListResult[domain.Alert]
	PollURL     string
	PollSeconds int
}

func (u *ui) alerts(w http.ResponseWriter, r *http.Request) {
	form, q, errs := parseForm(r)
	res, err := u.cfg.Store.ListAlerts(r.Context(), q)
	if err != nil {
		u.fail(w, r, err)
		return
	}
	newest := ""
	if len(res.Items) > 0 {
		newest = res.Items[0].ID
	}
	u.render(w, r, "alerts", alertsPage{
		page:        page{Title: "Alerts", Nav: "alerts"},
		Form:        form,
		Errors:      errs,
		Rules:       u.ruleNames(),
		Result:      res,
		PollURL:     withQuery(Prefix+"alerts/poll", "ip", q.IP, "severity", string(q.MinSeverity), "rule", q.Rule, "newest", newest),
		PollSeconds: alertPollSeconds,
	})
}

// pollAlerts answers the alert list's periodic check: 204 (htmx keeps the
// element and polls again) while the newest matching alert is still the one
// shown, otherwise a notice with a link that reloads the list.
func (u *ui) pollAlerts(w http.ResponseWriter, r *http.Request) {
	form, q, _ := parseForm(r)
	q.Limit = 1
	res, err := u.cfg.Store.ListAlerts(r.Context(), q)
	if err != nil {
		u.fail(w, r, err)
		return
	}
	if len(res.Items) == 0 || res.Items[0].ID == r.URL.Query().Get("newest") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := u.pages["alerts"].ExecuteTemplate(w, "new-alerts", form); err != nil {
		u.cfg.Logger.ErrorContext(r.Context(), "rendering web UI page failed", slog.String("error", err.Error()))
	}
}

type eventsPage struct {
	page
	Form   listForm
	Errors []string
	Types  []domain.EventType
	Result repository.ListResult[domain.Event]
}

func (u *ui) events(w http.ResponseWriter, r *http.Request) {
	form, q, errs := parseForm(r)
	q.MinSeverity, q.Rule = "", ""
	res, err := u.cfg.Store.ListEvents(r.Context(), q)
	if err != nil {
		u.fail(w, r, err)
		return
	}
	u.render(w, r, "events", eventsPage{
		page:   page{Title: "Events", Nav: "events"},
		Form:   form,
		Errors: errs,
		Types: []domain.EventType{domain.EventHTTPRequest, domain.EventFailedLogin, domain.EventNetworkConnection,
			domain.EventFirewallBlock, domain.EventPortOpened, domain.EventDNSQuery, domain.EventPortScan, domain.EventUnknown},
		Result: res,
	})
}

type ipPage struct {
	page
	IP     string
	Alerts repository.ListResult[domain.Alert]
	Events repository.ListResult[domain.Event]
}

func (u *ui) ip(w http.ResponseWriter, r *http.Request) {
	ip, err := domain.NormalizeIP(r.PathValue("ip"))
	if err != nil {
		http.Error(w, "not a valid IP address", http.StatusBadRequest)
		return
	}
	alerts, err := u.cfg.Store.ListAlerts(r.Context(), repository.ListQuery{IP: ip, Limit: ipPageAlerts})
	if err != nil {
		u.fail(w, r, err)
		return
	}
	events, err := u.cfg.Store.ListEvents(r.Context(), repository.ListQuery{IP: ip, Limit: ipPageEvents})
	if err != nil {
		u.fail(w, r, err)
		return
	}
	u.render(w, r, "ip", ipPage{page: page{Title: ip, Nav: ""}, IP: ip, Alerts: alerts, Events: events})
}

type rulesPage struct {
	page
	Rules []service.RuleSpec
}

func (u *ui) rules(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, "rules", rulesPage{page: page{Title: "Rules", Nav: "rules"}, Rules: u.cfg.Rules})
}

func (u *ui) ruleNames() []string {
	names := make([]string, 0, len(u.cfg.Rules))
	for _, spec := range u.cfg.Rules {
		names = append(names, spec.Name)
	}
	return names
}
