// Package collector produces security events from local sources (web server
// access logs, firewall and DNS logs, the connection table) and feeds them
// into the ingestion pipeline in-process.
package collector

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/service"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Sink receives the events a collector produces. *service.IngestionService satisfies it.
type Sink interface {
	Ingest(ctx context.Context, event domain.Event) (*domain.Alert, error)
}

// LineRecorder counts processed lines per collector and result.
type LineRecorder interface {
	RecordCollectorLine(collector, result string)
}

// Results reported to the LineRecorder.
const (
	ResultIngested    = "ingested"
	ResultSkipped     = "skipped" // not an event, e.g. comments or unrelated kernel messages
	ResultParseError  = "parse_error"
	ResultIngestError = "ingest_error"
)

// Collector is a long-running event source.
type Collector interface {
	Name() string
	// Run blocks until ctx is cancelled.
	Run(ctx context.Context) error
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

// Config is the structure of the collectors file (COLLECTORS_FILE).
type Config struct {
	// PollInterval is how often files are checked for new data. Default 1s.
	PollInterval *service.Duration   `json:"poll_interval,omitempty"`
	AccessLogs   []AccessLogConfig   `json:"access_logs,omitempty"`
	FirewallLogs []FirewallLogConfig `json:"firewall_logs,omitempty"`
	DNSLogs      []DNSLogConfig      `json:"dns_logs,omitempty"`
	Connections  *ConnectionsConfig  `json:"connections,omitempty"`
}

// fileOptions are the settings every file-based collector shares.
type fileOptions struct {
	// Name identifies the collector in logs, metrics and event metadata. Defaults to the file name.
	Name string `json:"name,omitempty"`
	Path string `json:"path"`
	// FromStart reads the existing file content on startup instead of only new lines.
	FromStart bool `json:"from_start,omitempty"`
}

const (
	defaultPollInterval = time.Second
	maxLineBytes        = 64 << 10
	ingestTimeout       = 10 * time.Second
)

// LoadConfigFile reads and validates a collectors file. Like rule files it is
// parsed strictly: unknown or mis-cased keys, duplicate keys and trailing
// content are rejected.
func LoadConfigFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("opening collectors file: %w", err)
	}
	defer f.Close()

	var cfg Config
	if err := json.UnmarshalRead(f, &cfg, json.RejectUnknownMembers(true)); err != nil {
		return Config{}, fmt.Errorf("decoding collectors file: %w", err)
	}
	return cfg, nil
}

// Build creates the collectors described by cfg.
func Build(cfg Config, sink Sink, rec LineRecorder, logger *slog.Logger) ([]Collector, error) {
	poll := defaultPollInterval
	if cfg.PollInterval != nil {
		poll = time.Duration(*cfg.PollInterval)
	}
	if poll <= 0 {
		return nil, errors.New("poll_interval must be > 0")
	}

	var (
		collectors []Collector
		errs       []error
		names      = make(map[string]bool)
	)
	add := func(section string, i int, opts fileOptions, decode decodeFunc, err error) {
		var c *fileCollector
		if err == nil {
			c, err = newFileCollector(opts, decode, poll, sink, rec, logger)
		}
		if err == nil && names[c.name] {
			err = fmt.Errorf("duplicate name %q", c.name)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s #%d: %w", section, i+1, err))
			return
		}
		names[c.name] = true
		collectors = append(collectors, c)
	}

	for i, c := range cfg.AccessLogs {
		decode, err := newAccessLogDecoder(c)
		add("access_logs", i, c.fileOptions, decode, err)
	}
	for i, c := range cfg.FirewallLogs {
		decode, err := newFirewallDecoder(c)
		add("firewall_logs", i, c.fileOptions, decode, err)
	}
	for i, c := range cfg.DNSLogs {
		decode, err := newDNSDecoder(c)
		add("dns_logs", i, c.fileOptions, decode, err)
	}

	if cfg.Connections != nil {
		src, err := newConnSource()
		var c *connCollector
		if err == nil {
			c, err = newConnCollector(*cfg.Connections, src, sink, rec, logger)
		}
		if err == nil && names[c.name] {
			err = fmt.Errorf("duplicate name %q", c.name)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("connections: %w", err))
		} else {
			collectors = append(collectors, c)
		}
	}
	return collectors, errors.Join(errs...)
}

// ─────────────────────────────────────────────────────────────────────────────
// File collector – follows a log file and decodes each line into an event
// ─────────────────────────────────────────────────────────────────────────────

// decodeFunc turns one log line into an event. source is the collector name.
// It returns errSkip for lines that are valid but carry no event.
type decodeFunc func(line, source string) (domain.Event, error)

var errSkip = errors.New("line carries no event")

type fileCollector struct {
	name        string
	decode      decodeFunc
	tailer      *tailer
	sink        Sink
	rec         LineRecorder
	logger      *slog.Logger
	parseErrors int
}

func newFileCollector(opts fileOptions, decode decodeFunc, poll time.Duration, sink Sink, rec LineRecorder, logger *slog.Logger) (*fileCollector, error) {
	if opts.Path == "" {
		return nil, errors.New("path is required")
	}
	name := opts.Name
	if name == "" {
		name = filepath.Base(opts.Path)
	}
	logger = logger.With(slog.String("collector", name))
	return &fileCollector{
		name:   name,
		decode: decode,
		tailer: &tailer{
			path:      opts.Path,
			fromStart: opts.FromStart,
			poll:      poll,
			maxLine:   maxLineBytes,
			logger:    logger,
		},
		sink:   sink,
		rec:    rec,
		logger: logger,
	}, nil
}

func (c *fileCollector) Name() string { return c.name }

func (c *fileCollector) Run(ctx context.Context) error {
	c.logger.Info("log collector started", slog.String("path", c.tailer.path))
	return c.tailer.run(ctx, func(line string) { c.handleLine(ctx, line) })
}

func (c *fileCollector) handleLine(ctx context.Context, line string) {
	event, err := c.decode(line, c.name)
	if errors.Is(err, errSkip) {
		c.record(ResultSkipped)
		return
	}
	if err == nil {
		err = event.Normalize()
	}
	if err != nil {
		c.parseErrors++
		// A wrong format setting fails every line; log the first error and then only occasionally.
		if c.parseErrors == 1 || c.parseErrors%1000 == 0 {
			c.logger.Warn("unparseable log line", slog.String("error", err.Error()), slog.Int("total_parse_errors", c.parseErrors))
		}
		c.record(ResultParseError)
		return
	}

	ingestCtx, cancel := context.WithTimeout(ctx, ingestTimeout)
	defer cancel()
	if _, err := c.sink.Ingest(ingestCtx, event); err != nil {
		c.logger.Error("ingesting log event failed", slog.String("error", err.Error()))
		c.record(ResultIngestError)
		return
	}
	c.record(ResultIngested)
}

func (c *fileCollector) record(result string) {
	if c.rec != nil {
		c.rec.RecordCollectorLine(c.name, result)
	}
}
