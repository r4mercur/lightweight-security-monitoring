package collector

import (
	"context"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/service"
	"log/slog"
	"net/netip"
	"strconv"
	"time"
)

// ConnectionsConfig enables the connection-table collector, which watches the
// host's TCP sockets (Linux: /proc/net/tcp*, Windows: GetExtendedTcpTable).
type ConnectionsConfig struct {
	// Name identifies the collector in logs, metrics and event metadata. Default "connections".
	Name string `json:"name,omitempty"`
	// Interval between two snapshots of the connection table. Default 5s.
	Interval *service.Duration `json:"interval,omitempty"`
	// IncludeLoopback also reports connections between two loopback addresses.
	IncludeLoopback bool `json:"include_loopback,omitempty"`
}

const defaultConnInterval = 5 * time.Second

type sockState int

const (
	stateListen sockState = iota + 1
	stateEstablished
	stateSynSent
)

func (s sockState) String() string {
	switch s {
	case stateListen:
		return "listen"
	case stateEstablished:
		return "established"
	case stateSynSent:
		return "syn_sent"
	}
	return "unknown"
}

// socket is one entry of the connection table.
type socket struct {
	Proto   string
	Local   netip.AddrPort
	Remote  netip.AddrPort
	State   sockState
	PID     int
	Process string
	UID     string
	Inode   string // Linux only, used to find the owning process
}

// connSource reads the platform's connection table.
type connSource interface {
	// snapshot lists the current TCP sockets.
	snapshot() ([]socket, error)
	// resolve fills in the owning process of the given sockets, best effort.
	resolve(socks []*socket)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tracker – turns successive snapshots into "new connection" / "new listener"
// ─────────────────────────────────────────────────────────────────────────────

type connTracker struct {
	includeLoopback bool
	seen            map[string]bool // connections of the previous snapshot
	listeners       map[string]bool // listeners of the previous snapshot
	primed          bool
}

// update returns the sockets that are new since the previous snapshot and the
// set of listening ports ("tcp/443"). Listeners present in the very first
// snapshot are the baseline and not reported; connections always are.
func (t *connTracker) update(socks []socket) (added []*socket, listenPorts map[string]bool) {
	seen := make(map[string]bool)
	listeners := make(map[string]bool)
	listenPorts = make(map[string]bool)

	for i := range socks {
		s := &socks[i]
		if s.State == stateListen {
			key := s.Proto + " " + s.Local.String()
			listeners[key] = true
			listenPorts[s.Proto+"/"+strconv.Itoa(int(s.Local.Port()))] = true
			if t.primed && !t.listeners[key] {
				added = append(added, s)
			}
			continue
		}
		if !s.Remote.Addr().IsValid() || s.Remote.Addr().IsUnspecified() {
			continue
		}
		if !t.includeLoopback && s.Local.Addr().IsLoopback() && s.Remote.Addr().IsLoopback() {
			continue
		}
		// The state is not part of the key: SYN_SENT → ESTABLISHED is the same connection.
		key := s.Proto + " " + s.Local.String() + " " + s.Remote.String()
		seen[key] = true
		if !t.seen[key] {
			added = append(added, s)
		}
	}

	t.seen, t.listeners, t.primed = seen, listeners, true
	return added, listenPorts
}

// toEvent converts a new socket into an event. For connections, IP is the side
// that initiated it: the remote peer for inbound, the local host for outbound.
func (s *socket) toEvent(listenPorts map[string]bool, source string, now time.Time) domain.Event {
	meta := map[string]string{"source": source, "state": s.State.String()}
	for k, v := range map[string]string{"process": s.Process, "uid": s.UID} {
		if v != "" {
			meta[k] = v
		}
	}
	if s.PID > 0 {
		meta["pid"] = strconv.Itoa(s.PID)
	}

	if s.State == stateListen {
		return domain.Event{
			Timestamp: now,
			IP:        s.Local.Addr().String(),
			EventType: domain.EventPortOpened,
			Port:      int(s.Local.Port()),
			Protocol:  s.Proto,
			Message:   fmt.Sprintf("listening on %s %s", s.Proto, s.Local),
			Metadata:  meta,
		}
	}

	e := domain.Event{Timestamp: now, EventType: domain.EventNetworkConnection, Protocol: s.Proto, Metadata: meta}
	inbound := s.State != stateSynSent && listenPorts[s.Proto+"/"+strconv.Itoa(int(s.Local.Port()))]
	if inbound {
		e.Direction = domain.DirectionInbound
		e.IP, e.SrcPort = s.Remote.Addr().String(), int(s.Remote.Port())
		e.DstIP, e.Port = s.Local.Addr().String(), int(s.Local.Port())
	} else {
		e.Direction = domain.DirectionOutbound
		e.IP, e.SrcPort = s.Local.Addr().String(), int(s.Local.Port())
		e.DstIP, e.Port = s.Remote.Addr().String(), int(s.Remote.Port())
	}
	e.Message = fmt.Sprintf("%s %s %s -> %s", e.Direction, s.Proto, hostPort(e.IP, e.SrcPort), hostPort(e.DstIP, e.Port))
	return e
}

// ─────────────────────────────────────────────────────────────────────────────
// Collector
// ─────────────────────────────────────────────────────────────────────────────

type connCollector struct {
	name     string
	interval time.Duration
	source   connSource
	tracker  *connTracker
	sink     Sink
	rec      LineRecorder
	logger   *slog.Logger
	lastErr  string
}

func newConnCollector(cfg ConnectionsConfig, src connSource, sink Sink, rec LineRecorder, logger *slog.Logger) (*connCollector, error) {
	interval := defaultConnInterval
	if cfg.Interval != nil {
		interval = time.Duration(*cfg.Interval)
	}
	if interval < time.Second {
		return nil, errors.New("interval must be at least 1s")
	}
	name := cfg.Name
	if name == "" {
		name = "connections"
	}
	return &connCollector{
		name:     name,
		interval: interval,
		source:   src,
		tracker:  &connTracker{includeLoopback: cfg.IncludeLoopback},
		sink:     sink,
		rec:      rec,
		logger:   logger.With(slog.String("collector", name)),
	}, nil
}

func (c *connCollector) Name() string { return c.name }

func (c *connCollector) Run(ctx context.Context) error {
	c.logger.Info("connection collector started", slog.String("interval", c.interval.String()))
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		c.poll(ctx, time.Now().UTC())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *connCollector) poll(ctx context.Context, now time.Time) {
	socks, err := c.source.snapshot()
	if err != nil {
		// Log each distinct error once instead of on every poll.
		if msg := err.Error(); msg != c.lastErr {
			c.lastErr = msg
			c.logger.Warn("reading connection table failed", slog.String("error", msg))
		}
		return
	}
	c.lastErr = ""

	added, listenPorts := c.tracker.update(socks)
	if len(added) == 0 {
		return
	}
	c.source.resolve(added)

	for _, s := range added {
		event := s.toEvent(listenPorts, c.name, now)
		if err := event.Normalize(); err != nil {
			c.record(ResultParseError)
			continue
		}
		ingestCtx, cancel := context.WithTimeout(ctx, ingestTimeout)
		_, err := c.sink.Ingest(ingestCtx, event)
		cancel()
		if err != nil {
			c.logger.Error("ingesting connection event failed", slog.String("error", err.Error()))
			c.record(ResultIngestError)
			continue
		}
		c.record(ResultIngested)
	}
}

func (c *connCollector) record(result string) {
	if c.rec != nil {
		c.rec.RecordCollectorLine(c.name, result)
	}
}
