package collector

import (
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DNSLogConfig describes one DNS server query log to follow.
type DNSLogConfig struct {
	fileOptions
	// Format is "dnsmasq" (also Pi-hole), "bind" (BIND query log) or "unbound".
	Format string `json:"format"`
}

func newDNSDecoder(cfg DNSLogConfig) (decodeFunc, error) {
	var parse func(line string, now time.Time) (dnsRecord, error)
	switch cfg.Format {
	case "dnsmasq":
		parse = parseDnsmasq
	case "bind":
		parse = parseBind
	case "unbound":
		parse = parseUnbound
	default:
		return nil, fmt.Errorf("unknown format %q (use dnsmasq, bind or unbound)", cfg.Format)
	}
	return func(line, source string) (domain.Event, error) {
		rec, err := parse(line, time.Now())
		if err != nil {
			return domain.Event{}, err
		}
		return rec.toEvent(source), nil
	}, nil
}

type dnsRecord struct {
	Time   time.Time
	Client string
	Domain string
	QType  string
}

func (r dnsRecord) toEvent(source string) domain.Event {
	name := strings.TrimSuffix(strings.ToLower(r.Domain), ".")
	return domain.Event{
		Timestamp: r.Time,
		IP:        r.Client,
		EventType: domain.EventDNSQuery,
		Domain:    name,
		// metadata.base_domain is derived by Event.Normalize for every source.
		Metadata: map[string]string{
			"source":     source,
			"query_type": strings.ToUpper(r.QType),
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// dnsmasq / Pi-hole (log-queries):
//   Sep 28 18:00:01 dnsmasq[1234]: query[A] www.example.com from 192.168.1.5
// Only "query" lines are events; forwarded/reply/cached lines are skipped.
// ─────────────────────────────────────────────────────────────────────────────

var dnsmasqQuery = regexp.MustCompile(`(?:dnsmasq|pihole-FTL)\[\d+\]: query\[(\w+)\] (\S+) from (\S+)`)

func parseDnsmasq(line string, now time.Time) (dnsRecord, error) {
	m := dnsmasqQuery.FindStringSubmatchIndex(line)
	if m == nil {
		return dnsRecord{}, errSkip
	}
	return dnsRecord{
		Time:   syslogTime(line[:m[0]], now),
		QType:  line[m[2]:m[3]],
		Domain: line[m[4]:m[5]],
		Client: line[m[6]:m[7]],
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// BIND query log:
//   28-Sep-2026 18:00:01.123 queries: info: client @0x7f 192.168.1.5#53422 (www.example.com): query: www.example.com IN A +E(0)K (192.168.1.1)
// Timestamps are local time.
// ─────────────────────────────────────────────────────────────────────────────

var bindQuery = regexp.MustCompile(`client (?:@\S+ )?(\S+)#\d+ \([^)]*\): (?:view \S+: )?query: (\S+) IN (\S+)`)

func parseBind(line string, _ time.Time) (dnsRecord, error) {
	m := bindQuery.FindStringSubmatch(line)
	if m == nil {
		return dnsRecord{}, errSkip
	}
	rec := dnsRecord{Client: m[1], Domain: m[2], QType: m[3]}
	if fields := strings.Fields(line); len(fields) >= 2 {
		rec.Time, _ = time.ParseInLocation("02-Jan-2006 15:04:05.000", fields[0]+" "+fields[1], time.Local)
	}
	return rec, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Unbound (log-queries: yes), with Unix or syslog timestamps:
//   [1790604001] unbound[1234:0] info: 192.168.1.5 www.example.com. A IN
//   Sep 28 18:00:01 unbound[1234:0] info: 192.168.1.5 www.example.com. A IN
// ─────────────────────────────────────────────────────────────────────────────

var (
	unboundQuery = regexp.MustCompile(`unbound\[[\d:]+\] info: (\S+) (\S+) (\S+) IN\s*$`)
	unixPrefix   = regexp.MustCompile(`^\[(\d+)\]`)
)

func parseUnbound(line string, now time.Time) (dnsRecord, error) {
	m := unboundQuery.FindStringSubmatch(line)
	if m == nil {
		return dnsRecord{}, errSkip
	}
	rec := dnsRecord{Client: m[1], Domain: m[2], QType: m[3]}
	if u := unixPrefix.FindStringSubmatch(line); u != nil {
		sec, _ := strconv.ParseInt(u[1], 10, 64)
		rec.Time = time.Unix(sec, 0).UTC()
	} else {
		rec.Time = syslogTime(line, now)
	}
	return rec, nil
}
