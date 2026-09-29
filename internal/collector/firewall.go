package collector

import (
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FirewallLogConfig describes one firewall log to follow.
type FirewallLogConfig struct {
	fileOptions
	// Format is "netfilter" (iptables / nftables / UFW LOG lines, e.g. from
	// /var/log/kern.log or /var/log/ufw.log) or "windows" (pfirewall.log).
	Format string `json:"format"`
	// DefaultAction applies to netfilter lines whose log prefix contains none of
	// the known keywords: "block" (default, LOG usually precedes DROP) or "allow".
	DefaultAction string `json:"default_action,omitempty"`
}

const (
	actionBlock = "block"
	actionAllow = "allow"
)

func newFirewallDecoder(cfg FirewallLogConfig) (decodeFunc, error) {
	var parse func(line string) (fwRecord, error)
	switch cfg.Format {
	case "netfilter":
		p := &netfilterParser{defaultAction: actionBlock, now: time.Now}
		switch cfg.DefaultAction {
		case "", actionBlock:
		case actionAllow:
			p.defaultAction = actionAllow
		default:
			return nil, fmt.Errorf("default_action must be block or allow, got %q", cfg.DefaultAction)
		}
		parse = p.parse
	case "windows":
		if cfg.DefaultAction != "" {
			return nil, errors.New("default_action is only supported for the netfilter format")
		}
		parse = newWindowsFirewallParser().parse
	default:
		return nil, fmt.Errorf("unknown format %q (use netfilter or windows)", cfg.Format)
	}

	return func(line, source string) (domain.Event, error) {
		rec, err := parse(line)
		if err != nil {
			return domain.Event{}, err
		}
		return rec.toEvent(source), nil
	}, nil
}

// fwRecord is the format-independent content of one firewall log line.
type fwRecord struct {
	Time      time.Time
	Action    string // block or allow
	Protocol  string
	Src, Dst  string
	SrcPort   int
	DstPort   int
	Direction string
	Meta      map[string]string
}

func (r fwRecord) toEvent(source string) domain.Event {
	eventType := domain.EventNetworkConnection
	if r.Action == actionBlock {
		eventType = domain.EventFirewallBlock
	}
	meta := map[string]string{"source": source, "action": r.Action}
	for k, v := range r.Meta {
		if v != "" {
			meta[k] = v
		}
	}
	return domain.Event{
		Timestamp: r.Time,
		IP:        r.Src,
		EventType: eventType,
		DstIP:     r.Dst,
		Port:      r.DstPort,
		SrcPort:   r.SrcPort,
		Protocol:  r.Protocol,
		Direction: r.Direction,
		Message:   fmt.Sprintf("%s %s %s -> %s", r.Action, r.Protocol, hostPort(r.Src, r.SrcPort), hostPort(r.Dst, r.DstPort)),
		Metadata:  meta,
	}
}

func hostPort(ip string, port int) string {
	if port == 0 {
		return ip
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

// ─────────────────────────────────────────────────────────────────────────────
// Format: netfilter (iptables / nftables LOG target, UFW)
//
//   Sep 28 18:00:01 host kernel: [1234.56] [UFW BLOCK] IN=eth0 OUT= MAC=…
//     SRC=203.0.113.5 DST=192.0.2.10 LEN=44 … PROTO=TCP SPT=54321 DPT=22 … SYN URGP=0
//
// The action is derived from the log prefix ("[UFW BLOCK]", "nft-drop:", …).
// ─────────────────────────────────────────────────────────────────────────────

var (
	blockKeywords = []string{"BLOCK", "DROP", "REJECT", "DENY"}
	allowKeywords = []string{"ALLOW", "ACCEPT", "AUDIT"}
	kernelUptime  = regexp.MustCompile(`^\[\s*\d+\.\d+\]\s*`)
)

type netfilterParser struct {
	defaultAction string
	now           func() time.Time
}

func (p *netfilterParser) parse(line string) (fwRecord, error) {
	start := strings.Index(line, "IN=")
	if start < 0 || !strings.Contains(line[start:], " SRC=") {
		return fwRecord{}, errSkip // some other kernel / syslog message
	}

	kv := make(map[string]string)
	for token := range strings.FieldsSeq(line[start:]) {
		if k, v, ok := strings.Cut(token, "="); ok {
			kv[k] = v
		}
	}
	if kv["SRC"] == "" {
		return fwRecord{}, errors.New("netfilter line without SRC")
	}

	head := line[:start]
	prefix := logPrefix(head)
	rec := fwRecord{
		Time:      syslogTime(head, p.now()),
		Action:    p.classify(prefix),
		Protocol:  strings.ToLower(kv["PROTO"]),
		Src:       kv["SRC"],
		Dst:       kv["DST"],
		SrcPort:   atoi(kv["SPT"]),
		DstPort:   atoi(kv["DPT"]),
		Direction: direction(kv["IN"], kv["OUT"]),
		Meta:      map[string]string{"log_prefix": prefix, "in_interface": kv["IN"], "out_interface": kv["OUT"]},
	}
	return rec, nil
}

func (p *netfilterParser) classify(prefix string) string {
	upper := strings.ToUpper(prefix)
	// Block first: "[UFW LIMIT BLOCK]" must not count as allowed.
	for _, k := range blockKeywords {
		if strings.Contains(upper, k) {
			return actionBlock
		}
	}
	for _, k := range allowKeywords {
		if strings.Contains(upper, k) {
			return actionAllow
		}
	}
	return p.defaultAction
}

// logPrefix extracts the LOG prefix from the part of the line before "IN=",
// dropping the syslog header and the kernel uptime.
func logPrefix(head string) string {
	if _, rest, ok := strings.Cut(head, "kernel:"); ok {
		head = rest
	}
	head = strings.TrimSpace(head)
	return strings.TrimSpace(kernelUptime.ReplaceAllString(head, ""))
}

func direction(in, out string) string {
	switch {
	case in != "" && out != "":
		return domain.DirectionForward
	case in != "":
		return domain.DirectionInbound
	case out != "":
		return domain.DirectionOutbound
	}
	return ""
}

// syslogTime parses the timestamp at the start of a syslog line: RFC 3339
// (rsyslog high precision, journalctl -o short-iso) or RFC 3164 ("Sep 28
// 18:00:01", local time without year). Unknown formats yield the zero time,
// which the ingestion service replaces with the receive time.
func syslogTime(head string, now time.Time) time.Time {
	first, _, _ := strings.Cut(head, " ")
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700"} {
		if t, err := time.Parse(layout, first); err == nil {
			return t
		}
	}
	if len(head) < 15 {
		return time.Time{}
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", head[:15], time.Local)
	if err != nil {
		return time.Time{}
	}
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
	// A line from December read in January belongs to the previous year.
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// Format: windows (Windows Defender Firewall, pfirewall.log)
//
//   #Fields: date time action protocol src-ip dst-ip src-port dst-port size … path pid
//   2026-09-28 18:00:01 DROP TCP 203.0.113.5 192.168.1.10 54321 3389 52 S … RECEIVE 4
//
// A leading UTF-8 byte order mark is ignored. Columns are taken from the "#Fields:" header; until one is seen (e.g. when
// starting at the end of the file) the default column order is assumed.
// Timestamps are in local time.
// ─────────────────────────────────────────────────────────────────────────────

// byteOrderMark may precede the first line of files written by Windows tools.
const byteOrderMark = string(rune(0xFEFF))

var defaultWindowsFields = strings.Fields(
	"date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid",
)

type windowsFirewallParser struct {
	index map[string]int
}

func newWindowsFirewallParser() *windowsFirewallParser {
	p := &windowsFirewallParser{}
	p.setFields(defaultWindowsFields)
	return p
}

func (p *windowsFirewallParser) setFields(names []string) {
	p.index = make(map[string]int, len(names))
	for i, n := range names {
		p.index[strings.ToLower(n)] = i
	}
}

func (p *windowsFirewallParser) parse(line string) (fwRecord, error) {
	line = strings.TrimSpace(strings.TrimPrefix(line, byteOrderMark))
	if rest, ok := strings.CutPrefix(line, "#Fields:"); ok {
		p.setFields(strings.Fields(rest))
		return fwRecord{}, errSkip
	}
	if line == "" || strings.HasPrefix(line, "#") {
		return fwRecord{}, errSkip
	}

	cols := strings.Fields(line)
	get := func(name string) string {
		i, ok := p.index[name]
		if !ok || i >= len(cols) || cols[i] == "-" {
			return ""
		}
		return cols[i]
	}

	var action string
	switch strings.ToUpper(get("action")) {
	case "DROP":
		action = actionBlock
	case "ALLOW":
		action = actionAllow
	default:
		return fwRecord{}, errSkip // e.g. INFO-EVENTS-LOST
	}

	ts, err := time.ParseInLocation("2006-01-02 15:04:05", get("date")+" "+get("time"), time.Local)
	if err != nil {
		return fwRecord{}, fmt.Errorf("invalid timestamp: %w", err)
	}

	var dir string
	switch strings.ToUpper(get("path")) {
	case "RECEIVE":
		dir = domain.DirectionInbound
	case "SEND":
		dir = domain.DirectionOutbound
	case "FORWARD":
		dir = domain.DirectionForward
	}

	return fwRecord{
		Time:      ts,
		Action:    action,
		Protocol:  strings.ToLower(get("protocol")),
		Src:       get("src-ip"),
		Dst:       get("dst-ip"),
		SrcPort:   atoi(get("src-port")),
		DstPort:   atoi(get("dst-port")),
		Direction: dir,
		Meta:      map[string]string{"tcp_flags": get("tcpflags"), "pid": get("pid")},
	}, nil
}
