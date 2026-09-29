package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// EventType defines the category of a security event.
type EventType string

const (
	EventFailedLogin   EventType = "failed_login"
	EventHTTPRequest   EventType = "http_request"
	EventPortScan      EventType = "port_scan"
	EventUnusualAccess EventType = "unusual_access"
	EventSQLInjection  EventType = "sql_injection"
	EventUnknown       EventType = "unknown"

	// Network events, e.g. from firewall logs.
	EventNetworkConnection EventType = "network_connection" // allowed / logged connection
	EventFirewallBlock     EventType = "firewall_block"     // dropped or rejected packet
	EventPortOpened        EventType = "port_opened"        // new listening socket on the monitored host
	EventDNSQuery          EventType = "dns_query"
)

// Alert categories produced by the default detection rules.
const (
	EventPathTraversal     EventType = "path_traversal"
	EventCommandInjection  EventType = "command_injection"
	EventXSS               EventType = "xss"
	EventSSRF              EventType = "ssrf"
	EventReconnaissance    EventType = "reconnaissance"
	EventMultiVector       EventType = "multi_vector"
	EventCommandAndControl EventType = "command_and_control"
	EventDNSTunneling      EventType = "dns_tunneling"
)

// Direction of network traffic, seen from the monitored host.
const (
	DirectionInbound  = "inbound"
	DirectionOutbound = "outbound"
	DirectionForward  = "forward"
)

// Event represents a raw security log entry received from a client.
//
// IP is always the source of the activity: the client of an HTTP request or
// the sender of a packet. For outbound traffic that is the monitored host
// itself, so rules then describe what the host does (e.g. scanning others).
type Event struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	IP         string            `json:"ip"`
	EventType  EventType         `json:"event_type"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Path       string            `json:"path,omitempty"`
	Port       int               `json:"port,omitempty"` // destination port
	StatusCode int               `json:"status_code,omitempty"`
	Message    string            `json:"message,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`

	// Network fields
	DstIP     string `json:"dst_ip,omitempty"`
	SrcPort   int    `json:"src_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`  // lower case: tcp, udp, icmp, …
	Direction string `json:"direction,omitempty"` // inbound, outbound, forward

	// DNS
	Domain string `json:"domain,omitempty"` // queried name, lower case, without trailing dot
}

// Normalize validates the event and brings it into canonical form: IP
// addresses are normalized, protocol and domain are lower-cased and a missing event
// type becomes "unknown". Every source should pass events through it so that
// per-IP state and field comparisons are consistent.
func (e *Event) Normalize() error {
	var errs []error

	if e.IP == "" {
		errs = append(errs, errors.New("field 'ip' is required"))
	} else if ip, err := NormalizeIP(e.IP); err != nil {
		errs = append(errs, fmt.Errorf("field 'ip' is not a valid IP address: %q", e.IP))
	} else {
		e.IP = ip
	}

	if e.DstIP != "" {
		if ip, err := NormalizeIP(e.DstIP); err != nil {
			errs = append(errs, fmt.Errorf("field 'dst_ip' is not a valid IP address: %q", e.DstIP))
		} else {
			e.DstIP = ip
		}
	}

	for name, port := range map[string]int{"port": e.Port, "src_port": e.SrcPort} {
		if port < 0 || port > 65535 {
			errs = append(errs, fmt.Errorf("field '%s' must be between 0 and 65535, got %d", name, port))
		}
	}

	e.Protocol = strings.ToLower(strings.TrimSpace(e.Protocol))
	e.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.Domain)), ".")
	e.Direction = strings.ToLower(strings.TrimSpace(e.Direction))
	switch e.Direction {
	case "", DirectionInbound, DirectionOutbound, DirectionForward:
	default:
		errs = append(errs, fmt.Errorf("field 'direction' must be inbound, outbound or forward, got %q", e.Direction))
	}

	if e.EventType == "" {
		e.EventType = EventUnknown
	}
	// DNS rules group by base domain; derive it here so they work for every
	// source (DNS collector, log shippers via the API), not only one.
	if e.EventType == EventDNSQuery && e.Domain != "" && e.Metadata["base_domain"] == "" {
		if e.Metadata == nil {
			e.Metadata = make(map[string]string)
		}
		e.Metadata["base_domain"] = BaseDomain(e.Domain)
	}
	return errors.Join(errs...)
}

// NormalizeIP parses an IPv4/IPv6 address and returns its canonical form, so
// that different spellings of one address ("2001:DB8::1", "2001:db8:0::1",
// "::ffff:10.0.0.1") share the same per-IP state.
func NormalizeIP(s string) (string, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q", s)
	}
	return addr.Unmap().WithZone("").String(), nil
}

// secondLevelLabels are common second-level labels under country-code TLDs
// ("example.co.uk"). Without a full public suffix list this keeps the most
// frequent cases apart; other multi-label suffixes are grouped one level too high.
var secondLevelLabels = []string{"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}

// BaseDomain returns the registrable part of a DNS name, e.g. "a.b.example.com"
// → "example.com" and "x.example.co.uk" → "example.co.uk".
func BaseDomain(name string) string {
	labels := strings.Split(name, ".")
	n := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && slices.Contains(secondLevelLabels, labels[len(labels)-2]) {
		n = 3
	}
	if len(labels) <= n {
		return name
	}
	return strings.Join(labels[len(labels)-n:], ".")
}
