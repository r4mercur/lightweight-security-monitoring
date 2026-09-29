package service_test

import (
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ── Egress & DNS rules ────────────────────────────────────────────────────────

func outboundTo(dst string, port int, ts time.Time) domain.Event {
	return domain.Event{
		ID: "conn", IP: "10.0.7.1", EventType: domain.EventNetworkConnection, Timestamp: ts,
		DstIP: dst, Port: port, Protocol: "tcp", Direction: domain.DirectionOutbound,
		Metadata: map[string]string{"process": "updater.exe"},
	}
}

func TestBeaconingRule_RegularIntervals(t *testing.T) {
	p := newPipeline(t)
	start := time.Now().UTC().Add(-time.Hour)
	jitter := []time.Duration{0, 2, -3, 1, -2, 3} // seconds, as a 5 s polling collector would see them
	var alerts []*domain.Alert
	for i, j := range jitter {
		ts := start.Add(time.Duration(i)*time.Minute + j*time.Second)
		if a, ok := p.ingest(outboundTo("203.0.113.50", 443, ts)); ok {
			alerts = append(alerts, a)
		}
	}
	if len(alerts) != 1 || alerts[0].TriggerRule != "Beaconing" {
		t.Fatalf("expected one Beaconing alert on the 6th contact, got %v", ruleNames(alerts))
	}
	for _, want := range []string{"updater.exe", "203.0.113.50:443", "every ~1m"} {
		if !strings.Contains(alerts[0].Reason, want) {
			t.Errorf("reason %q does not contain %q", alerts[0].Reason, want)
		}
	}
}

func TestBeaconingRule_ParallelConnectionsCountOnce(t *testing.T) {
	p := newPipeline(t)
	start := time.Now().UTC().Add(-time.Hour)
	var alerts []*domain.Alert
	for i := range 6 {
		for k := range 3 { // a burst of parallel connections per contact
			ts := start.Add(time.Duration(i)*time.Minute + time.Duration(k)*100*time.Millisecond)
			if a, ok := p.ingest(outboundTo("203.0.113.51", 443, ts)); ok {
				alerts = append(alerts, a)
			}
		}
	}
	if len(alerts) != 1 || alerts[0].TriggerRule != "Beaconing" || alerts[0].EventCount != 6 {
		t.Fatalf("expected one Beaconing alert with 6 contacts, got %v", ruleNames(alerts))
	}
}

func TestBeaconingRule_NoAlert(t *testing.T) {
	start := time.Now().UTC().Add(-time.Hour)
	cases := map[string][]domain.Event{}

	var irregular []domain.Event
	offset := time.Duration(0)
	for _, gap := range []time.Duration{0, 10, 200, 45, 600, 30} {
		offset += gap * time.Second
		irregular = append(irregular, outboundTo("203.0.113.52", 443, start.Add(offset)))
	}
	cases["irregular intervals"] = irregular

	var private, inbound []domain.Event
	for i := range 8 {
		ts := start.Add(time.Duration(i) * time.Minute)
		private = append(private, outboundTo("10.20.30.40", 9100, ts))
		e := outboundTo("203.0.113.53", 443, ts)
		e.Direction = domain.DirectionInbound
		inbound = append(inbound, e)
	}
	cases["private destination"] = private
	cases["inbound"] = inbound

	for name, events := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPipeline(t)
			for _, e := range events {
				if a, ok := p.ingest(e); ok {
					t.Fatalf("unexpected %s alert: %s", a.TriggerRule, a.Reason)
				}
			}
		})
	}
}

func TestSuspiciousOutboundPortRule(t *testing.T) {
	alert := expectRule(t, outboundTo("203.0.113.60", 4444, time.Now().UTC()), "SuspiciousOutboundPort")
	if alert.EventType != domain.EventCommandAndControl || !strings.Contains(alert.Reason, "updater.exe") {
		t.Errorf("unexpected alert %+v", alert)
	}

	inbound := outboundTo("203.0.113.60", 4444, time.Now().UTC())
	inbound.Direction = domain.DirectionInbound
	expectNoAlert(t, inbound)
}

func TestOutboundTrafficIsNotAScan(t *testing.T) {
	p := newPipeline(t)
	start := time.Now().UTC().Add(-time.Minute)
	// A browser opening a news site (30 hosts) and a P2P client (30 ports).
	for i := range 30 {
		ts := start.Add(time.Duration(i) * time.Second)
		for _, e := range []domain.Event{
			outboundTo("198.51.100."+strconv.Itoa(i+1), 443, ts),
			outboundTo("203.0.113.70", 20000+i, ts),
		} {
			if a, ok := p.ingest(e); ok {
				t.Fatalf("outbound traffic triggered %s: %s", a.TriggerRule, a.Reason)
			}
		}
	}
}

// dnsQuery builds a DNS event as a log shipper would send it via the API: no
// metadata. Normalize derives metadata.base_domain, which the DNS rules need.
func dnsQuery(ip, name string, ts time.Time) domain.Event {
	e := domain.Event{ID: "dns", IP: ip, EventType: domain.EventDNSQuery, Timestamp: ts, Domain: name}
	if err := e.Normalize(); err != nil {
		panic(err)
	}
	return e
}

func TestDNSTunnelingRule(t *testing.T) {
	p := newPipeline(t)
	start := time.Now().UTC().Add(-time.Minute)
	var alerts []*domain.Alert
	for i := range 50 {
		name := fmt.Sprintf("c%03d.aGVsbG8gd29ybGQ.t.evil-example.net", i)
		if a, ok := p.ingest(dnsQuery("10.0.8.1", name, start.Add(time.Duration(i)*time.Second))); ok {
			alerts = append(alerts, a)
		}
	}
	if len(alerts) != 1 || alerts[0].TriggerRule != "DNSTunneling" || !strings.Contains(alerts[0].Reason, "evil-example.net") {
		t.Fatalf("expected one DNSTunneling alert naming the domain, got %v", ruleNames(alerts))
	}
}

func TestDNSTunnelingRule_NoAlert(t *testing.T) {
	start := time.Now().UTC().Add(-time.Minute)
	cases := map[string]func(i int) string{
		"many different sites": func(i int) string { return fmt.Sprintf("www.site%d.example", i) },
		"reverse lookups":      func(i int) string { return fmt.Sprintf("%d.2.0.192.in-addr.arpa", i) },
	}
	for name, domainFor := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPipeline(t)
			for i := range 80 {
				if a, ok := p.ingest(dnsQuery("10.0.8.2", domainFor(i), start.Add(time.Duration(i)*500*time.Millisecond))); ok {
					t.Fatalf("unexpected %s alert: %s", a.TriggerRule, a.Reason)
				}
			}
		})
	}
}

func TestLongDNSLabelRule(t *testing.T) {
	name := strings.Repeat("a1b2c3d4e5", 6) + ".exfil.example.com"
	expectRule(t, dnsQuery("10.0.8.3", name, time.Now().UTC()), "LongDNSLabel")
	expectNoAlert(t, dnsQuery("10.0.8.3", "www.example.com", time.Now().UTC()))
}

func TestNewListeningPortRule(t *testing.T) {
	e := domain.Event{
		IP: "0.0.0.0", EventType: domain.EventPortOpened, Timestamp: time.Now().UTC(), Port: 31337, Protocol: "tcp",
		Metadata: map[string]string{"process": "nc"},
	}
	alert := expectRule(t, e, "NewListeningPort")
	if alert.Severity != domain.SeverityLow || alert.Reason != "New listening port: tcp port 31337 on 0.0.0.0 opened by nc" {
		t.Errorf("unexpected alert %+v", alert)
	}
}
