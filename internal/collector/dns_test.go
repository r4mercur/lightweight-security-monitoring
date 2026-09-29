package collector

import (
	"errors"
	"lightweight-security-monitoring/internal/domain"
	"testing"
	"time"
)

func TestDNSFormats(t *testing.T) {
	cases := []struct {
		format, line string
		wantIP       string
		wantDomain   string
		wantType     string
	}{
		{"dnsmasq", `Sep 28 18:00:01 dnsmasq[1234]: query[A] WWW.Example.com from 192.168.1.5`, "192.168.1.5", "www.example.com", "A"},
		{"dnsmasq", `Sep 28 18:00:01 pihole-FTL[99]: query[AAAA] api.github.com from 2001:db8::5`, "2001:db8::5", "api.github.com", "AAAA"},
		{"bind", `28-Sep-2026 18:00:01.123 queries: info: client @0x7f8b2c0 192.168.1.5#53422 (www.example.com): query: www.example.com IN A +E(0)K (192.168.1.1)`, "192.168.1.5", "www.example.com", "A"},
		{"bind", `28-Sep-2026 18:00:01.123 client 10.0.0.9#1053 (x.example.org): view internal: query: x.example.org IN TXT + (10.0.0.1)`, "10.0.0.9", "x.example.org", "TXT"},
		{"unbound", `[1790604001] unbound[1234:0] info: 192.168.1.5 www.example.com. A IN`, "192.168.1.5", "www.example.com", "A"},
		{"unbound", `Sep 28 18:00:01 unbound[1234:0] info: 192.168.1.6 mail.example.com. MX IN`, "192.168.1.6", "mail.example.com", "MX"},
	}
	for _, tc := range cases {
		t.Run(tc.format+"/"+tc.wantDomain, func(t *testing.T) {
			decode, err := newDNSDecoder(DNSLogConfig{Format: tc.format})
			if err != nil {
				t.Fatal(err)
			}
			e, err := decode(tc.line, "dns")
			if err == nil {
				err = e.Normalize()
			}
			if err != nil {
				t.Fatal(err)
			}
			if e.EventType != domain.EventDNSQuery || e.IP != tc.wantIP || e.Domain != tc.wantDomain || e.Metadata["query_type"] != tc.wantType {
				t.Errorf("got type=%s ip=%s domain=%s qtype=%s", e.EventType, e.IP, e.Domain, e.Metadata["query_type"])
			}
			if e.Timestamp.IsZero() || e.Timestamp.Year() < 2026 {
				t.Errorf("timestamp not parsed: %v", e.Timestamp)
			}
			if e.Message != "" {
				t.Errorf("DNS events carry the name in Domain only, got message %q", e.Message)
			}
		})
	}
}

func TestDNSFormats_SkipNonQueryLines(t *testing.T) {
	lines := map[string]string{
		"dnsmasq": `Sep 28 18:00:01 dnsmasq[1234]: forwarded www.example.com to 1.1.1.1`,
		"bind":    `28-Sep-2026 18:00:01.123 general: info: zone example.com/IN: loaded serial 1`,
		"unbound": `[1790604001] unbound[1234:0] info: server stats for thread 0: 12 queries`,
	}
	for format, line := range lines {
		decode, _ := newDNSDecoder(DNSLogConfig{Format: format})
		if _, err := decode(line, "dns"); !errors.Is(err, errSkip) {
			t.Errorf("%s: expected errSkip, got %v", format, err)
		}
	}
	if _, err := newDNSDecoder(DNSLogConfig{Format: "powerdns"}); err == nil {
		t.Error("expected unknown format to be rejected")
	}
}

func TestUnboundUnixTimestamp(t *testing.T) {
	rec, err := parseUnbound(`[1790604001] unbound[1:0] info: 10.0.0.1 a.example.com. A IN`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Time.Equal(time.Unix(1790604001, 0)) {
		t.Errorf("time = %v", rec.Time)
	}
}
