package domain

import (
	"strings"
	"testing"
)

func TestEventNormalize(t *testing.T) {
	e := Event{IP: "::ffff:10.0.0.1", DstIP: "2001:0DB8::0001", Protocol: " TCP ", Direction: "Inbound", Port: 22, SrcPort: 50000}
	if err := e.Normalize(); err != nil {
		t.Fatal(err)
	}
	if e.IP != "10.0.0.1" || e.DstIP != "2001:db8::1" || e.Protocol != "tcp" || e.Direction != DirectionInbound || e.EventType != EventUnknown {
		t.Errorf("not normalized: %+v", e)
	}
}

func TestEventNormalize_ReportsAllErrors(t *testing.T) {
	e := Event{IP: "nope", DstIP: "also-nope", Port: 70000, SrcPort: -1, Direction: "sideways"}
	err := e.Normalize()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, field := range []string{"'ip'", "'dst_ip'", "'port'", "'src_port'", "'direction'"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error does not mention %s: %v", field, err)
		}
	}

	if err := (&Event{}).Normalize(); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("expected missing ip to be reported, got %v", err)
	}
}

func TestBaseDomain(t *testing.T) {
	cases := map[string]string{
		"a.b.example.com":           "example.com",
		"example.com":               "example.com",
		"localhost":                 "localhost",
		"x.y.example.co.uk":         "example.co.uk",
		"shop.example.com.au":       "example.com.au",
		"5.1.168.192.in-addr.arpa":  "in-addr.arpa",
		"aGVsbG8.t.evil.example.io": "example.io",
	}
	for name, want := range cases {
		if got := BaseDomain(name); got != want {
			t.Errorf("BaseDomain(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestEventNormalize_DNSBaseDomain(t *testing.T) {
	// A DNS query as a log shipper sends it: no metadata, trailing dot, mixed case.
	e := Event{IP: "10.244.1.7", EventType: EventDNSQuery, Domain: "C01.Data.Exfil.Example.COM."}
	if err := e.Normalize(); err != nil {
		t.Fatal(err)
	}
	if e.Domain != "c01.data.exfil.example.com" || e.Metadata["base_domain"] != "example.com" {
		t.Errorf("got domain %q, base_domain %q", e.Domain, e.Metadata["base_domain"])
	}

	// An explicit base_domain from the source is kept; other event types get none.
	e = Event{IP: "10.0.0.1", EventType: EventDNSQuery, Domain: "a.b.corp.internal", Metadata: map[string]string{"base_domain": "b.corp.internal"}}
	_ = e.Normalize()
	if e.Metadata["base_domain"] != "b.corp.internal" {
		t.Errorf("explicit base_domain overwritten: %q", e.Metadata["base_domain"])
	}
	e = Event{IP: "10.0.0.1", EventType: EventHTTPRequest, Domain: "x.example.com"}
	_ = e.Normalize()
	if e.Metadata != nil {
		t.Errorf("base_domain set on a non-DNS event: %v", e.Metadata)
	}
}
