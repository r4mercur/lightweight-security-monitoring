package collector

import (
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/metrics"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func decodeFirewall(t *testing.T, cfg FirewallLogConfig, line string) (domain.Event, error) {
	t.Helper()
	decode, err := newFirewallDecoder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	event, err := decode(line, "fw")
	if err == nil {
		err = event.Normalize()
	}
	return event, err
}

// ── netfilter ─────────────────────────────────────────────────────────────────

func TestNetfilter_UFWBlock(t *testing.T) {
	line := `Sep 28 18:00:01 web01 kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 SRC=203.0.113.5 DST=192.0.2.10 LEN=44 TOS=0x00 PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0`
	e, err := decodeFirewall(t, FirewallLogConfig{Format: "netfilter"}, line)
	if err != nil {
		t.Fatal(err)
	}

	want := domain.Event{
		IP: "203.0.113.5", EventType: domain.EventFirewallBlock, DstIP: "192.0.2.10",
		Port: 22, SrcPort: 54321, Protocol: "tcp", Direction: domain.DirectionInbound,
		Message: "block tcp 203.0.113.5:54321 -> 192.0.2.10:22",
	}
	got := e
	got.Timestamp, got.Metadata = time.Time{}, nil
	if !equalEvents(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if e.Metadata["log_prefix"] != "[UFW BLOCK]" || e.Metadata["in_interface"] != "eth0" || e.Metadata["action"] != "block" {
		t.Errorf("unexpected metadata %v", e.Metadata)
	}
	if e.Timestamp.Month() != time.September || e.Timestamp.Day() != 28 || e.Timestamp.Hour() != 18 {
		t.Errorf("timestamp = %v", e.Timestamp)
	}
}

func equalEvents(a, b domain.Event) bool {
	return a.IP == b.IP && a.EventType == b.EventType && a.DstIP == b.DstIP && a.Port == b.Port &&
		a.SrcPort == b.SrcPort && a.Protocol == b.Protocol && a.Direction == b.Direction && a.Message == b.Message
}

func TestNetfilter_Variants(t *testing.T) {
	cases := []struct {
		name, line    string
		cfg           FirewallLogConfig
		wantType      domain.EventType
		wantDirection string
		wantIP        string
		wantPort      int
		wantTime      string // RFC 3339, empty = don't check
	}{
		{
			name:     "nftables accept, rsyslog RFC 3339",
			line:     `2026-09-28T18:00:01.123456+02:00 gw kernel: nft-accept: IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40000 DPT=443`,
			wantType: domain.EventNetworkConnection, wantDirection: domain.DirectionInbound, wantIP: "198.51.100.7", wantPort: 443,
			wantTime: "2026-09-28T16:00:01.123456Z",
		},
		{
			name:     "journalctl short-iso, outbound reject",
			line:     `2026-09-28T18:00:01+0200 host kernel: OUT-REJECT: IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.99 LEN=60 PROTO=TCP SPT=40001 DPT=4444`,
			wantType: domain.EventFirewallBlock, wantDirection: domain.DirectionOutbound, wantIP: "10.0.0.5", wantPort: 4444,
			wantTime: "2026-09-28T16:00:01Z",
		},
		{
			name:     "forwarded ICMP without ports",
			line:     `Sep 28 18:00:01 gw kernel: [UFW BLOCK] IN=eth1 OUT=eth0 SRC=10.1.0.2 DST=8.8.8.8 LEN=84 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1`,
			wantType: domain.EventFirewallBlock, wantDirection: domain.DirectionForward, wantIP: "10.1.0.2",
		},
		{
			name:     "IPv6 is normalized",
			line:     `Sep 28 18:00:01 gw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=2001:0DB8:0000::0001 DST=2001:db8::2 LEN=80 PROTO=UDP SPT=5353 DPT=5353`,
			wantType: domain.EventFirewallBlock, wantDirection: domain.DirectionInbound, wantIP: "2001:db8::1", wantPort: 5353,
		},
		{
			name:     "UFW LIMIT BLOCK is a block, not an allow",
			line:     `Sep 28 18:00:01 gw kernel: [UFW LIMIT BLOCK] IN=eth0 OUT= SRC=203.0.113.8 DST=192.0.2.10 PROTO=TCP SPT=1 DPT=22`,
			wantType: domain.EventFirewallBlock, wantDirection: domain.DirectionInbound, wantIP: "203.0.113.8", wantPort: 22,
		},
		{
			name:     "unknown prefix uses default_action allow",
			line:     `Sep 28 18:00:01 gw kernel: fw-log: IN=eth0 OUT= SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP SPT=1 DPT=80`,
			cfg:      FirewallLogConfig{DefaultAction: "allow"},
			wantType: domain.EventNetworkConnection, wantDirection: domain.DirectionInbound, wantIP: "203.0.113.9", wantPort: 80,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Format = "netfilter"
			e, err := decodeFirewall(t, tc.cfg, tc.line)
			if err != nil {
				t.Fatal(err)
			}
			if e.EventType != tc.wantType || e.Direction != tc.wantDirection || e.IP != tc.wantIP || e.Port != tc.wantPort {
				t.Errorf("got type=%s dir=%s ip=%s port=%d", e.EventType, e.Direction, e.IP, e.Port)
			}
			if tc.wantTime != "" && e.Timestamp.UTC().Format(time.RFC3339Nano) != tc.wantTime {
				t.Errorf("timestamp = %s, want %s", e.Timestamp.UTC().Format(time.RFC3339Nano), tc.wantTime)
			}
		})
	}
}

func TestNetfilter_SkipsOtherKernelMessages(t *testing.T) {
	for _, line := range []string{
		`Sep 28 18:00:01 host kernel: [ 1.234] usb 1-1: new high-speed USB device number 2`,
		`Sep 28 18:00:01 host systemd[1]: Started Daily apt download activities.`,
	} {
		if _, err := decodeFirewall(t, FirewallLogConfig{Format: "netfilter"}, line); !errors.Is(err, errSkip) {
			t.Errorf("expected errSkip for %q, got %v", line, err)
		}
	}
}

func TestSyslogTime_YearRollover(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 30, 0, time.Local)
	got := syslogTime("Dec 31 23:59:59 host kernel: ", now)
	if got.Year() != 2026 || got.Month() != time.December {
		t.Errorf("got %v, want 31 Dec 2026", got)
	}
}

// ── Windows Firewall ──────────────────────────────────────────────────────────

func TestWindowsFirewall(t *testing.T) {
	decode, err := newFirewallDecoder(FirewallLogConfig{Format: "windows"})
	if err != nil {
		t.Fatal(err)
	}

	// Without a header the default column order applies; a UTF-8 BOM is ignored.
	e, err := decode(byteOrderMark+`2026-09-28 18:00:01 DROP TCP 203.0.113.5 192.168.1.10 54321 3389 52 S 1234 0 64240 - - - RECEIVE 4`, "winfw")
	if err != nil {
		t.Fatal(err)
	}
	if e.EventType != domain.EventFirewallBlock || e.IP != "203.0.113.5" || e.Port != 3389 || e.Direction != domain.DirectionInbound || e.Protocol != "tcp" {
		t.Errorf("unexpected event %+v", e)
	}
	if e.Metadata["pid"] != "4" || e.Metadata["tcp_flags"] != "S" || e.Timestamp.Hour() != 18 {
		t.Errorf("unexpected metadata/time %v %v", e.Metadata, e.Timestamp)
	}

	// A header with a different column order is honoured.
	if _, err := decode(`#Fields: date time action protocol dst-ip src-ip dst-port src-port path`, "winfw"); !errors.Is(err, errSkip) {
		t.Fatalf("header line: expected errSkip, got %v", err)
	}
	e, err = decode(`2026-09-28 18:00:02 ALLOW UDP 8.8.8.8 192.168.1.10 53 50000 SEND`, "winfw")
	if err != nil {
		t.Fatal(err)
	}
	if e.EventType != domain.EventNetworkConnection || e.IP != "192.168.1.10" || e.DstIP != "8.8.8.8" || e.Port != 53 || e.Direction != domain.DirectionOutbound {
		t.Errorf("unexpected event with custom header %+v", e)
	}

	for _, line := range []string{"#Version: 1.5", "", "2026-09-28 18:00:03 INFO-EVENTS-LOST - - - - - - - - - - - - - 12"} {
		if _, err := decode(line, "winfw"); !errors.Is(err, errSkip) {
			t.Errorf("expected errSkip for %q, got %v", line, err)
		}
	}
}

// ── Configuration ─────────────────────────────────────────────────────────────

func TestLoadConfigFile_AllCollectorKinds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collectors.json")
	js := `{
		"poll_interval": "500ms",
		"access_logs":   [{"name": "nginx", "path": "/var/log/nginx/access.log", "format": "combined", "from_start": true}],
		"firewall_logs": [{"name": "ufw", "path": "/var/log/ufw.log", "format": "netfilter", "default_action": "block"},
		                  {"name": "winfw", "path": "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log", "format": "windows"}]
	}`
	if err := os.WriteFile(path, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AccessLogs[0].FromStart || cfg.FirewallLogs[0].Name != "ufw" || cfg.FirewallLogs[1].Format != "windows" {
		t.Errorf("embedded options not decoded: %+v", cfg)
	}
	collectors, err := Build(cfg, &recordingSink{}, nil, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range collectors {
		names = append(names, c.Name())
	}
	if !slices.Equal(names, []string{"nginx", "ufw", "winfw"}) {
		t.Errorf("collector names = %v", names)
	}

	for name, js := range map[string]string{
		"unknown key":   `{"firewall_logs": [{"path": "x", "format": "netfilter", "defaultaction": "allow"}]}`,
		"duplicate key": `{"firewall_logs": [{"path": "/var/log/ufw.log", "format": "netfilter", "path": "/tmp/x"}]}`,
		"mis-cased key": `{"firewall_logs": [{"Path": "x", "format": "netfilter"}]}`,
	} {
		if err := os.WriteFile(path, []byte(js), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfigFile(path); err == nil {
			t.Errorf("%s: expected the collectors file to be rejected", name)
		}
	}
}

func TestBuild_FirewallValidation(t *testing.T) {
	cases := map[string]FirewallLogConfig{
		"unknown format":     {fileOptions: fileOptions{Path: "a.log"}, Format: "pf"},
		"bad default action": {fileOptions: fileOptions{Path: "a.log"}, Format: "netfilter", DefaultAction: "log"},
		"action on windows":  {fileOptions: fileOptions{Path: "a.log"}, Format: "windows", DefaultAction: "block"},
		"missing path":       {Format: "netfilter"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(Config{FirewallLogs: []FirewallLogConfig{cfg}}, &recordingSink{}, nil, discardLogger); err == nil {
				t.Error("expected an error")
			}
		})
	}

	sameName := Config{
		AccessLogs:   []AccessLogConfig{{Name: "log", Path: "a", Format: "combined"}},
		FirewallLogs: []FirewallLogConfig{{Name: "log", Path: "b", Format: "netfilter"}},
	}
	if _, err := Build(sameName, &recordingSink{}, nil, discardLogger); err == nil {
		t.Error("expected names to be unique across collector kinds")
	}
}

// ── End to end: UFW log → detection ───────────────────────────────────────────

func TestFirewallCollector_DetectsPortScanAndSweep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ufw.log")
		var lines []string
		ts := time.Now().Add(-30 * time.Second).Format(time.RFC3339)
		for i := range 10 { // vertical scan: 10 ports on one host
			lines = append(lines, fmt.Sprintf(`%s gw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=192.0.2.10 PROTO=TCP SPT=40000 DPT=%d`, ts, 20+i))
		}
		for i := range 10 { // horizontal sweep: port 22 on 10 hosts
			lines = append(lines, fmt.Sprintf(`%s gw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=192.0.2.%d PROTO=TCP SPT=40000 DPT=22`, ts, 100+i))
		}
		lines = append(lines, `Sep 28 18:00:01 gw kernel: [ 1.2] eth0: link up`)
		appendFile(t, path, strings.Join(lines, "\n")+"\n")

		store := repository.NewMemoryStore()
		rules, err := service.DefaultRules()
		if err != nil {
			t.Fatal(err)
		}
		engine, err := service.NewDetectionEngine(rules)
		if err != nil {
			t.Fatal(err)
		}
		ingestion := service.NewIngestionService(store, store, engine, nil, metrics.NewMetrics(), discardLogger)

		rec := &countingRecorder{counts: map[string]int{}}
		collectors, err := Build(Config{FirewallLogs: []FirewallLogConfig{{
			Name:      "ufw",
			Path:      path,
			FromStart: true,
			Format:    "netfilter",
		}}}, ingestion, rec, discardLogger)
		if err != nil {
			t.Fatal(err)
		}
		runUntilIdle(t, collectors[0])

		if rec.get("ufw/"+ResultIngested) != 20 || rec.get("ufw/"+ResultSkipped) != 1 {
			t.Fatalf("unexpected line results %v", rec.counts)
		}
		alerts, _ := store.ListAlerts(t.Context(), repository.ListQuery{Limit: 10})
		got := map[string]string{}
		for _, a := range alerts.Items {
			got[a.IP] = a.TriggerRule
		}
		if got["203.0.113.5"] != "PortScan" || got["198.51.100.9"] != "NetworkSweep" {
			t.Errorf("expected PortScan and NetworkSweep alerts, got %v", got)
		}
	})
}
