package collector

import (
	"lightweight-security-monitoring/internal/domain"
	"testing"
	"time"
)

func TestCombinedParser(t *testing.T) {
	line := `203.0.113.7 - frank [10/Oct/2026:13:55:36 +0200] "GET /search?q=%27+OR+1%3D1 HTTP/1.1" 200 2326 "https://example.com/" "Mozilla/5.0 (X11)"`
	rec, err := combinedParser{}.parse(line)
	if err != nil {
		t.Fatal(err)
	}
	want := accessRecord{
		IP:        "203.0.113.7",
		Time:      time.Date(2026, 10, 10, 11, 55, 36, 0, time.UTC),
		Method:    "GET",
		Path:      "/search?q=%27+OR+1%3D1",
		Request:   "GET /search?q=%27+OR+1%3D1 HTTP/1.1",
		Status:    200,
		UserAgent: "Mozilla/5.0 (X11)",
		Referer:   "https://example.com/",
	}
	if !rec.Time.Equal(want.Time) {
		t.Errorf("time = %v, want %v", rec.Time, want.Time)
	}
	rec.Time = want.Time
	if rec != want {
		t.Errorf("got  %+v\nwant %+v", rec, want)
	}
}

func TestCombinedParser_EscapesAndMalformedRequests(t *testing.T) {
	// Nginx escapes quotes as \x22; TLS probes produce binary garbage instead of a request line.
	rec, err := combinedParser{}.parse(`198.51.100.1 - - [10/Oct/2026:13:55:36 +0000] "GET /a?x=\x22<script> HTTP/1.1" 400 0 "-" "-"`)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Path != `/a?x="<script>` {
		t.Errorf("path = %q", rec.Path)
	}

	rec, err = combinedParser{}.parse(`198.51.100.1 - - [10/Oct/2026:13:55:36 +0000] "\x16\x03\x01" 400 157 "-" "-"`)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Path != "" || rec.Status != 400 {
		t.Errorf("expected empty path and status 400, got %+v", rec)
	}

	// Common log format (no referer / user agent) is accepted as well.
	if _, err := (combinedParser{}).parse(`10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.0" 200 12`); err != nil {
		t.Errorf("common log format: %v", err)
	}

	if _, err := (combinedParser{}).parse(`not an access log line`); err == nil {
		t.Error("expected parse error")
	}
}

func TestJSONParser_Presets(t *testing.T) {
	cases := []struct {
		format, line string
		want         accessRecord
	}{
		{
			format: "json",
			line:   `{"time_iso8601":"2026-10-10T13:55:36+00:00","remote_addr":"10.0.0.5","request_method":"POST","request_uri":"/login","status":"401","http_user_agent":"curl/8.0","http_referer":"","host":"example.com"}`,
			want:   accessRecord{IP: "10.0.0.5", Method: "POST", Path: "/login", Status: 401, UserAgent: "curl/8.0", Host: "example.com"},
		},
		{
			format: "caddy",
			line:   `{"level":"info","ts":1791640536.5,"logger":"http.log.access","request":{"remote_ip":"10.0.0.6","client_ip":"10.0.0.7","method":"GET","host":"example.com","uri":"/.env","headers":{"User-Agent":["sqlmap/1.7"]}},"status":404}`,
			want:   accessRecord{IP: "10.0.0.7", Method: "GET", Path: "/.env", Status: 404, UserAgent: "sqlmap/1.7", Host: "example.com"},
		},
		{
			format: "traefik",
			line:   `{"ClientHost":"10.0.0.8","RequestMethod":"GET","RequestPath":"/admin","DownstreamStatus":403,"RequestHost":"example.com","request_User-Agent":"nuclei","StartUTC":"2026-10-10T13:55:36.123Z"}`,
			want:   accessRecord{IP: "10.0.0.8", Method: "GET", Path: "/admin", Status: 403, UserAgent: "nuclei", Host: "example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			p, err := newJSONParser(tc.format, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec, err := p.parse(tc.line)
			if err != nil {
				t.Fatal(err)
			}
			if rec.Time.IsZero() {
				t.Error("timestamp was not parsed")
			}
			rec.Time = time.Time{}
			if rec != tc.want {
				t.Errorf("got  %+v\nwant %+v", rec, tc.want)
			}
		})
	}
}

func TestJSONParser_FieldOverrides(t *testing.T) {
	p, err := newJSONParser("json", map[string]string{"ip": "http_x_real_ip|remote_addr"})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := p.parse(`{"remote_addr":"10.0.0.1","http_x_real_ip":"203.0.113.9"}`)
	if rec.IP != "203.0.113.9" {
		t.Errorf("ip = %q, want first alternative", rec.IP)
	}
	rec, _ = p.parse(`{"remote_addr":"10.0.0.1"}`)
	if rec.IP != "10.0.0.1" {
		t.Errorf("ip = %q, want fallback alternative", rec.IP)
	}

	if _, err := newJSONParser("json", map[string]string{"client": "x"}); err == nil {
		t.Error("expected unknown field to be rejected")
	}
}

func TestToEvent(t *testing.T) {
	login := &FailedLoginConfig{Paths: []string{"/login"}}
	if err := login.validate(); err != nil {
		t.Fatal(err)
	}

	rec := accessRecord{IP: "10.0.0.1:51234", Method: "POST", Path: "/Login/?next=/", Status: 401, UserAgent: "-", Referer: "-"}
	event, err := toEvent(rec, "nginx", login)
	if err != nil {
		t.Fatal(err)
	}
	if event.IP != "10.0.0.1" {
		t.Errorf("ip = %q, want port stripped", event.IP)
	}
	if event.EventType != domain.EventFailedLogin {
		t.Errorf("event type = %s, want failed_login", event.EventType)
	}
	if event.UserAgent != "" || event.Metadata["referer"] != "" {
		t.Errorf("'-' placeholders should be dropped: %+v", event)
	}
	if event.Metadata["source"] != "nginx" || event.Metadata["method"] != "POST" {
		t.Errorf("unexpected metadata %v", event.Metadata)
	}

	rec.Status = 200
	if event, _ := toEvent(rec, "nginx", login); event.EventType != domain.EventHTTPRequest {
		t.Errorf("successful login must stay http_request, got %s", event.EventType)
	}

	if _, err := toEvent(accessRecord{IP: "unknown"}, "nginx", nil); err == nil {
		t.Error("expected invalid IP to be rejected")
	}
}
