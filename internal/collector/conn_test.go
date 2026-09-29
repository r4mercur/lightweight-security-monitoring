package collector

import (
	"encoding/binary"
	"lightweight-security-monitoring/internal/domain"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// ── Table parsers ─────────────────────────────────────────────────────────────

func TestParseProcNet(t *testing.T) {
	v4 := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109        0 23456 1 0000000000000000 100 0 0 10 0
   1: 0500000A:C350 0C0DA8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 20 4 30 10 -1
   2: 0500000A:C351 0C0DA8C0:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000000000000000 20 4 30 10 -1
`
	socks, err := parseProcNet(strings.NewReader(v4), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 2 { // TIME_WAIT (06) is skipped
		t.Fatalf("got %d sockets, want 2", len(socks))
	}
	if socks[0].State != stateListen || socks[0].Local != ap("127.0.0.1:3306") || socks[0].UID != "109" || socks[0].Inode != "23456" {
		t.Errorf("listener: %+v", socks[0])
	}
	if socks[1].State != stateEstablished || socks[1].Local != ap("10.0.0.5:50000") || socks[1].Remote != ap("192.168.13.12:443") {
		t.Errorf("connection: %+v", socks[1])
	}

	// IPv6, including an IPv4-mapped address on a dual-stack socket.
	v6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1
   1: 0000000000000000FFFF00000500000A:0016 0000000000000000FFFF00000C0DA8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 222 1
   2: B80D0120000000000000000001000000:01BB B80D0120000000000000000002000000:C000 02 00000000:00000000 00:00000000 00000000     0        0 333 1
`
	socks, err = parseProcNet(strings.NewReader(v6), true)
	if err != nil {
		t.Fatal(err)
	}
	if socks[0].Local != ap("[::]:22") || socks[0].State != stateListen {
		t.Errorf("v6 listener: %+v", socks[0])
	}
	if socks[1].Local != ap("10.0.0.5:22") || socks[1].Remote != ap("192.168.13.12:54321") {
		t.Errorf("mapped v4 was not unmapped: %+v", socks[1])
	}
	if socks[2].Local != ap("[2001:db8::1]:443") || socks[2].Remote != ap("[2001:db8::2]:49152") || socks[2].State != stateSynSent {
		t.Errorf("v6 connection: %+v", socks[2])
	}

	if _, err := parseProcNet(strings.NewReader("hdr\n 0: XYZ:0016 00000000:0000 0A a b c d e f\n"), false); err == nil {
		t.Error("expected an error for a malformed address")
	}
}

func TestDecodeTCPTables(t *testing.T) {
	row4 := func(state uint32, local, remote netip.AddrPort, pid uint32) []byte {
		b := make([]byte, 24)
		binary.LittleEndian.PutUint32(b[0:], state)
		copy(b[4:8], local.Addr().AsSlice())
		binary.BigEndian.PutUint16(b[8:], local.Port())
		copy(b[12:16], remote.Addr().AsSlice())
		binary.BigEndian.PutUint16(b[16:], remote.Port())
		binary.LittleEndian.PutUint32(b[20:], pid)
		return b
	}
	table := binary.LittleEndian.AppendUint32(nil, 3)
	table = append(table, row4(2, ap("0.0.0.0:445"), ap("0.0.0.0:0"), 4)...)
	table = append(table, row4(5, ap("10.0.0.5:50000"), ap("203.0.113.9:4444"), 1234)...)
	table = append(table, row4(11, ap("10.0.0.5:50001"), ap("203.0.113.9:80"), 1234)...) // TIME_WAIT

	socks, err := decodeTCPTable(table)
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 2 || socks[0].State != stateListen || socks[0].Local != ap("0.0.0.0:445") || socks[0].PID != 4 {
		t.Fatalf("unexpected v4 sockets %+v", socks)
	}
	if socks[1].Remote != ap("203.0.113.9:4444") || socks[1].PID != 1234 || socks[1].State != stateEstablished {
		t.Errorf("v4 connection: %+v", socks[1])
	}

	row6 := make([]byte, 56)
	copy(row6[0:16], netip.MustParseAddr("2001:db8::1").AsSlice())
	binary.BigEndian.PutUint16(row6[20:], 50000)
	copy(row6[24:40], netip.MustParseAddr("2001:db8::99").AsSlice())
	binary.BigEndian.PutUint16(row6[44:], 443)
	binary.LittleEndian.PutUint32(row6[48:], 3) // SYN_SENT
	binary.LittleEndian.PutUint32(row6[52:], 77)
	socks, err = decodeTCP6Table(append(binary.LittleEndian.AppendUint32(nil, 1), row6...))
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 1 || socks[0].Local != ap("[2001:db8::1]:50000") || socks[0].Remote != ap("[2001:db8::99]:443") || socks[0].State != stateSynSent || socks[0].PID != 77 {
		t.Errorf("v6 connection: %+v", socks)
	}

	if _, err := decodeTCPTable(binary.LittleEndian.AppendUint32(nil, 2)); err == nil {
		t.Error("expected an error for a truncated table")
	}
}

// ── Tracker ───────────────────────────────────────────────────────────────────

func TestConnTracker(t *testing.T) {
	tr := &connTracker{}
	listener := socket{Proto: "tcp", Local: ap("0.0.0.0:443"), State: stateListen}
	inbound := socket{Proto: "tcp", Local: ap("10.0.0.5:443"), Remote: ap("198.51.100.7:40000"), State: stateEstablished}
	outbound := socket{Proto: "tcp", Local: ap("10.0.0.5:50000"), Remote: ap("203.0.113.9:4444"), State: stateSynSent}
	loopback := socket{Proto: "tcp", Local: ap("127.0.0.1:50001"), Remote: ap("127.0.0.1:5432"), State: stateEstablished}

	// First snapshot: listeners are the baseline, connections are reported.
	added, ports := tr.update([]socket{listener, inbound, outbound, loopback})
	if len(added) != 2 || !ports["tcp/443"] {
		t.Fatalf("first snapshot: added %d, ports %v", len(added), ports)
	}
	in := added[0].toEvent(ports, "conn", time.Now())
	if in.Direction != domain.DirectionInbound || in.IP != "198.51.100.7" || in.DstIP != "10.0.0.5" || in.Port != 443 || in.SrcPort != 40000 {
		t.Errorf("inbound event: %+v", in)
	}
	out := added[1].toEvent(ports, "conn", time.Now())
	if out.Direction != domain.DirectionOutbound || out.IP != "10.0.0.5" || out.DstIP != "203.0.113.9" || out.Port != 4444 || out.EventType != domain.EventNetworkConnection {
		t.Errorf("outbound event: %+v", out)
	}

	// Same connections again (one changed SYN_SENT → ESTABLISHED): nothing new.
	outbound.State = stateEstablished
	if added, _ := tr.update([]socket{listener, inbound, outbound}); len(added) != 0 {
		t.Errorf("unchanged connections reported again: %v", added)
	}

	// A new listener after the baseline is reported as port_opened.
	backdoor := socket{Proto: "tcp", Local: ap("0.0.0.0:31337"), State: stateListen, Process: "nc"}
	added, ports = tr.update([]socket{listener, backdoor, inbound})
	if len(added) != 1 {
		t.Fatalf("expected the new listener, got %v", added)
	}
	e := added[0].toEvent(ports, "conn", time.Now())
	if e.EventType != domain.EventPortOpened || e.Port != 31337 || e.IP != "0.0.0.0" || e.Metadata["process"] != "nc" {
		t.Errorf("port_opened event: %+v", e)
	}

	// A connection that disappeared and comes back is new again.
	if added, _ := tr.update([]socket{listener, backdoor, inbound, outbound}); len(added) != 1 {
		t.Errorf("expected the reappearing connection, got %v", added)
	}
}

func TestConnTracker_IncludeLoopback(t *testing.T) {
	tr := &connTracker{includeLoopback: true}
	added, _ := tr.update([]socket{{Proto: "tcp", Local: ap("127.0.0.1:50001"), Remote: ap("127.0.0.1:5432"), State: stateEstablished}})
	if len(added) != 1 {
		t.Errorf("loopback connection not reported with include_loopback")
	}
}

// ── Live: the real connection table of this machine ───────────────────────────

func TestConnSource_Live(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("connection collector not supported on " + runtime.GOOS)
	}
	src, err := newConnSource()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks, err := src.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := ap(ln.Addr().String())
	clientAddr := ap(conn.LocalAddr().String())
	var mine []*socket
	for i := range socks {
		s := &socks[i]
		if (s.State == stateListen && s.Local == listenAddr) || (s.Local == clientAddr && s.Remote == listenAddr) {
			mine = append(mine, s)
		}
	}
	if len(mine) != 2 {
		t.Fatalf("expected our listener and client connection among %d sockets, found %d", len(socks), len(mine))
	}

	src.resolve(mine)
	for _, s := range mine {
		if s.PID != os.Getpid() || s.Process == "" {
			t.Errorf("socket %s %s not resolved to this process: pid=%d process=%q", s.State, s.Local, s.PID, s.Process)
		}
	}
}
