package collector

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Parsers for the platform connection tables. They are pure functions so they
// can be tested on every platform.

// ─────────────────────────────────────────────────────────────────────────────
// Linux: /proc/net/tcp and /proc/net/tcp6
//
//   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
//    0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109        0 23456 …
//
// Addresses are the in-memory 32-bit words printed as hex (little-endian on
// x86/arm), ports are big-endian hex.
// ─────────────────────────────────────────────────────────────────────────────

var procNetStates = map[string]sockState{"01": stateEstablished, "02": stateSynSent, "0A": stateListen}

func parseProcNet(r io.Reader, v6 bool) ([]socket, error) {
	var socks []socket
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		state, ok := procNetStates[f[3]]
		if !ok {
			continue // TIME_WAIT, CLOSE_WAIT, …
		}
		local, err := parseProcAddr(f[1], v6)
		if err != nil {
			return nil, err
		}
		remote, err := parseProcAddr(f[2], v6)
		if err != nil {
			return nil, err
		}
		socks = append(socks, socket{Proto: "tcp", Local: local, Remote: remote, State: state, UID: f[7], Inode: f[9]})
	}
	return socks, sc.Err()
}

func parseProcAddr(s string, v6 bool) (netip.AddrPort, error) {
	hexAddr, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("invalid address %q", s)
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid port in %q", s)
	}
	words := 1
	if v6 {
		words = 4
	}
	if len(hexAddr) != words*8 {
		return netip.AddrPort{}, fmt.Errorf("invalid address %q", s)
	}
	var b [16]byte
	for i := range words {
		w, err := strconv.ParseUint(hexAddr[i*8:(i+1)*8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid address %q", s)
		}
		binary.LittleEndian.PutUint32(b[i*4:], uint32(w))
	}
	var addr netip.Addr
	if v6 {
		addr = netip.AddrFrom16(b).Unmap() // dual-stack sockets show IPv4 as ::ffff:a.b.c.d
	} else {
		addr = netip.AddrFrom4([4]byte(b[:4]))
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows: GetExtendedTcpTable with TCP_TABLE_OWNER_PID_ALL
//
//   MIB_TCPTABLE_OWNER_PID   { DWORD n; MIB_TCPROW_OWNER_PID  rows[n] }  row = 24 bytes
//     state, localAddr, localPort, remoteAddr, remotePort, pid
//   MIB_TCP6TABLE_OWNER_PID  { DWORD n; MIB_TCP6ROW_OWNER_PID rows[n] }  row = 56 bytes
//     localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
//
// Addresses and ports are stored in network byte order; ports use the low two
// bytes of their DWORD.
// ─────────────────────────────────────────────────────────────────────────────

var mibTCPStates = map[uint32]sockState{2: stateListen, 3: stateSynSent, 5: stateEstablished}

func decodeTCPTable(b []byte) ([]socket, error) {
	return decodeMIBTable(b, 24, func(row []byte) (socket, bool) {
		state, ok := mibTCPStates[binary.LittleEndian.Uint32(row[0:])]
		return socket{
			Proto:  "tcp",
			State:  state,
			Local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(row[4:8])), binary.BigEndian.Uint16(row[8:])),
			Remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte(row[12:16])), binary.BigEndian.Uint16(row[16:])),
			PID:    int(binary.LittleEndian.Uint32(row[20:])),
		}, ok
	})
}

func decodeTCP6Table(b []byte) ([]socket, error) {
	return decodeMIBTable(b, 56, func(row []byte) (socket, bool) {
		state, ok := mibTCPStates[binary.LittleEndian.Uint32(row[48:])]
		return socket{
			Proto:  "tcp",
			State:  state,
			Local:  netip.AddrPortFrom(netip.AddrFrom16([16]byte(row[0:16])).Unmap(), binary.BigEndian.Uint16(row[20:])),
			Remote: netip.AddrPortFrom(netip.AddrFrom16([16]byte(row[24:40])).Unmap(), binary.BigEndian.Uint16(row[44:])),
			PID:    int(binary.LittleEndian.Uint32(row[52:])),
		}, ok
	})
}

func decodeMIBTable(b []byte, rowSize int, decode func(row []byte) (socket, bool)) ([]socket, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("connection table too short: %d bytes", len(b))
	}
	n := int(binary.LittleEndian.Uint32(b))
	if len(b) < 4+n*rowSize {
		return nil, fmt.Errorf("connection table truncated: %d rows need %d bytes, got %d", n, 4+n*rowSize, len(b))
	}
	var socks []socket
	for i := range n {
		row := b[4+i*rowSize : 4+(i+1)*rowSize]
		if s, ok := decode(row); ok {
			socks = append(socks, s)
		}
	}
	return socks, nil
}
