//go:build windows

package collector

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afInet                       = 2
	afInet6                      = 23
	tcpTableOwnerPIDAll          = 5
	errorInsufficientBuffer      = 122
	maxConnTableRetries          = 5
	initialConnTableBufferLength = 64 << 10
)

// iphlpSource reads the TCP tables via GetExtendedTcpTable. It needs no
// administrator rights.
type iphlpSource struct{}

func newConnSource() (connSource, error) {
	if err := procGetExtendedTcpTable.Find(); err != nil {
		return nil, fmt.Errorf("GetExtendedTcpTable not available: %w", err)
	}
	return iphlpSource{}, nil
}

func (iphlpSource) snapshot() ([]socket, error) {
	v4, err := extendedTCPTable(afInet)
	if err != nil {
		return nil, err
	}
	socks, err := decodeTCPTable(v4)
	if err != nil {
		return nil, err
	}
	v6, err := extendedTCPTable(afInet6)
	if err != nil {
		return nil, err
	}
	socks6, err := decodeTCP6Table(v6)
	if err != nil {
		return nil, err
	}
	return append(socks, socks6...), nil
}

// extendedTCPTable calls GetExtendedTcpTable, growing the buffer while the
// table grows between the size query and the actual call.
func extendedTCPTable(family uint32) ([]byte, error) {
	buf := make([]byte, initialConnTableBufferLength)
	for range maxConnTableRetries {
		size := uint32(len(buf))
		r, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, // unsorted
			uintptr(family),
			tcpTableOwnerPIDAll,
			0,
		)
		switch r {
		case 0:
			return buf[:size], nil
		case errorInsufficientBuffer:
			buf = make([]byte, size+4096)
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", syscall.Errno(r))
		}
	}
	return nil, fmt.Errorf("GetExtendedTcpTable: table kept growing")
}

// resolve looks up the executable names via a process snapshot
// (CreateToolhelp32Snapshot). Unlike opening each process, this works for
// processes of every user and service without administrator rights.
func (iphlpSource) resolve(socks []*socket) {
	names, err := processNames()
	if err != nil {
		return
	}
	for _, s := range socks {
		s.Process = names[s.PID]
	}
}

func processNames() (map[int]string, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = syscall.CloseHandle(snap) }()

	names := map[int]string{0: "System Idle Process"}
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = syscall.Process32First(snap, &entry); err == nil; err = syscall.Process32Next(snap, &entry) {
		names[int(entry.ProcessID)] = syscall.UTF16ToString(entry.ExeFile[:])
	}
	return names, nil
}
