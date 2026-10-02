//go:build linux

package collector

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// procNetSource reads /proc/net/tcp{,6}. Inside a container this is the
// container's network namespace; run with the host network to see the host.
type procNetSource struct {
	procRoot string
	buf      []byte // read buffer, reused between snapshots
}

// procTableBuffer holds ~1700 sockets, so most hosts' tables fit in one read.
const procTableBuffer = 256 << 10

func newConnSource() (connSource, error) {
	return &procNetSource{procRoot: "/proc"}, nil
}

func (p *procNetSource) snapshot() ([]socket, error) {
	var all []socket
	for _, t := range []struct {
		name string
		v6   bool
	}{{"tcp", false}, {"tcp6", true}} {
		data, err := p.readTable(filepath.Join(p.procRoot, "net", t.name))
		if err != nil {
			if t.v6 && errors.Is(err, fs.ErrNotExist) {
				continue // IPv6 disabled
			}
			return nil, err
		}
		socks, err := parseProcNet(bytes.NewReader(data), t.v6)
		if err != nil {
			return nil, err
		}
		all = append(all, socks...)
	}
	return all, nil
}

// readTable reads a /proc/net table. The kernel generates the table anew for
// every read call; when sockets come and go between two calls, the next call
// repeats or skips entries. A large buffer gets the whole table in a single
// call on all but very busy hosts; connTracker drops the remaining duplicates.
// The returned slice is valid until the next call.
func (p *procNetSource) readTable(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if p.buf == nil {
		p.buf = make([]byte, 0, procTableBuffer)
	}
	buf := p.buf[:0]
	for {
		if len(buf) == cap(buf) {
			buf = slices.Grow(buf, cap(buf))
		}
		n, err := f.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	p.buf = buf
	return buf, nil
}

// resolve maps socket inodes to processes by scanning /proc/<pid>/fd. Only
// processes whose fd directory is readable (same user, or root / CAP_SYS_PTRACE)
// can be resolved; the others stay without process information.
func (p *procNetSource) resolve(socks []*socket) {
	byInode := make(map[string][]*socket, len(socks))
	for _, s := range socks {
		if s.Inode != "" && s.Inode != "0" {
			byInode["socket:["+s.Inode+"]"] = append(byInode["socket:["+s.Inode+"]"], s)
		}
	}
	if len(byInode) == 0 {
		return
	}

	entries, err := os.ReadDir(p.procRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(p.procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			matches, ok := byInode[link]
			if !ok {
				continue
			}
			if comm == "" {
				b, _ := os.ReadFile(filepath.Join(p.procRoot, e.Name(), "comm"))
				comm = strings.TrimSpace(string(b))
			}
			for _, s := range matches {
				s.PID, s.Process = pid, comm
			}
			delete(byInode, link)
			if len(byInode) == 0 {
				return
			}
		}
	}
}
