//go:build linux

package collector

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procNetSource reads /proc/net/tcp{,6}. Inside a container this is the
// container's network namespace; run with the host network to see the host.
type procNetSource struct {
	procRoot string
}

func newConnSource() (connSource, error) {
	return &procNetSource{procRoot: "/proc"}, nil
}

func (p *procNetSource) snapshot() ([]socket, error) {
	var all []socket
	for _, t := range []struct {
		name string
		v6   bool
	}{{"tcp", false}, {"tcp6", true}} {
		f, err := os.Open(filepath.Join(p.procRoot, "net", t.name))
		if err != nil {
			if t.v6 && errors.Is(err, fs.ErrNotExist) {
				continue // IPv6 disabled
			}
			return nil, err
		}
		socks, err := parseProcNet(f, t.v6)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, socks...)
	}
	return all, nil
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
