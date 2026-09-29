//go:build !windows

package collector

import "os"

// openShared opens path for reading. On Unix, open files never block rotation.
func openShared(path string) (*os.File, error) {
	return os.Open(path)
}
