//go:build !linux && !windows

package collector

import "errors"

func newConnSource() (connSource, error) {
	return nil, errors.New("the connection collector is only supported on Linux and Windows")
}
