package secure_ssh

import (
	"io"
	"os/exec"
)

// PTYSession wraps an OS pseudo-terminal session.
type PTYSession struct {
	inner *ptySession
}

func (p *PTYSession) Resize(rows, cols int) error {
	if p == nil || p.inner == nil {
		return nil
	}
	return p.inner.resize(rows, cols)
}

func (p *PTYSession) Close() {
	if p != nil && p.inner != nil {
		p.inner.close()
	}
}

// StartPTY launches cmd attached to a PTY when supported.
func StartPTY(cmd *exec.Cmd, rows, cols int) (io.ReadWriter, *PTYSession, error) {
	rw, inner, err := startPTY(cmd, rows, cols)
	if err != nil {
		return nil, nil, err
	}
	return rw, &PTYSession{inner: inner}, nil
}