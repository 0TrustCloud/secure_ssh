//go:build unix

package secure_ssh

import (
	"io"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

type ptySession struct {
	pty  *os.File
	cmd  *exec.Cmd
	size *ptySize
}

type ptySize struct{ rows, cols int }

func startPTY(cmd *exec.Cmd, rows, cols int) (io.ReadWriter, *ptySession, error) {
	if rows <= 0 {
		rows = 24
	}
	if cols <= 0 {
		cols = 80
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, nil, err
	}
	_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	return ptmx, &ptySession{pty: ptmx, cmd: cmd, size: &ptySize{rows: rows, cols: cols}}, nil
}

func (s *ptySession) resize(rows, cols int) error {
	if s == nil || s.pty == nil {
		return nil
	}
	if rows <= 0 {
		rows = s.size.rows
	}
	if cols <= 0 {
		cols = s.size.cols
	}
	s.size.rows, s.size.cols = rows, cols
	return pty.Setsize(s.pty, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
}

func (s *ptySession) close() {
	if s == nil {
		return
	}
	if s.pty != nil {
		_ = s.pty.Close()
	}
}