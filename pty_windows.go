//go:build windows

package secure_ssh

import (
	"io"
	"os/exec"
)

type ptySession struct {
	stdin io.WriteCloser
}

func startPTY(cmd *exec.Cmd, _, _ int) (io.ReadWriter, *ptySession, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	_, _ = cmd.StderrPipe()
	return &pipeRW{stdin: stdin, stdout: stdout}, &ptySession{stdin: stdin}, nil
}

type pipeRW struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func (p *pipeRW) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *pipeRW) Write(b []byte) (int, error) { return p.stdin.Write(b) }

func (s *ptySession) resize(_, _ int) error { return nil }

func (s *ptySession) close() {
	if s != nil && s.stdin != nil {
		_ = s.stdin.Close()
	}
}