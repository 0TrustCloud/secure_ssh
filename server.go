package secure_ssh

import (
	"context"
	"io"
	"os/exec"
	"runtime"
	"sync"

	"github.com/0TrustCloud/secure_network"
)

type Session struct {
	id     string
	node   *secure_network.MeshNode
	cmd    *exec.Cmd
	stdin  io.Writer
	pty    *ptySession
	ctx    context.Context
	cancel context.CancelFunc
}

type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	node     *secure_network.MeshNode
}

func NewManager(node *secure_network.MeshNode) *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		node:     node,
	}
}

func (sm *Manager) HandlePacket(_ context.Context, content string) error {
	msg, err := ParseMessage(content)
	if err != nil {
		return err
	}
	sm.HandleIngress(msg)
	return nil
}

func (sm *Manager) HandleIngress(msg Message) {
	sm.mu.Lock()
	session, exists := sm.sessions[msg.SessionID]
	sm.mu.Unlock()

	switch msg.Action {
	case ActionExec:
		if !exists {
			ctx, cancel := context.WithCancel(context.Background())
			session = &Session{
				id:     msg.SessionID,
				node:   sm.node,
				ctx:    ctx,
				cancel: cancel,
			}
			sm.mu.Lock()
			sm.sessions[msg.SessionID] = session
			sm.mu.Unlock()
			go session.start(string(msg.Payload), msg.Rows, msg.Cols)
		}
	case ActionStdin:
		if exists && session.stdin != nil {
			_, _ = session.stdin.Write(msg.Payload)
		}
	case ActionResize:
		if exists && session.pty != nil {
			_ = session.pty.resize(msg.Rows, msg.Cols)
		}
	case ActionExit:
		if exists {
			session.cleanup()
			sm.mu.Lock()
			delete(sm.sessions, msg.SessionID)
			sm.mu.Unlock()
		}
	}
}

func defaultShell(command string) (string, []string) {
	if command != "" {
		if runtime.GOOS == "windows" {
			return "cmd.exe", []string{"/C", command}
		}
		return "/bin/sh", []string{"-c", command}
	}
	if runtime.GOOS == "windows" {
		return "cmd.exe", nil
	}
	return "/bin/bash", nil
}

func (s *Session) start(command string, rows, cols int) {
	bin, args := defaultShell(command)
	s.cmd = exec.CommandContext(s.ctx, bin, args...)

	tty, ptySess, err := startPTY(s.cmd, rows, cols)
	if err != nil {
		s.sendExit(1)
		return
	}
	s.stdin = tty
	s.pty = ptySess

	if err := s.cmd.Start(); err != nil {
		s.sendExit(1)
		return
	}

	go s.pipeToMesh(tty, ActionStdout)

	err = s.cmd.Wait()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}
	s.sendExit(exitCode)
}

func (s *Session) pipeToMesh(reader io.Reader, action Action) {
	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			payload, _ := NewAPIPayload(Message{
				SessionID: s.id,
				Action:    action,
				Payload:   append([]byte(nil), buf[:n]...),
			})
			_ = s.node.SendAction(payload)
		}
		if err != nil {
			break
		}
	}
}

func (s *Session) sendExit(code int) {
	payload, _ := NewAPIPayload(Message{
		SessionID: s.id,
		Action:    ActionExit,
		Payload:   []byte{byte(code)},
	})
	_ = s.node.SendAction(payload)
	s.cleanup()
}

func (s *Session) cleanup() {
	s.cancel()
	if s.pty != nil {
		s.pty.close()
	}
}