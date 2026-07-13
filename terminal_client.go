package secure_ssh

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/0TrustCloud/secure_network"
	"golang.org/x/term"
)

func (tc *Client) OpenInteractiveSession(ctx context.Context, sessionID, command, host string, newPayload func(Message) (secure_network.APIPayload, error)) error {
	if !tc.node.Connected() {
		return fmt.Errorf("mesh not connected")
	}
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		cols, rows = 80, 24
	}

	session := &ClientSession{
		id:       sessionID,
		node:     tc.node,
		doneChan: make(chan struct{}),
	}

	tc.mu.Lock()
	tc.sessions[sessionID] = session
	tc.mu.Unlock()

	defer func() {
		tc.mu.Lock()
		delete(tc.sessions, sessionID)
		tc.mu.Unlock()
	}()

	payload, err := newPayload(Message{
		SessionID: sessionID,
		Action:    ActionExec,
		Payload:   []byte(command),
		Rows:      rows,
		Cols:      cols,
		Host:      host,
	})
	if err != nil {
		return err
	}
	if err := tc.node.SendAction(payload); err != nil {
		return err
	}

	go session.readLocalStdin()
	go session.watchResize(rows, cols)

	select {
	case <-ctx.Done():
		session.Close()
		return ctx.Err()
	case <-session.doneChan:
		return nil
	}
}

func (s *ClientSession) watchResize(initialRows, initialCols int) {
	rows, cols := initialRows, initialCols
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.stateMu.Lock()
		closed := s.isClosed
		s.stateMu.Unlock()
		if closed {
			return
		}
		select {
		case <-s.doneChan:
			return
		case <-ticker.C:
			r, c, err := term.GetSize(int(os.Stdout.Fd()))
			if err != nil || (r == rows && c == cols) {
				continue
			}
			rows, cols = r, c
			payload, _ := NewAPIPayload(Message{
				SessionID: s.id,
				Action:    ActionResize,
				Rows:      rows,
				Cols:      cols,
			})
			_ = s.node.SendAction(payload)
		}
	}
}