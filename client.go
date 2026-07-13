package secure_ssh

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/0TrustCloud/secure_network"
)

type ClientSession struct {
	id       string
	node     *secure_network.MeshNode
	doneChan chan struct{}
	stateMu  sync.Mutex
	isClosed bool
}

type Client struct {
	node     *secure_network.MeshNode
	mu       sync.RWMutex
	sessions map[string]*ClientSession
}

func NewClient(node *secure_network.MeshNode) *Client {
	return &Client{
		node:     node,
		sessions: make(map[string]*ClientSession),
	}
}

func (tc *Client) HandlePacket(_ context.Context, content string) error {
	msg, err := ParseMessage(content)
	if err != nil {
		return err
	}
	tc.HandleDemux(msg)
	return nil
}

func (tc *Client) OpenSession(ctx context.Context, sessionID, command string) error {
	return tc.OpenSessionOnHost(ctx, sessionID, command, "")
}

func (tc *Client) OpenSessionOnHost(ctx context.Context, sessionID, command, host string) error {
	if !tc.node.Connected() {
		return fmt.Errorf("mesh not connected")
	}
	return tc.OpenInteractiveSession(ctx, sessionID, command, host, NewAPIPayload)
}

func (tc *Client) HandleDemux(msg Message) {
	tc.mu.RLock()
	session, exists := tc.sessions[msg.SessionID]
	tc.mu.RUnlock()
	if !exists {
		return
	}

	switch msg.Action {
	case ActionStdout, ActionStderr:
		_, _ = os.Stdout.Write(msg.Payload)
	case ActionExit:
		session.Close()
	}
}

func (s *ClientSession) readLocalStdin() {
	buf := make([]byte, 1024)
	for {
		s.stateMu.Lock()
		closed := s.isClosed
		s.stateMu.Unlock()
		if closed {
			return
		}

		n, err := os.Stdin.Read(buf)
		if n > 0 {
			payload, _ := NewAPIPayload(Message{
				SessionID: s.id,
				Action:    ActionStdin,
				Payload:   buf[:n],
			})
			if sendErr := s.node.SendAction(payload); sendErr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				s.Close()
			}
			return
		}
	}
}

func (s *ClientSession) Close() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if !s.isClosed {
		s.isClosed = true
		close(s.doneChan)
	}
}