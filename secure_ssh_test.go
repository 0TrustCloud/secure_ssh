package secure_ssh

import "testing"

func TestNewAPIPayload(t *testing.T) {
	payload, err := NewAPIPayload(Message{
		SessionID: "sess-1",
		Action:    ActionExec,
		Payload:   []byte("echo hi"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if payload.Action != ActionSSH {
		t.Fatalf("expected %s got %s", ActionSSH, payload.Action)
	}
	msg, err := ParseMessage(payload.Content)
	if err != nil {
		t.Fatal(err)
	}
	if msg.SessionID != "sess-1" {
		t.Fatalf("session mismatch: %s", msg.SessionID)
	}
}