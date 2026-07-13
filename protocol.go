package secure_ssh

import (
	"encoding/json"

	"github.com/0TrustCloud/secure_network"
)

const ActionSSH = "ssh_proto"

type Action string

const (
	ActionExec   Action = "exec"
	ActionStdin  Action = "stdin"
	ActionStdout Action = "stdout"
	ActionStderr Action = "stderr"
	ActionResize Action = "resize"
	ActionExit   Action = "exit"
)

type Message struct {
	SessionID string `json:"session_id"`
	Action    Action `json:"action"`
	Payload   []byte `json:"payload,omitempty"`
	Rows      int    `json:"rows,omitempty"`
	Cols      int    `json:"cols,omitempty"`
	Host      string `json:"host,omitempty"`
	User      string `json:"user,omitempty"`
}

func NewAPIPayload(msg Message) (secure_network.APIPayload, error) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return secure_network.APIPayload{}, err
	}
	target := "ssh:exec"
	if msg.Host != "" {
		target = "host:" + msg.Host
	}
	return secure_network.APIPayload{
		Action:  ActionSSH,
		Content: string(raw),
		Target:  target,
	}, nil
}

func ParseMessage(content string) (Message, error) {
	var msg Message
	return msg, json.Unmarshal([]byte(content), &msg)
}