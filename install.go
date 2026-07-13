package secure_ssh

import (
	"context"
	"fmt"

	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_policy"
)

// Install wires SSH server and client handlers into the mesh router and node.
func Install(router *secure_network.Router, node *secure_network.MeshNode, pe *secure_policy.PolicyEngine) (*Manager, *Client) {
	mgr := NewManager(node)
	client := NewClient(node)

	router.RegisterProtocol(ActionSSH, func(ctx context.Context, signer []byte, content string) error {
		if pe != nil && len(signer) > 0 && !pe.Evaluate(signer, "ssh", "exec", nil) {
			return fmt.Errorf("policy denied ssh exec")
		}
		return mgr.HandlePacket(ctx, content)
	})

	node.RegisterInbound(ActionSSH, client)
	return mgr, client
}