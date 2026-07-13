package secure_ssh

import (
	"context"
	"fmt"

	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_policy"
)

type PolicyMiddleware struct {
	engine *secure_policy.PolicyEngine
	next   secure_network.PacketHandler
}

func NewPolicyMiddleware(engine *secure_policy.PolicyEngine, next secure_network.PacketHandler) *PolicyMiddleware {
	return &PolicyMiddleware{engine: engine, next: next}
}

func (pm *PolicyMiddleware) HandlePacket(ctx context.Context, content string) error {
	signer, _ := ctx.Value("signer").([]byte)
	action, _ := ctx.Value("action_type").(string)
	if action == "" {
		action = "ssh"
	}
	resource := "exec"
	if pm.engine != nil && len(signer) > 0 {
		if !pm.engine.Evaluate(signer, action, resource, nil) {
			return fmt.Errorf("security policy exception: unauthorized ssh action")
		}
	}
	return pm.next.HandlePacket(ctx, content)
}