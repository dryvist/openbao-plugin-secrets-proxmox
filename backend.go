package proxmox

import (
	"context"
	"fmt"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type backend struct {
	*framework.Backend
	// ponytail: serialize mount mutations; split into per-role locks if throughput requires it.
	mu     sync.RWMutex
	client *pveClient
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}
	b.Backend = &framework.Backend{
		Help:        "Configure Proxmox VE 9 API-token roles. Credential issuance is not available in this foundation release.",
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"config"},
		},
		Paths:      append([]*framework.Path{pathConfig(b)}, pathsRoles(b)...),
		Invalidate: b.invalidate,
		Clean:      b.clean,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *backend) invalidate(_ context.Context, key string) {
	if key == "config" {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.client != nil {
			b.client.transport.CloseIdleConnections()
		}
		b.client = nil
	}
}

func (b *backend) clean(ctx context.Context) {
	b.invalidate(ctx, "config")
}

// clientLocked is called while holding mu to keep configuration and client consistent.
func (b *backend) clientLocked(ctx context.Context, storage logical.Storage) (*pveClient, error) {
	if b.client != nil {
		return b.client, nil
	}
	cfg, err := readConfig(ctx, storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("configure the engine before writing roles")
	}
	b.client, err = newPVEClient(cfg)
	return b.client, err
}
