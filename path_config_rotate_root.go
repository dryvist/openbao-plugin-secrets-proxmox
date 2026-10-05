package proxmox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	pve "github.com/luthermonson/go-proxmox"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const rootWALKind = "proxmox-root-rotation"

// Only the active seal-wrapped config stores the replacement credential.
type rootRotation struct {
	OldID string `json:"old_id"`
	NewID string `json:"new_id"`
}

func pathConfigRotateRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.rotateRoot, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
		},
		HelpSynopsis: "Privately replace the dedicated management token and retire its predecessor.",
	}
}

func pendingRootRotation(ctx context.Context, s logical.Storage) (string, *rootRotation, error) {
	ids, err := framework.ListWAL(ctx, s)
	if err != nil {
		return "", nil, fmt.Errorf("cannot list rotation recovery")
	}
	for _, id := range ids {
		entry, err := framework.GetWAL(ctx, s, id)
		if err != nil || entry == nil {
			return "", nil, fmt.Errorf("cannot read rotation recovery")
		}
		if entry.Kind != rootWALKind {
			continue
		}
		encoded, err := json.Marshal(entry.Data)
		if err != nil {
			return "", nil, fmt.Errorf("invalid rotation recovery")
		}
		var rotation rootRotation
		if err := json.Unmarshal(encoded, &rotation); err != nil {
			return "", nil, fmt.Errorf("invalid rotation recovery")
		}
		return id, &rotation, nil
	}
	return "", nil, nil
}

func (b *backend) rotateRoot(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := d.ValidateStrict(); err != nil {
		return logical.ErrorResponse("invalid rotation fields"), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, provisionTimeout)
	defer cancel()
	id, pending, err := pendingRootRotation(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if pending != nil {
		cfg, err := readConfig(ctx, req.Storage)
		if err != nil || cfg == nil {
			return nil, fmt.Errorf("cannot read rotation configuration")
		}
		committed := cfg.TokenID == pending.NewID
		if err := b.recoverRootLocked(ctx, req.Storage, pending); err != nil {
			return nil, err
		}
		if err := framework.DeleteWAL(ctx, req.Storage, id); err != nil {
			return nil, fmt.Errorf("cannot commit rotation recovery")
		}
		if committed {
			return &logical.Response{Data: map[string]interface{}{"token_id": cfg.TokenID}}, nil
		}
	}
	cfg, err := readConfig(ctx, req.Storage)
	if err != nil || cfg == nil {
		return nil, fmt.Errorf("configure the engine before rotation")
	}
	c, err := b.clientLocked(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	user, oldToken, _ := strings.Cut(cfg.TokenID, "!")
	old := &tokenRecord{User: user, TokenID: oldToken}
	var info pve.Token
	if err := c.api.Get(ctx, tokenPath(old), &info); err != nil {
		return nil, pveError("management token read", err)
	}
	if !bool(info.Privsep) || (info.Expire != 0 && int64(info.Expire) <= time.Now().Unix()) {
		return nil, fmt.Errorf("management token is not valid for rotation")
	}
	acl, err := c.api.ACL(ctx)
	if err != nil || acl == nil {
		return nil, fmt.Errorf("cannot read management token ACLs")
	}
	grants := pve.ACLs{}
	for _, grant := range acl {
		if grant == nil {
			return nil, fmt.Errorf("invalid management token ACL collection")
		}
		if grant.Type == "token" && grant.UGID == cfg.TokenID {
			if !validIdentifier(grant.RoleID) || !strings.HasPrefix(grant.Path, "/") {
				return nil, fmt.Errorf("invalid management token ACL")
			}
			grants = append(grants, grant)
		}
	}
	if len(grants) == 0 {
		return nil, fmt.Errorf("management token requires explicit ACLs for rotation")
	}
	newID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("cannot allocate rotation identity")
	}
	replacement := &tokenRecord{User: user, TokenID: "bao-root-" + newID}
	present, err := c.tokenExists(ctx, replacement)
	if err != nil || present {
		return nil, fmt.Errorf("cannot allocate an unused management token identity")
	}
	rotation := &rootRotation{OldID: cfg.TokenID, NewID: replacement.fullID()}
	walID, err := framework.PutWAL(ctx, req.Storage, rootWALKind, rotation)
	if err != nil {
		return nil, fmt.Errorf("cannot persist rotation recovery")
	}
	var token pve.NewAPIToken
	if err := c.api.Post(ctx, tokenPath(replacement), map[string]interface{}{"expire": int64(info.Expire), "privsep": 1}, &token); err != nil {
		return nil, pveError("management token creation", err)
	}
	if token.FullTokenID != replacement.fullID() || token.Value == "" || strings.Contains(token.Value, cfg.TokenSecret) {
		return nil, fmt.Errorf("invalid replacement credential response")
	}
	for _, grant := range grants {
		if err := c.api.UpdateACL(ctx, pve.ACLOptions{Path: grant.Path, Roles: grant.RoleID, Tokens: replacement.fullID(), Propagate: grant.Propagate}); err != nil {
			return nil, pveError("management token ACL creation", err)
		}
	}
	next := *cfg
	next.TokenID, next.TokenSecret = token.FullTokenID, token.Value
	if err := next.validate(); err != nil {
		return nil, fmt.Errorf("invalid replacement configuration")
	}
	client, err := newPVEClient(&next)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize replacement client")
	}
	defer client.transport.CloseIdleConnections()
	if err := client.validateConfig(ctx, &next); err != nil {
		return nil, err
	}
	var replacementInfo pve.Token
	if err := client.api.Get(ctx, tokenPath(replacement), &replacementInfo); err != nil {
		return nil, pveError("replacement token read", err)
	}
	if int64(replacementInfo.Expire) != int64(info.Expire) {
		return nil, fmt.Errorf("replacement expiration was not preserved")
	}
	if err := verifyRootACLs(ctx, client, replacement.fullID(), grants); err != nil {
		return nil, err
	}
	if err := putRecord(ctx, req.Storage, "config", &next); err != nil {
		return nil, err
	}
	c.transport.CloseIdleConnections()
	b.client = client
	if err := b.recoverRootLocked(ctx, req.Storage, rotation); err != nil {
		return nil, err
	}
	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		return nil, fmt.Errorf("cannot commit management rotation")
	}
	return &logical.Response{Data: map[string]interface{}{"token_id": next.TokenID}}, nil
}

func verifyRootACLs(ctx context.Context, c *pveClient, id string, expected pve.ACLs) error {
	acl, err := c.api.ACL(ctx)
	if err != nil || acl == nil {
		return fmt.Errorf("cannot verify replacement ACLs")
	}
	remaining := append(pve.ACLs(nil), expected...)
	for _, grant := range acl {
		if grant == nil {
			return fmt.Errorf("invalid replacement ACL collection")
		}
		if grant.Type != "token" || grant.UGID != id {
			continue
		}
		matched := false
		for i, wanted := range remaining {
			if wanted.Path == grant.Path && wanted.RoleID == grant.RoleID && wanted.Propagate == grant.Propagate {
				remaining = append(remaining[:i], remaining[i+1:]...)
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("replacement management token has unexpected ACLs")
		}
	}
	if len(remaining) != 0 {
		return fmt.Errorf("replacement management token is missing ACLs")
	}
	return nil
}

func (b *backend) recoverRootLocked(ctx context.Context, s logical.Storage, rotation *rootRotation) error {
	cfg, err := readConfig(ctx, s)
	if err != nil || cfg == nil {
		return fmt.Errorf("cannot read rotation configuration")
	}
	oldUser, oldToken, oldOK := strings.Cut(rotation.OldID, "!")
	newUser, newToken, newOK := strings.Cut(rotation.NewID, "!")
	if !oldOK || !newOK || oldUser != newUser || !validUser(oldUser) || !validIdentifier(oldToken) || !validIdentifier(newToken) || rotation.OldID == rotation.NewID {
		return fmt.Errorf("invalid management rotation identities")
	}
	target := oldToken
	if cfg.TokenID == rotation.OldID {
		target = newToken
	} else if cfg.TokenID != rotation.NewID {
		return fmt.Errorf("management configuration changed during rotation")
	}
	c, err := b.clientLocked(ctx, s)
	if err != nil {
		return err
	}
	record := &tokenRecord{User: oldUser, TokenID: target}
	present, err := c.tokenExists(ctx, record)
	if err != nil {
		return err
	}
	if present {
		if err := c.api.Delete(ctx, tokenPath(record), nil); err != nil {
			return pveError("retired management token deletion", err)
		}
		present, err = c.tokenExists(ctx, record)
		if err != nil || present {
			return fmt.Errorf("retired management token deletion was not confirmed")
		}
	}
	acl, err := c.api.ACL(ctx)
	if err != nil || acl == nil {
		return fmt.Errorf("cannot read retired management ACLs")
	}
	for _, grant := range acl {
		if grant == nil {
			return fmt.Errorf("invalid retired management ACL collection")
		}
		if grant.Type == "token" && grant.UGID == record.fullID() {
			record.ACLPath, record.RoleID = grant.Path, grant.RoleID
			if err := c.removeACL(ctx, record, false); err != nil {
				return err
			}
		}
	}
	return nil
}
