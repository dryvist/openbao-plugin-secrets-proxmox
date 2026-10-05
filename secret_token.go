package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	pve "github.com/luthermonson/go-proxmox"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func secretToken(b *backend) *framework.Secret {
	return &framework.Secret{Type: "pve_token", Renew: b.tokenRenew, Revoke: b.tokenRevoke}
}

func leaseRecord(req *logical.Request) (*tokenRecord, error) {
	if req.Secret == nil {
		return nil, fmt.Errorf("missing token lease")
	}
	snapshot, ok := req.Secret.InternalData["record"].(string)
	if !ok {
		return nil, fmt.Errorf("missing token lease identity")
	}
	var record tokenRecord
	if err := json.Unmarshal([]byte(snapshot), &record); err != nil {
		return nil, fmt.Errorf("invalid token lease identity")
	}
	if !validUser(record.User) || !validIdentifier(record.TokenID) || !validIdentifier(record.RoleID) || record.StaticRole != "" || record.MaxTTL <= 0 || record.IssuedAt <= 0 {
		return nil, fmt.Errorf("invalid token lease identity")
	}
	return &record, nil
}

func (b *backend) tokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	record, err := leaseRecord(req)
	if err != nil {
		return nil, err
	}
	stored, err := readTokenRecord(ctx, req.Storage, record.TokenID)
	if err != nil {
		return nil, err
	}
	if stored == nil || stored.fullID() != record.fullID() || stored.ExpiresAt <= time.Now().Unix() {
		return nil, fmt.Errorf("token is absent or expired")
	}
	record = stored
	ttl, warnings, err := framework.CalculateTTL(b.System(), req.Secret.Increment, time.Duration(record.TTL)*time.Second, 0, time.Duration(record.MaxTTL)*time.Second, time.Duration(record.MaxTTL)*time.Second, time.Unix(record.IssuedAt, 0))
	if err != nil || ttl < time.Second {
		return nil, fmt.Errorf("token has reached its maximum lifetime")
	}
	c, err := b.clientLocked(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	var remote pve.Token
	if err := c.api.Get(ctx, tokenPath(record), &remote); err != nil {
		return nil, pveError("token read", err)
	}
	if int64(remote.Expire) > record.IssuedAt+record.MaxTTL {
		return nil, fmt.Errorf("token expiration exceeds its original maximum")
	}
	observed := *record
	observed.ExpiresAt = int64(remote.Expire)
	if err := c.verifyToken(ctx, &observed); err != nil {
		return nil, err
	}
	record.ExpiresAt = time.Now().UTC().Truncate(time.Second).Add(ttl).Unix()
	if record.ExpiresAt > record.IssuedAt+record.MaxTTL {
		record.ExpiresAt = record.IssuedAt + record.MaxTTL
	}
	if err := c.api.Put(ctx, tokenPath(record), map[string]interface{}{"expire": record.ExpiresAt, "privsep": 1}, nil); err != nil {
		return nil, pveError("token renewal", err)
	}
	if err := c.verifyToken(ctx, record); err != nil {
		return nil, err
	}
	// Commit only a verified renewal. A failed write or interruption leaves the
	// original cleanup deadline intact, so an unacknowledged remote extension
	// cannot prolong ownership of the token or its ACLs.
	if err := putRecord(ctx, req.Storage, tokenPrefix+record.TokenID, record); err != nil {
		return nil, err
	}
	remaining := time.Until(time.Unix(record.ExpiresAt, 0)).Truncate(time.Second)
	if remaining < time.Second {
		return nil, fmt.Errorf("token has expired")
	}
	req.Secret.TTL = remaining
	req.Secret.MaxTTL = time.Duration(record.MaxTTL) * time.Second
	resp := &logical.Response{Secret: req.Secret}
	for _, warning := range warnings {
		resp.AddWarning(warning)
	}
	return resp, nil
}

func (b *backend) tokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	record, err := leaseRecord(req)
	if err != nil {
		return nil, err
	}
	c, err := b.clientLocked(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return nil, b.cleanupTokenLocked(ctx, req.Storage, c, record)
}

func (b *backend) cleanupTokenLocked(ctx context.Context, s logical.Storage, c *pveClient, record *tokenRecord) error {
	cfg, err := readConfig(ctx, s)
	if err != nil {
		return err
	}
	if cfg == nil || record.User == managementUser(cfg.TokenID) {
		return fmt.Errorf("refusing management credential cleanup")
	}
	present, err := c.tokenExists(ctx, record)
	if err != nil {
		return err
	}
	if present {
		if err := c.api.Delete(ctx, tokenPath(record), nil); err != nil {
			return pveError("token deletion", err)
		}
		present, err = c.tokenExists(ctx, record)
		if err != nil {
			return err
		}
		if present {
			return fmt.Errorf("PVE token deletion was not confirmed")
		}
	}
	if err := c.removeACL(ctx, record, false); err != nil {
		return err
	}
	if record.UserMarker != "" {
		if err := c.removeACL(ctx, record, true); err != nil {
			return err
		}
	}
	if err := c.deleteRole(ctx, record); err != nil {
		return err
	}
	if err := s.Delete(ctx, tokenPrefix+record.TokenID); err != nil {
		return fmt.Errorf("cannot remove token record")
	}
	return b.cleanupUsersLocked(ctx, s, c)
}

func (b *backend) cleanupUsersLocked(ctx context.Context, s logical.Storage, c *pveClient) error {
	owned, err := s.List(ctx, userPrefix)
	if err != nil {
		return fmt.Errorf("cannot list user ownership")
	}
	if len(owned) == 0 {
		return nil
	}
	needed := map[string]bool{}
	roles, err := s.List(ctx, "roles/")
	if err != nil {
		return fmt.Errorf("cannot list roles")
	}
	for _, name := range roles {
		r, err := readRole(ctx, s, name)
		if err != nil {
			return err
		}
		if r != nil {
			needed[r.User] = true
		}
	}
	staticNames, err := s.List(ctx, staticPrefix)
	if err != nil {
		return fmt.Errorf("cannot list static roles")
	}
	for _, name := range staticNames {
		r, err := readStaticRole(ctx, s, name)
		if err != nil {
			return err
		}
		if r != nil {
			needed[r.Role.User] = true
		}
	}
	tokens, err := s.List(ctx, tokenPrefix)
	if err != nil {
		return fmt.Errorf("cannot list token records")
	}
	for _, id := range tokens {
		record, err := readTokenRecord(ctx, s, id)
		if err != nil {
			return err
		}
		if record != nil {
			needed[record.User] = true
		}
	}
	users, err := c.users(ctx)
	if err != nil {
		return err
	}
	for _, user := range owned {
		if needed[user] {
			continue
		}
		entry, err := s.Get(ctx, userPrefix+user)
		if err != nil || entry == nil {
			return fmt.Errorf("cannot read user ownership")
		}
		var marker string
		if err := entry.DecodeJSON(&marker); err != nil || marker == "" {
			return fmt.Errorf("invalid user ownership")
		}
		present := false
		for _, existing := range users {
			if existing.UserID != user {
				continue
			}
			present = true
			if existing.Comment != marker {
				return fmt.Errorf("PVE user ownership changed")
			}
		}
		if present {
			var tokens pve.Tokens
			if err := c.api.Get(ctx, "/access/users/"+url.PathEscape(user)+"/token", &tokens); err != nil {
				return pveError("token list", err)
			}
			if tokens == nil {
				return fmt.Errorf("invalid PVE token collection")
			}
			if len(tokens) > 0 {
				continue
			}
			if err := c.api.Delete(ctx, "/access/users/"+url.PathEscape(user), nil); err != nil {
				return pveError("user deletion", err)
			}
			remaining, err := c.users(ctx)
			if err != nil {
				return err
			}
			for _, existing := range remaining {
				if existing.UserID == user {
					return fmt.Errorf("PVE user deletion was not confirmed")
				}
			}
		}
		if err := s.Delete(ctx, userPrefix+user); err != nil {
			return fmt.Errorf("cannot remove user ownership")
		}
	}
	return nil
}

func (b *backend) periodic(ctx context.Context, req *logical.Request) error {
	ctx, cancel := context.WithTimeout(ctx, provisionTimeout)
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	ids, err := req.Storage.List(ctx, tokenPrefix)
	if err != nil {
		return fmt.Errorf("cannot list token records")
	}
	owned, err := req.Storage.List(ctx, userPrefix)
	if err != nil {
		return fmt.Errorf("cannot list user ownership")
	}
	staticErr := b.periodicStaticLocked(ctx, req.Storage)
	if len(ids) == 0 && len(owned) == 0 {
		return staticErr
	}
	c, err := b.clientLocked(ctx, req.Storage)
	if err != nil {
		return err
	}
	result := staticErr
	for _, id := range ids {
		record, err := readTokenRecord(ctx, req.Storage, id)
		if err != nil {
			return err
		}
		if record != nil && record.StaticRole == "" && record.ExpiresAt <= time.Now().Unix() {
			if err := b.cleanupTokenLocked(ctx, req.Storage, c, record); err != nil {
				result = errors.Join(result, err)
			}
		}
	}
	return errors.Join(result, b.cleanupUsersLocked(ctx, req.Storage, c))
}

func (b *backend) rollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	if kind == staticWALKind {
		rotation, err := decodeStaticRotation(data)
		if err != nil {
			return err
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.recoverStaticLocked(ctx, req.Storage, rotation)
	}
	if kind == rootWALKind {
		encoded, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("invalid management recovery record")
		}
		var rotation rootRotation
		if err := json.Unmarshal(encoded, &rotation); err != nil {
			return fmt.Errorf("invalid management recovery record")
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.recoverRootLocked(ctx, req.Storage, &rotation)
	}
	if kind != tokenWALKind {
		return fmt.Errorf("unknown provisioning recovery kind")
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("invalid provisioning recovery record")
	}
	var record tokenRecord
	if err := json.Unmarshal(encoded, &record); err != nil || record.StaticRole != "" || !validUser(record.User) || !validIdentifier(record.TokenID) || !validIdentifier(record.RoleID) {
		return fmt.Errorf("invalid provisioning recovery identity")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := b.clientLocked(ctx, req.Storage)
	if err != nil {
		return err
	}
	return b.cleanupTokenLocked(ctx, req.Storage, c, &record)
}
