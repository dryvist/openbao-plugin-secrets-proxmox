package proxmox

import (
	"context"
	"fmt"
	"net/url"
	"time"

	pve "github.com/luthermonson/go-proxmox"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func tokenPath(r *tokenRecord) string {
	return "/access/users/" + url.PathEscape(r.User) + "/token/" + url.PathEscape(r.TokenID)
}

func (c *pveClient) users(ctx context.Context) (pve.Users, error) {
	var users pve.Users
	if err := c.api.Get(ctx, "/access/users", &users); err != nil {
		return nil, pveError("user list", err)
	}
	if users == nil {
		return nil, fmt.Errorf("invalid PVE user collection")
	}
	for _, user := range users {
		if user == nil || user.UserID == "" {
			return nil, fmt.Errorf("invalid PVE user collection")
		}
	}
	return users, nil
}

func (c *pveClient) ownedUser(ctx context.Context, s logical.Storage, user, marker string) (string, bool, error) {
	entry, err := s.Get(ctx, userPrefix+user)
	if err != nil {
		return "", false, fmt.Errorf("cannot read user ownership")
	}
	owned := ""
	if entry != nil {
		if err := entry.DecodeJSON(&owned); err != nil || owned == "" {
			return "", false, fmt.Errorf("invalid user ownership record")
		}
	}
	users, err := c.users(ctx)
	if err != nil {
		return "", false, err
	}
	for _, existing := range users {
		if existing.UserID == user {
			if owned == "" || existing.Comment != owned {
				return "", false, fmt.Errorf("auto_create_user cannot adopt an existing user")
			}
			return owned, false, nil
		}
	}
	if owned != "" {
		marker = owned
	}
	return marker, true, nil
}

func (c *pveClient) tokenExists(ctx context.Context, r *tokenRecord) (bool, error) {
	users, err := c.users(ctx)
	if err != nil {
		return false, err
	}
	present := false
	for _, user := range users {
		if user.UserID == r.User {
			present = true
			break
		}
	}
	if !present {
		return false, nil
	}
	var tokens pve.Tokens
	if err := c.api.Get(ctx, "/access/users/"+url.PathEscape(r.User)+"/token", &tokens); err != nil {
		return false, pveError("token list", err)
	}
	if tokens == nil {
		return false, fmt.Errorf("invalid PVE token collection")
	}
	for _, token := range tokens {
		if token == nil || !validIdentifier(token.TokenID) {
			return false, fmt.Errorf("invalid PVE token collection")
		}
		if token.TokenID == r.TokenID {
			return true, nil
		}
	}
	return false, nil
}

func (c *pveClient) verifyToken(ctx context.Context, r *tokenRecord) error {
	var info pve.Token
	if err := c.api.Get(ctx, tokenPath(r), &info); err != nil {
		return pveError("token read", err)
	}
	if !bool(info.Privsep) || int64(info.Expire) != r.ExpiresAt || (r.ExpiresAt <= time.Now().Unix() && !(r.StaticRole != "" && r.ExpiresAt == 0)) || (info.TokenID != "" && info.TokenID != r.TokenID) {
		return fmt.Errorf("issued token does not match its privilege separation or expiration")
	}
	acl, err := c.api.ACL(ctx)
	if err != nil {
		return pveError("ACL read", err)
	}
	if acl == nil {
		return fmt.Errorf("invalid PVE ACL collection")
	}
	found := false
	userGrantFound := r.UserMarker == ""
	for _, grant := range acl {
		if grant == nil {
			return fmt.Errorf("invalid PVE ACL collection")
		}
		if grant.Type == "token" && grant.UGID == r.fullID() {
			if grant.Path != r.ACLPath || grant.RoleID != r.RoleID || bool(grant.Propagate) != r.Propagate {
				return fmt.Errorf("issued token has an unexpected ACL")
			}
			if found {
				return fmt.Errorf("issued token has duplicate ACLs")
			}
			found = true
		}
		if grant.Type == "user" && grant.UGID == r.User && grant.RoleID == r.RoleID && grant.Path == r.ACLPath && bool(grant.Propagate) == r.Propagate {
			userGrantFound = true
		}
	}
	if !found {
		return fmt.Errorf("issued token ACL was not established")
	}
	if !userGrantFound {
		return fmt.Errorf("owned user permission ceiling was not established")
	}
	permissions, err := c.api.Role(ctx, r.RoleID)
	if err != nil {
		return pveError("owned role read", err)
	}
	wanted := make(map[string]bool, len(r.Privileges))
	for _, privilege := range r.Privileges {
		wanted[privilege] = true
	}
	grantedCount := 0
	for privilege, granted := range permissions {
		if granted {
			if !wanted[privilege] {
				return fmt.Errorf("owned role privileges changed")
			}
			grantedCount++
		}
	}
	if grantedCount != len(wanted) {
		return fmt.Errorf("owned role privileges changed")
	}
	return nil
}

func (c *pveClient) removeACL(ctx context.Context, r *tokenRecord, userGrant bool) error {
	acl, err := c.api.ACL(ctx)
	if err != nil {
		return pveError("ACL read", err)
	}
	if acl == nil {
		return fmt.Errorf("invalid PVE ACL collection")
	}
	kind, principal := "token", r.fullID()
	if userGrant {
		kind, principal = "user", r.User
	}
	present := false
	for _, grant := range acl {
		if grant == nil {
			return fmt.Errorf("invalid PVE ACL collection")
		}
		if grant.Path == r.ACLPath && grant.RoleID == r.RoleID && grant.Type == kind && grant.UGID == principal {
			present = true
		}
	}
	if !present {
		return nil
	}
	options := &pve.ACLOptions{Path: r.ACLPath, Roles: r.RoleID, Delete: true}
	if userGrant {
		options.Users = principal
	} else {
		options.Tokens = principal
	}
	if err := c.api.UpdateACL(ctx, *options); err != nil {
		return pveError("ACL deletion", err)
	}
	acl, err = c.api.ACL(ctx)
	if err != nil {
		return pveError("ACL read", err)
	}
	if acl == nil {
		return fmt.Errorf("invalid PVE ACL collection")
	}
	for _, grant := range acl {
		if grant == nil {
			return fmt.Errorf("invalid PVE ACL collection")
		}
		if grant.Path == r.ACLPath && grant.RoleID == r.RoleID && grant.Type == kind && grant.UGID == principal {
			return fmt.Errorf("PVE ACL deletion was not confirmed")
		}
	}
	return nil
}

func (c *pveClient) deleteRole(ctx context.Context, r *tokenRecord) error {
	roles, err := c.api.Roles(ctx)
	if err != nil {
		return pveError("role list", err)
	}
	if roles == nil {
		return fmt.Errorf("invalid PVE role collection")
	}
	present := false
	for _, role := range roles {
		if role == nil {
			return fmt.Errorf("invalid PVE role collection")
		}
		if role.RoleID == r.RoleID {
			present = true
		}
	}
	if !present {
		return nil
	}
	acl, err := c.api.ACL(ctx)
	if err != nil {
		return pveError("ACL read", err)
	}
	if acl == nil {
		return fmt.Errorf("invalid PVE ACL collection")
	}
	for _, grant := range acl {
		if grant == nil || grant.RoleID == r.RoleID {
			return fmt.Errorf("owned PVE role still has ACL references")
		}
	}
	if err := c.api.Delete(ctx, "/access/roles/"+url.PathEscape(r.RoleID), nil); err != nil {
		return pveError("role deletion", err)
	}
	roles, err = c.api.Roles(ctx)
	if err != nil {
		return pveError("role list", err)
	}
	if roles == nil {
		return fmt.Errorf("invalid PVE role collection")
	}
	for _, role := range roles {
		if role == nil || role.RoleID == r.RoleID {
			return fmt.Errorf("PVE role deletion was not confirmed")
		}
	}
	return nil
}
