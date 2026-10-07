package proxmox

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	pve "github.com/luthermonson/go-proxmox"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const tokenPrefix = "managed/tokens/"
const userPrefix = "managed/users/"
const tokenWALKind = "proxmox-token"
const provisionTimeout = 5 * time.Minute

// No credential value belongs in ownership records, WAL, or lease internal data.
type tokenRecord struct {
	StaticRole string   `json:"static_role,omitempty"`
	TokenID    string   `json:"token_id"`
	User       string   `json:"user"`
	RoleID     string   `json:"role_id"`
	Privileges []string `json:"privileges"`
	ACLPath    string   `json:"acl_path"`
	Propagate  bool     `json:"propagate"`
	UserMarker string   `json:"user_marker,omitempty"`
	IssuedAt   int64    `json:"issued_at"`
	ExpiresAt  int64    `json:"expires_at"`
	TTL        int64    `json:"ttl"`
	MaxTTL     int64    `json:"max_ttl"`
}

func (r *tokenRecord) fullID() string { return r.User + "!" + r.TokenID }

func pathCreds(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name") + "$",
		Fields:  map[string]*framework.FieldSchema{"name": {Type: framework.TypeString, Description: "Credential role name."}},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.credsRead, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
		},
		HelpSynopsis: "Issue a renewable, leased privilege-separated API token.",
	}
}

func putRecord(ctx context.Context, s logical.Storage, key string, value interface{}) error {
	entry, err := logical.StorageEntryJSON(key, value)
	if err != nil {
		return fmt.Errorf("cannot encode resource record")
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("cannot persist resource record")
	}
	return nil
}

func readTokenRecord(ctx context.Context, s logical.Storage, id string) (*tokenRecord, error) {
	entry, err := s.Get(ctx, tokenPrefix+id)
	if err != nil {
		return nil, fmt.Errorf("cannot read token record")
	}
	if entry == nil {
		return nil, nil
	}
	var record tokenRecord
	if err := entry.DecodeJSON(&record); err != nil {
		return nil, fmt.Errorf("cannot decode token record")
	}
	return &record, nil
}

func (b *backend) credsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (resp *logical.Response, retErr error) {
	if err := d.ValidateStrict(); err != nil || !validIdentifier(d.Get("name").(string)) {
		return logical.ErrorResponse("invalid credential request"), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, provisionTimeout)
	defer cancel()
	r, err := readRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil || r == nil {
		return nil, err
	}
	c, err := b.clientLocked(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	ttl, warnings, err := framework.CalculateTTL(b.System(), 0, time.Duration(r.TTL)*time.Second, 0, time.Duration(r.MaxTTL)*time.Second, 0, time.Time{})
	if err != nil || ttl < time.Second {
		return logical.ErrorResponse("cannot calculate a positive credential lifetime"), nil
	}
	maxTTL := b.System().MaxLeaseTTL()
	if r.MaxTTL > 0 && time.Duration(r.MaxTTL)*time.Second < maxTTL {
		maxTTL = time.Duration(r.MaxTTL) * time.Second
	}
	record, createUser, err := prepareToken(ctx, req.Storage, c, r, ttl, maxTTL)
	if err != nil {
		return nil, err
	}
	walID, err := framework.PutWAL(ctx, req.Storage, tokenWALKind, record)
	if err != nil {
		return nil, fmt.Errorf("cannot persist provisioning recovery record")
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), provisionTimeout)
		defer cleanupCancel()
		if err := b.cleanupTokenLocked(cleanupCtx, req.Storage, c, record); err == nil {
			if err := framework.DeleteWAL(cleanupCtx, req.Storage, walID); err != nil {
				retErr = fmt.Errorf("credential provisioning failed; recovery remains pending")
			}
		} else {
			retErr = fmt.Errorf("credential provisioning failed; recovery remains pending")
		}
		resp = nil
	}()
	value, err := provisionToken(ctx, req.Storage, c, record, createUser)
	if err != nil {
		return nil, err
	}
	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		return nil, fmt.Errorf("cannot commit provisioning recovery record")
	}
	remaining := time.Until(time.Unix(record.ExpiresAt, 0)).Truncate(time.Second)
	if remaining < time.Second {
		return nil, fmt.Errorf("credential expired during provisioning")
	}
	snapshot, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("cannot encode lease identity")
	}
	resp = b.Secret("pve_token").Response(map[string]interface{}{"token_id": record.TokenID, "token_id_full": record.fullID(), "secret": value}, map[string]interface{}{"record": string(snapshot)})
	resp.Secret.TTL = remaining
	resp.Secret.MaxTTL = maxTTL
	for _, warning := range warnings {
		resp.AddWarning(warning)
	}
	committed = true
	return resp, nil
}

// prepareToken resolves a permission snapshot before callers write their WAL.
func prepareToken(ctx context.Context, storage logical.Storage, c *pveClient, r *role, ttl, maxTTL time.Duration) (*tokenRecord, bool, error) {
	cfg, err := readConfig(ctx, storage)
	if err != nil {
		return nil, false, err
	}
	if cfg == nil || r.User == managementUser(cfg.TokenID) {
		return nil, false, fmt.Errorf("invalid credential owner")
	}
	if err := c.validateRole(ctx, r); err != nil {
		return nil, false, err
	}
	privileges := append([]string(nil), r.Privileges...)
	if r.PVERole != "" {
		permissions, err := c.api.Role(ctx, r.PVERole)
		if err != nil {
			return nil, false, pveError("role read", err)
		}
		for privilege, granted := range permissions {
			if granted {
				privileges = append(privileges, privilege)
			}
		}
	}
	if len(privileges) == 0 {
		return nil, false, fmt.Errorf("role must grant at least one privilege")
	}
	sort.Strings(privileges)
	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, false, fmt.Errorf("cannot allocate token identity")
	}
	now := time.Now().UTC().Truncate(time.Second)
	record := &tokenRecord{TokenID: "bao-" + id, User: r.User, RoleID: "Bao" + strings.ReplaceAll(id, "-", ""), Privileges: privileges, ACLPath: r.ACLPath, Propagate: r.Propagate, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), TTL: int64(ttl / time.Second), MaxTTL: int64(maxTTL / time.Second)}
	createUser := false
	if r.AutoCreateUser {
		record.UserMarker, createUser, err = c.ownedUser(ctx, storage, record.User, "openbao-proxmox:"+id)
		if err != nil {
			return nil, false, err
		}
	}
	roles, err := c.roles(ctx)
	if err != nil {
		return nil, false, err
	}
	for _, existing := range roles {
		if existing.RoleID == record.RoleID {
			return nil, false, fmt.Errorf("cannot allocate an unused role identity")
		}
	}
	if ttl == 0 {
		record.ExpiresAt = 0
	}
	return record, createUser, nil
}

// provisionToken performs remote creation; the caller owns recovery and publication.
func provisionToken(ctx context.Context, storage logical.Storage, c *pveClient, record *tokenRecord, createUser bool) (string, error) {
	cfg, err := readConfig(ctx, storage)
	if err != nil {
		return "", err
	}
	if cfg == nil || record.User == managementUser(cfg.TokenID) {
		return "", fmt.Errorf("invalid credential owner")
	}
	if record.UserMarker != "" {
		if err := putRecord(ctx, storage, userPrefix+record.User, record.UserMarker); err != nil {
			return "", err
		}
		if createUser {
			if err := c.api.NewUser(ctx, &pve.NewUser{UserID: record.User, Enable: true, Comment: record.UserMarker}); err != nil {
				return "", pveError("user creation", err)
			}
		}
		if _, missing, err := c.ownedUser(ctx, storage, record.User, record.UserMarker); err != nil || missing {
			return "", fmt.Errorf("owned user creation was not confirmed")
		}
	}
	if err := c.api.NewRole(ctx, record.RoleID, strings.Join(record.Privileges, " ")); err != nil {
		return "", pveError("role creation", err)
	}
	if record.UserMarker != "" {
		if err := c.api.UpdateACL(ctx, pve.ACLOptions{Path: record.ACLPath, Roles: record.RoleID, Users: record.User, Propagate: pve.IntOrBool(record.Propagate)}); err != nil {
			return "", pveError("user ACL creation", err)
		}
	}
	var token pve.NewAPIToken
	err = c.api.Post(ctx, tokenPath(record), map[string]interface{}{"expire": record.ExpiresAt, "privsep": 1}, &token)
	if err != nil {
		return "", pveError("token creation", err)
	}
	if token.FullTokenID != record.fullID() || token.Value == "" || strings.Contains(token.Value, cfg.TokenSecret) {
		return "", fmt.Errorf("invalid issued credential response")
	}
	if err := c.api.UpdateACL(ctx, pve.ACLOptions{Path: record.ACLPath, Roles: record.RoleID, Tokens: record.fullID(), Propagate: pve.IntOrBool(record.Propagate)}); err != nil {
		return "", pveError("token ACL creation", err)
	}
	if err := c.verifyToken(ctx, record); err != nil {
		return "", err
	}
	if err := putRecord(ctx, storage, tokenPrefix+record.TokenID, record); err != nil {
		return "", err
	}
	return token.Value, nil
}
