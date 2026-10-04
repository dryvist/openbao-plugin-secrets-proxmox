package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const staticPrefix = "static-roles/"
const staticWALKind = "proxmox-static-rotation"

// The only persistent copy of a static secret is in this seal-wrapped entry.
// Role configuration and the current credential commit together.
type staticRole struct {
	Role           role              `json:"role"`
	RotationPeriod int               `json:"rotation_period"`
	Credential     *staticCredential `json:"credential,omitempty"`
}
type staticCredential struct {
	Record       tokenRecord `json:"record"`
	Secret       string      `json:"secret"`
	NextRotation int64       `json:"next_rotation"`
}
type staticRotation struct {
	Name string       `json:"name"`
	Old  *tokenRecord `json:"old,omitempty"`
	New  *tokenRecord `json:"new,omitempty"`
}

func pathsStatic(b *backend) []*framework.Path {
	fields := roleFields()
	delete(fields, "ttl")
	delete(fields, "max_ttl")
	fields["rotation_period"] = &framework.FieldSchema{Type: framework.TypeDurationSecond, Description: "Required rotation interval, between 1 minute and 365 days."}
	return []*framework.Path{
		{Pattern: "static-roles/?$", Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.staticList},
		}, HelpSynopsis: "List static token roles."},
		{Pattern: "static-roles/" + framework.GenericNameRegex("name") + "$", Fields: fields, Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.staticRoleRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.staticRoleWrite, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.staticRoleDelete, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
		}, HelpSynopsis: "Manage a privilege-separated token on a rotation interval."},
		{Pattern: "static-creds/" + framework.GenericNameRegex("name") + "$", Fields: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString, Description: "Static role name."}}, Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.staticCredsRead, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
		}, HelpSynopsis: "Read the current static token without creating a lease."},
	}
}

func readStaticRole(ctx context.Context, s logical.Storage, name string) (*staticRole, error) {
	entry, err := s.Get(ctx, staticPrefix+name)
	if err != nil {
		return nil, fmt.Errorf("cannot read static role")
	}
	if entry == nil {
		return nil, nil
	}
	var r staticRole
	if err := entry.DecodeJSON(&r); err != nil {
		return nil, fmt.Errorf("cannot decode static role")
	}
	return &r, nil
}
func (b *backend) staticList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names, err := req.Storage.List(ctx, staticPrefix)
	return logical.ListResponse(names), err
}
func (b *backend) staticRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	r, err := readStaticRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil || r == nil {
		return nil, err
	}
	data := r.Role.data()
	delete(data, "ttl")
	delete(data, "max_ttl")
	data["rotation_period"] = r.RotationPeriod
	return &logical.Response{Data: data}, nil
}
func (b *backend) staticCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := d.ValidateStrict(); err != nil || !validIdentifier(d.Get("name").(string)) {
		return logical.ErrorResponse("invalid static credential request"), nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	r, err := readStaticRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil || r == nil {
		return nil, err
	}
	if r.Credential == nil {
		return nil, fmt.Errorf("static credential is not available")
	}
	cfg, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	c := r.Credential
	if cfg == nil || c.Record.User == managementUser(cfg.TokenID) || c.Secret == "" {
		return nil, fmt.Errorf("invalid static credential owner")
	}
	ttl := c.NextRotation - time.Now().Unix()
	if ttl < 0 {
		ttl = 0
	}
	return &logical.Response{Data: map[string]interface{}{
		"token_id": c.Record.TokenID, "token_id_full": c.Record.fullID(), "secret": c.Secret,
		"rotation_period": r.RotationPeriod, "last_rotation": c.Record.IssuedAt,
		"next_rotation": c.NextRotation, "ttl": ttl,
	}}, nil
}
func (b *backend) staticRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := d.ValidateStrict(); err != nil || !validIdentifier(d.Get("name").(string)) {
		return logical.ErrorResponse("invalid static role fields"), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, provisionTimeout)
	defer cancel()
	name := d.Get("name").(string)
	if err := b.recoverPendingStaticLocked(ctx, req.Storage, name); err != nil {
		return nil, err
	}
	r, err := readStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		r = &staticRole{}
	}
	if err := applyRoleFields(d, &r.Role); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	if _, ok := d.Raw["rotation_period"]; ok {
		r.RotationPeriod = d.Get("rotation_period").(int)
	}
	if r.RotationPeriod < 60 || r.RotationPeriod > 365*24*60*60 {
		return logical.ErrorResponse("rotation_period must be between 1 minute and 365 days"), nil
	}
	if err := b.validateRole(&r.Role); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	return nil, b.rotateStaticLocked(ctx, req.Storage, name, r)
}
func (b *backend) rotateStaticLocked(ctx context.Context, s logical.Storage, name string, r *staticRole) error {
	c, err := b.clientLocked(ctx, s)
	if err != nil {
		return err
	}
	record, createUser, err := prepareToken(ctx, s, c, &r.Role, 0, 0)
	if err != nil {
		return err
	}
	record.StaticRole = name
	rotation := &staticRotation{Name: name, New: record}
	if r.Credential != nil {
		old := r.Credential.Record
		rotation.Old = &old
	}
	walID, err := framework.PutWAL(ctx, s, staticWALKind, rotation)
	if err != nil {
		return fmt.Errorf("cannot persist static rotation recovery")
	}
	value, err := provisionToken(ctx, s, c, record, createUser)
	if err != nil {
		return err
	}
	r.Credential = &staticCredential{Record: *record, Secret: value, NextRotation: time.Now().Unix() + int64(r.RotationPeriod)}
	if err := putRecord(ctx, s, staticPrefix+name, r); err != nil {
		return err
	}
	if err := b.recoverStaticLocked(ctx, s, rotation); err != nil {
		return err
	}
	if err := framework.DeleteWAL(ctx, s, walID); err != nil {
		return fmt.Errorf("cannot commit static rotation recovery")
	}
	return nil
}
func (b *backend) staticRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := d.ValidateStrict(); err != nil || !validIdentifier(d.Get("name").(string)) {
		return logical.ErrorResponse("invalid static role request"), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, provisionTimeout)
	defer cancel()
	name := d.Get("name").(string)
	if err := b.recoverPendingStaticLocked(ctx, req.Storage, name); err != nil {
		return nil, err
	}
	r, err := readStaticRole(ctx, req.Storage, name)
	if err != nil || r == nil {
		return nil, err
	}
	if r.Credential == nil {
		return nil, fmt.Errorf("static credential is not available")
	}
	rotation := &staticRotation{Name: name, Old: &r.Credential.Record}
	walID, err := framework.PutWAL(ctx, req.Storage, staticWALKind, rotation)
	if err != nil {
		return nil, fmt.Errorf("cannot persist static deletion recovery")
	}
	if err := b.recoverStaticLocked(ctx, req.Storage, rotation); err != nil {
		return nil, err
	}
	return nil, framework.DeleteWAL(ctx, req.Storage, walID)
}

func decodeStaticRotation(data interface{}) (*staticRotation, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("invalid static recovery record")
	}
	var r staticRotation
	if err := json.Unmarshal(encoded, &r); err != nil || !validIdentifier(r.Name) || (r.Old == nil && r.New == nil) {
		return nil, fmt.Errorf("invalid static recovery identity")
	}
	for _, record := range []*tokenRecord{r.Old, r.New} {
		if record != nil && (!validUser(record.User) || !validIdentifier(record.TokenID) || !validIdentifier(record.RoleID) || record.StaticRole != r.Name || record.ExpiresAt != 0) {
			return nil, fmt.Errorf("invalid static recovery identity")
		}
	}
	if r.Old != nil && r.New != nil && r.Old.TokenID == r.New.TokenID {
		return nil, fmt.Errorf("invalid static recovery identity")
	}
	return &r, nil
}
func (b *backend) recoverStaticLocked(ctx context.Context, s logical.Storage, rotation *staticRotation) error {
	c, err := b.clientLocked(ctx, s)
	if err != nil {
		return err
	}
	r, err := readStaticRole(ctx, s, rotation.Name)
	if err != nil {
		return err
	}
	var current *tokenRecord
	if r != nil && r.Credential != nil {
		current = &r.Credential.Record
	}
	if rotation.New == nil {
		// A durable deletion intent removes the credential before remote retirement.
		if current != nil && (rotation.Old == nil || current.fullID() != rotation.Old.fullID()) {
			return fmt.Errorf("static deletion identity changed")
		}
		if err := s.Delete(ctx, staticPrefix+rotation.Name); err != nil {
			return fmt.Errorf("cannot remove static role")
		}
		return b.cleanupTokenLocked(ctx, s, c, rotation.Old)
	}
	if current != nil && current.fullID() == rotation.New.fullID() {
		if rotation.Old != nil {
			return b.cleanupTokenLocked(ctx, s, c, rotation.Old)
		}
		return nil
	}
	if current != nil && (rotation.Old == nil || current.fullID() != rotation.Old.fullID()) {
		return fmt.Errorf("static rotation identity changed")
	}
	return b.cleanupTokenLocked(ctx, s, c, rotation.New)
}
func (b *backend) recoverPendingStaticLocked(ctx context.Context, s logical.Storage, name string) error {
	ids, err := framework.ListWAL(ctx, s)
	if err != nil {
		return fmt.Errorf("cannot list static recovery records")
	}
	for _, id := range ids {
		wal, err := framework.GetWAL(ctx, s, id)
		if err != nil {
			return fmt.Errorf("cannot read static recovery record")
		}
		if wal == nil || wal.Kind != staticWALKind {
			continue
		}
		rotation, err := decodeStaticRotation(wal.Data)
		if err != nil {
			return err
		}
		if name != "" && rotation.Name != name {
			continue
		}
		if err := b.recoverStaticLocked(ctx, s, rotation); err != nil {
			return err
		}
		if err := framework.DeleteWAL(ctx, s, id); err != nil {
			return fmt.Errorf("cannot clear static recovery record")
		}
	}
	return nil
}
func (b *backend) periodicStaticLocked(ctx context.Context, s logical.Storage) error {
	if err := b.recoverPendingStaticLocked(ctx, s, ""); err != nil {
		return err
	}
	names, err := s.List(ctx, staticPrefix)
	if err != nil {
		return fmt.Errorf("cannot list static roles")
	}
	var result error
	for _, name := range names {
		r, err := readStaticRole(ctx, s, name)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if r != nil && r.Credential != nil && r.Credential.NextRotation <= time.Now().Unix() {
			if err := b.rotateStaticLocked(ctx, s, name, r); err != nil {
				result = errors.Join(result, err)
			}
		}
	}
	return result
}
