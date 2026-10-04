package proxmox

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
var userPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}@[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }
func validUser(value string) bool       { return userPattern.MatchString(value) }

type role struct {
	User           string   `json:"user"`
	AutoCreateUser bool     `json:"auto_create_user"`
	PVERole        string   `json:"pve_role"`
	Privileges     []string `json:"privileges"`
	ACLPath        string   `json:"acl_path"`
	Propagate      bool     `json:"propagate"`
	TTL            int      `json:"ttl"`
	MaxTTL         int      `json:"max_ttl"`
}

func pathsRoles(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.rolesList},
			},
			HelpSynopsis: "List credential role definitions.",
		},
		{
			Pattern: "roles/" + framework.GenericNameRegex("name") + "$",
			Fields:  roleFields(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.roleRead},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.roleWrite, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.roleDelete, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
			},
			HelpSynopsis: "Define a privilege-separated credential role. Provisioning occurs at credential issuance.",
		},
	}
}

func readRole(ctx context.Context, storage logical.Storage, name string) (*role, error) {
	entry, err := storage.Get(ctx, "roles/"+name)
	if err != nil || entry == nil {
		return nil, err
	}
	var r role
	if err := entry.DecodeJSON(&r); err != nil {
		return nil, fmt.Errorf("cannot decode stored role")
	}
	return &r, nil
}

func (r *role) data() map[string]interface{} {
	return map[string]interface{}{
		"user": r.User, "auto_create_user": r.AutoCreateUser, "pve_role": r.PVERole, "privileges": r.Privileges,
		"acl_path": r.ACLPath, "propagate": r.Propagate, "ttl": r.TTL, "max_ttl": r.MaxTTL,
	}
}

func (b *backend) roleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	r, err := readRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil || r == nil {
		return nil, err
	}
	return &logical.Response{Data: r.data()}, nil
}

func (b *backend) rolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names, err := req.Storage.List(ctx, "roles/")
	return logical.ListResponse(names), err
}

func (b *backend) roleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return nil, req.Storage.Delete(ctx, "roles/"+d.Get("name").(string))
}

func (b *backend) roleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := d.ValidateStrict(); err != nil {
		return logical.ErrorResponse("invalid role fields"), nil
	}
	name := d.Get("name").(string)
	if !validIdentifier(name) {
		return logical.ErrorResponse("invalid role name"), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := readRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		r = &role{}
	}
	if err := applyRoleFields(d, r); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	if err := b.validateRole(r); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	cfg, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("configure the engine before writing roles"), nil
	}
	if r.User == managementUser(cfg.TokenID) {
		return logical.ErrorResponse("credential roles cannot target the management user"), nil
	}
	client, err := b.clientLocked(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if err := client.validateRole(ctx, r); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	entry, err := logical.StorageEntryJSON("roles/"+name, r)
	if err != nil {
		return nil, fmt.Errorf("cannot encode role")
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) validateRole(r *role) error {
	if !validUser(r.User) {
		return fmt.Errorf("user must be a valid user@realm")
	}
	if r.AutoCreateUser && !strings.HasSuffix(r.User, "@pve") {
		return fmt.Errorf("auto-created users must use the pve realm")
	}
	if (r.PVERole == "") == (len(r.Privileges) == 0) {
		return fmt.Errorf("set exactly one of pve_role or privileges")
	}
	if r.PVERole != "" && !validIdentifier(r.PVERole) {
		return fmt.Errorf("invalid pve_role")
	}
	seen := make(map[string]bool, len(r.Privileges))
	for _, privilege := range r.Privileges {
		if !validIdentifier(privilege) || seen[privilege] {
			return fmt.Errorf("privileges must be unique valid PVE privilege names")
		}
		seen[privilege] = true
	}
	if r.ACLPath != "/" {
		if !strings.HasPrefix(r.ACLPath, "/") || strings.HasSuffix(r.ACLPath, "/") {
			return fmt.Errorf("acl_path must be a canonical absolute PVE path")
		}
		for _, segment := range strings.Split(strings.TrimPrefix(r.ACLPath, "/"), "/") {
			if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "!@%?#\\ \t\r\n") {
				return fmt.Errorf("acl_path must be a canonical absolute PVE path")
			}
		}
	}
	if r.TTL < 0 || r.MaxTTL < 0 {
		return fmt.Errorf("ttl and max_ttl cannot be negative")
	}
	if r.MaxTTL > 0 && r.TTL > r.MaxTTL {
		return fmt.Errorf("ttl cannot exceed max_ttl")
	}
	_, _, err := framework.CalculateTTL(b.System(), 0, time.Duration(r.TTL)*time.Second, 0, time.Duration(r.MaxTTL)*time.Second, 0, time.Time{})
	if err != nil {
		return fmt.Errorf("role TTLs cannot produce a bounded lease")
	}
	return nil
}

func roleFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name":             {Type: framework.TypeString, Description: "Role name."},
		"user":             {Type: framework.TypeString, Description: "PVE token owner, user@realm."},
		"auto_create_user": {Type: framework.TypeBool, Default: false, Description: "Create an engine-owned passwordless pve-realm user at credential issuance."},
		"pve_role":         {Type: framework.TypeString, Description: "Existing PVE role; mutually exclusive with privileges."},
		"privileges":       {Type: framework.TypeCommaStringSlice, Description: "PVE privileges for an engine-owned custom role; mutually exclusive with pve_role."},
		"acl_path":         {Type: framework.TypeString, Description: "Absolute PVE ACL path."},
		"propagate":        {Type: framework.TypeBool, Default: false, Description: "Propagate the token ACL to child paths."},
		"ttl":              {Type: framework.TypeDurationSecond, Description: "Default lease TTL; zero uses the mount default."},
		"max_ttl":          {Type: framework.TypeDurationSecond, Description: "Maximum lease TTL; zero uses the mount maximum."},
	}
}

func applyRoleFields(d *framework.FieldData, r *role) error {
	for field, target := range map[string]*string{"user": &r.User, "pve_role": &r.PVERole, "acl_path": &r.ACLPath} {
		if value, ok := d.Raw[field]; ok {
			text, ok := value.(string)
			if !ok {
				return fmt.Errorf("role fields must have their declared types")
			}
			*target = text
		}
	}
	if _, ok := d.Raw["privileges"]; ok {
		r.Privileges = d.Get("privileges").([]string)
	}
	if _, ok := d.Raw["auto_create_user"]; ok {
		r.AutoCreateUser = d.Get("auto_create_user").(bool)
	}
	if _, ok := d.Raw["propagate"]; ok {
		r.Propagate = d.Get("propagate").(bool)
	}
	if _, ok := d.Raw["ttl"]; ok {
		r.TTL = d.Get("ttl").(int)
	}
	if _, ok := d.Raw["max_ttl"]; ok {
		r.MaxTTL = d.Get("max_ttl").(int)
	}
	return nil
}
