package proxmox

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type config struct {
	Endpoint    string        `json:"endpoint"`
	TokenID     string        `json:"token_id"`
	TokenSecret string        `json:"token_secret"`
	CACert      string        `json:"ca_cert"`
	Timeout     time.Duration `json:"timeout"`
}

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		Fields: map[string]*framework.FieldSchema{
			"endpoint":     {Type: framework.TypeString, Description: "HTTPS Proxmox endpoint, optionally ending in /api2/json."},
			"token_id":     {Type: framework.TypeString, Description: "Dedicated management token ID: user@realm!token."},
			"token_secret": {Type: framework.TypeString, Description: "Management token secret; write-only.", DisplayAttrs: &framework.DisplayAttributes{Sensitive: true}},
			"ca_cert":      {Type: framework.TypeString, Description: "Optional PEM CA certificates in addition to system roots."},
			"timeout":      {Type: framework.TypeDurationSecond, Default: 30, Description: "Request timeout, between 1s and 5m."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.configRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.configWrite, ForwardPerformanceStandby: true, ForwardPerformanceSecondary: true},
		},
		HelpSynopsis: "Configure the engine's private management credential.",
	}
}

func readConfig(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, fmt.Errorf("cannot read stored configuration")
	}
	if entry == nil {
		return nil, nil
	}
	var cfg config
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("cannot decode stored configuration")
	}
	return &cfg, nil
}

func (b *backend) configRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	cfg, err := readConfig(ctx, req.Storage)
	if err != nil || cfg == nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]interface{}{
		"endpoint": cfg.Endpoint, "token_id": cfg.TokenID, "ca_cert": cfg.CACert, "timeout": int(cfg.Timeout.Seconds()),
	}}, nil
}

func (b *backend) configWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := d.ValidateStrict(); err != nil {
		return logical.ErrorResponse("invalid configuration fields"), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	previous, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	cfg := config{Timeout: 30 * time.Second}
	if previous != nil {
		cfg = *previous
	}
	for name, target := range map[string]*string{"endpoint": &cfg.Endpoint, "token_id": &cfg.TokenID, "token_secret": &cfg.TokenSecret, "ca_cert": &cfg.CACert} {
		if value, ok := d.Raw[name]; ok {
			text, ok := value.(string)
			if !ok {
				return logical.ErrorResponse("configuration fields must have their declared types"), nil
			}
			*target = text
		}
	}
	if _, ok := d.Raw["timeout"]; ok {
		cfg.Timeout = time.Duration(d.Get("timeout").(int)) * time.Second
	}
	if err := cfg.validate(); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}
	if previous != nil && (previous.Endpoint != cfg.Endpoint || managementUser(previous.TokenID) != managementUser(cfg.TokenID)) {
		roles, err := req.Storage.List(ctx, "roles/")
		if err != nil {
			return nil, err
		}
		if len(roles) > 0 {
			return logical.ErrorResponse("endpoint and management user cannot change while roles exist"), nil
		}
	}
	client, err := newPVEClient(&cfg)
	if err != nil {
		return logical.ErrorResponse("cannot initialize PVE client"), nil
	}
	if err := client.validateConfig(ctx, &cfg); err != nil {
		client.transport.CloseIdleConnections()
		return logical.ErrorResponse("%s", err), nil
	}
	entry, err := logical.StorageEntryJSON("config", &cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot encode configuration")
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		client.transport.CloseIdleConnections()
		return nil, fmt.Errorf("cannot persist configuration")
	}
	if b.client != nil {
		b.client.transport.CloseIdleConnections()
	}
	b.client = client
	return nil, nil
}

func (c *config) validate() error {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("endpoint must be an HTTPS URL without credentials, query, or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.Path = "/api2/json"
	}
	if u.Path != "/api2/json" || u.RawPath != "" {
		return fmt.Errorf("endpoint path must be /api2/json")
	}
	c.Endpoint = u.String()
	user, token, found := strings.Cut(c.TokenID, "!")
	if !found || !validUser(user) || !validIdentifier(token) {
		return fmt.Errorf("token_id must be user@realm!token with valid PVE identifiers")
	}
	if c.TokenSecret == "" || strings.ContainsAny(c.TokenSecret, "\r\n") {
		return fmt.Errorf("token_secret must be nonempty and contain no line breaks")
	}
	if c.Timeout < time.Second || c.Timeout > 5*time.Minute {
		return fmt.Errorf("timeout must be between 1s and 5m")
	}
	certificates := []byte(strings.TrimSpace(c.CACert))
	for len(certificates) > 0 {
		if !strings.HasPrefix(string(certificates), "-----BEGIN CERTIFICATE-----") {
			return fmt.Errorf("ca_cert must contain only PEM certificates")
		}
		block, rest := pem.Decode(certificates)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("ca_cert must contain only PEM certificates")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("ca_cert contains an invalid certificate")
		}
		certificates = []byte(strings.TrimSpace(string(rest)))
	}
	return nil
}

func managementUser(tokenID string) string {
	user, _, _ := strings.Cut(tokenID, "!")
	return user
}
