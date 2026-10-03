package proxmox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	pve "github.com/luthermonson/go-proxmox"
)

type pveClient struct {
	api       *pve.Client
	transport *http.Transport
}

// The upstream client does not reject every unsuccessful HTTP status.
// Enforce that boundary without retaining or logging response bodies.
type statusTransport struct{ base http.RoundTripper }

func (t statusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, pve.ErrNotAuthorized
		}
		return nil, fmt.Errorf("unsuccessful PVE HTTP status %d", resp.StatusCode)
	}
	return resp, nil
}

func newPVEClient(cfg *config) (*pveClient, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("cannot load system CA certificates")
	}
	if cfg.CACert != "" && !roots.AppendCertsFromPEM([]byte(cfg.CACert)) {
		return nil, fmt.Errorf("cannot load configured CA certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	client := &http.Client{
		Transport: statusTransport{base: transport},
		Timeout:   cfg.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &pveClient{transport: transport, api: pve.NewClient(cfg.Endpoint,
		pve.WithAPIToken(cfg.TokenID, cfg.TokenSecret),
		pve.WithHTTPClient(client),
		// The upstream logger can print token response bodies at debug level.
		pve.WithLogger(&pve.LeveledLogger{}),
	)}, nil
}

func pveError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("PVE %s canceled or timed out", operation)
	}
	if pve.IsNotAuthorized(err) {
		return fmt.Errorf("PVE %s denied; check the management credential and permissions", operation)
	}
	// Do not wrap upstream errors: they can contain credential-bearing response bodies.
	return fmt.Errorf("PVE %s failed", operation)
}

func (c *pveClient) validateConfig(ctx context.Context, cfg *config) error {
	version, err := c.api.Version(ctx)
	if err != nil {
		return pveError("version read", err)
	}
	if version == nil || !strings.HasPrefix(version.Version, "9.") {
		return fmt.Errorf("this engine requires Proxmox VE 9")
	}
	user := managementUser(cfg.TokenID)
	var userInfo pve.User
	err = c.api.Get(ctx, "/access/users/"+url.PathEscape(user), &userInfo)
	if err != nil {
		return pveError("management user read", err)
	}
	_, token, _ := strings.Cut(cfg.TokenID, "!")
	var info pve.Token
	err = c.api.Get(ctx, "/access/users/"+url.PathEscape(user)+"/token/"+url.PathEscape(token), &info)
	if err != nil {
		return pveError("management token read", err)
	}
	if !bool(info.Privsep) {
		return fmt.Errorf("management token must use privilege separation")
	}
	return nil
}

func (c *pveClient) validateRole(ctx context.Context, r *role) error {
	var privileges pve.Permission
	if r.PVERole != "" {
		var err error
		privileges, err = c.api.Role(ctx, r.PVERole)
		if err != nil {
			return pveError("role read", err)
		}
		if len(privileges) == 0 {
			return fmt.Errorf("PVE role must grant at least one privilege")
		}
	} else {
		available, err := c.api.Role(ctx, "Administrator")
		if err != nil {
			return pveError("privilege catalog read", err)
		}
		privileges = make(pve.Permission, len(r.Privileges))
		for _, privilege := range r.Privileges {
			if _, ok := available[privilege]; !ok {
				return fmt.Errorf("privileges contains an unknown PVE privilege")
			}
			privileges[privilege] = true
		}
	}
	if r.AutoCreateUser {
		return nil
	}
	var userInfo pve.User
	if err := c.api.Get(ctx, "/access/users/"+url.PathEscape(r.User), &userInfo); err != nil {
		return pveError("role user read", err)
	}
	permissions, err := c.api.Permissions(ctx, &pve.PermissionsOptions{Path: r.ACLPath, UserID: r.User})
	if err != nil {
		return pveError("user permission read", err)
	}
	for privilege := range privileges {
		propagates, ok := permissions[r.ACLPath][privilege]
		if !ok || (r.Propagate && !bool(propagates)) {
			return fmt.Errorf("role user lacks the required permission ceiling at acl_path")
		}
	}
	return nil
}
