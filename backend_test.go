package proxmox

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// This fixture accepts authenticated reads only. Any provisioning request fails.
type pveFixture struct {
	server    *httptest.Server
	mu        sync.Mutex
	version   string
	privsep   bool
	fail      bool
	ceiling   bool
	propagate bool
	requests  int
	secret    string
}

func newFixture(t *testing.T, secret string) *pveFixture {
	t.Helper()
	f := &pveFixture{version: "9.0.3", privsep: true, ceiling: true, propagate: true, secret: secret}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests++
		if r.Method != http.MethodGet {
			t.Errorf("foundation attempted PVE mutation: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "PVEAPIToken=manager@pve!engine="+f.secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.fail {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, f.secret)
			return
		}
		var data interface{}
		switch r.URL.Path {
		case "/api2/json/version":
			data = map[string]string{"version": f.version, "release": "9.0"}
		case "/api2/json/access/users/manager@pve", "/api2/json/access/users/reader@pve":
			data = map[string]interface{}{"enable": 1}
		case "/api2/json/access/users/manager@pve/token/engine":
			data = map[string]interface{}{"privsep": f.privsep, "expire": 0}
		case "/api2/json/access/roles/PVEAuditor":
			data = map[string]int{"VM.Audit": 1}
		case "/api2/json/access/roles/Administrator":
			data = map[string]int{"VM.Audit": 1, "Sys.Audit": 1}
		case "/api2/json/access/roles/NoAccess":
			data = map[string]int{}
		case "/api2/json/access/permissions":
			if r.URL.Query().Get("userid") != "reader@pve" {
				t.Errorf("permission lookup used unexpected user")
			}
			privileges := map[string]bool{}
			if f.ceiling {
				privileges["VM.Audit"] = f.propagate
			}
			data = map[string]interface{}{r.URL.Query().Get("path"): privileges}
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"data": data}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *pveFixture) configData() map[string]interface{} {
	return map[string]interface{}{
		"endpoint": f.server.URL, "token_id": "manager@pve!engine", "token_secret": f.secret,
		"ca_cert": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})),
	}
}

func newTestBackend(t *testing.T) (*backend, *logical.InmemStorage) {
	t.Helper()
	s := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = s
	conf.System = &logical.StaticSystemView{DefaultLeaseTTLVal: time.Hour, MaxLeaseTTLVal: 24 * time.Hour}
	b, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Cleanup(context.Background()) })
	return b.(*backend), s
}

func request(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: path, Storage: s, Data: data})
	if err != nil {
		t.Fatalf("%s %s: %v", op, path, err)
	}
	return resp
}

func requireSuccess(t *testing.T, resp *logical.Response) {
	t.Helper()
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected response: %v", resp.Data)
	}
}

func requireError(t *testing.T, resp *logical.Response, secret string) {
	t.Helper()
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response")
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" && strings.Contains(string(encoded), secret) {
		t.Fatal("response disclosed management secret")
	}
}

func roleData() map[string]interface{} {
	return map[string]interface{}{"user": "reader@pve", "pve_role": "PVEAuditor", "acl_path": "/vms", "ttl": "15m", "max_ttl": "1h"}
}

func TestConfigSecretAndFailedUpdate(t *testing.T) {
	f := newFixture(t, "test-management-secret-A")
	b, s := newTestBackend(t)
	if request(t, b, s, logical.ReadOperation, "config", nil) != nil {
		t.Fatal("unconfigured read should be empty")
	}
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "config", f.configData()))
	resp := request(t, b, s, logical.ReadOperation, "config", nil)
	encoded, _ := json.Marshal(resp)
	if strings.Contains(string(encoded), f.secret) {
		t.Fatal("config read disclosed management secret")
	}
	if _, ok := resp.Data["token_secret"]; ok {
		t.Fatal("config read returned secret field")
	}
	if resp.Data["endpoint"] != f.server.URL+"/api2/json" {
		t.Fatal("endpoint not normalized")
	}
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "config", map[string]interface{}{"timeout": "45s"}))
	stored, err := readConfig(context.Background(), s)
	if err != nil || stored.TokenSecret != f.secret {
		t.Fatal("partial update lost secret")
	}
	oldClient := b.client
	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	requireError(t, request(t, b, s, logical.UpdateOperation, "config", map[string]interface{}{"timeout": "20s"}), f.secret)
	stored, err = readConfig(context.Background(), s)
	if err != nil || stored.Timeout != 45*time.Second || b.client != oldClient {
		t.Fatal("failed update changed stored configuration or client")
	}
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		value interface{}
	}{
		{"http", "endpoint", "http://pve.example.com"},
		{"userinfo", "endpoint", "https://user:password@pve.example.com"},
		{"query", "endpoint", "https://pve.example.com?secret=hidden"},
		{"path", "endpoint", "https://pve.example.com/other"},
		{"escaped-path", "endpoint", "https://pve.example.com/api2/%6ason"},
		{"identifier", "token_id", "manager@pve"},
		{"empty-secret", "token_secret", ""},
		{"secret-type", "token_secret", []string{"test-management-secret-A"}},
		{"newline", "token_secret", "test-management-secret-A\n"},
		{"timeout-low", "timeout", "0s"},
		{"timeout-high", "timeout", "6m"},
		{"ca", "ca_cert", "invalid"},
		{"unknown", "unexpected", "test-management-secret-A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "test-management-secret-A")
			b, s := newTestBackend(t)
			data := f.configData()
			data[tc.field] = tc.value
			requireError(t, request(t, b, s, logical.UpdateOperation, "config", data), f.secret)
			if entry, _ := s.Get(context.Background(), "config"); entry != nil {
				t.Fatal("invalid configuration persisted")
			}
		})
	}
	for _, tc := range []string{"version", "privsep", "untrusted-ca"} {
		t.Run(tc, func(t *testing.T) {
			f := newFixture(t, "test-management-secret-A")
			b, s := newTestBackend(t)
			data := f.configData()
			if tc == "version" {
				f.version = "8.4.1"
			}
			if tc == "privsep" {
				f.privsep = false
			}
			if tc == "untrusted-ca" {
				delete(data, "ca_cert")
			}
			requireError(t, request(t, b, s, logical.UpdateOperation, "config", data), f.secret)
		})
	}
}

func TestRolesCRUDAndPermissionCeiling(t *testing.T) {
	f := newFixture(t, "test-management-secret-A")
	b, s := newTestBackend(t)
	requireError(t, request(t, b, s, logical.UpdateOperation, "roles/reader", roleData()), f.secret)
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "config", f.configData()))
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/reader", roleData()))
	resp := request(t, b, s, logical.ReadOperation, "roles/reader", nil)
	if resp.Data["user"] != "reader@pve" || resp.Data["ttl"] != 900 {
		t.Fatal("role read mismatch")
	}
	resp = request(t, b, s, logical.ListOperation, "roles", nil)
	if keys := resp.Data["keys"].([]string); len(keys) != 1 || keys[0] != "reader" {
		t.Fatal("role list mismatch")
	}
	f.mu.Lock()
	f.propagate = false
	f.mu.Unlock()
	// A false propagation flag still grants the privilege at the exact ACL path.
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/reader", map[string]interface{}{"ttl": "10m"}))
	requireError(t, request(t, b, s, logical.UpdateOperation, "roles/reader", map[string]interface{}{"propagate": true}), f.secret)
	f.mu.Lock()
	f.ceiling = false
	f.mu.Unlock()
	requireError(t, request(t, b, s, logical.UpdateOperation, "roles/reader", map[string]interface{}{"ttl": "5m"}), f.secret)
	resp = request(t, b, s, logical.ReadOperation, "roles/reader", nil)
	if resp.Data["ttl"] != 600 {
		t.Fatal("failed role update persisted")
	}
	other := newFixture(t, "test-management-secret-B")
	requireError(t, request(t, b, s, logical.UpdateOperation, "config", other.configData()), f.secret)
	requireSuccess(t, request(t, b, s, logical.DeleteOperation, "roles/reader", nil))
	if request(t, b, s, logical.ReadOperation, "roles/reader", nil) != nil {
		t.Fatal("role was not deleted")
	}
	// No role remains; endpoint changes are safe at the foundation stage.
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "config", other.configData()))
}

func TestRoleValidation(t *testing.T) {
	f := newFixture(t, "test-management-secret-A")
	b, s := newTestBackend(t)
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "config", f.configData()))
	for _, tc := range []struct {
		name   string
		fields map[string]interface{}
	}{
		{"management-user", map[string]interface{}{"user": "manager@pve"}},
		{"invalid-user", map[string]interface{}{"user": "reader@pve!existing"}},
		{"auto-pam", map[string]interface{}{"user": "reader@pam", "auto_create_user": true}},
		{"both-privilege-inputs", map[string]interface{}{"privileges": []string{"VM.Audit"}}},
		{"no-privileges", map[string]interface{}{"pve_role": ""}},
		{"duplicates", map[string]interface{}{"pve_role": "", "privileges": []string{"VM.Audit", "VM.Audit"}}},
		{"unknown-privilege", map[string]interface{}{"pve_role": "", "privileges": []string{"VM.Nonexistent"}}},
		{"empty-pve-role", map[string]interface{}{"pve_role": "NoAccess"}},
		{"relative-path", map[string]interface{}{"acl_path": "vms"}},
		{"traversal", map[string]interface{}{"acl_path": "/vms/../access"}},
		{"trailing-slash", map[string]interface{}{"acl_path": "/vms/"}},
		{"encoded-path", map[string]interface{}{"acl_path": "/vms/%2f"}},
		{"negative-ttl", map[string]interface{}{"ttl": -1}},
		{"ttl-over-max", map[string]interface{}{"ttl": "2h"}},
		{"unknown-field", map[string]interface{}{"unexpected": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := roleData()
			for k, v := range tc.fields {
				data[k] = v
			}
			requireError(t, request(t, b, s, logical.UpdateOperation, "roles/invalid", data), f.secret)
			if entry, _ := s.Get(context.Background(), "roles/invalid"); entry != nil {
				t.Fatal("invalid role persisted")
			}
		})
	}
	data := roleData()
	data["pve_role"] = ""
	data["privileges"] = "VM.Audit"
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/explicit", data))
	data = roleData()
	data["user"] = "future@pve"
	data["auto_create_user"] = true
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/future", data))
}

func TestConcurrentMountIsolationAndInvalidation(t *testing.T) {
	a := newFixture(t, "test-management-secret-A")
	b := newFixture(t, "test-management-secret-B")
	first, firstStorage := newTestBackend(t)
	second, secondStorage := newTestBackend(t)
	var wg sync.WaitGroup
	for _, item := range []struct {
		b    *backend
		s    *logical.InmemStorage
		f    *pveFixture
		name string
	}{
		{first, firstStorage, a, "first"}, {second, secondStorage, b, "second"},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			requireSuccess(t, request(t, item.b, item.s, logical.UpdateOperation, "config", item.f.configData()))
			for range 10 {
				requireSuccess(t, request(t, item.b, item.s, logical.UpdateOperation, "roles/"+item.name, roleData()))
				requireSuccess(t, request(t, item.b, item.s, logical.ReadOperation, "config", nil))
			}
		}()
	}
	wg.Wait()
	if first.client == second.client {
		t.Fatal("mounts share client")
	}
	if request(t, first, firstStorage, logical.ReadOperation, "roles/second", nil) != nil {
		t.Fatal("mounts share roles")
	}
	old := first.client
	first.invalidate(context.Background(), "config")
	if first.client != nil {
		t.Fatal("config invalidation did not discard client")
	}
	requireSuccess(t, request(t, first, firstStorage, logical.UpdateOperation, "roles/first", roleData()))
	if first.client == old {
		t.Fatal("config invalidation did not rebuild client")
	}
}

func TestPrivateKeyInCABundleRejected(t *testing.T) {
	f := newFixture(t, "test-management-secret-A")
	b, s := newTestBackend(t)
	data := f.configData()
	data["ca_cert"] = data["ca_cert"].(string) + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(f.secret)}))
	requireError(t, request(t, b, s, logical.UpdateOperation, "config", data), f.secret)
	if entry, _ := s.Get(context.Background(), "config"); entry != nil {
		t.Fatal("private key bundle persisted")
	}
}

func TestManagementTokenNeverFollowsRedirect(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("management client followed redirect")
	}))
	defer target.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}))
	cfg := &config{Endpoint: origin.URL + "/api2/json", TokenID: "manager@pve!engine", TokenSecret: "test-management-secret-A", CACert: ca, Timeout: time.Second}
	client, err := newPVEClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.transport.CloseIdleConnections()
	if err := client.validateConfig(context.Background(), cfg); err == nil || strings.Contains(err.Error(), cfg.TokenSecret) {
		t.Fatal("redirect must fail without exposing management credential")
	}
}
