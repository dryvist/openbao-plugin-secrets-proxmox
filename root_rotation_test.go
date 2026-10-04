package proxmox

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	pve "github.com/luthermonson/go-proxmox"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func setupRootRotation(t *testing.T) (*backend, *logical.InmemStorage, *lifecycleFixture) {
	b, s, f := setupLifecycle(t)
	f.mu.Lock()
	f.acl = append(f.acl, &pve.ACL{Path: "/", RoleID: "Administrator", Type: "token", UGID: "manager@pve!engine", Propagate: true})
	f.mu.Unlock()
	return b, s, f
}

func TestRootRotationPrivateCredentialAndScope(t *testing.T) {
	b, s, f := setupRootRotation(t)
	resp := request(t, b, s, logical.UpdateOperation, "config/rotate-root", nil)
	requireSuccess(t, resp)
	cfg, err := readConfig(context.Background(), s)
	if err != nil || cfg.TokenID == "manager@pve!engine" || cfg.TokenSecret == f.secret {
		t.Fatal("management credential was not replaced")
	}
	assertPrivate(t, s, resp, cfg.TokenSecret)
	assertPrivate(t, s, request(t, b, s, logical.ReadOperation, "config", nil), cfg.TokenSecret)
	f.mu.Lock()
	if f.secrets["manager@pve!engine"] != "" || f.secrets[cfg.TokenID] != cfg.TokenSecret || len(f.acl) != 1 || f.acl[0].UGID != cfg.TokenID || f.acl[0].Path != "/" || f.acl[0].RoleID != "Administrator" || !bool(f.acl[0].Propagate) {
		t.Fatal("rotation did not preserve scope and retire the old credential")
	}
	f.mu.Unlock()
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	requireSuccess(t, issued)
	assertPrivate(t, s, issued, cfg.TokenSecret)
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err != nil {
		t.Fatalf("rotated management credential cannot revoke: %v", err)
	}
	wal, err := framework.ListWAL(context.Background(), s)
	if err != nil || len(wal) != 0 {
		t.Fatal("completed rotation left recovery records")
	}
}

func TestRootRotationRetirementFailureAndRestart(t *testing.T) {
	b, s, f := setupRootRotation(t)
	f.mu.Lock()
	f.failMethod, f.failPath, f.failCount = http.MethodDelete, "/access/users/manager@pve/token/engine", 1
	f.mu.Unlock()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: s})
	if err == nil || resp != nil || strings.Contains(err.Error(), f.secret) {
		t.Fatal("failed retirement reported completion or disclosed a credential")
	}
	cfg, err := readConfig(context.Background(), s)
	if err != nil || cfg.TokenID == "manager@pve!engine" {
		t.Fatal("verified replacement was not retained after retirement failure")
	}
	assertPrivate(t, s, resp, cfg.TokenSecret)
	requireError(t, request(t, b, s, logical.UpdateOperation, "config", map[string]interface{}{"timeout": "20s"}), cfg.TokenSecret)
	conf := logical.TestBackendConfig()
	conf.StorageView, conf.System = s, b.System()
	restarted, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Cleanup(context.Background()) })
	resp, err = restarted.HandleRequest(context.Background(), &logical.Request{Operation: logical.RollbackOperation, Storage: s, Data: map[string]interface{}{"immediate": true}})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("root rotation restart recovery failed: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.secrets["manager@pve!engine"] != "" || f.secrets[cfg.TokenID] != cfg.TokenSecret {
		t.Fatal("recovery retired the wrong management token")
	}
}

type rejectConfigStorage struct{ logical.Storage }

func (s rejectConfigStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if entry.Key == "config" {
		return errors.New("synthetic config write failure")
	}
	return s.Storage.Put(ctx, entry)
}

func TestRootRotationBeforeSwitchRecovery(t *testing.T) {
	for _, scenario := range []string{"acl", "verification", "storage"} {
		t.Run(scenario, func(t *testing.T) {
			b, s, f := setupRootRotation(t)
			var storage logical.Storage = s
			if scenario == "storage" {
				storage = rejectConfigStorage{s}
			} else {
				f.mu.Lock()
				f.failCount = 1
				if scenario == "acl" {
					f.failMethod, f.failPath = http.MethodPut, "/access/acl"
				} else {
					f.failMethod, f.failPath = http.MethodGet, "/version"
				}
				f.mu.Unlock()
			}
			resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "config/rotate-root", Storage: storage})
			if err == nil || resp != nil || strings.Contains(err.Error(), f.secret) {
				t.Fatal("failed rotation reported completion or disclosed a credential")
			}
			cfg, err := readConfig(context.Background(), s)
			if err != nil || cfg.TokenID != "manager@pve!engine" || cfg.TokenSecret != f.secret {
				t.Fatal("uncommitted replacement changed active configuration")
			}
			_, pending, err := pendingRootRotation(context.Background(), s)
			if err != nil || pending == nil {
				t.Fatal("failed rotation lost recovery identity")
			}
			f.mu.Lock()
			replacementSecret := f.secrets[pending.NewID]
			f.mu.Unlock()
			if replacementSecret == "" {
				t.Fatal("test did not create a replacement before failure")
			}
			assertPrivate(t, s, resp, replacementSecret)
			conf := logical.TestBackendConfig()
			conf.StorageView, conf.System = s, b.System()
			restarted, err := Factory(context.Background(), conf)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { restarted.Cleanup(context.Background()) })
			resp, err = restarted.HandleRequest(context.Background(), &logical.Request{Operation: logical.RollbackOperation, Storage: s, Data: map[string]interface{}{"immediate": true}})
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("uncommitted rotation recovery failed: %v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.secrets[pending.NewID] != "" || f.secrets[cfg.TokenID] != cfg.TokenSecret || len(f.acl) != 1 || f.acl[0].UGID != cfg.TokenID {
				t.Fatal("recovery did not retain the active token and remove the uncommitted replacement")
			}
		})
	}
}

func TestRootRotationUnrelatedTokenSyntax(t *testing.T) {
	b, s, f := setupRootRotation(t)
	external := "external-" + strings.Repeat("x", 80)
	f.mu.Lock()
	f.tokens["manager@pve"][external] = pve.Token{TokenID: external, Privsep: true}
	f.mu.Unlock()
	resp := request(t, b, s, logical.UpdateOperation, "config/rotate-root", nil)
	requireSuccess(t, resp)
	cfg, err := readConfig(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, s, resp, cfg.TokenSecret)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.tokens["manager@pve"]["engine"]; ok {
		t.Fatal("rotation did not retire predecessor")
	}
	if f.tokens["manager@pve"][external].TokenID != external {
		t.Fatal("rotation changed an unrelated management-user token")
	}
}
