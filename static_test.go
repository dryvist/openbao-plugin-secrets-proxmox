package proxmox

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func staticData() map[string]interface{} {
	d := roleData()
	delete(d, "ttl")
	delete(d, "max_ttl")
	d["rotation_period"] = "1h"
	return d
}
func setupStatic(t *testing.T) (*backend, *logical.InmemStorage, *lifecycleFixture) {
	b, s, f := setupLifecycle(t)
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "static-roles/reader", staticData()))
	return b, s, f
}
func restartedRollback(t *testing.T, b *backend, s logical.Storage) {
	t.Helper()
	conf := logical.TestBackendConfig()
	conf.StorageView, conf.System = s, b.System()
	restarted, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Cleanup(context.Background()) })
	resp, err := restarted.HandleRequest(context.Background(), &logical.Request{Operation: logical.RollbackOperation, Storage: s, Data: map[string]interface{}{"immediate": true}})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("restart recovery failed: %v", err)
	}
}
func TestStaticScheduleAndDynamicIsolation(t *testing.T) {
	b, s, f := setupStatic(t)
	first := request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
	requireSuccess(t, first)
	again := request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
	requireSuccess(t, again)
	if first.Secret != nil || first.Data["secret"] != again.Data["secret"] || f.tokenCount() != 1 {
		t.Fatal("static read minted a credential or lease")
	}
	assertPrivate(t, s, first, f.secret)
	roleResp := request(t, b, s, logical.ReadOperation, "static-roles/reader", nil)
	requireSuccess(t, roleResp)
	if _, ok := roleResp.Data["secret"]; ok {
		t.Fatal("static role read disclosed credential")
	}
	r, err := readStaticRole(context.Background(), s, "reader")
	if err != nil {
		t.Fatal(err)
	}
	old := r.Credential.Record
	if old.ExpiresAt != 0 || old.StaticRole != "reader" {
		t.Fatal("static token has dynamic expiration")
	}
	dynamic := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	requireSuccess(t, dynamic)
	record, err := leaseRecord(&logical.Request{Secret: dynamic.Secret})
	if err != nil {
		t.Fatal(err)
	}
	record.ExpiresAt = time.Now().Unix() - 1
	if err := putRecord(context.Background(), s, tokenPrefix+record.TokenID, record); err != nil {
		t.Fatal(err)
	}
	if err := b.periodic(context.Background(), &logical.Request{Storage: s}); err != nil {
		t.Fatal(err)
	}
	if f.tokenCount() != 1 {
		t.Fatal("dynamic expiry retired static credential")
	}
	r.Credential.NextRotation = time.Now().Unix() - 1
	if err := putRecord(context.Background(), s, staticPrefix+"reader", r); err != nil {
		t.Fatal(err)
	}
	conf := logical.TestBackendConfig()
	conf.StorageView, conf.System = s, b.System()
	restarted, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Cleanup(context.Background()) })
	if err := restarted.(*backend).periodic(context.Background(), &logical.Request{Storage: s}); err != nil {
		t.Fatal(err)
	}
	next := request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
	requireSuccess(t, next)
	if next.Data["token_id_full"] == first.Data["token_id_full"] || f.tokenCount() != 1 {
		t.Fatal("scheduled rotation did not replace and retire")
	}
	f.mu.Lock()
	if f.secrets[old.fullID()] != "" || len(f.acl) != 1 || f.acl[0].UGID != next.Data["token_id_full"] {
		t.Fatal("rotation retained old secret or ACL")
	}
	f.mu.Unlock()
	wal, err := framework.ListWAL(context.Background(), s)
	if err != nil || len(wal) != 0 {
		t.Fatal("rotation left recovery records")
	}
	requireSuccess(t, request(t, b, s, logical.DeleteOperation, "static-roles/reader", nil))
	if f.tokenCount() != 0 {
		t.Fatal("static role deletion retained token")
	}
}

type rejectStaticStorage struct{ logical.Storage }

func (s rejectStaticStorage) Put(ctx context.Context, e *logical.StorageEntry) error {
	if strings.HasPrefix(e.Key, staticPrefix) {
		return errors.New("synthetic static commit failure")
	}
	return s.Storage.Put(ctx, e)
}
func TestStaticBeforeCommitRecovery(t *testing.T) {
	for _, scenario := range []string{"acl", "storage"} {
		t.Run(scenario, func(t *testing.T) {
			b, s, f := setupStatic(t)
			before := request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
			var storage logical.Storage = s
			if scenario == "storage" {
				storage = rejectStaticStorage{s}
			} else {
				f.mu.Lock()
				f.failMethod, f.failPath, f.failCount = http.MethodPut, "/access/acl", 1
				f.mu.Unlock()
			}
			resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "static-roles/reader", Storage: storage, Data: map[string]interface{}{"rotation_period": "2h"}})
			if err == nil || resp != nil || strings.Contains(err.Error(), f.secret) {
				t.Fatal("failed rotation disclosed credential or reported success")
			}
			current := request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
			if current.Data["secret"] != before.Data["secret"] || current.Data["rotation_period"] != before.Data["rotation_period"] {
				t.Fatal("failed replacement changed active credential")
			}
			assertPrivate(t, s, resp, before.Data["secret"].(string))
			restartedRollback(t, b, s)
			if f.tokenCount() != 1 {
				t.Fatal("recovery did not retain exactly the committed token")
			}
			current = request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
			if current.Data["token_id_full"] != before.Data["token_id_full"] {
				t.Fatal("recovery retired active credential")
			}
		})
	}
}
func TestStaticRetirementFailureRecovery(t *testing.T) {
	b, s, f := setupStatic(t)
	before := request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
	r, _ := readStaticRole(context.Background(), s, "reader")
	f.mu.Lock()
	f.failMethod, f.failPath, f.failCount = http.MethodDelete, strings.TrimPrefix(tokenPath(&r.Credential.Record), "/api2/json"), 1
	f.mu.Unlock()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "static-roles/reader", Storage: s, Data: map[string]interface{}{"rotation_period": "2h"}})
	if err == nil || resp != nil {
		t.Fatal("retirement failure reported success")
	}
	current := request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
	requireSuccess(t, current)
	if current.Data["token_id_full"] == before.Data["token_id_full"] || f.tokenCount() != 2 {
		t.Fatal("committed replacement was not retained")
	}
	assertPrivate(t, s, resp, current.Data["secret"].(string))
	restartedRollback(t, b, s)
	if f.tokenCount() != 1 {
		t.Fatal("restart did not retire previous credential")
	}
	next := request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
	if next.Data["secret"] != current.Data["secret"] {
		t.Fatal("restart removed committed replacement")
	}
}
func TestStaticOwnedUserDeletionRecovery(t *testing.T) {
	b, s, f := setupLifecycle(t)
	d := staticData()
	d["user"], d["auto_create_user"] = "staticowned@pve", true
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "static-roles/owned", d))
	r, _ := readStaticRole(context.Background(), s, "owned")
	f.mu.Lock()
	f.failMethod, f.failPath, f.failCount = http.MethodDelete, tokenPath(&r.Credential.Record), 1
	f.mu.Unlock()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.DeleteOperation, Path: "static-roles/owned", Storage: s})
	if err == nil || resp != nil {
		t.Fatal("deletion failure reported completion")
	}
	if r, _ := readStaticRole(context.Background(), s, "owned"); r != nil {
		t.Fatal("deletion intent retained readable credential")
	}
	restartedRollback(t, b, s)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.users["staticowned@pve"] != nil || len(f.tokens["staticowned@pve"]) != 0 || len(f.acl) != 0 {
		t.Fatal("owned static resources were not retired")
	}
	if f.users["manager@pve"] == nil || f.secrets["manager@pve!engine"] != f.secret {
		t.Fatal("deletion changed manager credential")
	}
}
func TestStaticStrictInputsAndManagementExclusion(t *testing.T) {
	b, s, f := setupLifecycle(t)
	for _, field := range []string{"ttl", "max_ttl", "secret", "unknown"} {
		d := staticData()
		d[field] = "1h"
		requireError(t, request(t, b, s, logical.UpdateOperation, "static-roles/bad", d), f.secret)
	}
	for _, period := range []string{"0s", "59s", "31622400s"} {
		d := staticData()
		d["rotation_period"] = period
		requireError(t, request(t, b, s, logical.UpdateOperation, "static-roles/bad", d), f.secret)
	}
	d := staticData()
	d["user"] = "manager@pve"
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "static-roles/bad", Storage: s, Data: d})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("management user was accepted")
	}
	assertPrivate(t, s, resp, f.secret)
	if f.tokenCount() != 0 {
		t.Fatal("invalid static role provisioned a token")
	}
}

type rejectWALDeleteStorage struct {
	logical.Storage
	rejected bool
}

func (s *rejectWALDeleteStorage) Delete(ctx context.Context, key string) error {
	if strings.HasPrefix(key, framework.WALPrefix) && !s.rejected {
		s.rejected = true
		return errors.New("synthetic WAL deletion failure")
	}
	return s.Storage.Delete(ctx, key)
}
func TestStaticCommittedWALRecovery(t *testing.T) {
	b, s, f := setupLifecycle(t)
	storage := &rejectWALDeleteStorage{Storage: s}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "static-roles/stable", Storage: storage, Data: staticData()})
	if err == nil || resp != nil {
		t.Fatal("failed WAL retirement reported success")
	}
	current := request(t, b, s, logical.ReadOperation, "static-creds/stable", nil)
	requireSuccess(t, current)
	restartedRollback(t, b, s)
	next := request(t, b, s, logical.ReadOperation, "static-creds/stable", nil)
	requireSuccess(t, next)
	if next.Data["secret"] != current.Data["secret"] || f.tokenCount() != 1 {
		t.Fatal("WAL recovery removed committed static credential")
	}
}

func TestStaticRecoveryDoesNotBlockOtherSchedules(t *testing.T) {
	b, s, f := setupStatic(t)
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "static-roles/healthy", staticData()))
	stalled, err := readStaticRole(context.Background(), s, "reader")
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failMethod, f.failPath, f.failCount = http.MethodDelete, tokenPath(&stalled.Credential.Record), 100
	f.mu.Unlock()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "static-roles/reader", Storage: s, Data: map[string]interface{}{"rotation_period": "2h"}})
	if err == nil || resp != nil {
		t.Fatal("expected pending retirement")
	}
	active, err := readStaticRole(context.Background(), s, "reader")
	if err != nil {
		t.Fatal(err)
	}
	activeID := active.Credential.Record.fullID()
	active.Credential.NextRotation = time.Now().Unix() - 1
	if err := putRecord(context.Background(), s, staticPrefix+"reader", active); err != nil {
		t.Fatal(err)
	}
	healthy, err := readStaticRole(context.Background(), s, "healthy")
	if err != nil {
		t.Fatal(err)
	}
	old := healthy.Credential.Record.fullID()
	healthy.Credential.NextRotation = time.Now().Unix() - 1
	if err := putRecord(context.Background(), s, staticPrefix+"healthy", healthy); err != nil {
		t.Fatal(err)
	}
	if err := b.periodic(context.Background(), &logical.Request{Storage: s}); err == nil {
		t.Fatal("pending retirement error was not reported")
	}
	current := request(t, b, s, logical.ReadOperation, "static-creds/healthy", nil)
	requireSuccess(t, current)
	if current.Data["token_id_full"] == old {
		t.Fatal("pending recovery blocked an unrelated due schedule")
	}
	retained := request(t, b, s, logical.ReadOperation, "static-creds/reader", nil)
	requireSuccess(t, retained)
	if retained.Data["token_id_full"] != activeID {
		t.Fatal("pending recovery allowed another replacement for the affected role")
	}
	assertPrivate(t, s, current, f.secret)
}
