package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	pve "github.com/luthermonson/go-proxmox"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func setupLifecycle(t *testing.T) (*backend, *logical.InmemStorage, *lifecycleFixture) {
	t.Helper()
	f := newLifecycleFixture(t)
	b, s := newTestBackend(t)
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "config", f.configData()))
	data := roleData()
	data["ttl"], data["max_ttl"] = "30s", "90s"
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/reader", data))
	return b, s, f
}

func operateLease(b *backend, s logical.Storage, issued *logical.Response, op logical.Operation) (*logical.Response, error) {
	return b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: "creds/reader", Storage: s, Secret: issued.Secret, Data: issued.Data})
}

func assertPrivate(t *testing.T, s logical.Storage, resp *logical.Response, secret string) {
	t.Helper()
	encoded, err := json.Marshal(resp)
	if err != nil || strings.Contains(string(encoded), secret) {
		t.Fatal("response disclosed management credential")
	}
	for _, prefix := range []string{tokenPrefix, userPrefix, framework.WALPrefix} {
		keys, err := s.List(context.Background(), prefix)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range keys {
			entry, err := s.Get(context.Background(), prefix+key)
			if err != nil || entry == nil {
				t.Fatal("cannot read recovery evidence")
			}
			if strings.Contains(string(entry.Value), secret) {
				t.Fatal("recovery evidence disclosed management credential")
			}
		}
	}
}

func TestDynamicLeaseIdentityAndSnapshot(t *testing.T) {
	b, s, f := setupLifecycle(t)
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	requireSuccess(t, issued)
	if issued == nil || issued.Secret == nil || !issued.Secret.Renewable || issued.Secret.TTL <= 0 || f.tokenCount() != 1 {
		t.Fatal("missing renewable token lease")
	}
	assertPrivate(t, s, issued, f.secret)
	record, err := leaseRecord(&logical.Request{Secret: issued.Secret})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if !bool(f.tokens[record.User][record.TokenID].Privsep) || len(f.acl) != 1 || f.acl[0].UGID != record.fullID() || f.acl[0].Path != "/vms" || bool(f.acl[0].Propagate) {
		t.Fatal("unexpected token privilege separation or ACL")
	}
	f.roles["PVEAuditor"]["Sys.Audit"] = true
	if f.roles[record.RoleID]["Sys.Audit"] {
		t.Fatal("mutable source role changed token privileges")
	}
	f.mu.Unlock()
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/reader", map[string]interface{}{"user": "reader@pve", "ttl": "60s", "max_ttl": "2h"}))
	requireSuccess(t, request(t, b, s, logical.DeleteOperation, "roles/reader", nil))
	issued.Secret.Increment = time.Hour
	renewed, err := operateLease(b, s, issued, logical.RenewOperation)
	if err != nil || renewed == nil || renewed.Secret.TTL > 90*time.Second {
		t.Fatalf("bounded renewal failed: %v", err)
	}
	stored, err := readTokenRecord(context.Background(), s, record.TokenID)
	if err != nil || stored.MaxTTL != 90 || stored.ExpiresAt > stored.IssuedAt+90 {
		t.Fatal("renewal expanded original maximum")
	}
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err != nil {
		t.Fatal(err)
	}
	if f.tokenCount() != 0 {
		t.Fatal("lease revoke did not delete token")
	}
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err != nil {
		t.Fatal("repeated revocation was not idempotent")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.acl) != 0 || f.roles[record.RoleID] != nil || f.users["reader@pve"] == nil {
		t.Fatal("cleanup left owned resources or removed external user")
	}
}

func TestDynamicProvisioningFailureAndRecovery(t *testing.T) {
	for _, scenario := range []string{"acl", "echo", "delete-retry"} {
		t.Run(scenario, func(t *testing.T) {
			b, s, f := setupLifecycle(t)
			f.mu.Lock()
			if scenario == "echo" {
				f.echoSecret = true
			} else {
				f.failMethod, f.failPath, f.failCount = http.MethodPut, "/access/acl", 1
			}
			f.mu.Unlock()
			if scenario == "delete-retry" {
				f.mu.Lock()
				f.echoSecret = true
				f.failMethod, f.failPath, f.failCount = http.MethodDelete, "/access/users/reader@pve/token/", 1
				f.mu.Unlock()
			}
			resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "creds/reader", Storage: s})
			if err == nil || resp != nil || strings.Contains(err.Error(), f.secret) {
				t.Fatal("failed provisioning produced credentials or an unsafe error")
			}
			assertPrivate(t, s, resp, f.secret)
			wal, err := framework.ListWAL(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "delete-retry" {
				if len(wal) != 1 || f.tokenCount() != 1 {
					t.Fatal("failed cleanup lost native recovery record")
				}
				resp = request(t, b, s, logical.RollbackOperation, "", map[string]interface{}{"immediate": true})
				requireSuccess(t, resp)
				wal, _ = framework.ListWAL(context.Background(), s)
			}
			if f.tokenCount() != 0 || len(wal) != 0 {
				t.Fatal("partial token was not cleaned up")
			}
		})
	}
}

func TestDynamicRevokeRetryAndInvalidCollection(t *testing.T) {
	b, s, f := setupLifecycle(t)
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	record, _ := leaseRecord(&logical.Request{Secret: issued.Secret})
	f.mu.Lock()
	f.failMethod, f.failPath, f.failCount = http.MethodDelete, "/access/users/reader@pve/token/", 1
	f.mu.Unlock()
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err == nil {
		t.Fatal("failed delete reported success")
	}
	if stored, _ := readTokenRecord(context.Background(), s, record.TokenID); stored == nil {
		t.Fatal("cleanup failure lost ownership evidence")
	}
	f.mu.Lock()
	f.nullTokens = true
	f.mu.Unlock()
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err == nil {
		t.Fatal("null token collection was treated as absence")
	}
	f.mu.Lock()
	f.nullTokens = false
	f.mu.Unlock()
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err != nil {
		t.Fatal(err)
	}
	if f.tokenCount() != 0 {
		t.Fatal("retry did not remove token")
	}
}

func TestDynamicRenewalRetry(t *testing.T) {
	b, s, f := setupLifecycle(t)
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	original, err := leaseRecord(&logical.Request{Secret: issued.Secret})
	if err != nil {
		t.Fatal(err)
	}
	issued.Secret.Increment = time.Minute
	f.mu.Lock()
	f.failMethod, f.failPath, f.failCount = http.MethodPut, "/access/users/reader@pve/token/", 1
	f.mu.Unlock()
	if _, err := operateLease(b, s, issued, logical.RenewOperation); err == nil {
		t.Fatal("upstream renewal failure reported success")
	}
	stored, err := readTokenRecord(context.Background(), s, original.TokenID)
	if err != nil || stored == nil || stored.ExpiresAt != original.ExpiresAt {
		t.Fatal("rejected renewal changed the committed cleanup deadline")
	}
	if _, err := operateLease(b, s, issued, logical.RenewOperation); err != nil {
		t.Fatalf("renewal retry failed: %v", err)
	}
}

type rejectTokenWriteStorage struct{ logical.Storage }

func (s rejectTokenWriteStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if strings.HasPrefix(entry.Key, tokenPrefix) {
		return errors.New("synthetic token record write failure")
	}
	return s.Storage.Put(ctx, entry)
}

func TestDynamicRenewalPersistenceFailure(t *testing.T) {
	b, s, f := setupLifecycle(t)
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/reader", map[string]interface{}{"ttl": "2s"}))
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	requireSuccess(t, issued)
	original, err := leaseRecord(&logical.Request{Secret: issued.Secret})
	if err != nil {
		t.Fatal(err)
	}
	issued.Secret.Increment = time.Minute
	resp, err := operateLease(b, rejectTokenWriteStorage{s}, issued, logical.RenewOperation)
	if err == nil || resp != nil || strings.Contains(err.Error(), f.secret) {
		t.Fatal("uncommitted renewal returned success or a management secret")
	}
	stored, err := readTokenRecord(context.Background(), s, original.TokenID)
	if err != nil || stored == nil || stored.ExpiresAt != original.ExpiresAt {
		t.Fatal("uncommitted renewal changed the cleanup deadline")
	}
	f.mu.Lock()
	remoteExpiry := int64(f.tokens[original.User][original.TokenID].Expire)
	f.mu.Unlock()
	if remoteExpiry <= original.ExpiresAt {
		t.Fatal("test did not exercise remote success before storage failure")
	}
	conf := logical.TestBackendConfig()
	conf.StorageView, conf.System = s, b.System()
	restarted, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Cleanup(context.Background()) })
	time.Sleep(time.Until(time.Unix(original.ExpiresAt, 0)) + 50*time.Millisecond)
	resp, err = restarted.HandleRequest(context.Background(), &logical.Request{Operation: logical.RollbackOperation, Storage: s})
	if err != nil || (resp != nil && resp.IsError()) || f.tokenCount() != 0 {
		t.Fatalf("restart did not clean up unacknowledged renewal: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.acl) != 0 || f.roles[original.RoleID] != nil {
		t.Fatal("unacknowledged renewal left ACL or role resources")
	}
}

func TestDynamicAutoUserAndPrivilegeList(t *testing.T) {
	b, s, f := setupLifecycle(t)
	data := map[string]interface{}{"user": "owned@pve", "auto_create_user": true, "privileges": []string{"VM.Audit"}, "acl_path": "/vms/100", "ttl": "30s", "max_ttl": "90s"}
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/owned", data))
	first := request(t, b, s, logical.ReadOperation, "creds/owned", nil)
	second := request(t, b, s, logical.ReadOperation, "creds/owned", nil)
	assertPrivate(t, s, first, f.secret)
	requireSuccess(t, request(t, b, s, logical.DeleteOperation, "roles/owned", nil))
	if _, err := operateLease(b, s, first, logical.RevokeOperation); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	present := f.users["owned@pve"] != nil
	f.mu.Unlock()
	if !present {
		t.Fatal("auto user removed while a credential depends on it")
	}
	if _, err := operateLease(b, s, second, logical.RevokeOperation); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	present = f.users["owned@pve"] != nil
	f.mu.Unlock()
	if present {
		t.Fatal("unreferenced owned user was not removed")
	}
	data["user"] = "reader@pve"
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/unowned", data))
	if resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "creds/unowned", Storage: s}); err == nil || resp != nil {
		t.Fatal("auto user adopted an external identity")
	}
}

func TestDynamicRestartAndRegistrationGap(t *testing.T) {
	b, s, f := setupLifecycle(t)
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	record, _ := leaseRecord(&logical.Request{Secret: issued.Secret})
	requireSuccess(t, request(t, b, s, logical.DeleteOperation, "roles/reader", nil))
	other := newLifecycleFixture(t)
	requireError(t, request(t, b, s, logical.UpdateOperation, "config", other.configData()), f.secret)
	record.ExpiresAt = time.Now().Add(-time.Second).Unix()
	if err := putRecord(context.Background(), s, tokenPrefix+record.TokenID, record); err != nil {
		t.Fatal(err)
	}
	conf := logical.TestBackendConfig()
	conf.StorageView = s
	conf.System = b.System()
	restarted, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Cleanup(context.Background()) })
	resp, err := restarted.HandleRequest(context.Background(), &logical.Request{Operation: logical.RollbackOperation, Storage: s})
	if err != nil || (resp != nil && resp.IsError()) || f.tokenCount() != 0 {
		t.Fatalf("persisted recovery failed: %v", err)
	}
}

func TestDynamicUnrelatedUserSyntax(t *testing.T) {
	b, s, f := setupLifecycle(t)
	f.mu.Lock()
	f.users["ops+ci@pve"] = &pve.User{UserID: "ops+ci@pve", Enable: true}
	f.mu.Unlock()
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	requireSuccess(t, issued)
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err != nil {
		t.Fatalf("unrelated user prevented revocation: %v", err)
	}
	data := roleData()
	data["user"], data["auto_create_user"] = "owned@pve", true
	requireSuccess(t, request(t, b, s, logical.UpdateOperation, "roles/owned", data))
	issued = request(t, b, s, logical.ReadOperation, "creds/owned", nil)
	requireSuccess(t, issued)
	record, err := leaseRecord(&logical.Request{Secret: issued.Secret})
	if err != nil {
		t.Fatal(err)
	}
	record.ExpiresAt = time.Now().Add(-time.Second).Unix()
	if err := putRecord(context.Background(), s, tokenPrefix+record.TokenID, record); err != nil {
		t.Fatal(err)
	}
	if err := b.periodic(context.Background(), &logical.Request{Storage: s}); err != nil {
		t.Fatalf("unrelated user prevented periodic cleanup: %v", err)
	}
	if f.tokenCount() != 0 {
		t.Fatal("unrelated user prevented token deletion")
	}
}

func TestDynamicMalformedUserCollection(t *testing.T) {
	for _, user := range []*pve.User{nil, {}} {
		b, s, f := setupLifecycle(t)
		issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
		requireSuccess(t, issued)
		f.mu.Lock()
		f.users["malformed"] = user
		f.mu.Unlock()
		if _, err := operateLease(b, s, issued, logical.RevokeOperation); err == nil || f.tokenCount() != 1 {
			t.Fatal("malformed user collection did not fail closed")
		}
		f.mu.Lock()
		delete(f.users, "malformed")
		f.mu.Unlock()
		if _, err := operateLease(b, s, issued, logical.RevokeOperation); err != nil {
			t.Fatalf("corrected user collection prevented retry: %v", err)
		}
	}
}

func TestDynamicMalformedRoleCollection(t *testing.T) {
	b, s, f := setupLifecycle(t)
	f.mu.Lock()
	f.nullRole = true
	f.mu.Unlock()
	if resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "creds/reader", Storage: s}); err == nil && !resp.IsError() {
		t.Fatal("malformed role collection did not block issuance")
	}
	f.mu.Lock()
	f.nullRole = false
	f.mu.Unlock()
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	requireSuccess(t, issued)
	f.mu.Lock()
	f.nullRole = true
	f.mu.Unlock()
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err == nil {
		t.Fatal("malformed role collection did not fail closed")
	}
	f.mu.Lock()
	f.nullRole = false
	f.mu.Unlock()
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err != nil {
		t.Fatalf("corrected role collection prevented retry: %v", err)
	}
}

func TestDynamicUnrelatedTokenSyntax(t *testing.T) {
	b, s, f := setupLifecycle(t)
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	requireSuccess(t, issued)
	external := "external-" + strings.Repeat("x", 80)
	f.mu.Lock()
	f.tokens["reader@pve"][external] = pve.Token{TokenID: external, Privsep: true}
	f.mu.Unlock()
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err != nil {
		t.Fatalf("unrelated token prevented revocation: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tokens["reader@pve"]) != 1 || f.tokens["reader@pve"][external].TokenID != external {
		t.Fatal("revocation changed an unrelated token")
	}
}

func TestDynamicMalformedTokenEntry(t *testing.T) {
	b, s, f := setupLifecycle(t)
	issued := request(t, b, s, logical.ReadOperation, "creds/reader", nil)
	requireSuccess(t, issued)
	f.mu.Lock()
	f.tokens["reader@pve"]["malformed"] = pve.Token{}
	f.mu.Unlock()
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err == nil {
		t.Fatal("empty token identity did not fail closed")
	}
	f.mu.Lock()
	delete(f.tokens["reader@pve"], "malformed")
	f.mu.Unlock()
	if _, err := operateLease(b, s, issued, logical.RevokeOperation); err != nil {
		t.Fatalf("corrected token entry prevented cleanup retry: %v", err)
	}
}
