package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pve "github.com/luthermonson/go-proxmox"
	"github.com/openbao/openbao/api/v2"
)

// Opt in with BAO_TEST_BINARY and run from the repository development shell.
// This starts an isolated, loopback-only, in-memory server; it never uses ambient credentials.
func TestOpenBaoMounts(t *testing.T) {
	bao := os.Getenv("BAO_TEST_BINARY")
	if bao == "" {
		t.Skip("set BAO_TEST_BINARY to run real plugin registration and mount tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pluginName := "openbao-plugin-secrets-proxmox"
	binary := filepath.Join(dir, pluginName)
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/"+pluginName)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}
	content, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "server.hcl")
	if err := os.WriteFile(configFile, []byte(fmt.Sprintf("plugin_directory = %q\n", dir)), 0600); err != nil {
		t.Fatal(err)
	}
	server := exec.CommandContext(ctx, bao, "server", "-dev", "-dev-no-store-token", "-dev-root-token-id=foundation-test-root", "-dev-listen-address="+address, "-config="+configFile)
	server.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
	server.Stdout, server.Stderr = io.Discard, io.Discard
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	client, err := api.NewClient(&api.Config{Address: "http://" + address, HttpClient: &http.Client{Timeout: 5 * time.Second}, DisableEnvironment: true})
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("foundation-test-root")
	readyCtx, readyCancel := context.WithTimeout(ctx, 20*time.Second)
	defer readyCancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := client.Sys().HealthWithContext(readyCtx); err == nil {
			break
		}
		select {
		case <-readyCtx.Done():
			t.Fatal("local OpenBao server did not become ready")
		case <-ticker.C:
		}
	}
	if err := client.Sys().RegisterPluginWithContext(ctx, &api.RegisterPluginInput{Name: pluginName, Type: api.PluginTypeSecrets, Command: pluginName, SHA256: fmt.Sprintf("%x", digest)}); err != nil {
		t.Fatal(err)
	}
	first := newLifecycleFixture(t)
	second := newLifecycleFixture(t)
	second.secret = "synthetic-private-management-sentinel-B"
	second.secrets["manager@pve!engine"] = second.secret
	for _, mount := range []struct {
		name    string
		fixture *lifecycleFixture
	}{{"first", first}, {"second", second}} {
		if err := client.Sys().MountWithContext(ctx, mount.name, &api.MountInput{Type: pluginName}); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Logical().WriteWithContext(ctx, mount.name+"/config", mount.fixture.configData()); err != nil {
			t.Fatal("configuration write failed")
		}
		if _, err := client.Logical().WriteWithContext(ctx, mount.name+"/roles/"+mount.name, roleData()); err != nil {
			t.Fatal(err)
		}
		secret, err := client.Logical().ReadWithContext(ctx, mount.name+"/config")
		if err != nil || secret == nil {
			t.Fatal("configuration read failed")
		}
		if _, ok := secret.Data["token_secret"]; ok {
			t.Fatal("configuration disclosed secret field")
		}
		if secret.Data["endpoint"] != mount.fixture.server.URL+"/api2/json" {
			t.Fatal("configuration crossed mount boundary")
		}
		if strings.Contains(fmt.Sprint(secret.Data), mount.fixture.secret) {
			t.Fatal("configuration disclosed management secret")
		}
	}
	if secret, err := client.Logical().ReadWithContext(ctx, "first/roles/second"); err != nil || secret != nil {
		t.Fatal("roles crossed mount boundary")
	}
	first.mu.Lock()
	first.acl = append(first.acl, &pve.ACL{Path: "/", RoleID: "Administrator", Type: "token", UGID: "manager@pve!engine", Propagate: true})
	first.mu.Unlock()
	rotation, err := client.Logical().WriteWithContext(ctx, "first/config/rotate-root", map[string]interface{}{})
	if err != nil || rotation == nil || rotation.LeaseID != "" {
		t.Fatal("native management rotation did not complete without a credential lease")
	}
	rotatedID, ok := rotation.Data["token_id"].(string)
	if !ok || rotatedID == "manager@pve!engine" {
		t.Fatal("native management rotation did not replace the token")
	}
	first.mu.Lock()
	rotatedSecret := first.secrets[rotatedID]
	retired := first.secrets["manager@pve!engine"] == ""
	first.mu.Unlock()
	encodedRotation, err := json.Marshal(rotation)
	if err != nil || rotatedSecret == "" || !retired || strings.Contains(string(encodedRotation), rotatedSecret) {
		t.Fatal("native rotation did not privately replace and retire management credentials")
	}
	secondConfig, err := client.Logical().ReadWithContext(ctx, "second/config")
	if err != nil || secondConfig == nil || secondConfig.Data["token_id"] != "manager@pve!engine" {
		t.Fatal("native rotation crossed mount boundary")
	}
	if _, err := client.Logical().WriteWithContext(ctx, "first/static-roles/stable", staticData()); err != nil {
		t.Fatalf("native static provisioning failed: %v", err)
	}
	static, err := client.Logical().ReadWithContext(ctx, "first/static-creds/stable")
	if err != nil || static == nil || static.LeaseID != "" || static.Renewable || static.Data["secret"] == "" {
		t.Fatal("static credentials did not return an unleased token")
	}
	encodedStatic, err := json.Marshal(static)
	if err != nil || strings.Contains(string(encodedStatic), rotatedSecret) {
		t.Fatal("static response disclosed management credentials")
	}
	if absent, err := client.Logical().ReadWithContext(ctx, "second/static-creds/stable"); err != nil || absent != nil {
		t.Fatal("static credentials crossed mount boundary")
	}
	if _, err := client.Logical().WriteWithContext(ctx, "first/static-roles/stable", map[string]interface{}{"rotation_period": "2h"}); err != nil {
		t.Fatalf("native static rotation failed: %v", err)
	}
	replacement, err := client.Logical().ReadWithContext(ctx, "first/static-creds/stable")
	if err != nil || replacement == nil || replacement.Data["token_id_full"] == static.Data["token_id_full"] || first.tokenCount() != 1 {
		t.Fatal("native static rotation did not replace predecessor")
	}
	if _, err := client.Logical().DeleteWithContext(ctx, "first/static-roles/stable"); err != nil || first.tokenCount() != 0 {
		t.Fatalf("native static deletion failed: %v", err)
	}
	mint := func(c *api.Client, path string, fixture *lifecycleFixture) *api.Secret {
		t.Helper()
		secret, err := c.Logical().ReadWithContext(ctx, path)
		if err != nil || secret == nil || secret.LeaseID == "" || !secret.Renewable || secret.LeaseDuration <= 0 {
			t.Fatalf("dynamic issuance did not return a renewable lease: %v", err)
		}
		encoded, err := json.Marshal(secret)
		if err != nil || strings.Contains(string(encoded), fixture.secret) {
			t.Fatal("dynamic response disclosed management credentials")
		}
		fixture.mu.Lock()
		disclosed := false
		for id, value := range fixture.secrets {
			if strings.HasPrefix(id, "manager@pve!") && strings.Contains(string(encoded), value) {
				disclosed = true
			}
		}
		fixture.mu.Unlock()
		if disclosed {
			t.Fatal("dynamic response disclosed a rotated management credential")
		}
		if secret.Data["secret"] == "" || secret.Data["token_id_full"] == "" {
			t.Fatal("dynamic response omitted issued credentials")
		}
		return secret
	}
	waitForDeletion := func(fixture *lifecycleFixture, scenario string) {
		t.Helper()
		deletionCtx, deletionCancel := context.WithTimeout(ctx, 15*time.Second)
		defer deletionCancel()
		for fixture.tokenCount() != 0 {
			select {
			case <-deletionCtx.Done():
				t.Fatalf("%s did not delete the PVE token", scenario)
			case <-ticker.C:
			}
		}
	}
	issued := mint(client, "first/creds/first", first)
	if first.tokenCount() != 1 || second.tokenCount() != 0 {
		t.Fatal("issuance crossed mount boundary")
	}
	if _, err := client.Logical().DeleteWithContext(ctx, "first/roles/first"); err != nil {
		t.Fatal(err)
	}
	renewed, err := client.Sys().RenewWithContext(ctx, issued.LeaseID, 1200)
	if err != nil || renewed == nil || renewed.LeaseDuration <= 900 || renewed.LeaseDuration > 3600 {
		t.Fatalf("native renewal did not honor the original maximum: %v", err)
	}
	if err := client.Sys().RevokeWithContext(ctx, issued.LeaseID); err != nil {
		t.Fatal(err)
	}
	if first.tokenCount() != 0 {
		t.Fatal("native lease revocation did not delete the PVE token")
	}
	shortRole := roleData()
	shortRole["ttl"], shortRole["max_ttl"] = "5s", "10s"
	if _, err := client.Logical().WriteWithContext(ctx, "first/roles/short", shortRole); err != nil {
		t.Fatal(err)
	}
	mint(client, "first/creds/short", first)
	waitForDeletion(first, "OpenBao lease expiry")
	if err := client.Sys().PutPolicyWithContext(ctx, "mint-test", `path "second/creds/second" { capabilities = ["read"] }`); err != nil {
		t.Fatal(err)
	}
	parent, err := client.Auth().Token().CreateWithContext(ctx, &api.TokenCreateRequest{Policies: []string{"mint-test"}, TTL: "1m"})
	if err != nil || parent == nil || parent.Auth == nil {
		t.Fatalf("could not create test parent token: %v", err)
	}
	childClient, err := api.NewClient(&api.Config{Address: "http://" + address, HttpClient: &http.Client{Timeout: 5 * time.Second}, DisableEnvironment: true})
	if err != nil {
		t.Fatal(err)
	}
	childClient.SetToken(parent.Auth.ClientToken)
	mint(childClient, "second/creds/second", second)
	if err := client.Auth().Token().RevokeTreeWithContext(ctx, parent.Auth.ClientToken); err != nil {
		t.Fatal(err)
	}
	waitForDeletion(second, "parent token revocation")
	mint(client, "first/creds/short", first)
	mint(client, "second/creds/second", second)
	// Unmounting one multiplexed instance must leave the other operational.
	if err := client.Sys().UnmountWithContext(ctx, "first"); err != nil {
		t.Fatal(err)
	}
	if first.tokenCount() != 0 || second.tokenCount() != 1 {
		t.Fatal("unmount did not revoke only its own leases")
	}
	if secret, err := client.Logical().ReadWithContext(ctx, "second/roles/second"); err != nil || secret == nil {
		t.Fatal("remaining mount stopped after unmount")
	}
	if _, err := client.Logical().WriteWithContext(ctx, "second/roles/second", map[string]interface{}{"ttl": "10m"}); err != nil {
		t.Fatal(err)
	}
	if err := client.Sys().UnmountWithContext(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if second.tokenCount() != 0 {
		t.Fatal("final unmount did not delete its leased PVE token")
	}
}
