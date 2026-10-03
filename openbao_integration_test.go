package proxmox

import (
	"context"
	"crypto/sha256"
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

	"github.com/openbao/openbao/api/v2"
)

// Opt in with BAO_TEST_BINARY and run from the repository development shell.
// This starts an isolated, loopback-only, in-memory server; it never uses ambient credentials.
func TestOpenBaoMounts(t *testing.T) {
	bao := os.Getenv("BAO_TEST_BINARY")
	if bao == "" {
		t.Skip("set BAO_TEST_BINARY to run real plugin registration and mount tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
	first := newFixture(t, "test-management-secret-A")
	second := newFixture(t, "test-management-secret-B")
	for _, mount := range []struct {
		name    string
		fixture *pveFixture
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
	// Unmounting one multiplexed instance must leave the other operational.
	if err := client.Sys().UnmountWithContext(ctx, "first"); err != nil {
		t.Fatal(err)
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
}
