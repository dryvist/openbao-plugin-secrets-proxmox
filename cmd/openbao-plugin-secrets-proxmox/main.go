package main

import (
	"os"

	proxmox "github.com/dryvist/openbao-plugin-secrets-proxmox"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{})
	meta := &api.PluginAPIClientMeta{}
	flags := meta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logger.Error("invalid plugin flags", "error", err)
		os.Exit(1)
	}
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: proxmox.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(meta.GetTLSConfig()),
	}); err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
