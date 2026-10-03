package main

import (
	"fmt"
	"os"

	proxmox "github.com/dryvist/openbao-plugin-secrets-proxmox"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	meta := &api.PluginAPIClientMeta{}
	flags := meta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: proxmox.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(meta.GetTLSConfig()),
	}); err != nil {
		fmt.Fprintln(os.Stderr, "plugin server stopped")
		os.Exit(1)
	}
}
